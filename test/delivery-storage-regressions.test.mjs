import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs, { chmodSync, existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { DatabaseSync } from 'node:sqlite';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseConfig } from '../dist/config.js';
import { deliverPending, smtpProblem } from '../dist/delivery.js';
import { decide } from '../dist/assessment.js';
import { Store, SCHEMA_VERSION } from '../dist/store.js';
import { NetworkError } from '../dist/http.js';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const now = Date.parse('2026-11-13T10:00:00Z');
const assessment = (extra = {}) => ({
  id: 'F1',
  event_id: 'CVE-2026-50001',
  system_id: 'prod',
  component_id: 'alpha',
  category: 'library',
  applicability: 'affected',
  source_severity: 'critical',
  priority: 'critical',
  title: 'alpha remote code execution',
  summary: 'alpha in prod: affected.',
  reasons: [],
  evidence_ids: [],
  urls: [],
  exploited: false,
  updated_at: new Date(now).toISOString(),
  ...extra,
});
const emailConfig = (to) =>
  parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false },
    policy: { library: { levels: ['critical'], channels: ['email'] } },
    notifications: { email: { smtp_url_env: 'REGRESSION_SMTP', from: 'watch@example.org', to } },
  });
const slackConfig = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'REGRESSION_SLACK' } },
});
const credentials = {
  REGRESSION_SMTP: 'smtps://alerts:secret@mail.example.org',
  REGRESSION_SLACK: 'https://hooks.slack.com/services/T/B/x',
};
const noHttp = async () => {
  throw new Error('no network');
};
function queued(config, finding = assessment()) {
  const store = new Store(':memory:');
  store.saveAssessment(finding, decide(finding, config), now);
  return store;
}
const statuses = (store) => store.jobs().map((job) => [job.revision, job.status, job.last_error ?? '']);

test('an email receipt matches recipients whatever the letter case of their domain', async () => {
  for (const [configured, reported, expected] of [
    [['Ops@Example.ORG'], ['Ops@example.org'], 'accepted'],
    [['Ops@Example.ORG', 'sec@example.org'], ['Ops@example.org', 'sec@EXAMPLE.org'], 'accepted'],
    // The mailbox part is case-sensitive, and a missing recipient is still uncertain.
    [['Ops@example.org'], ['ops@example.org'], 'unknown'],
    [['ops@example.org', 'sec@example.org'], ['ops@example.org'], 'unknown'],
  ]) {
    const config = emailConfig(configured);
    const store = queued(config);
    const result = await deliverPending(
      store,
      config,
      noHttp,
      now,
      async () => ({ accepted: reported, rejected: [] }),
      undefined,
      credentials,
    );
    assert.equal(result[expected], 1, JSON.stringify([configured, reported]));
  }
});

test('an unusable SMTP address is a configuration failure, never an uncertain receipt', async () => {
  assert.equal(smtpProblem('smtps://alerts:secret@mail.example.org'), undefined);
  assert.equal(smtpProblem('smtp://mail.example.org:587'), undefined);
  assert.equal(smtpProblem('smtps://alerts:pa%25ss@mail.example.org'), undefined);
  for (const address of [
    'smtps://alerts:pa%ss@mail.example.org',
    'https://mail.example.org',
    'smtps://mail.example.org/path',
    'smtps://mail.example.org?x=1',
    'not a url',
  ])
    assert.match(smtpProblem(address), /^Invalid SMTP configuration/, address);

  const config = emailConfig(['ops@example.org']);
  const store = queued(config);
  let sent = 0;
  const result = await deliverPending(
    store,
    config,
    noHttp,
    now,
    async () => {
      sent++;
      return { accepted: [], rejected: [] };
    },
    undefined,
    { REGRESSION_SMTP: 'smtps://alerts:pa%ss@mail.example.org' },
  );
  assert.equal(sent, 0);
  assert.deepEqual(result, { accepted: 0, failed: 1, unknown: 0 });
  assert.match(statuses(store)[0][2], /percent-encoded/);
});

// What each SMTP failure becomes is tested against a real loopback server in smtp-outcomes.test.mjs.

test('acknowledging a revision the operator did not read is refused', () => {
  const store = queued(slackConfig);
  assert.equal(store.revisionOf('F1'), 1);
  assert.equal(store.revisionOf('missing'), undefined);
  const exploited = assessment({ exploited: true });
  store.saveAssessment(exploited, decide(exploited, slackConfig), now + 1000);
  assert.throws(() => store.acknowledge('F1', 1), /now at revision 2, not 1/);
  assert.ok(
    store.jobs().some((job) => job.revision === 2 && job.status === 'pending'),
    'the unseen revision still has its alert',
  );
  assert.equal(store.acknowledge('F1', 2), 2);
  assert.throws(() => store.acknowledge('missing'), /Finding not found/);
  const other = queued(slackConfig);
  assert.equal(other.acknowledge('F1'), 1);
});

test('a job superseded while it was being sent does not linger as pending after a failed attempt', async () => {
  const store = queued(slackConfig);
  const http = async () => {
    // A scan saves a new revision while this request is in flight.
    const exploited = assessment({ exploited: true });
    store.saveAssessment(exploited, decide(exploited, slackConfig), now);
    throw new NetworkError('CONNECTION_FAILED');
  };
  await deliverPending(store, slackConfig, http, now, undefined, undefined, credentials);
  const jobs = statuses(store);
  assert.deepEqual(
    jobs.filter(([revision]) => revision === 1).map(([, status, error]) => [status, error]),
    [['failed', 'Superseded by a newer assessment']],
  );
  assert.ok(jobs.some(([revision, status]) => revision === 2 && status === 'pending'));
});

test('a job taken back by another handle during a send is recorded as uncertain without stopping the worker', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'watch-displaced-'));
  try {
    const path = join(directory, 'watch.db');
    const store = new Store(path);
    const finding = assessment();
    store.saveAssessment(finding, decide(finding, slackConfig), now);
    const http = async () => {
      const second = new Store(path);
      second.recoverSending(now);
      second.close();
      return { status: 200, headers: {}, body: 'ok' };
    };
    const result = await deliverPending(store, slackConfig, http, now, undefined, undefined, credentials);
    assert.equal(result.unknown, 1);
    const [job] = store.jobs();
    assert.equal(job.status, 'unknown');
    assert.match(job.last_error, /receipt is unknown|Verify receipt/);
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('two processes opening an old database at once both finish on the current schema', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'watch-migrate-race-'));
  try {
    for (let round = 0; round < 6; round++) {
      const path = join(directory, `race-${round}.db`);
      const seed = new Store(path);
      seed.close();
      // Take the file back to schema 5: drop what steps 6 and 7 add.
      const raw = new DatabaseSync(path);
      raw.exec(
        'DROP INDEX IF EXISTS notifications_by_acceptance; ALTER TABLE notifications DROP COLUMN accepted_at; DROP TABLE ai_reviews; PRAGMA user_version = 5;',
      );
      raw.close();
      chmodSync(path, 0o600);
      const open = () =>
        new Promise((resolve) => {
          const child = spawn(
            process.execPath,
            [
              '--input-type=module',
              '-e',
              `import { Store } from ${JSON.stringify(new URL('../dist/store.js', import.meta.url).href)};
               try { new Store(${JSON.stringify(path)}).close(); console.log('ok'); } catch (error) { console.log('ERR ' + error.message); }`,
            ],
            { stdio: ['ignore', 'pipe', 'inherit'] },
          );
          let out = '';
          child.stdout.on('data', (chunk) => (out += chunk));
          child.on('close', () => resolve(out.trim()));
        });
      const results = await Promise.all([open(), open(), open()]);
      assert.deepEqual(results, ['ok', 'ok', 'ok'], `round ${round}`);
      const check = new DatabaseSync(path, { readOnly: true });
      assert.equal(check.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
      check.close();
      new Store(path).close();
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

// What made the test above fail on a macOS runner: SQLite deletes -wal and -shm when the last
// connection closes, and lstat in another process can still find the file, with no links left.
test('a sidecar another process is deleting is not taken for a hard link', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'watch-sidecar-race-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'watch.db');
  new Store(path).close();
  const real = fs.lstatSync;
  const sidecar =
    (links) =>
    (file, ...rest) => {
      const stat = real(file, ...rest);
      if (!String(file).endsWith('-wal') && !String(file).endsWith('-shm')) return stat;
      return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, { nlink: links });
    };
  t.after(() => {
    fs.lstatSync = real;
    syncBuiltinESMExports();
  });
  writeFileSync(`${path}-wal`, '', { mode: 0o600 });
  // Being deleted: no links left. The store opens.
  fs.lstatSync = sidecar(0);
  syncBuiltinESMExports();
  new Store(path).close();
  // A real second link is still refused.
  fs.lstatSync = sidecar(2);
  syncBuiltinESMExports();
  assert.throws(() => new Store(path), /without symbolic or hard links/);
});

test('a manual backup that fails verification leaves nothing at the requested path', () => {
  const directory = mkdtempSync(join(tmpdir(), 'watch-backup-verify-'));
  try {
    const systems = join(directory, 'systems.yaml');
    writeFileSync(
      systems,
      `systems:\n  - id: api\n    name: API\n    updated_at: ${new Date().toISOString()}\n    libraries: ["npm:alpha@1.0.0"]\n`,
    );
    const configFile = (name, maxBytes) => {
      const file = join(directory, name);
      writeFileSync(
        file,
        [
          'version: 1',
          'inventory: ./systems.yaml',
          'database: ./data/watch.db',
          'sources: { cve_now: false, hacker_news: false }',
          `maintenance: { interval_hours: 24, backup: { directory: ./backups, keep: 2, max_bytes: ${maxBytes} } }`,
          '',
        ].join('\n'),
        { mode: 0o600 },
      );
      return file;
    };
    const run = (...args) =>
      spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: 'utf8' });
    const fixture = join(directory, 'none.json');
    writeFileSync(fixture, '[]');
    const small = configFile('small.yaml', 1024);
    assert.equal(run('scan', '--config', small, '--fixture', fixture).status, 0);

    const refused = run('backup', '--config', small, '--output', 'out/first.db');
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /byte limit/);
    assert.equal(existsSync(join(directory, 'out', 'first.db')), false);
    assert.deepEqual(readdirSync(join(directory, 'out')), []);

    const large = configFile('large.yaml', 100_000_000);
    const accepted = run('backup', '--config', large, '--output', 'out/first.db');
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(existsSync(join(directory, 'out', 'first.db')), true);
    assert.equal(JSON.parse(accepted.stdout).backup_created, true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('doctor reports an unusable SMTP address and does not print feed addresses in full', () => {
  const directory = mkdtempSync(join(tmpdir(), 'watch-doctor-'));
  try {
    writeFileSync(
      join(directory, 'systems.yaml'),
      `systems:\n  - id: api\n    name: API\n    updated_at: ${new Date().toISOString()}\n`,
    );
    writeFileSync(
      join(directory, 'security-watch.yaml'),
      [
        'version: 1',
        'inventory: ./systems.yaml',
        'database: ./data/watch.db',
        'sources:',
        '  cve_now: false',
        '  hacker_news: false',
        '  feeds: ["https://feeds.example.org/private/${DOCTOR_FEED_TOKEN}/rss.xml"]',
        'policy: { library: { levels: [critical], channels: [email] } }',
        'notifications: { email: { smtp_url_env: DOCTOR_SMTP, from: watch@example.org, to: [ops@example.org] } }',
        '',
      ].join('\n'),
      { mode: 0o600 },
    );
    const result = spawnSync(process.execPath, [cli, 'doctor'], {
      cwd: directory,
      encoding: 'utf8',
      env: {
        ...process.env,
        DOCTOR_FEED_TOKEN: 'feed-token-canary',
        DOCTOR_SMTP: 'smtps://alerts:pa%ss-canary@mail.example.org',
      },
    });
    const report = JSON.parse(result.stdout);
    assert.equal(report.ok, false);
    assert.match(report.problems[0], /^DOCTOR_SMTP: Invalid SMTP configuration/);
    assert.deepEqual(report.sources.feeds, ['https://feeds.example.org/…']);
    assert.ok(!`${result.stdout}${result.stderr}`.includes('canary'));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
