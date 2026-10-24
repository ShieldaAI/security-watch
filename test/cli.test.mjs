import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  rmSync,
  statSync,
  chmodSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { acquireLock } from '../dist/lock.js';
import { Store } from '../dist/store.js';
import { parse } from 'yaml';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
// Fail closed if an offline fixture accidentally attempts any network request.
const noNetwork =
  'data:text/javascript,' +
  encodeURIComponent(
    "import http from 'node:http'; import https from 'node:https'; import {syncBuiltinESMExports} from 'node:module'; const fail=()=>{throw new Error('TEST_NETWORK_FORBIDDEN')}; http.request=fail; https.request=fail; globalThis.fetch=fail; syncBuiltinESMExports();",
  );
function run(args, cwd, extraEnv = {}) {
  const result = spawnSync(process.execPath, ['--import', noNetwork, cli, ...args], {
    cwd,
    env: { ...process.env, ...extraEnv },
    encoding: 'utf8',
    timeout: 8000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error) throw result.error;
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}
function fixture(t, overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-cli-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const now = new Date().toISOString();
  const config = {
    version: 1,
    inventory: './systems.json',
    database: './state/watch.db',
    sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false, feeds: [] },
    models: { enabled: false },
    policy: { library: { levels: ['critical'], channels: ['slack'] }, health_channels: [] },
    notifications: { slack: { webhook_url_env: 'WATCH_CLI_SLACK_TOKEN' } },
    ...overrides,
  };
  writeFileSync(join(dir, 'security-watch.yaml'), JSON.stringify(config));
  writeFileSync(
    join(dir, 'systems.json'),
    JSON.stringify({
      systems: [
        {
          id: 'prod',
          name: 'Production',
          environment: 'production',
          exposure: 'internet',
          criticality: 'high',
          updated_at: now,
          components: [{ id: 'parser', ecosystem: 'npm', name: 'test-parser', version: '1.0.0' }],
          products: [],
          keywords: [],
        },
      ],
    }),
  );
  const evidence = [
    {
      id: 'GHSA-test-test-test',
      source: 'github',
      kind: 'advisory',
      title: 'Test parser critical issue',
      url: 'https://example.com/advisory',
      description: 'Offline fixture only.',
      aliases: ['CVE-2026-12345'],
      severity: 'critical',
      modified_at: now,
      fetched_at: now,
      packages: [{ ecosystem: 'npm', name: 'test-parser', range: '<2.0.0', fixed: '2.0.0' }],
    },
  ];
  const evidencePath = join(dir, 'evidence.json');
  writeFileSync(evidencePath, JSON.stringify(evidence));
  return {
    dir,
    configPath: join(dir, 'security-watch.yaml'),
    db: join(dir, 'state/watch.db'),
    evidencePath,
    config,
  };
}
function scan(f, extra = []) {
  return run(['scan', '--fixture', f.evidencePath, ...extra], f.dir);
}
async function waitFor(fn, milliseconds = 6000) {
  const end = Date.now() + milliseconds;
  while (Date.now() < end) {
    if (fn()) return;
    await delay(25);
  }
  assert.fail('Timed out waiting for child process');
}
function worker(t, f, env = {}) {
  const child = spawn(process.execPath, ['--import', noNetwork, cli, 'start', '--config', f.configPath], {
    cwd: f.dir,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = { stdout: '', stderr: '' };
  child.stdout.on('data', (chunk) => {
    logs.stdout += chunk;
  });
  child.stderr.on('data', (chunk) => {
    logs.stderr += chunk;
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await delay(1100);
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }
  });
  return { child, logs };
}

test('providers lists supported protocols without configuration, credentials or network access', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-providers-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const result = run(['providers'], dir);
  assert.equal(result.code, 0, result.stderr);
  const providers = JSON.parse(result.stdout);
  for (const id of ['openai', 'anthropic', 'gemini', 'cohere', 'azure-openai', 'openai-compatible', 'ollama'])
    assert(
      providers.some((provider) => provider.id === id),
      id,
    );
  assert(!existsSync(join(dir, 'data')));
  assert.equal(run(['providers', '--notify'], dir).code, 1);
});

test('init --yes creates private config without overwriting existing user files', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-init-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const first = run(['init', '--yes'], dir);
  assert.equal(first.code, 0, first.stderr);
  const path = join(dir, 'security-watch.yaml');
  const initial = readFileSync(path, 'utf8');
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert(existsSync(join(dir, 'systems.yaml')));
  const second = run(['init', '--yes'], dir);
  assert.equal(second.code, 1);
  assert.match(second.stderr, /never overwrites/);
  assert.equal(readFileSync(path, 'utf8'), initial);
  assert(!existsSync(join(dir, 'data/watch.db')));
});

test('init creates a usable platform inventory, provider config and independent scan timing', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-setup-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const result = run(
    [
      'init',
      '--yes',
      '--systems',
      'nodejs,python,nodejs',
      '--provider',
      'openai',
      '--model',
      'test-model',
      '--poll-minutes',
      '30',
      '--lookback-minutes',
      '40',
    ],
    dir,
  );
  assert.equal(result.code, 0, result.stderr);
  const config = parse(readFileSync(join(dir, 'security-watch.yaml'), 'utf8'));
  const inventory = parse(readFileSync(join(dir, 'systems.yaml'), 'utf8'));
  assert.deepEqual(
    inventory.systems.map((s) => s.id),
    ['nodejs', 'python'],
  );
  assert(inventory.systems.every((s) => s.products.every((p) => p.version === undefined)));
  assert.equal(config.poll_interval_minutes, 30);
  assert.equal(config.news_lookback_minutes, 40);
  assert.equal(config.models.analysis.provider, 'openai');
  assert.equal(config.models.analysis.api_key_env, 'OPENAI_API_KEY');
  assert.deepEqual(config.policy.news.channels, []);
  assert.match(readFileSync(join(dir, '.env.example'), 'utf8'), /OPENAI_API_KEY=/);
  assert.equal(statSync(join(dir, '.env.example')).mode & 0o777, 0o600);
  assert.match(result.stdout, /--credentials-file/);
  const templates = JSON.parse(run(['templates'], dir).stdout);
  assert.equal(templates.length, 24);
  assert(templates.some((s) => s.id === 'python'));
});

test('invalid setup options fail before creating files', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-invalid-setup-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const args of [
    ['--systems', 'nodejs,unknown'],
    ['--systems', ''],
    ['--model', 'test-model'],
    ['--provider', 'unknown', '--model', 'test-model'],
    ['--provider', 'openai'],
    ['--poll-minutes', '0'],
    ['--lookback-minutes', '10081'],
  ]) {
    assert.equal(run(['init', '--yes', ...args], dir).code, 1, args.join(' '));
    assert(!existsSync(join(dir, 'security-watch.yaml')));
    assert(!existsSync(join(dir, 'systems.yaml')));
  }
});

test('explicit env files supply credentials as data without exposing values or evaluating shell text', (t) => {
  const f = fixture(t, {
    models: {
      enabled: true,
      analysis: { provider: 'openai', model: 'test-model', api_key_env: 'WATCH_SETUP_KEY' },
    },
  });
  const secret = 'synthetic-private-token';
  const envPath = join(f.dir, '.env');
  const marker = join(f.dir, 'must-not-exist');
  writeFileSync(
    envPath,
    `WATCH_SETUP_KEY=${secret}\nWATCH_CLI_SLACK_TOKEN=synthetic-webhook\nIGNORED_SHELL=$(touch ${marker})\n`,
    { mode: 0o600 },
  );
  const result = run(['doctor', '--credentials-file', envPath], f.dir, {
    WATCH_SETUP_KEY: undefined,
    WATCH_CLI_SLACK_TOKEN: undefined,
  });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).ok, true);
  assert(!result.stdout.includes(secret));
  assert(!result.stderr.includes(secret));
  assert(!existsSync(marker));
  assert(!existsSync(f.db));
  assert.equal(run(['providers', '--credentials-file', envPath], f.dir).code, 1);
});

test('env file access rejects shared permissions and symlinks, and preserves exported values', (t) => {
  const f = fixture(t, {
    models: {
      enabled: true,
      analysis: { provider: 'openai', model: 'test-model', api_key_env: 'WATCH_SETUP_KEY' },
    },
  });
  const envPath = join(f.dir, '.env');
  writeFileSync(envPath, 'WATCH_SETUP_KEY=\nWATCH_CLI_SLACK_TOKEN=\n', { mode: 0o600 });
  const inherited = {
    WATCH_SETUP_KEY: 'synthetic-exported-key',
    WATCH_CLI_SLACK_TOKEN: 'synthetic-exported-webhook',
  };
  assert.equal(run(['doctor', '--credentials-file', envPath], f.dir, inherited).code, 0);
  chmodSync(envPath, 0o644);
  assert.equal(run(['doctor', '--credentials-file', envPath], f.dir, inherited).code, 1);
  chmodSync(envPath, 0o600);
  const link = join(f.dir, 'linked.env');
  symlinkSync(envPath, link);
  assert.equal(run(['doctor', '--credentials-file', link], f.dir, inherited).code, 1);
  writeFileSync(envPath, 'NODE_TLS_REJECT_UNAUTHORIZED=0\n', { mode: 0o600 });
  assert.equal(run(['doctor', '--credentials-file', envPath], f.dir, inherited).code, 1);
  writeFileSync(envPath, 'node_tls_reject_unauthorized=0\n', { mode: 0o600 });
  assert.equal(run(['doctor', '--credentials-file', envPath], f.dir, inherited).code, 1);
  assert(!existsSync(f.db));
});

test(
  'env file loading rejects a named pipe without waiting for a writer',
  { skip: process.platform === 'win32' },
  (t) => {
    const f = fixture(t);
    const path = join(f.dir, 'credentials.pipe');
    const created = spawnSync('mkfifo', [path], { encoding: 'utf8', timeout: 2000 });
    assert.equal(created.status, 0, created.stderr);
    const result = run(['doctor', '--credentials-file', path], f.dir);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /regular private file/);
    assert(!existsSync(f.db));
  },
);

test('credential files cannot run Node preload code before validation', (t) => {
  const f = fixture(t);
  const envPath = join(f.dir, '.env');
  const marker = join(f.dir, 'preload-ran');
  const preload = join(f.dir, 'preload.mjs');
  writeFileSync(
    preload,
    `import {writeFileSync} from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'ran');`,
  );
  writeFileSync(envPath, `NODE_OPTIONS=--import=${preload}\n`, { mode: 0o600 });
  const result = run(['doctor', '--credentials-file', envPath], f.dir, { NODE_OPTIONS: undefined });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /runtime settings/);
  assert(!existsSync(marker));
  assert(!existsSync(f.db));
});

test('offline fixture dry-run previews findings without database, outbox or worker lock', (t) => {
  const f = fixture(t);
  const result = scan(f, ['--dry-run']);
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].applicability, 'affected');
  assert(!existsSync(f.db));
  assert(!existsSync(`${f.db}.lock`));
  assert(!existsSync(`${f.db}.worker-lock`));
  const conflict = scan(f, ['--dry-run', '--notify']);
  assert.equal(conflict.code, 1);
  assert.match(conflict.stderr, /cannot be combined/);
});

test('scan persists and replay deduplicates; configuration paths resolve from config directory', (t) => {
  const f = fixture(t);
  const other = join(f.dir, 'elsewhere');
  mkdirSync(other);
  const first = run(['scan', '--config', f.configPath, '--fixture', f.evidencePath], other);
  assert.equal(first.code, 0, first.stderr);
  const finding = JSON.parse(first.stdout).findings[0];
  assert.equal(finding.system_id, 'prod');
  assert(existsSync(f.db));
  assert(!existsSync(join(other, 'state/watch.db')));
  const replay = scan(f);
  assert.equal(replay.code, 0, replay.stderr);
  const jobs = JSON.parse(run(['deliveries'], f.dir).stdout);
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].status, 'pending');
  assert(!('payload' in jobs[0]));
  assert.equal(JSON.parse(run(['history', finding.id], f.dir).stdout).length, 1);
  assert(!existsSync(`${f.db}.lock`));
});

test('doctor reports variable names without exposing supplied secrets or making requests', (t) => {
  const f = fixture(t, {
    models: {
      enabled: true,
      analysis: { provider: 'openai', model: 'offline-test-model', api_key_env: 'WATCH_CLI_MODEL_SECRET' },
    },
  });
  const secret = 'DO_NOT_PRINT_MODEL_SECRET';
  const webhookSecret = 'DO_NOT_PRINT_SLACK_SECRET';
  const webhook = `https://hooks.slack.com/services/${webhookSecret}`;
  const ready = run(['doctor'], f.dir, { WATCH_CLI_MODEL_SECRET: secret, WATCH_CLI_SLACK_TOKEN: webhook });
  assert.equal(ready.code, 0, ready.stderr);
  assert.equal(JSON.parse(ready.stdout).ok, true);
  assert(!ready.stdout.includes(secret));
  assert(!ready.stdout.includes(webhookSecret));
  assert(!ready.stderr.includes(secret));
  assert(!ready.stderr.includes(webhookSecret));
  const missing = run(['doctor'], f.dir, { WATCH_CLI_MODEL_SECRET: '', WATCH_CLI_SLACK_TOKEN: '' });
  assert.equal(missing.code, 2);
  const report = JSON.parse(missing.stdout);
  assert(report.missing_environment_variables.includes('WATCH_CLI_MODEL_SECRET'));
  assert(!existsSync(f.db));
});

test('read commands and acknowledgement work while an exclusive worker lock is held', (t) => {
  const f = fixture(t);
  const report = scan(f);
  assert.equal(report.code, 0, report.stderr);
  const finding = JSON.parse(report.stdout).findings[0];
  const release = acquireLock(f.db);
  try {
    assert.equal(run(['status'], f.dir).code, 0);
    assert.equal(run(['findings'], f.dir).code, 0);
    const acknowledged = run(['acknowledge', finding.id], f.dir);
    assert.equal(acknowledged.code, 0, acknowledged.stderr);
    assert.equal(JSON.parse(run(['deliveries'], f.dir).stdout)[0].status, 'failed');
    const blocked = scan(f);
    assert.equal(blocked.code, 1);
    assert.match(blocked.stderr, /Another scan or worker/);
    const backup = run(['backup', '--output', join(f.dir, 'live-backup.db')], f.dir);
    assert.equal(backup.code, 0, backup.stderr);
  } finally {
    release();
  }
});

test('backup and history CLI retain findings, outbox, and evidence revisions', (t) => {
  const f = fixture(t);
  const result = scan(f);
  assert.equal(result.code, 0, result.stderr);
  const finding = JSON.parse(result.stdout).findings[0];
  const history = run(['history', finding.id], f.dir);
  assert.equal(history.code, 0, history.stderr);
  assert.equal(JSON.parse(history.stdout)[0].assessment.id, finding.id);
  const destination = join(f.dir, 'backup.db');
  const saved = run(['backup', '--output', destination], f.dir);
  assert.equal(saved.code, 0, saved.stderr);
  const restored = new Store(destination, { readOnly: true });
  try {
    assert.equal(restored.findings().length, 1);
    assert.equal(restored.jobs().length, 1);
    assert.equal(restored.history(finding.id).length, 1);
    assert.equal(restored.evidenceHistory('github', 'GHSA-test-test-test').length, 1);
  } finally {
    restored.close();
  }
  assert.equal(run(['backup', '--output', destination], f.dir).code, 1);
});

test('schema initialization failure releases worker lock before returning an error', (t) => {
  const f = fixture(t);
  mkdirSync(join(f.dir, 'state'));
  const db = new DatabaseSync(f.db);
  db.exec('PRAGMA user_version=999');
  db.close();
  const result = scan(f);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /newer than supported/);
  assert(!existsSync(`${f.db}.lock`));
  const release = acquireLock(f.db);
  release();
});

test('foreground worker continues with missing model credentials and disabled sources; SIGKILL releases ownership', async (t) => {
  const f = fixture(t, {
    models: {
      enabled: true,
      analysis: { provider: 'openai', model: 'offline-test-model', api_key_env: 'WATCH_CLI_MISSING_MODEL' },
    },
    policy: {
      library: { levels: ['critical'], channels: [] },
      news: { levels: ['high', 'critical'], channels: [] },
      product: { levels: ['high', 'critical'], channels: [] },
      health_channels: [],
    },
    notifications: {},
  });
  const { child, logs } = worker(t, f, { WATCH_CLI_MISSING_MODEL: '' });
  await waitFor(
    () => logs.stdout.includes('running in the foreground') && logs.stdout.includes('"degraded":true'),
  ).catch((error) => {
    t.diagnostic(JSON.stringify(logs));
    throw error;
  });
  assert.equal(child.exitCode, null);
  assert.match(logs.stderr, /Missing environment variables/);
  assert(!logs.stderr.includes('TEST_NETWORK_FORBIDDEN'));
  const status = run(['status'], f.dir);
  assert.equal(status.code, 0, status.stderr);
  assert.equal(JSON.parse(status.stdout).worker_lock, true);
  const findings = JSON.parse(run(['findings'], f.dir).stdout);
  const health = findings.find(
    (finding) => finding.event_id === 'health:credentials' && finding.active !== false,
  );
  assert(health, 'Missing credentials must remain an active health finding after the first scan');
  assert(JSON.parse(status.stdout).last_scan.errors.some((error) => error.source === 'credentials'));
  assert.equal(run(['acknowledge', health.id], f.dir).code, 0);
  child.kill('SIGKILL');
  await waitFor(() => child.signalCode !== null);
  const release = acquireLock(f.db);
  release();
  assert.equal(run(['unlock'], f.dir).code, 0);
});
