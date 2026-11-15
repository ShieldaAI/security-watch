import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store, readPilotReport, readPilotBackupReport, verifyBackup } from '../dist/index.js';
import { acquireLock } from '../dist/lock.js';

const WINDOW = { from: '2025-04-01', until: '2025-04-04' };
const START = Date.parse(WINDOW.from),
  END = Date.parse(WINDOW.until),
  DAY = 86_400_000;
const iso = (time) => new Date(time).toISOString();
const SECRET = 'PILOT_PRIVATE_OPERATOR_AND_WEBHOOK';
const fixture = (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-pilot-test-'));
  const path = join(dir, SECRET + '.db');
  const store = new Store(path);
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return { dir, path, store };
};
const evidence = (time, description = SECRET) => ({
  source: SECRET,
  id: SECRET,
  kind: 'advisory',
  title: SECRET,
  url: 'https://private.invalid/' + SECRET,
  description,
  aliases: [],
  severity: 'critical',
  modified_at: iso(time),
  fetched_at: iso(time),
  packages: [],
});
const finding = (id, time) => ({
  id: SECRET + id,
  event_id: SECRET,
  system_id: SECRET,
  component_id: SECRET,
  category: 'library',
  applicability: 'affected',
  source_severity: 'critical',
  priority: 'critical',
  title: SECRET,
  summary: SECRET,
  reasons: [SECRET],
  evidence_ids: [SECRET],
  urls: ['https://private.invalid/' + SECRET],
  exploited: false,
  updated_at: iso(time),
});
const decision = (action, channels = []) => ({ action, channels, reason: SECRET });
function snapshot(store) {
  return {
    jobs: store.jobs(),
    findings: store.findings(),
    reviews: store.reviews({ includeResolved: true }),
    budget: store.budgets(),
    evidence: store.evidence(),
  };
}
function assertPrivate(value) {
  const text = JSON.stringify(value);
  for (const secret of [
    SECRET,
    'private.invalid',
    'hooks.slack.com',
    'localhost:',
    'INJECT_',
    'api_key_env',
    '"reason"',
    '"payload"',
  ])
    assert(!text.includes(secret), secret);
}

test('half-open UTC window counts distinct retained revisions and groups each current job state by its owning revision', (t) => {
  const { store, path } = fixture(t);
  store.saveEvidence([evidence(START)], {});
  store.saveEvidence([{ ...evidence(START), fetched_at: iso(START + DAY) }], {});
  store.saveEvidence([evidence(START + 2 * DAY, SECRET + 'changed')], {});
  store.saveEvidence([evidence(END, SECRET + 'excluded')], {});
  store.saveAssessment(finding('outside', START - 1), decision('notify', ['slack']), START - 1);
  store.completeJob(store.claimDue(START - 1).id, 'accepted', START + 2 * DAY);
  const first = finding('first', START);
  store.saveAssessment(first, decision('notify', ['slack', 'email']), START);
  let claimed;
  while ((claimed = store.claimDue(START)))
    store.completeJob(claimed.id, claimed.channel === 'email' ? 'accepted' : 'unknown', END + 100, SECRET);
  store.saveAssessment(first, decision('notify', ['slack', 'email']), START + 100);
  store.saveAssessment({ ...first, withdrawn: true }, decision('record'), START + DAY);
  store.saveAssessment(finding('second', START + 2 * DAY), decision('digest', ['email']), START + 2 * DAY);
  store.saveAssessment(finding('exclusive', END), decision('notify', ['email']), END);
  const before = snapshot(store);
  const report = readPilotReport(path, WINDOW);
  assert.deepEqual(report.window, { ...WINDOW, days: 3 });
  assert.equal(report.activity.finding_revisions, 3);
  assert.equal(report.activity.distinct_findings, 2);
  assert.equal(report.activity.evidence_revisions, 2);
  assert.deepEqual(report.activity.decisions, { record: 1, digest: 1, notify: 1 });
  assert.deepEqual(
    report.activity.daily.map((row) => [row.date, row.evidence_revisions, row.finding_revisions]),
    [
      ['2025-04-01', 1, 1],
      ['2025-04-02', 0, 1],
      ['2025-04-03', 1, 1],
    ],
  );
  assert.deepEqual(report.activity.delivery_states_for_revisions, {
    pending: 1,
    sending: 0,
    accepted: 1,
    failed: 0,
    unknown: 1,
  });
  assert.deepEqual(report.snapshot.delivery_states, {
    pending: 2,
    sending: 0,
    accepted: 2,
    failed: 0,
    unknown: 1,
  });
  assert(Object.values(report.unmeasured).every((value) => value === null));
  assertPrivate(report);
  assert.deepEqual(snapshot(store), before);
});

test('review timing counts retained latest responses with a sample denominator and backlog separately', (t) => {
  const { store, path } = fixture(t);
  store.saveEvidence([evidence(START)], {});
  const open = (id, time) => {
    const entry = finding(id, time);
    store.saveAssessment(entry, { ...decision('digest'), review: 'ai_general_news' }, time);
    return entry.id;
  };
  const answer = (id, time, disposition) =>
    store.reviewFinding(id, 1, { disposition, reviewer: SECRET, reason: SECRET }, time);
  const first = open('1', START - 10);
  answer(first, START + 10, 'investigate');
  answer(first, START + 25, 'dismiss');
  const next = open('2', START + 100);
  answer(next, START + 200, 'investigate');
  const skew = open('3', START + 1000);
  answer(skew, START + 500, 'dismiss');
  const reassessed = open('4', START + 2000);
  answer(reassessed, START + 2100, 'investigate');
  answer(reassessed, END, 'dismiss');
  open('pending', END + 100);
  const r = readPilotReport(path, WINDOW);
  assert.deepEqual(r.activity.reviews, {
    opened: 3,
    latest_response_rows: 3,
    latency_samples: 2,
    invalid_latency_rows: 1,
    open_to_latest_response_p95_ms: 100,
  });
  assert.equal(r.snapshot.reviews.investigate, 1);
  assert.equal(r.snapshot.reviews.pending, 1);
  assert(r.snapshot.reviews.oldest_open_age_ms > 0);
  assertPrivate(r);
});

test('returns UTC-day model reservations and exposes unknown pricing without inferring actual spend', (t) => {
  const { store, path } = fixture(t);
  store.reserveBudget('2025-03-31', 9, 500, undefined, 1, 1);
  store.reserveBudget('2025-04-01', 9, 500, undefined, 10, 0.25);
  store.reserveBudget('2025-04-03', 9, 500, undefined, 20, undefined);
  store.reserveBudget('2025-04-04', 9, 500, undefined, 200, 4);
  const result = readPilotReport(path, WINDOW);
  assert.deepEqual(result.activity.model_reservations, {
    requests: 2,
    tokens: 30,
    unpriced_requests: 1,
    known_reserved_usd: 0.25,
    reserved_usd: null,
  });
  assert.equal(result.activity.days_with_retained_revisions, 0);
  assert.equal(result.unmeasured.actual_model_spend_usd, null);
  assert.equal(
    readPilotReport(path, { from: '2025-04-01', until: '2025-04-02' }).activity.model_reservations
      .reserved_usd,
    0.25,
  );
});

test('stored source health is re-evaluated at read time, independently of the activity window', (t) => {
  const { store, path } = fixture(t);
  const now = Date.now();
  store.setMeta(
    'source:coverage',
    JSON.stringify([
      {
        source: SECRET,
        status: 'complete',
        freshness: 'stale',
        last_success_at: iso(now - 1000),
        fresh_until: iso(now + 60_000),
        errors: [SECRET],
      },
      {
        source: SECRET,
        status: 'partial',
        freshness: 'fresh',
        last_success_at: iso(START),
        fresh_until: iso(END),
        scope: SECRET,
      },
      { source: SECRET, status: 'failed', freshness: 'fresh', errors: [SECRET] },
    ]),
  );
  store.setMeta(
    'last_scan',
    JSON.stringify({
      started_at: iso(now - 5000),
      completed_at: iso(now - 1000),
      degraded: true,
      errors: [SECRET],
    }),
  );
  const r = readPilotReport(path, WINDOW);
  assert.deepEqual(r.snapshot.source_coverage, {
    receipts: 3,
    status: { complete: 1, partial: 1, failed: 1 },
    freshness: { fresh: 1, stale: 1, never: 1 },
  });
  assert.equal(r.snapshot.last_scan.duration_ms, 4000);
  assert.equal(r.snapshot.last_scan.degraded, true);
  assert(r.snapshot.last_scan.age_ms >= 1000);
  assert.equal(r.activity.finding_revisions, 0);
  assertPrivate(r);
});

test('empty and invalid date windows never imply zero missed cases, continuous coverage or measured latency', (t) => {
  const { path } = fixture(t);
  const empty = readPilotReport(path, WINDOW);
  assert.equal(empty.activity.days_with_retained_revisions, 0);
  assert.equal(empty.activity.reviews.open_to_latest_response_p95_ms, null);
  assert.equal(empty.snapshot.source_coverage, null);
  assert.equal(empty.snapshot.last_scan, null);
  assert.equal(empty.snapshot.reviews.oldest_open_age_ms, null);
  for (const [from, until] of [
    ['2025-02-30', '2025-03-04'],
    ['2025-01-01', '2025-02-02'],
    ['2025-04-01', '2025-04-01'],
    ['2040-01-01', '2040-01-02'],
    ['2025-04-01T10:00Z', '2025-04-02'],
    [SECRET, '2025-04-02'],
  ])
    assert.throws(
      () => readPilotReport(path, { from, until }),
      (error) => error.message.includes('complete UTC days') && !error.message.includes(SECRET),
    );
  let reads = 0;
  const mutable = {
    get from() {
      return ++reads === 1 ? WINDOW.from : SECRET;
    },
    until: WINDOW.until,
  };
  assert.equal(readPilotReport(path, mutable).window.from, WINDOW.from);
  assert.equal(reads, 1);
});

test('a live WAL commit during reporting cannot mix revisions and receipt cohorts across one read snapshot', (t) => {
  const { store, path } = fixture(t);
  store.saveAssessment(finding('before', START), decision('notify', ['slack']), START);
  const release = acquireLock(path);
  const prepare = DatabaseSync.prototype.prepare;
  let committed = false;
  const intercept = t.mock.method(DatabaseSync.prototype, 'prepare', function (sql, ...rest) {
    if (!committed && typeof sql === 'string' && sql.includes('COUNT(DISTINCT finding_id)')) {
      committed = true;
      store.saveAssessment(finding('during', START + 100), decision('notify', ['slack']), START + 100);
    }
    return prepare.call(this, sql, ...rest);
  });
  try {
    const report = readPilotReport(path, WINDOW);
    assert(committed);
    assert.equal(report.activity.finding_revisions, 1);
    assert.equal(report.activity.distinct_findings, 1);
    assert.equal(report.snapshot.delivery_states.pending, 1);
    assert.equal(readPilotReport(path, WINDOW).snapshot.delivery_states.pending, 2);
  } finally {
    intercept.mock.restore();
    release();
  }
});

test('verified backup path keeps the original standalone and never infers live ages from stored state', async (t) => {
  const { store, dir, path } = fixture(t);
  store.saveAssessment(finding('review', START), { ...decision('digest'), review: 'ai_general_news' }, START);
  store.setMeta('last_scan', JSON.stringify({ at: iso(START), degraded: false }));
  store.setMeta(
    'source:coverage',
    JSON.stringify([
      { source: SECRET, status: 'complete', last_success_at: iso(START), fresh_until: iso(START + 1000) },
    ]),
  );
  const backup = join(dir, 'verified.db');
  await store.backup(backup);
  const original = readFileSync(backup);
  const r = await readPilotBackupReport(backup, WINDOW);
  assert.equal(r.snapshot.source, 'verified_backup');
  assert.equal(r.snapshot.reviews.pending, 1);
  assert.equal(r.snapshot.reviews.oldest_open_age_ms, null);
  assert.equal(r.snapshot.source_coverage.freshness, null);
  assert.equal(r.snapshot.last_scan.age_ms, null);
  assert.equal(r.snapshot.last_scan.degraded, false);
  assert.deepEqual(original, readFileSync(backup));
  for (const suffix of ['-wal', '-shm', '-journal']) assert(!existsSync(backup + suffix));
  assert((await verifyBackup(backup)).ok);
  await assert.rejects(readPilotBackupReport(path, WINDOW), (error) => !error.message.includes(SECRET));
  if (process.platform !== 'win32') {
    chmodSync(backup, 0o644);
    await assert.rejects(readPilotBackupReport(backup, WINDOW));
  }
});

test('missing, outdated, unsafe linked and over-permissive databases fail without migration or secret-bearing errors', (t) => {
  const { store, path, dir } = fixture(t);
  const rejects = (file) =>
    assert.throws(
      () => readPilotReport(file, WINDOW),
      (error) => !error.message.includes(SECRET) && error.message.includes('database'),
    );
  const missing = join(dir, 'missing-' + SECRET);
  rejects(missing);
  assert(!existsSync(missing));
  const sym = join(dir, 'symlink');
  symlinkSync(path, sym);
  rejects(sym);
  const hard = join(dir, 'hardlink');
  linkSync(path, hard);
  rejects(hard);
  rmSync(hard);
  if (process.platform !== 'win32') {
    chmodSync(path, 0o644);
    rejects(path);
    chmodSync(path, 0o600);
  }
  const legacy = join(dir, 'legacy.db');
  const db = new DatabaseSync(legacy);
  db.exec('PRAGMA user_version=4');
  db.close();
  chmodSync(legacy, 0o600);
  rejects(legacy);
  const check = new DatabaseSync(legacy, { readOnly: true });
  try {
    assert.equal(check.prepare('PRAGMA user_version').get().user_version, 4);
  } finally {
    check.close();
  }
  assert.deepEqual(store.jobs(), []);
});

test('oversized cohorts and unsupported or oversized stored values fail with content-free errors', (t) => {
  const { store, path } = fixture(t);
  const bad = (pattern) =>
    assert.throws(
      () => readPilotReport(path, WINDOW),
      (error) => pattern.test(error.message) && !error.message.includes(SECRET),
    );
  store.setMeta('source:coverage', JSON.stringify([{ status: SECRET }]));
  bad(/validate/);
  store.setMeta('source:coverage', '[' + ' '.repeat(1024 * 1024) + ']');
  bad(/size limit/);
  store.setMeta('source:coverage', '[]');
  store.reserveBudget('2025-04-01', 1, 100, undefined, 10, undefined);
  store.setMeta('unpriced:2025-04-01', SECRET.repeat(100));
  bad(/validate/);
  store.setMeta('unpriced:2025-04-01', '1');
  const db = new DatabaseSync(path);
  try {
    db.exec(`WITH RECURSIVE ids(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM ids WHERE x<100001)
    INSERT INTO evidence_revisions(source,id,content_hash,payload,recorded_at) SELECT 'source',x,'hash','{}',${START} FROM ids`);
    bad(/size limit/);
  } finally {
    db.close();
  }
});

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const noNetwork =
  'data:text/javascript,' +
  encodeURIComponent(
    "import http from 'node:http';import https from 'node:https';import net from 'node:net';import {syncBuiltinESMExports} from 'node:module';const fail=()=>{throw new Error('EXTERNAL_CALL_FORBIDDEN')};http.request=fail;https.request=fail;net.createConnection=fail;globalThis.fetch=fail;syncBuiltinESMExports();",
  );
const run = (args, cwd) =>
  spawnSync(process.execPath, ['--import', noNetwork, cli, 'pilot-report', ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 10000,
  });
test('installed CLI contract refuses credentials, output collisions and sidecars; exports only private aggregates', async (t) => {
  const { store, path, dir } = fixture(t);
  store.saveAssessment(finding('cli', START), decision('notify', ['slack']), START);
  const backup = join(dir, 'for-report.db');
  await store.backup(backup);
  const args = ['--backup', backup, '--from', WINDOW.from, '--until', WINDOW.until];
  const out = join(dir, 'report.json');
  const result = run([...args, '--output', out], dir);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  const content = readFileSync(out, 'utf8');
  assertPrivate(JSON.parse(content));
  if (process.platform !== 'win32') assert.equal(statSync(out).mode & 0o777, 0o600);
  symlinkSync(out, join(dir, 'linked.json'));
  symlinkSync(dir, join(dir, 'alias'), 'dir');
  for (const flags of [
    ['--credentials-file', SECRET],
    ['--config', SECRET],
    ['--notify'],
    ['--database', path],
    ['--output', out],
    ['--output', 'linked.json'],
    ['--output', join(dir, 'alias', 'for-report.db-wal')],
  ]) {
    const denied = run([...args, ...flags], dir);
    assert.equal(denied.status, 1);
    assert.equal(denied.stdout, '');
    assert(!denied.stderr.includes(SECRET));
  }
  assert.equal(readFileSync(out, 'utf8'), content);
  assert(!existsSync(backup + '-wal'));
  assert(!readdirSync(dir).some((name) => name.startsWith('.pilot-report-')));
  const live = run(['--database', path, '--from', WINDOW.from, '--until', WINDOW.until], dir);
  assert.equal(live.status, 0, live.stderr);
  const report = JSON.parse(live.stdout);
  assertPrivate(report);
  assert.equal(report.snapshot.source, 'monitor_database');
});
