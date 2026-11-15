import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  readdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { runRehearsal, readRehearsal, parseConfig, Store, readFixture } from '../dist/index.js';
import { acquireLock } from '../dist/lock.js';

// Some tests compare what a rehearsal leaves in the temporary folder. Another process rehearsing at
// the same time (a second run of this suite) would be counted too, so this file gets its own folder.
const privateTemp = mkdtempSync(join(tmpdir(), 'watch-rehearsal-private-'));
process.env.TMPDIR = privateTemp;
process.on('exit', () => rmSync(privateTemp, { recursive: true, force: true }));

const NOW = Date.parse('2026-11-05T12:00:00Z');
const at = (offset = 0) => new Date(NOW + offset).toISOString();
const CANARY = 'PRIVATE_REHEARSAL_CANARY';
const inventory = () => ({
  systems: [
    {
      id: CANARY,
      name: CANARY,
      owner: CANARY,
      environment: CANARY,
      exposure: 'unknown',
      criticality: 'low',
      updated_at: at(),
      source_url: `https://private.invalid/${CANARY}`,
      configuration: { private: CANARY },
      components: [{ id: CANARY, ecosystem: 'npm', name: 'example-parser', version: '1.0.0' }],
      products: [],
      keywords: [],
    },
  ],
});
const evidence = (extra = {}) => ({
  id: CANARY,
  source: `osv:${CANARY}`,
  kind: 'advisory',
  title: CANARY,
  description: CANARY,
  url: `https://example.invalid/${CANARY}`,
  aliases: ['CVE-2099-99901'],
  severity: 'critical',
  modified_at: at(),
  fetched_at: at(),
  packages: [{ ecosystem: 'npm', name: 'example-parser', range: '<2.0.0' }],
  ...extra,
});
const config = (channels = ['slack', 'email']) =>
  parseConfig({
    version: 1,
    database: `/nonexistent/${CANARY}/live.db`,
    models: { enabled: true, analysis: { provider: 'openai', model: CANARY, api_key_env: CANARY } },
    sources: {
      cve_now: true,
      hacker_news: true,
      osv: true,
      github: true,
      kev: true,
      feeds: [`https://feed.invalid/${CANARY}`],
    },
    policy: {
      library: { levels: ['critical'], channels },
      news: { levels: ['critical'], channels },
      health_channels: [],
    },
    notifications: {
      slack: { webhook_url_env: CANARY },
      email: { smtp_url_env: CANARY, from: 'private@example.invalid', to: ['private@example.invalid'] },
    },
  });
const options = (sink = 'accepted') => ({
  config: config(),
  inventory: inventory(),
  sink,
  scenario: {
    version: 1,
    frames: [
      { at: at(), evidence: [evidence()] },
      { at: at(60_000), evidence: [evidence()] },
    ],
  },
});
const temporary = (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-rehearsal-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
const privateReport = (report) => {
  const json = JSON.stringify(report);
  for (const secret of [
    CANARY,
    'example-parser',
    'example.invalid',
    'hooks.slack.com',
    'smtp',
    'CVE-',
    'api_key',
    'webhook',
  ])
    assert(!json.includes(secret), secret);
  for (const frame of report.frames) {
    const refs = new Set(frame.evidence.map((item) => item.ref));
    for (const ref of frame.ingest.evidence_refs) assert(refs.has(ref));
    for (const finding of frame.findings) for (const ref of finding.evidence_refs) assert(refs.has(ref));
    for (const delivery of frame.deliveries) {
      assert.match(delivery.ref, /^[a-f0-9]{64}$/);
      assert(Number.isSafeInteger(delivery.revision));
      assert(frame.findings.some((finding) => finding.ref === delivery.finding_ref));
    }
  }
};

test('rehearsal uses real scan, both simulated delivery channels, dedup and backup/recovery with private joins', async () => {
  const input = options();
  const before = JSON.stringify(input);
  const report = await runRehearsal(input);
  assert.equal(JSON.stringify(input), before);
  assert.equal(report.mode, 'offline_rehearsal');
  assert.equal(report.summary.delivery_states.accepted, 2);
  assert.equal(report.summary.sink_calls, 2);
  assert.equal(report.frames[0].findings[0].decision, 'notify');
  assert.equal(report.frames[1].findings[0].revision, 1);
  assert.equal(report.frames[0].findings[0].ref, report.frames[1].findings[0].ref);
  assert(report.frames[1].deliveries.every((item) => item.revision === 1 && item.attempts === 1));
  assert.deepEqual(report.safety, {
    models_disabled: true,
    sources_disabled: true,
    network_requests: 0,
    external_deliveries: 0,
    live_database_opened: false,
    credentials_loaded: false,
  });
  assert.equal(report.recovery.restored, true);
  assert.equal(report.recovery.receipts_preserved, true);
  assert.equal(report.recovery.dispatcher_probe, 'passed');
  assert.equal(report.recovery.probe_sink_calls, 0);
  assert(Object.values(report.unmeasured).every((value) => value === null));
  privateReport(report);
});

test('ambiguous and failed simulated receipts never retry on repeated scan or restored dispatcher', async () => {
  for (const sink of ['unknown', 'failed']) {
    const report = await runRehearsal(options(sink));
    assert.equal(report.summary.delivery_states[sink], 2);
    assert.equal(report.summary.sink_calls, 2);
    assert(report.frames[1].deliveries.every((item) => item.attempts === 1));
    assert.equal(report.recovery.terminal_receipts_not_retried, true);
    assert.equal(report.recovery.probe_sink_calls, 0);
    privateReport(report);
  }
});

test('delivery-disabled rehearsal preserves pending receipts through actual backup and reopen without dispatch', async () => {
  const report = await runRehearsal(options('disabled'));
  assert.equal(report.summary.delivery_states.pending, 2);
  assert.equal(report.summary.sink_calls, 0);
  assert.equal(report.recovery.dispatcher_probe, 'disabled');
  assert(report.frames[1].deliveries.every((item) => item.attempts === 0));
});

test('digest jobs stay scheduled until their scenario due time, without implicit clock advance', async () => {
  const input = options();
  delete input.inventory.systems[0].components[0].version;
  for (const frame of input.scenario.frames) frame.evidence[0].severity = 'high';
  input.scenario.frames.push({
    at: '2026-11-06T00:00:00Z',
    evidence: [{ ...evidence(), severity: 'high', fetched_at: '2026-11-06T00:00:00Z' }],
  });
  const report = await runRehearsal(input);
  assert.equal(report.frames[0].findings[0].decision, 'digest');
  assert.equal(report.frames[0].counters.delivery_states.pending, 2);
  assert.equal(report.frames[0].deliveries[0].scheduled_in_ms, 12 * 3_600_000);
  assert.equal(report.frames[1].counters.delivery_states.pending, 2);
  assert.equal(report.frames[2].counters.delivery_states.accepted, 2);
});

test('withdrawal supersedes pending digest; stale inventory keeps a critical case uncertain', async () => {
  const input = options();
  delete input.inventory.systems[0].components[0].version;
  input.scenario.frames[0].evidence[0].severity = 'high';
  input.scenario.frames[1].evidence[0] = evidence({
    severity: 'high',
    withdrawn: true,
    modified_at: at(60_000),
    fetched_at: at(60_000),
  });
  const report = await runRehearsal(input);
  assert.equal(report.frames[0].counters.delivery_states.pending, 2);
  assert.equal(report.frames[1].findings[0].decision, 'record');
  assert.equal(report.summary.sink_calls, 0);
  assert.equal(report.summary.delivery_states.failed, 2);
  assert.equal(report.frames[1].findings[0].revision, 2);
  const stale = options();
  stale.inventory.systems[0].updated_at = '2025-01-01T00:00:00Z';
  const staleReport = await runRehearsal(stale);
  assert(
    staleReport.frames[0].findings.some(
      (item) => item.category === 'library' && item.applicability === 'unknown' && item.decision === 'notify',
    ),
  );
  assert.equal(staleReport.frames[0].degraded, true);
});

test('older received evidence remains an explicit unretained join and cross-source IDs are rejected', async () => {
  const input = options();
  input.scenario.frames[1].evidence[0] = evidence({
    description: 'older',
    modified_at: '2026-11-04T00:00:00Z',
  });
  const report = await runRehearsal(input);
  const frame = report.frames[1];
  assert.equal(frame.evidence.length, 2);
  assert.equal(frame.evidence.filter((item) => !item.retained).length, 1);
  assert.notEqual(frame.ingest.evidence_refs[0], frame.findings[0].evidence_refs[0]);
  privateReport(report);
  input.scenario.frames[1].evidence[0].source = 'other';
  await assert.rejects(runRehearsal(input), /Invalid rehearsal input/);
});

test('reports use fresh keyed references per run and leave a concurrently locked live store untouched', async (t) => {
  const dir = temporary(t);
  const livePath = join(dir, 'live.db');
  const live = new Store(livePath);
  const release = acquireLock(livePath);
  try {
    live.setMeta('sentinel', CANARY);
    const input = options();
    input.config.database = livePath;
    const [a, b] = await Promise.all([runRehearsal(input), runRehearsal(input)]);
    assert.notEqual(a.frames[0].findings[0].ref, b.frames[0].findings[0].ref);
    assert.equal(live.getMeta('sentinel'), CANARY);
    assert.deepEqual(live.findings(), []);
    assert.deepEqual(live.jobs(), []);
  } finally {
    release();
    live.close();
  }
});

test('invalid, excessive and model-like direct API input fails with bounded content-free errors', async () => {
  const inputs = [];
  const extra = options();
  extra.scenario.frames[0].evidence[0].ai = { prompt: CANARY };
  inputs.push(extra);
  const order = options();
  order.scenario.frames[1].at = order.scenario.frames[0].at;
  inputs.push(order);
  const empty = options();
  empty.scenario.frames = [];
  inputs.push(empty);
  const noEvidence = options();
  noEvidence.scenario.frames.forEach((frame) => (frame.evidence = []));
  inputs.push(noEvidence);
  const sink = options('https://private.invalid/' + CANARY);
  inputs.push(sink);
  const huge = options();
  huge.scenario.frames[0].evidence[0].description = CANARY.repeat(2_000_000);
  inputs.push(huge);
  const importPath = options();
  importPath.scenario.frames[0].inventory = inventory();
  importPath.scenario.frames[0].inventory.systems[0].lockfile = CANARY;
  inputs.push(importPath);
  for (const input of inputs)
    await assert.rejects(
      runRehearsal(input),
      (error) => error.message === 'Invalid rehearsal input; check the documented schema and bounds.',
    );
});

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const noNetwork =
  'data:text/javascript,' +
  encodeURIComponent(
    "import http from 'node:http';import https from 'node:https';import net from 'node:net';import {syncBuiltinESMExports} from 'node:module';const fail=()=>{throw new Error('TEST_NETWORK_FORBIDDEN')};http.request=fail;https.request=fail;net.createConnection=fail;globalThis.fetch=fail;syncBuiltinESMExports();",
  );
const run = (args, cwd) =>
  spawnSync(process.execPath, ['--import', noNetwork, cli, 'rehearse', ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 15000,
  });

test('packaged CLI path produces only a private new report and rejects credentials, destinations and existing/symlink outputs', (t) => {
  const dir = temporary(t);
  const input = options();
  writeFileSync(join(dir, 'inventory.json'), JSON.stringify(input.inventory));
  writeFileSync(join(dir, 'config.json'), JSON.stringify({ ...input.config, inventory: './inventory.json' }));
  writeFileSync(join(dir, 'scenario.json'), JSON.stringify(input.scenario));
  const args = ['--config', 'config.json', '--input', 'scenario.json', '--sink', 'accepted'];
  const first = run([...args, '--output', 'report.json'], dir);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stdout, '');
  privateReport(JSON.parse(readFileSync(join(dir, 'report.json'), 'utf8')));
  if (process.platform !== 'win32') assert.equal(statSync(join(dir, 'report.json')).mode & 0o777, 0o600);
  const before = readFileSync(join(dir, 'report.json'), 'utf8');
  symlinkSync(join(dir, 'report.json'), join(dir, 'alias.json'));
  for (const more of [
    ['--output', 'report.json'],
    ['--output', 'alias.json'],
    ['--credentials-file', CANARY],
    ['--notify'],
    ['--sink', CANARY],
  ]) {
    const result = run([...args, ...more], dir);
    assert.equal(result.status, 1);
    assert(!result.stderr.includes(CANARY));
    assert.equal(result.stdout, '');
  }
  assert.equal(readFileSync(join(dir, 'report.json'), 'utf8'), before);
  const stdout = run(args, dir);
  assert.equal(stdout.status, 0, stdout.stderr);
  privateReport(JSON.parse(stdout.stdout));
});

test('scenario and legacy fixture readers retain strictly validated CVSS v4 metadata', (t) => {
  const dir = temporary(t);
  const input = options();
  const vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
  input.scenario.frames[0].evidence[0].cvss_v4 = {
    base_scores: [{ vector, base_vector: vector, score: 9.3, context_removed: false }],
    unsupported_vectors: 0,
  };
  const path = join(dir, 'scenario.json');
  writeFileSync(path, JSON.stringify(input.scenario));
  assert.equal(readRehearsal(path).frames[0].evidence[0].cvss_v4.base_scores[0].score, 9.3);
  const fixture = join(dir, 'fixture.json');
  writeFileSync(fixture, JSON.stringify(input.scenario.frames[0].evidence));
  assert.equal(readFixture(fixture)[0].cvss_v4.base_scores[0].score, 9.3);
  input.scenario.frames[0].evidence[0].cvss_v4.base_scores[0].score = 1;
  writeFileSync(path, JSON.stringify(input.scenario));
  assert.throws(() => readRehearsal(path), /Invalid rehearsal scenario/);
});

test('temporary raw rehearsal state is cleaned up after successful processing', async () => {
  const before = new Set(
    readdirSync(tmpdir()).filter((name) => name.startsWith('security-watch-rehearsal-')),
  );
  await runRehearsal(options());
  assert.deepEqual(
    new Set(readdirSync(tmpdir()).filter((name) => name.startsWith('security-watch-rehearsal-'))),
    before,
  );
});

test('temporary raw state is removed even when closing the restored store fails', async (t) => {
  const before = new Set(
    readdirSync(tmpdir()).filter((name) => name.startsWith('security-watch-rehearsal-')),
  );
  const close = Store.prototype.close;
  let calls = 0;
  const mocked = t.mock.method(Store.prototype, 'close', function () {
    close.call(this);
    if (++calls === 3) throw new Error(CANARY);
  });
  await assert.rejects(
    runRehearsal(options()),
    (error) => error.message === 'Rehearsal cleanup failed; inspect private temporary storage locally.',
  );
  mocked.mock.restore();
  assert.deepEqual(
    new Set(readdirSync(tmpdir()).filter((name) => name.startsWith('security-watch-rehearsal-'))),
    before,
  );
});

test('work limits include cached evidence against later inventory and file input rejects links/non-files', async (t) => {
  const input = options();
  input.scenario.frames[0].evidence = Array.from({ length: 300 }, (_, index) =>
    evidence({ id: `bounded-${index}` }),
  );
  input.scenario.frames[1].evidence = [];
  input.scenario.frames[1].inventory = inventory();
  input.scenario.frames[1].inventory.systems[0].components = Array.from({ length: 300 }, (_, index) => ({
    id: `bounded-${index}`,
    ecosystem: 'npm',
    name: 'example-parser',
    version: '1.0.0',
  }));
  await assert.rejects(runRehearsal(input), /Invalid rehearsal input/);
  const dir = temporary(t);
  const path = join(dir, 'scenario.json');
  writeFileSync(path, JSON.stringify(options().scenario));
  symlinkSync(path, join(dir, 'linked.json'));
  assert.throws(() => readRehearsal(join(dir, 'linked.json')), /Invalid rehearsal scenario/);
  assert.throws(() => readRehearsal(dir), /Invalid rehearsal scenario/);
});
