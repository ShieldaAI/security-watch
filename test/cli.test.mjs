import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { acquireLock } from '../dist/lock.js';
import { Store } from '../dist/store.js';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
// Fail closed if an offline fixture accidentally attempts any network request.
const noNetwork = 'data:text/javascript,' + encodeURIComponent("import http from 'node:http'; import https from 'node:https'; import {syncBuiltinESMExports} from 'node:module'; const fail=()=>{throw new Error('TEST_NETWORK_FORBIDDEN')}; http.request=fail; https.request=fail; globalThis.fetch=fail; syncBuiltinESMExports();");
function run(args, cwd, extraEnv = {}) {
  const result = spawnSync(process.execPath, ['--import', noNetwork, cli, ...args], { cwd, env: { ...process.env, ...extraEnv }, encoding: 'utf8', timeout: 8000, stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error) throw result.error;
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}
function fixture(t, overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-cli-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const now = new Date().toISOString();
  const config = { version: 1, inventory: './systems.json', database: './state/watch.db', sources: { osv: false, github: false, kev: false, feeds: [] }, models: { enabled: false }, policy: { library: { levels: ['critical'], channels: ['slack'] }, health_channels: [] }, notifications: { slack: { webhook_url_env: 'WATCH_CLI_SLACK_TOKEN' } }, ...overrides };
  writeFileSync(join(dir, 'security-watch.yaml'), JSON.stringify(config));
  writeFileSync(join(dir, 'systems.json'), JSON.stringify({ systems: [{ id: 'prod', name: 'Production', environment: 'production', exposure: 'internet', criticality: 'high', updated_at: now, components: [{ id: 'parser', ecosystem: 'npm', name: 'test-parser', version: '1.0.0' }], products: [], keywords: [] }] }));
  const evidence = [{ id: 'GHSA-test-test-test', source: 'github', kind: 'advisory', title: 'Test parser critical issue', url: 'https://example.com/advisory', description: 'Offline fixture only.', aliases: ['CVE-2026-12345'], severity: 'critical', modified_at: now, fetched_at: now, packages: [{ ecosystem: 'npm', name: 'test-parser', range: '<2.0.0', fixed: '2.0.0' }] }];
  const evidencePath = join(dir, 'evidence.json'); writeFileSync(evidencePath, JSON.stringify(evidence));
  return { dir, configPath: join(dir, 'security-watch.yaml'), db: join(dir, 'state/watch.db'), evidencePath, config };
}
function scan(f, extra = []) { return run(['scan', '--fixture', f.evidencePath, ...extra], f.dir); }
async function waitFor(fn, milliseconds = 6000) {
  const end = Date.now() + milliseconds;
  while (Date.now() < end) { if (fn()) return; await delay(25); }
  assert.fail('Timed out waiting for child process');
}
function worker(t, f, env = {}) {
  const child = spawn(process.execPath, ['--import', noNetwork, cli, 'start', '--config', f.configPath], { cwd: f.dir, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  const logs = { stdout: '', stderr: '' }; child.stdout.on('data', chunk => { logs.stdout += chunk; }); child.stderr.on('data', chunk => { logs.stderr += chunk; });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) { child.kill('SIGTERM'); await delay(1100); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); } });
  return { child, logs };
}

test('init --yes creates private config without overwriting existing user files', t => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-init-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const first = run(['init', '--yes'], dir); assert.equal(first.code, 0, first.stderr);
  const path = join(dir, 'security-watch.yaml'); const initial = readFileSync(path, 'utf8');
  assert.equal(statSync(path).mode & 0o777, 0o600); assert(existsSync(join(dir, 'systems.yaml')));
  const second = run(['init', '--yes'], dir); assert.equal(second.code, 1); assert.match(second.stderr, /never overwrites/);
  assert.equal(readFileSync(path, 'utf8'), initial); assert(!existsSync(join(dir, 'data/watch.db')));
});

test('offline fixture dry-run previews findings without database, outbox or worker lock', t => {
  const f = fixture(t); const result = scan(f, ['--dry-run']);
  assert.equal(result.code, 0, result.stderr); const report = JSON.parse(result.stdout);
  assert.equal(report.findings.length, 1); assert.equal(report.findings[0].applicability, 'affected');
  assert(!existsSync(f.db)); assert(!existsSync(`${f.db}.lock`)); assert(!existsSync(`${f.db}.worker-lock`));
  const conflict = scan(f, ['--dry-run', '--notify']); assert.equal(conflict.code, 1); assert.match(conflict.stderr, /cannot be combined/);
});

test('scan persists and replay deduplicates; configuration paths resolve from config directory', t => {
  const f = fixture(t); const other = join(f.dir, 'elsewhere'); mkdirSync(other);
  const first = run(['scan', '--config', f.configPath, '--fixture', f.evidencePath], other); assert.equal(first.code, 0, first.stderr);
  const finding = JSON.parse(first.stdout).findings[0]; assert.equal(finding.system_id, 'prod');
  assert(existsSync(f.db)); assert(!existsSync(join(other, 'state/watch.db')));
  const replay = scan(f); assert.equal(replay.code, 0, replay.stderr);
  const jobs = JSON.parse(run(['deliveries'], f.dir).stdout); assert.equal(jobs.length, 1); assert.equal(jobs[0].status, 'pending');
  assert(!('payload' in jobs[0])); assert.equal(JSON.parse(run(['history', finding.id], f.dir).stdout).length, 1);
  assert(!existsSync(`${f.db}.lock`));
});

test('doctor reports variable names without exposing supplied secrets or making requests', t => {
  const f = fixture(t, { models: { enabled: true, analysis: { provider: 'openai', model: 'offline-test-model', api_key_env: 'WATCH_CLI_MODEL_SECRET' } } });
  const secret = 'DO_NOT_PRINT_MODEL_SECRET'; const webhook = 'https://hooks.slack.com/services/DO_NOT_PRINT_SLACK_SECRET';
  const ready = run(['doctor'], f.dir, { WATCH_CLI_MODEL_SECRET: secret, WATCH_CLI_SLACK_TOKEN: webhook });
  assert.equal(ready.code, 0, ready.stderr); assert.equal(JSON.parse(ready.stdout).ok, true);
  assert(!ready.stdout.includes(secret)); assert(!ready.stdout.includes(webhook)); assert(!ready.stderr.includes(secret));
  const missing = run(['doctor'], f.dir, { WATCH_CLI_MODEL_SECRET: '', WATCH_CLI_SLACK_TOKEN: '' });
  assert.equal(missing.code, 2); const report = JSON.parse(missing.stdout); assert(report.missing_environment_variables.includes('WATCH_CLI_MODEL_SECRET'));
  assert(!existsSync(f.db));
});

test('read commands and acknowledgement work while an exclusive worker lock is held', t => {
  const f = fixture(t); const report = scan(f); assert.equal(report.code, 0, report.stderr); const finding = JSON.parse(report.stdout).findings[0];
  const release = acquireLock(f.db);
  try {
    assert.equal(run(['status'], f.dir).code, 0); assert.equal(run(['findings'], f.dir).code, 0);
    const acknowledged = run(['acknowledge', finding.id], f.dir); assert.equal(acknowledged.code, 0, acknowledged.stderr);
    assert.equal(JSON.parse(run(['deliveries'], f.dir).stdout)[0].status, 'failed');
    const blocked = scan(f); assert.equal(blocked.code, 1); assert.match(blocked.stderr, /Another scan or worker/);
    const backup = run(['backup', '--output', join(f.dir, 'live-backup.db')], f.dir); assert.equal(backup.code, 0, backup.stderr);
  } finally { release(); }
});

test('backup and history CLI retain findings, outbox, and evidence revisions', t => {
  const f = fixture(t); const result = scan(f); assert.equal(result.code, 0, result.stderr); const finding = JSON.parse(result.stdout).findings[0];
  const history = run(['history', finding.id], f.dir); assert.equal(history.code, 0, history.stderr); assert.equal(JSON.parse(history.stdout)[0].assessment.id, finding.id);
  const destination = join(f.dir, 'backup.db'); const saved = run(['backup', '--output', destination], f.dir); assert.equal(saved.code, 0, saved.stderr);
  const restored = new Store(destination, { readOnly: true });
  try { assert.equal(restored.findings().length, 1); assert.equal(restored.jobs().length, 1); assert.equal(restored.history(finding.id).length, 1); assert.equal(restored.evidenceHistory('github', 'GHSA-test-test-test').length, 1); } finally { restored.close(); }
  assert.equal(run(['backup', '--output', destination], f.dir).code, 1);
});

test('schema initialization failure releases worker lock before returning an error', t => {
  const f = fixture(t); mkdirSync(join(f.dir, 'state')); const db = new DatabaseSync(f.db); db.exec('PRAGMA user_version=999'); db.close();
  const result = scan(f); assert.equal(result.code, 1); assert.match(result.stderr, /newer than supported/);
  assert(!existsSync(`${f.db}.lock`)); const release = acquireLock(f.db); release();
});

test('foreground worker continues with missing model credentials and disabled sources; SIGKILL releases ownership', async t => {
  const f = fixture(t, { models: { enabled: true, analysis: { provider: 'openai', model: 'offline-test-model', api_key_env: 'WATCH_CLI_MISSING_MODEL' } }, policy: { library: { levels: ['critical'], channels: [] }, news: { levels: ['high', 'critical'], channels: [] }, product: { levels: ['high', 'critical'], channels: [] }, health_channels: [] }, notifications: {} });
  const { child, logs } = worker(t, f, { WATCH_CLI_MISSING_MODEL: '' });
  await waitFor(() => logs.stdout.includes('running in the foreground') && logs.stdout.includes('"degraded":true')).catch(error => { t.diagnostic(JSON.stringify(logs)); throw error; });
  assert.equal(child.exitCode, null); assert.match(logs.stderr, /Missing environment variables/); assert(!logs.stderr.includes('TEST_NETWORK_FORBIDDEN'));
  const status = run(['status'], f.dir); assert.equal(status.code, 0, status.stderr); assert.equal(JSON.parse(status.stdout).worker_lock, true);
  const findings = JSON.parse(run(['findings'], f.dir).stdout); const health = findings.find(finding => finding.event_id === 'health:credentials' && finding.active !== false);
  assert(health, 'Missing credentials must remain an active health finding after the first scan');
  assert(JSON.parse(status.stdout).last_scan.errors.some(error => error.source === 'credentials'));
  assert.equal(run(['acknowledge', health.id], f.dir).code, 0);
  child.kill('SIGKILL'); await waitFor(() => child.signalCode !== null);
  const release = acquireLock(f.db); release();
  assert.equal(run(['unlock'], f.dir).code, 0);
});
