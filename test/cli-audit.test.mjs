import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-cli-audit-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const now = new Date().toISOString();
  const config = {
    version: 1,
    inventory: './systems.json',
    database: './state/watch.db',
    sources: { osv: false, github: false, kev: false },
    policy: { library: { levels: ['critical'], channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'AUDIT_SLACK_TOKEN' } },
  };
  writeFileSync(join(dir, 'security-watch.yaml'), JSON.stringify(config));
  writeFileSync(
    join(dir, 'systems.json'),
    JSON.stringify({
      systems: [
        {
          id: 'prod',
          name: 'Production',
          updated_at: now,
          components: [{ id: 'dep', ecosystem: 'npm', name: 'dep', version: '1.0.0' }],
        },
      ],
    }),
  );
  writeFileSync(
    join(dir, 'evidence.json'),
    JSON.stringify([
      {
        id: 'GHSA-aaaa-bbbb-cccc',
        source: 'github',
        kind: 'advisory',
        title: 'Synthetic critical fixture',
        description: 'Fixture only',
        url: 'https://example.com/advisory',
        aliases: [],
        severity: 'critical',
        modified_at: now,
        fetched_at: now,
        packages: [{ ecosystem: 'npm', name: 'dep', range: '<2.0.0' }],
      },
    ]),
  );
  return { dir, config };
}
const fakeTransport = (
  mode,
) => `import https from 'node:https';import http from 'node:http';import {EventEmitter} from 'node:events';import {syncBuiltinESMExports} from 'node:module';
https.request=(url,options,callback)=>{const req=new EventEmitter();req.write=()=>{};req.destroy=error=>{queueMicrotask(()=>req.emit('error',error??new Error('aborted')));};options.signal?.addEventListener('abort',()=>req.destroy(new Error('aborted')),{once:true});req.end=()=>{${mode === 'wait' ? `process.stdout.write('MOCK_NETWORK_WAIT\\n');` : `queueMicrotask(()=>{if(url.hostname!=='hooks.slack.com')throw new Error('UNEXPECTED_NETWORK');const res=new EventEmitter();res.statusCode=400;res.headers={};res.destroy=()=>{};callback(res);res.emit('data',Buffer.from('invalid_payload'));res.emit('end');});`}};return req;};
http.request=()=>{throw new Error('UNEXPECTED_NETWORK');};globalThis.fetch=()=>{throw new Error('UNEXPECTED_NETWORK');};syncBuiltinESMExports();`;
function run(dir, args, mode = 'reject') {
  return spawnSync(
    process.execPath,
    ['--import', 'data:text/javascript,' + encodeURIComponent(fakeTransport(mode)), cli, ...args],
    {
      cwd: dir,
      env: { ...process.env, AUDIT_SLACK_TOKEN: 'https://hooks.slack.com/services/TEST/ONLY/FIXTURE' },
      encoding: 'utf8',
      timeout: 8000,
    },
  );
}

test('unsafe cross-command flags are rejected before configuration, state or notification activity', (t) => {
  const { dir } = setup(t);
  for (const args of [
    ['test-notification', '--channel', 'slack', '--dry-run'],
    ['test-notification', '--channel', 'slack', '--fixture', 'evidence.json'],
    ['start', '--notify'],
    ['init', '--config', 'custom.yaml'],
  ]) {
    const result = run(dir, args);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /not supported/);
    assert(!existsSync(join(dir, 'state')));
  }
  const unknown = run(dir, ['scan', '--bogus']);
  assert.equal(unknown.status, 1);
  assert(!/\n\s+at /.test(unknown.stderr), 'Invalid CLI usage should not expose a stack trace');
});

test('an early urgent delivery failure remains counted and makes one-shot scan unsuccessful', (t) => {
  const { dir } = setup(t);
  const result = run(dir, ['scan', '--fixture', 'evidence.json', '--notify']);
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stdout, /"failed": 1/);
  const jobs = JSON.parse(run(dir, ['deliveries']).stdout);
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].status, 'failed');
});

test('health reports no database as unhealthy without creating state', (t) => {
  const { dir } = setup(t);
  const result = run(dir, ['health']);
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stdout).status, 'not_started');
  assert(!existsSync(join(dir, 'state')));
});

test('SIGTERM cancels a pending source request and records stopped worker state promptly', async (t) => {
  const { dir, config } = setup(t);
  config.sources.osv = true;
  config.policy.library.channels = [];
  writeFileSync(join(dir, 'security-watch.yaml'), JSON.stringify(config));
  const child = spawn(
    process.execPath,
    ['--import', 'data:text/javascript,' + encodeURIComponent(fakeTransport('wait')), cli, 'start'],
    { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let out = '',
    err = '';
  child.stdout.on('data', (data) => (out += data));
  child.stderr.on('data', (data) => (err += data));
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  });
  const readyDeadline = Date.now() + 5000;
  while (!out.includes('MOCK_NETWORK_WAIT') && Date.now() < readyDeadline) await delay(25);
  assert(out.includes('MOCK_NETWORK_WAIT'), out + err);
  const started = Date.now();
  child.kill('SIGTERM');
  const exitDeadline = started + 3000;
  while (child.exitCode === null && child.signalCode === null && Date.now() < exitDeadline) await delay(25);
  assert.equal(child.exitCode, 0, out + err);
  assert(Date.now() - started < 3000);
  assert(!existsSync(join(dir, 'state/watch.db.lock')));
  const health = run(dir, ['health']);
  assert.equal(health.status, 2);
  assert.match(health.stdout, /stopped or stale/);
});
