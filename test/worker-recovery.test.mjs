import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { parseConfig } from '../dist/config.js';
import { runScan, healthFinding } from '../dist/engine.js';
import { deliverPending } from '../dist/delivery.js';
import { safeHttp } from '../dist/http.js';
import { Store } from '../dist/store.js';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const webhookEnv = 'WATCH_WORKER_RECOVERY_SLACK';
const webhook = 'https://hooks.slack.com/services/TEST/RECOVERY/LOCAL';
const ids = { alpha: 'GHSA-aaaa-bbbb-cccc', beta: 'GHSA-dddd-eeee-ffff' };

function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-worker-recovery-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const now = new Date().toISOString();
  const inventory = {
    systems: [
      {
        id: 'app',
        name: 'Synthetic application',
        environment: 'production',
        exposure: 'internal',
        criticality: 'high',
        updated_at: now,
        products: [],
        keywords: [],
        components: Object.keys(ids).map((name) => ({ id: name, name, ecosystem: 'npm', version: '1.0.0' })),
      },
    ],
  };
  const config = {
    version: 1,
    inventory: './systems.json',
    database: './state.db',
    poll_interval_minutes: 1,
    sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false, feeds: [] },
    policy: { library: { levels: ['critical'], channels: ['slack'] }, health_channels: [] },
    notifications: { slack: { webhook_url_env: webhookEnv } },
  };
  const inventoryPath = join(dir, 'systems.json');
  const configPath = join(dir, 'security-watch.yaml');
  writeFileSync(inventoryPath, JSON.stringify(inventory));
  writeFileSync(configPath, JSON.stringify(config));
  return { dir, now, inventory, config, inventoryPath, configPath, db: join(dir, 'state.db') };
}

async function listener(t, handler) {
  const failures = [];
  const server = createServer(async (request, response) => {
    try {
      let text = '';
      for await (const chunk of request) {
        text += chunk;
        assert(text.length < 100_000, 'Synthetic request exceeded its bound');
      }
      const result = await handler(request.url, text ? JSON.parse(text) : undefined);
      response.writeHead(result.status ?? 200, { 'content-type': 'application/json' });
      response.end(typeof result.body === 'string' ? result.body : JSON.stringify(result.body));
    } catch (error) {
      failures.push(error);
      response.writeHead(500);
      response.end('{}');
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    assert.deepEqual(failures, []);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

function sourceReply(path, body, now) {
  if (path === '/api.osv.dev/v1/querybatch')
    return { body: { results: body.queries.map((query) => ({ vulns: [{ id: ids[query.package.name] }] })) } };
  if (path.startsWith('/api.osv.dev/v1/vulns/')) {
    const id = decodeURIComponent(path.split('/').at(-1));
    const name = Object.keys(ids).find((name) => ids[name] === id);
    assert(name, 'Unexpected synthetic advisory');
    return {
      body: {
        id,
        modified: now,
        summary: `${name} critical advisory`,
        details: `${name} version 1.0.0 is affected by this synthetic advisory.`,
        database_specific: { severity: 'CRITICAL' },
        affected: [
          {
            package: { ecosystem: 'npm', name },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
          },
        ],
      },
    };
  }
  return undefined;
}

function localTransport(origin) {
  return (value, options) => {
    const url = new URL(value);
    assert(['api.osv.dev', 'hooks.slack.com'].includes(url.hostname), 'Unexpected external destination');
    return safeHttp(`${origin}/${url.hostname}${url.pathname}`, { ...options, allowPrivate: true });
  };
}

async function waitFor(predicate, detail, timeout = 8000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await delay(25);
  }
  assert.fail(typeof detail === 'function' ? detail() : detail);
}

function snapshot(path) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return {
      jobs: db.prepare('SELECT finding_id,status,last_error,attempts FROM notifications').all(),
      findings: db
        .prepare('SELECT payload FROM findings')
        .all()
        .map((row) => JSON.parse(row.payload)),
      worker: JSON.parse(db.prepare("SELECT value FROM metadata WHERE key='worker'").get()?.value ?? 'null'),
    };
  } finally {
    db.close();
  }
}

function startWorker(t, fixture, origin, accelerated = false) {
  const hook = join(fixture.dir, 'loopback-transport.mjs');
  // Only the network edge is redirected. Production HTTP parsing, the CLI loop and SQLite remain real.
  writeFileSync(
    hook,
    `import http from 'node:http';
import https from 'node:https';
import {syncBuiltinESMExports} from 'node:module';
const request=http.request;
https.request=(url,options,callback)=>{
  if(!['api.osv.dev','hooks.slack.com'].includes(url.hostname))throw new Error('TEST_EXTERNAL_NETWORK_FORBIDDEN');
  return request(new URL(${JSON.stringify(origin)}+'/'+url.hostname+url.pathname),{...options,lookup:undefined},callback);
};
http.request=()=>{throw new Error('TEST_EXTERNAL_NETWORK_FORBIDDEN')};
globalThis.fetch=()=>{throw new Error('TEST_EXTERNAL_NETWORK_FORBIDDEN')};
${accelerated ? 'const realNow=Date.now;const began=realNow();Date.now=()=>began+(realNow()-began)*120;' : ''}
syncBuiltinESMExports();
`,
  );
  const child = spawn(process.execPath, ['--import', hook, cli, 'start', '--config', fixture.configPath], {
    cwd: fixture.dir,
    env: { ...process.env, [webhookEnv]: webhook },
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
      for (let i = 0; i < 40 && child.exitCode === null && child.signalCode === null; i++) await delay(25);
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }
  });
  return { child, logs };
}

function workerDetails(child, logs, extra = {}) {
  return JSON.stringify({ exitCode: child.exitCode, signalCode: child.signalCode, ...logs, ...extra });
}

async function stopWorker(child, logs) {
  assert.equal(child.exitCode, null, logs.stdout + logs.stderr);
  assert.equal(child.signalCode, null, logs.stdout + logs.stderr);
  child.kill('SIGTERM');
  await waitFor(
    () => child.exitCode !== null || child.signalCode !== null,
    () => logs.stdout + logs.stderr,
    4000,
  );
  assert.equal(child.exitCode, 0, logs.stdout + logs.stderr);
}

async function cliStatus(fixture) {
  const child = spawn(process.execPath, [cli, 'status', '--config', fixture.configPath], {
    cwd: fixture.dir,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 4000,
  });
  let stdout = '',
    stderr = '';
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });
  const [code, signal] = await once(child, 'close');
  assert.equal(code, 0, JSON.stringify({ code, signal, stdout, stderr }));
  return JSON.parse(stdout);
}

test('a malformed model response does not block later findings or alerts and is retried on a later scan', async (t) => {
  const f = setup(t);
  const previous = process.env[webhookEnv];
  process.env[webhookEnv] = webhook;
  t.after(() => {
    if (previous === undefined) delete process.env[webhookEnv];
    else process.env[webhookEnv] = previous;
  });
  const modelTargets = [],
    sent = [];
  const origin = await listener(t, (path, body) => {
    const source = sourceReply(path, body, f.now);
    if (source) return source;
    if (path.startsWith('/hooks.slack.com/')) {
      sent.push(body);
      return { body: 'ok' };
    }
    assert.equal(path, '/model');
    const context = JSON.parse(body.messages.find((message) => message.role === 'user').content);
    modelTargets.push(context.target.event_id);
    const text =
      modelTargets.length === 1
        ? '{invalid model JSON'
        : JSON.stringify({
            relevance: 'relevant',
            priority: 'critical',
            summary: 'The synthetic package and installed version match the advisory.',
            evidence_ids: [context.evidence[0].id],
            quotes: [{ excerpt_id: context.evidence[0].excerpts[0].id }],
            news_analysis: null,
          });
    return { body: { choices: [{ finish_reason: 'stop', message: { content: text } }] } };
  });
  const config = parseConfig({
    ...f.config,
    models: {
      enabled: true,
      analysis: {
        provider: 'openai-compatible',
        model: 'synthetic-model',
        api_key_env: 'WATCH_WORKER_RECOVERY_MODEL',
        endpoint: `${origin}/model`,
        allow_private_endpoint: true,
      },
      daily_request_limit: 20,
      daily_token_limit: 200000,
      max_input_chars: 4096,
      max_output_tokens: 512,
      timeout_seconds: 5,
    },
  });
  const store = new Store(f.db);
  t.after(() => store.close());
  const external = localTransport(origin);
  const http = (url, options) =>
    url.startsWith(origin + '/') ? safeHttp(url, options) : external(url, options);
  const now = Date.now();
  const first = await runScan({ config, inventory: f.inventory, store, http, now });
  const initial = first.findings.filter((finding) => finding.category === 'library');
  assert.equal(initial.length, 2);
  assert.deepEqual(initial.map((finding) => finding.ai.status).sort(), ['complete', 'unavailable']);
  assert.equal(modelTargets.length, 2, 'The invalid first output must not prevent the next model request');
  assert(first.errors.some((error) => error.source === 'models'));
  assert.equal((await deliverPending(store, config, http, now)).accepted, 1);
  assert.equal((await deliverPending(store, config, http, now + 1000)).accepted, 1);
  assert.equal(sent.length, 2, 'Both authoritative critical findings must reach the local destination');
  const second = await runScan({ config, inventory: f.inventory, store, http, now: now + 60_000 });
  assert(
    second.findings
      .filter((finding) => finding.category === 'library')
      .every((finding) => finding.ai.status === 'complete'),
  );
  assert.equal(
    modelTargets.length,
    3,
    'Retry unavailable analysis while retaining the successful cached result',
  );
  assert.equal(second.degraded, false);
  assert.equal((await deliverPending(store, config, http, now + 60_000)).accepted, 0);
  assert.equal(sent.length, 2, 'Recovery alone must not duplicate already accepted alerts');
});

test('the CLI quarantines malformed queued JSON and delivers unrelated work without exiting', async (t) => {
  const f = setup(t);
  f.config.policy.health_channels = ['slack'];
  writeFileSync(f.configPath, JSON.stringify(f.config));
  writeFileSync(f.inventoryPath, '{invalid inventory');
  const seed = new Store(f.db);
  for (const name of ['bad-queue', 'healthy-queue'])
    seed.saveAssessment(
      { ...healthFinding(name, 'Synthetic recovery test'), id: name },
      { action: 'notify', channels: ['slack'], reason: 'Synthetic test' },
    );
  seed.close();
  const database = new DatabaseSync(f.db);
  database
    .prepare('UPDATE notifications SET payload=? WHERE finding_id=?')
    .run('{invalid saved JSON', 'bad-queue');
  database.close();
  const sent = [];
  const origin = await listener(t, (path, body) => {
    assert(path.startsWith('/hooks.slack.com/'));
    sent.push(body.blocks[0].text.text);
    return { body: 'ok' };
  });
  const { child, logs } = startWorker(t, f, origin);
  await waitFor(
    () => {
      if (child.exitCode !== null || child.signalCode !== null) assert.fail(workerDetails(child, logs));
      return (
        sent.some((text) => text.includes('Finding: healthy-queue')) && logs.stderr.includes('"failed":1')
      );
    },
    () => workerDetails(child, logs),
  );
  await stopWorker(child, logs);
  const state = snapshot(f.db);
  const bad = state.jobs.find((job) => job.finding_id === 'bad-queue');
  assert.equal(bad.status, 'failed');
  assert.match(bad.last_error, /Invalid saved notification payload/);
  assert.equal(bad.attempts, 1);
  assert.equal(state.jobs.find((job) => job.finding_id === 'healthy-queue').status, 'accepted');
  assert(sent.some((text) => text.includes('Finding: healthy-queue')));
  assert(!sent.some((text) => text.includes('Finding: bad-queue')));
  assert.equal(state.worker.status, 'stopped');
});

test('the CLI keeps delivering after an inventory error and scans again after the file is repaired', async (t) => {
  const f = setup(t);
  f.config.policy.health_channels = ['slack'];
  writeFileSync(f.configPath, JSON.stringify(f.config));
  writeFileSync(f.inventoryPath, '{invalid inventory');
  const seed = new Store(f.db);
  seed.saveAssessment(
    { ...healthFinding('queued-before-error', 'Synthetic queued alert'), id: 'queued-before-error' },
    { action: 'notify', channels: ['slack'], reason: 'Synthetic test' },
  );
  seed.close();
  const sent = [];
  let queries = 0;
  const origin = await listener(t, (path, body) => {
    if (path.startsWith('/hooks.slack.com/')) {
      sent.push(body.blocks[0].text.text);
      return { body: 'ok' };
    }
    if (path === '/api.osv.dev/v1/querybatch') queries++;
    const source = sourceReply(path, body, f.now);
    assert(source, 'Unexpected local test request');
    return source;
  });
  // Advance only the child clock so the production one-minute minimum is exercised without a long test.
  const { child, logs } = startWorker(t, f, origin, true);
  await waitFor(
    () =>
      logs.stderr.includes('Scan failed') &&
      sent.some((text) => text.includes('Finding: queued-before-error')),
    () => workerDetails(child, logs, { queries }),
  );
  assert.equal(queries, 0, 'Invalid inventory must fail before querying a source');
  writeFileSync(f.inventoryPath, JSON.stringify(f.inventory));
  await waitFor(
    () => {
      if (child.exitCode !== null || child.signalCode !== null) assert.fail(workerDetails(child, logs));
      return Object.keys(ids).every((name) =>
        sent.some((text) => text.includes(`${name} critical advisory`)),
      );
    },
    () => workerDetails(child, logs, { queries }),
  );
  assert(queries >= 1);
  assert.equal(sent.filter((text) => text.includes('Finding: queued-before-error')).length, 1);
  await stopWorker(child, logs);
  const state = snapshot(f.db);
  const libraries = state.findings.filter((finding) => finding.category === 'library');
  assert.equal(libraries.length, 2);
  assert(
    libraries.every((finding) =>
      state.jobs.some((job) => job.finding_id === finding.id && job.status === 'accepted'),
    ),
  );
  assert.equal(state.worker.status, 'stopped');
});

test('CLI status reads coexist with an active scanning and delivering worker', async (t) => {
  const f = setup(t);
  const seed = new Store(f.db);
  seed.close();
  const sent = [];
  let queries = 0;
  const origin = await listener(t, (path, body) => {
    if (path.startsWith('/hooks.slack.com/')) {
      sent.push(body.blocks[0].text.text);
      return { body: 'ok' };
    }
    if (path === '/api.osv.dev/v1/querybatch') queries++;
    const source = sourceReply(path, body, f.now);
    assert(source, 'Unexpected local test request');
    return source;
  });
  const { child, logs } = startWorker(t, f, origin, true);
  await waitFor(
    () => logs.stdout.includes('running in the foreground'),
    () => workerDetails(child, logs),
  );
  for (let i = 0; i < 15; i++) {
    const status = await cliStatus(f);
    assert.equal(status.worker_lock, true);
    assert.equal(child.exitCode, null, workerDetails(child, logs));
    assert.equal(child.signalCode, null, workerDetails(child, logs));
  }
  await waitFor(
    () => Object.keys(ids).every((name) => sent.some((text) => text.includes(`${name} critical advisory`))),
    () => workerDetails(child, logs, { queries }),
  );
  await stopWorker(child, logs);
  assert(queries >= 2, 'Multiple scan cycles must complete while status commands read the database');
  assert.equal(snapshot(f.db).worker.status, 'stopped');
});
