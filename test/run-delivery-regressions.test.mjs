import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { parseConfig } from '../dist/config.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';
import { HeartbeatMonitor } from '../dist/heartbeat.js';
import { MaintenanceScheduler } from '../dist/operations.js';

const now = Date.parse('2026-10-24T12:00:00Z');
process.env.RUN_DELIVERY_UNUSED_KEY ??= 'unused';
const config = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
  models: {
    enabled: true,
    analysis: {
      provider: 'openai-compatible',
      model: 'test-model',
      api_key_env: 'RUN_DELIVERY_UNUSED_KEY',
      endpoint: 'http://127.0.0.1:1234',
      allow_private_endpoint: true,
    },
  },
  policy: { news: { levels: ['high', 'critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'RUN_DELIVERY_UNUSED_WEBHOOK' } },
});
const system = (components = []) => ({
  id: 'prod',
  name: 'Production',
  environment: 'production',
  exposure: 'internal',
  criticality: 'high',
  updated_at: new Date(now).toISOString(),
  components,
  products: [{ name: 'Example Database', version: '4.2', keywords: [] }],
  keywords: [],
});
const quote =
  'Example Database version 4.2 is affected by a newly disclosed remote code execution vulnerability.';
const story = {
  id: 'feed:example-flaw',
  source: 'feed:test',
  kind: 'news',
  title: 'Example Database flaw',
  url: 'https://example.com/flaw',
  description: quote,
  aliases: [],
  severity: 'unknown',
  modified_at: new Date(now).toISOString(),
  fetched_at: new Date(now).toISOString(),
  packages: [],
  content_status: 'full',
};
const http = async () => ({
  status: 200,
  headers: {},
  body: JSON.stringify({
    choices: [
      {
        finish_reason: 'stop',
        message: {
          content: JSON.stringify({
            relevance: 'relevant',
            priority: 'high',
            summary: 'The installed version is reported affected.',
            evidence_ids: [story.id],
            quotes: [{ evidence_id: story.id, quote }],
            news_analysis: {
              classification: 'new_vulnerability',
              impact: 'affected',
              affected_products: ['Example Database'],
              affected_versions: ['4.2'],
              prerequisites: [],
              rationale: 'The quoted report names version 4.2.',
              quotes: [{ evidence_id: story.id, quote }],
            },
          }),
        },
      },
    ],
  }),
});
const cited = { ...story, aliases: ['CVE-2026-12345'] };
const { content_status: _status, ...kev } = {
  ...story,
  id: 'CVE-2026-12345',
  source: 'kev',
  kind: 'kev',
  title: 'Example Database remote code execution',
  url: 'https://example.com/kev',
  description: 'Example Database remote code execution',
  exploited: true,
};
const library = { id: 'lodash', ecosystem: 'npm', name: 'lodash', version: '4.17.21' };

test('an unrelated inventory change does not send an AI-confirmed news alert again', async (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  store.saveEvidence([story], {});
  const first = await runScan({ config, inventory: { systems: [system()] }, store, http, now });
  const finding = first.findings.find((f) => f.category === 'news');
  assert.equal(first.decisions[finding.id].action, 'notify');
  const job = store.claimDue(now);
  store.completeJob(job.id, 'accepted', now, undefined, now);
  const revision = store.revisionOf(finding.id);
  // A new library in the same system changes the analysis basis, not the conclusion.
  const second = await runScan({
    config,
    inventory: { systems: [system([library])] },
    store,
    http,
    now: now + 60_000,
  });
  assert.equal(second.decisions[finding.id].action, 'notify');
  assert.equal(store.revisionOf(finding.id), revision);
  assert.deepEqual(
    store.jobs().map((j) => j.status),
    ['accepted'],
  );
});

test('a queued AI news alert waits for reassessment and is sent once when the conclusion holds', async (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  store.saveEvidence([story], {});
  await runScan({ config, inventory: { systems: [system()] }, store, http, now });
  const [queued] = store.jobs();
  assert.equal(queued.status, 'pending');
  await runScan({
    config,
    inventory: { systems: [system([library])] },
    store,
    http,
    now: now + 60_000,
    onUrgent: async () =>
      assert.equal(store.claimDue(now + 60_000), undefined, 'An old conclusion waits for its new analysis'),
  });
  const jobs = store.jobs();
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].id, queued.id);
  assert.equal(jobs[0].status, 'pending');
  assert.equal(jobs[0].available_at, queued.available_at);
  assert.equal(store.claimDue(now + 60_000)?.id, queued.id);
  assert.deepEqual(store.deliveryIssues(now + 60_000), { failed: 0, unknown: 0, overdue_pending: 0 });
});

test('an inventory change does not resend a known-exploited news alert', async (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  store.saveEvidence([cited, kev], {});
  const first = await runScan({ config, inventory: { systems: [system()] }, store, http, now });
  const finding = first.findings.find((f) => f.category === 'news');
  assert.equal(first.decisions[finding.id].action, 'notify');
  assert.equal(finding.news_analysis.impact, 'affected');
  for (let job; (job = store.claimDue(now));) store.completeJob(job.id, 'accepted', now, undefined, now);
  const revision = store.revisionOf(finding.id);
  let urgent;
  await runScan({
    config,
    inventory: { systems: [system([library])] },
    store,
    http,
    now: now + 60_000,
    onUrgent: async () => {
      urgent = store.claimDue(now + 60_000);
    },
  });
  assert.equal(urgent, undefined, 'Nothing new to send before analysis');
  assert.equal(store.revisionOf(finding.id), revision);
  assert.equal(store.jobs().filter((j) => j.status !== 'accepted' && j.status !== 'failed').length, 0);
});

test('newly known exploitation is sent before analysis while the analysis basis changes', async (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  store.saveEvidence([cited], {});
  const first = await runScan({ config, inventory: { systems: [system()] }, store, http, now });
  const finding = first.findings.find((f) => f.category === 'news');
  for (let job; (job = store.claimDue(now));) store.completeJob(job.id, 'accepted', now, undefined, now);
  store.saveEvidence([kev], {});
  let urgent;
  await runScan({
    config,
    inventory: { systems: [system([library])] },
    store,
    http,
    now: now + 60_000,
    onUrgent: async () => {
      urgent = store.claimDue(now + 60_000);
    },
  });
  assert.equal(urgent?.finding_id, finding.id);
  assert.equal(JSON.parse(urgent.payload).assessment.exploited, true);
});

test('a shorter suppression replaces a longer one for a queued alert', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const start = Date.now();
  const finding = {
    id: 'finding-1',
    event_id: 'CVE-2026-1',
    system_id: 'api',
    category: 'library',
    applicability: 'affected',
    source_severity: 'critical',
    priority: 'critical',
    title: 'Critical',
    summary: 'Critical',
    reasons: [],
    evidence_ids: [],
    urls: [],
    exploited: false,
    updated_at: new Date(start).toISOString(),
  };
  store.saveAssessment(finding, { action: 'notify', channels: ['slack'], reason: 'Rule' }, start);
  store.suppress('finding-1', start + 720 * 3_600_000, 'Typed the wrong number of hours');
  store.suppress('finding-1', start + 3_600_000, 'One hour');
  assert.equal(store.claimDue(start + 3_599_999), undefined);
  assert.equal(store.claimDue(start + 3_600_000)?.finding_id, 'finding-1');
});

test('external pings and maintenance resume at once when the clock is set back', async (t) => {
  const store = new Store(':memory:');
  const env = 'RUN_DELIVERY_HEARTBEAT_URL';
  process.env[env] = 'https://monitor.example/ping';
  t.after(() => {
    store.close();
    delete process.env[env];
  });
  const healthy = (at) => {
    store.setMeta(
      'worker',
      JSON.stringify({
        status: 'running',
        started_at: new Date(at - 300_000).toISOString(),
        heartbeat_at: new Date(at).toISOString(),
      }),
    );
    store.setMeta('last_scan', JSON.stringify({ at: new Date(at).toISOString(), degraded: false }));
  };
  const monitoring = parseConfig({ version: 1, monitoring: { heartbeat_url_env: env } });
  const monitor = new HeartbeatMonitor();
  const http = async () => ({ status: 200, body: 'ok', headers: {} });
  healthy(now);
  assert.equal((await monitor.tick(store, monitoring, http, now)).status, 'accepted');
  assert.equal(await monitor.tick(store, monitoring, http, now + 1000), undefined);
  const back = now - 3_600_000;
  healthy(back);
  assert.equal((await monitor.tick(store, monitoring, http, back)).status, 'accepted');

  const maintenance = parseConfig({
    version: 1,
    maintenance: { interval_hours: 24, retention: { analysis_cache_days: 30 } },
  });
  const scheduler = new MaintenanceScheduler();
  assert.equal((await scheduler.tick(store, maintenance, now)).ok, true);
  assert.equal(await scheduler.tick(store, maintenance, now + 3_600_000), undefined);
  assert.equal((await scheduler.tick(store, maintenance, now - 30 * 3_600_000)).ok, true);
});

test('the worker keeps its heartbeat when the clock is set back', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-clock-step-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(
    join(dir, 'systems.json'),
    JSON.stringify({
      systems: [
        {
          id: 'app',
          name: 'App',
          environment: 'production',
          exposure: 'internal',
          criticality: 'high',
          updated_at: new Date().toISOString(),
          products: [],
          keywords: [],
          components: [{ id: 'pad', name: 'left-pad', ecosystem: 'npm', version: '1.0.0' }],
        },
      ],
    }),
  );
  writeFileSync(
    join(dir, 'security-watch.yaml'),
    JSON.stringify({
      version: 1,
      inventory: './systems.json',
      database: './state.db',
      sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
    }),
  );
  // One second after start the wall clock is set back an hour, as an NTP correction can do.
  writeFileSync(
    join(dir, 'clock.mjs'),
    'const real = Date.now; const start = real(); Date.now = () => (real() - start > 1000 ? real() - 3_600_000 : real());',
  );
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const child = spawn(
    process.execPath,
    ['--import', join(dir, 'clock.mjs'), cli, 'start', '--config', join(dir, 'security-watch.yaml')],
    { stdio: 'ignore' },
  );
  const exited = new Promise((resolve) => child.once('exit', resolve));
  t.after(async () => {
    child.kill('SIGTERM');
    await exited;
  });
  const heartbeat = () => {
    try {
      const store = new Store(join(dir, 'state.db'), { readOnly: true });
      try {
        return JSON.parse(store.getMeta('worker') ?? 'null')?.heartbeat_at;
      } finally {
        store.close();
      }
    } catch {
      return undefined;
    }
  };
  let first;
  for (let i = 0; i < 100 && !first; i++) {
    await delay(100);
    first = heartbeat();
  }
  assert.ok(first, 'The worker started');
  let later = first;
  for (let i = 0; i < 250 && later === first; i++) {
    await delay(100);
    later = heartbeat();
  }
  assert.notEqual(later, first, 'A heartbeat is written within its usual interval after the clock step');
});
