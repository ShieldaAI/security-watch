import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig } from '../dist/config.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';
const now = Date.parse('2026-10-24T12:00:00Z');
const config = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'AUDIT_UNUSED_TOKEN' } },
});
const inventory = (version = '1.0.0') => ({
  systems: [
    {
      id: 'api',
      name: 'API',
      environment: 'production',
      exposure: 'internal',
      criticality: 'high',
      updated_at: new Date(now).toISOString(),
      components: [{ id: 'dep', ecosystem: 'npm', name: 'dep', version }],
      products: [],
      keywords: [],
    },
  ],
});
const advisory = (changes = {}) => ({
  id: 'osv:GHSA-aaaa-bbbb-cccc',
  source: 'osv',
  kind: 'advisory',
  title: 'Critical dependency advisory',
  url: 'https://example.com/advisory',
  description: 'Synthetic regression fixture.',
  aliases: ['GHSA-aaaa-bbbb-cccc'],
  severity: 'critical',
  modified_at: new Date(now - 3600000).toISOString(),
  fetched_at: new Date(now).toISOString(),
  packages: [{ ecosystem: 'npm', name: 'dep', range: '<2.0.0' }],
  ...changes,
});
function memory(t) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  return store;
}

test('an urgent delivery callback failure does not discard later findings or scan completion', async (t) => {
  const store = memory(t);
  let called = 0;
  const report = await runScan({
    config,
    inventory: inventory(),
    store,
    now,
    fixture: [advisory(), advisory({ id: 'second-advisory', aliases: ['CVE-2026-12345'] })],
    onUrgent: async () => {
      called++;
      throw new Error('private-transport-error');
    },
  });
  assert.equal(called, 1);
  assert.equal(report.degraded, true);
  assert.equal(report.findings.filter((finding) => finding.category === 'library').length, 2);
  assert(report.errors.some((error) => error.source === 'delivery'));
  assert(!JSON.stringify(report).includes('private-transport-error'));
  assert.equal(JSON.parse(store.getMeta('last_scan')).degraded, true);
  assert.equal(store.jobs().filter((job) => job.status === 'pending').length, 2);
});

test('fixed, withdrawn and removed findings are canceled before an urgent delivery callback', async (t) => {
  for (const mode of ['fixed', 'withdrawn', 'removed'])
    await t.test(mode, async (t) => {
      const store = memory(t);
      await runScan({ config, inventory: inventory(), store, fixture: [advisory()], now });
      assert.equal(store.jobs().filter((j) => j.status === 'pending').length, 1);
      let checked = false;
      await runScan({
        config,
        inventory: mode === 'removed' ? { systems: [] } : inventory(mode === 'fixed' ? '2.0.0' : '1.0.0'),
        store,
        fixture:
          mode === 'withdrawn'
            ? [
                advisory({
                  withdrawn: true,
                  modified_at: new Date(now + 1).toISOString(),
                  fetched_at: new Date(now + 1).toISOString(),
                }),
              ]
            : [],
        now: now + 1000,
        onUrgent: async () => {
          checked = true;
          assert.equal(
            store.jobs().filter((j) => j.status === 'pending').length,
            0,
            'Obsolete findings must not remain deliverable',
          );
        },
      });
      assert(checked);
    });
});

test('inventory exclusions cancel queued alerts before source HTTP yields to the concurrent delivery loop', async (t) => {
  const store = memory(t);
  await runScan({ config, inventory: inventory(), store, fixture: [advisory()], now });
  let calls = 0;
  await runScan({
    config: { ...config, sources: { ...config.sources, osv: true } },
    inventory: inventory('2.0.0'),
    store,
    now: now + 1000,
    http: async () => {
      calls++;
      assert.equal(store.jobs().filter((j) => j.status === 'pending').length, 0);
      return { status: 503, headers: {}, body: '' };
    },
  });
  assert(calls > 0);
  assert.equal(store.findings().find((f) => f.category === 'library').applicability, 'not_affected');
});

test('cancellation before or during collection performs no new analysis or successful scan checkpoint', async (t) => {
  const store = memory(t);
  const controller = new AbortController();
  controller.abort();
  let calls = 0;
  await assert.rejects(
    runScan({
      config,
      inventory: inventory(),
      store,
      signal: controller.signal,
      http: async () => {
        calls++;
        throw new Error('must not call');
      },
    }),
    { name: 'AbortError' },
  );
  assert.equal(calls, 0);
  assert.equal(store.getMeta('last_scan'), undefined);
  const ongoing = new AbortController();
  await assert.rejects(
    runScan({
      config: { ...config, sources: { ...config.sources, osv: true } },
      inventory: inventory(),
      store,
      signal: ongoing.signal,
      http: async () => {
        calls++;
        ongoing.abort();
        return { status: 200, headers: {}, body: JSON.stringify({ results: [{}] }) };
      },
    }),
    { name: 'AbortError' },
  );
  assert.equal(calls, 1);
  assert.equal(store.getMeta('last_scan'), undefined);
});

test('completed scan time is separate from start time so long successful scans have fresh health', async (t) => {
  const store = memory(t);
  const original = Date.now;
  let clock = now;
  Date.now = () => clock;
  t.after(() => {
    Date.now = original;
  });
  const report = await runScan({
    config,
    inventory: inventory(),
    store,
    fixture: [],
    onUrgent: async () => {
      clock += 45 * 60_000;
    },
  });
  assert.equal(report.at, new Date(now).toISOString());
  assert.equal(report.completed_at, new Date(clock).toISOString());
  const state = JSON.parse(store.getMeta('last_scan'));
  assert.equal(state.started_at, report.at);
  assert.equal(state.at, report.completed_at);
});
