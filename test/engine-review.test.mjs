import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig } from '../dist/config.js';
import { runScan } from '../dist/engine.js';
import { Store } from '../dist/store.js';

const now = Date.parse('2026-10-24T12:00:00Z');
const config = parseConfig({
  version: 1,
  sources: { osv: false, github: false, kev: false },
  policy: { library: { levels: ['critical'], channels: ['slack'] }, health_channels: ['slack'] },
  notifications: { slack: { webhook_url_env: 'UNUSED_TEST_WEBHOOK' } },
});
function inventory(version = '1.0.0', overrides = {}) {
  return { systems: [{ id: 'api', name: 'API', environment: 'production', exposure: 'internal', criticality: 'high', updated_at: new Date(now).toISOString(), components: [{ id: 'dep', ecosystem: 'npm', name: 'dep', version }], products: [], keywords: [], ...overrides }] };
}
function advisory(overrides = {}) {
  return { id: 'osv:GHSA-aaaa-bbbb-cccc', source: 'osv', kind: 'advisory', title: 'Dependency advisory', url: 'https://example.com/advisory', description: '', aliases: ['GHSA-aaaa-bbbb-cccc'], severity: 'critical', modified_at: '2026-10-23T12:00:00Z', fetched_at: new Date(now).toISOString(), packages: [{ ecosystem: 'npm', name: 'dep', range: '<2.0.0' }], ...overrides };
}
function storeFor(t) { const store = new Store(':memory:'); t.after(() => store.close()); return store; }

test('deterministic malware and exploitation overrides enter the outbox before optional analysis', async t => {
  for (const evidence of [advisory({ severity: 'unknown', malware: true }), advisory({ severity: 'high', exploited: true })]) {
    const store = storeFor(t);
    let earlyJobs;
    await runScan({ config, inventory: inventory(), store, fixture: [evidence], now, onUrgent: async () => { earlyJobs = store.jobs(); } });
    assert.equal(earlyJobs.length, 1, `${evidence.malware ? 'Malware' : 'Known exploitation'} must not wait for AI`);
    assert.equal(JSON.parse(earlyJobs[0].payload).mode, 'notify');
  }
});

test('a stale source replay cannot resurrect an advisory withdrawn by a newer revision', async t => {
  const store = storeFor(t);
  await runScan({ config, inventory: inventory(), store, fixture: [advisory({ withdrawn: true, modified_at: '2026-10-24T10:00:00Z' })], now });
  const report = await runScan({ config, inventory: inventory(), store, fixture: [advisory()], now: now + 60_000 });
  assert.equal(report.findings[0].withdrawn, true);
  assert.equal(report.decisions[report.findings[0].id].action, 'record');
  assert.equal(store.jobs().length, 0);
});

test('an inventory change reassesses stored evidence and cancels obsolete pending deliveries', async t => {
  const store = storeFor(t);
  await runScan({ config, inventory: inventory(), store, fixture: [advisory()], now });
  assert.equal(store.jobs()[0].status, 'pending');
  const report = await runScan({ config, inventory: inventory('2.0.0'), store, fixture: [], now: now + 60_000 });
  assert.equal(report.findings[0].applicability, 'not_affected');
  assert.equal(store.jobs()[0].status, 'failed');
  assert.equal(store.claimDue(now + 60_000), undefined);
});

test('stale inventory yields both an urgent uncertainty finding and a separate monitoring-health finding', async t => {
  const store = storeFor(t);
  const report = await runScan({ config, inventory: inventory('2.0.0', { updated_at: '2026-01-01T00:00:00Z' }), store, fixture: [advisory()], now });
  assert.equal(report.degraded, true);
  const vulnerability = report.findings.find(f => f.category === 'library');
  assert.equal(vulnerability.applicability, 'unknown');
  assert.equal(report.decisions[vulnerability.id].action, 'notify');
  assert.equal(report.findings.filter(f => f.category === 'health').length, 1);
});

test('future inventory timestamps are a monitoring-health error even when there are no advisories', async t => {
  const store = storeFor(t);
  const report = await runScan({ config, inventory: inventory('2.0.0', { updated_at: '2027-01-01T00:00:00Z' }), store, fixture: [], now });
  assert.equal(report.degraded, true);
  assert.equal(report.findings.some(f => f.category === 'health'), true);
});

test('configuration rejects digest intervals that cannot be represented as exact millisecond schedule times', () => {
  assert.throws(() => parseConfig({ version: 1, digest_interval_hours: 1.0000000001 }));
});
