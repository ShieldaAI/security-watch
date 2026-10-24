import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../dist/store.js';
import { parseConfig } from '../dist/config.js';
import { checkHealth } from '../dist/health.js';
const NOW = Date.parse('2026-10-24T12:00:00Z');
const config = parseConfig({ version: 1 });
const time = (offset) => new Date(NOW + offset).toISOString();
function storeFor(t) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  return store;
}
function running(store, change = {}) {
  store.setMeta(
    'worker',
    JSON.stringify({ status: 'running', started_at: time(-60_000), heartbeat_at: time(0), ...change }),
  );
}
function scanned(store, change = {}) {
  store.setMeta('last_scan', JSON.stringify({ at: time(-1000), degraded: false, errors: [], ...change }));
}

test('monitoring health distinguishes startup, successful scans and a stopped or stalled worker', (t) => {
  const store = storeFor(t);
  assert.equal(checkHealth(store, config, NOW).ok, false);
  running(store);
  assert.equal(checkHealth(store, config, NOW).status, 'starting');
  scanned(store);
  assert.equal(checkHealth(store, config, NOW).status, 'healthy');
  running(store, { heartbeat_at: time(-91_000) });
  assert.equal(checkHealth(store, config, NOW).ok, false);
  running(store, { status: 'stopped' });
  assert.equal(checkHealth(store, config, NOW).ok, false);
  assert.equal(
    checkHealth(store, config, NOW, false).ok,
    true,
    'Cron scan-only health does not require a foreground worker',
  );
});

test('startup is bounded and stale, future, corrupt and degraded scan records fail monitoring health', (t) => {
  const store = storeFor(t);
  running(store, { started_at: time(-121_000) });
  assert.equal(checkHealth(store, config, NOW).ok, false);
  for (const state of [{ at: time(-31 * 60_000) }, { at: time(6000) }, { degraded: true }]) {
    scanned(store, state);
    assert.equal(checkHealth(store, config, NOW).ok, false);
  }
  store.setMeta('last_scan', 'not JSON');
  assert.equal(checkHealth(store, config, NOW).ok, false);
});

test('maintenance health expires its initial grace and requires a recent successful run', (t) => {
  const store = storeFor(t);
  const cfg = parseConfig({
    version: 1,
    maintenance: { interval_hours: 1, retention: { analysis_cache_days: 7 } },
  });
  running(store);
  scanned(store);
  assert.equal(checkHealth(store, cfg, NOW).ok, true);
  running(store, { started_at: time(-121_000) });
  assert.equal(checkHealth(store, cfg, NOW).ok, false);
  store.setMeta('maintenance:last_run', 'invalid JSON');
  assert.equal(checkHealth(store, cfg, NOW).ok, false);
  for (const last_success_at of [time(-7_200_001), time(6000)]) {
    store.setMeta('maintenance:last_run', JSON.stringify({ ok: true, last_success_at }));
    assert.equal(checkHealth(store, cfg, NOW).ok, false);
  }
  store.setMeta('maintenance:last_run', JSON.stringify({ ok: true, last_success_at: time(-1000) }));
  assert.equal(checkHealth(store, cfg, NOW).ok, true);
  store.setMeta('maintenance:last_run', JSON.stringify({ ok: false, last_success_at: time(-1000) }));
  assert.equal(checkHealth(store, cfg, NOW).ok, false);
});

test('delivery health includes unresolved current transport outcomes and does not mistake findings for monitor failure', (t) => {
  const store = storeFor(t);
  running(store);
  scanned(store);
  const cfg = parseConfig({
    version: 1,
    policy: { library: { levels: ['critical'], channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'HEALTH_UNUSED_TOKEN' } },
  });
  const finding = {
    id: 'critical',
    event_id: 'CVE-fixture',
    system_id: 'prod',
    component_id: 'dep',
    category: 'library',
    applicability: 'affected',
    source_severity: 'critical',
    priority: 'critical',
    title: 'Synthetic fixture',
    summary: 'Fixture only',
    reasons: [],
    evidence_ids: [],
    urls: [],
    exploited: false,
    updated_at: time(-600_000),
  };
  store.saveAssessment(finding, { action: 'notify', channels: ['slack'], reason: 'Critical' }, NOW - 600_000);
  let health = checkHealth(store, cfg, NOW);
  assert.equal(health.delivery.overdue_pending, 1);
  assert.equal(health.ok, false);
  const job = store.claimDue(NOW);
  store.completeJob(job.id, 'unknown', NOW, 'Receipt uncertain');
  health = checkHealth(store, cfg, NOW);
  assert.equal(health.delivery.unknown, 1);
  assert.equal(health.ok, false);
  store.acknowledge(finding.id);
  assert.equal(checkHealth(store, cfg, NOW).ok, true);
  assert.equal(
    store.findings()[0].priority,
    'critical',
    'Healthy monitoring is not a clean security assessment',
  );
});
