import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../dist/store.js';
import { parseConfig } from '../dist/config.js';
import { HeartbeatMonitor } from '../dist/heartbeat.js';

const now = Date.parse('2026-10-24T12:00:00Z');
const env = 'WATCH_TEST_HEARTBEAT';
const config = () => parseConfig({ version: 1, monitoring: { heartbeat_url_env: env } });
function setup(t) {
  const store = new Store(':memory:');
  const previous = process.env[env];
  process.env[env] = 'https://monitor.example/private-test-token';
  t.after(() => {
    store.close();
    if (previous === undefined) delete process.env[env];
    else process.env[env] = previous;
  });
  healthy(store, now);
  return store;
}
function healthy(store, at) {
  store.setMeta(
    'worker',
    JSON.stringify({
      status: 'running',
      started_at: new Date(at - 300000).toISOString(),
      heartbeat_at: new Date(at).toISOString(),
    }),
  );
  store.setMeta('last_scan', JSON.stringify({ at: new Date(at).toISOString(), degraded: false }));
}
test('external pings stop during degraded scans and recover without disclosing inventory or tokens', async (t) => {
  const store = setup(t),
    monitor = new HeartbeatMonitor();
  let calls = 0;
  const http = async (url, options) => {
    calls++;
    assert.equal(url, process.env[env]);
    assert.equal(options.method, 'GET');
    assert.equal(options.body, undefined);
    assert.equal(options.redirects, 0);
    assert.equal(options.timeoutMs, 5000);
    if (calls === 2) throw new Error('transport private-test-token');
    return { status: 200, body: 'ok', headers: {} };
  };
  assert.equal((await monitor.tick(store, config(), http, now)).status, 'accepted');
  assert.equal(await monitor.tick(store, config(), http, now + 1000), undefined);
  healthy(store, now + 60000);
  store.setMeta('last_scan', JSON.stringify({ at: new Date(now + 60000).toISOString(), degraded: true }));
  assert.equal((await monitor.tick(store, config(), http, now + 60000)).status, 'withheld');
  assert.equal(calls, 1);
  healthy(store, now + 120000);
  assert.equal((await monitor.tick(store, config(), http, now + 120000)).status, 'failed');
  assert.doesNotMatch(store.getMeta('external_heartbeat'), /private-test-token/);
  healthy(store, now + 180000);
  assert.equal((await monitor.tick(store, config(), http, now + 180000)).status, 'accepted');
  assert.equal(calls, 3);
});
test('stale workers, missing credentials and rejected destinations never produce success pings', async (t) => {
  const store = setup(t);
  let calls = 0;
  const http = async () => {
    calls++;
    return { status: 302, body: '', headers: { location: 'https://other.example' } };
  };
  assert.equal((await new HeartbeatMonitor().tick(store, config(), http, now + 100000)).status, 'withheld');
  delete process.env[env];
  assert.equal((await new HeartbeatMonitor().tick(store, config(), http, now)).status, 'failed');
  process.env[env] = 'http://127.0.0.1/private-test-token';
  assert.equal((await new HeartbeatMonitor().tick(store, config(), http, now)).status, 'failed');
  assert.equal(calls, 0);
  process.env[env] = 'https://monitor.example/private-test-token';
  assert.equal((await new HeartbeatMonitor().tick(store, config(), http, now)).status, 'failed');
  assert.equal(calls, 1);
});
test('cancellation and durable state failures remain visible to the worker', async (t) => {
  const store = setup(t),
    controller = new AbortController();
  controller.abort();
  const http = async () => {
    throw new Error('must not request');
  };
  assert.equal(await new HeartbeatMonitor().tick(store, config(), http, now, controller.signal), undefined);
  assert.equal(store.getMeta('external_heartbeat'), undefined);
  store.getMeta = () => {
    throw new Error('storage failed');
  };
  await assert.rejects(new HeartbeatMonitor().tick(store, config(), http, now), /storage failed/);
});
