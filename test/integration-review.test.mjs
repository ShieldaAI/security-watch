import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../dist/store.js';
import { parseConfig } from '../dist/config.js';
import { runScan } from '../dist/engine.js';
import { deliverPending } from '../dist/delivery.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const WEBHOOK_ENV = 'SECURITY_WATCH_INTEGRATION_REVIEW_WEBHOOK';
const inventory = {
  systems: [
    {
      id: 'api',
      name: 'API',
      environment: 'production',
      exposure: 'internal',
      criticality: 'high',
      updated_at: new Date(NOW).toISOString(),
      components: [{ id: 'parser', ecosystem: 'npm', name: 'example-parser', version: '1.0.0' }],
      products: [],
      keywords: [],
    },
  ],
};
const config = parseConfig({
  version: 1,
  sources: { osv: false, github: false, kev: false },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: WEBHOOK_ENV } },
});
function evidence(changes = {}) {
  return {
    id: 'osv:GHSA-aaaa-bbbb-cccc',
    source: 'osv',
    kind: 'advisory',
    title: 'Example parser advisory',
    url: 'https://example.com/advisory/original',
    description: 'Synthetic integration fixture; no real vulnerability.',
    aliases: ['GHSA-aaaa-bbbb-cccc'],
    severity: 'critical',
    modified_at: new Date(NOW).toISOString(),
    fetched_at: new Date(NOW).toISOString(),
    packages: [{ ecosystem: 'npm', name: 'example-parser', range: '<2.0.0' }],
    ...changes,
  };
}

test('a delayed notification uses corrected current evidence without resetting due time or alert revision', async (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const previous = process.env[WEBHOOK_ENV];
  process.env[WEBHOOK_ENV] = 'https://hooks.slack.com/services/integration/fake/never-sent';
  t.after(() => {
    if (previous === undefined) delete process.env[WEBHOOK_ENV];
    else process.env[WEBHOOK_ENV] = previous;
  });
  await runScan({ config, inventory, store, fixture: [evidence()], now: NOW });
  const claimed = store.claimDue(NOW);
  store.completeJob(claimed.id, 'pending', NOW + 60_000, 'Synthetic rate limit rejection');
  const original = store.jobs()[0];
  await runScan({
    config,
    inventory,
    store,
    fixture: [
      evidence({
        url: 'https://example.com/advisory/corrected',
        modified_at: new Date(NOW + 1000).toISOString(),
        fetched_at: new Date(NOW + 1000).toISOString(),
      }),
    ],
    now: NOW + 1000,
  });
  assert.equal(store.jobs().length, 1, 'A citation correction is not a new security event');
  assert.equal(store.jobs()[0].id, original.id);
  assert.equal(
    store.jobs()[0].available_at,
    original.available_at,
    'Refreshing alert content must not postpone the existing delivery',
  );
  assert.equal(
    store.jobs()[0].attempts,
    1,
    'Refreshing alert content must retain the previous rejected attempt',
  );
  let body;
  const result = await deliverPending(
    store,
    config,
    async (_url, options) => {
      body = JSON.parse(options.body);
      return { status: 200, headers: {}, body: 'ok' };
    },
    NOW + 60_000,
  );
  assert.equal(result.accepted, 1);
  assert.match(body.blocks[0].text.text, /advisory\/corrected/);
  assert.doesNotMatch(body.blocks[0].text.text, /advisory\/original/);
  const acceptedPayload = store.jobs()[0].payload;
  await runScan({
    config,
    inventory,
    store,
    fixture: [
      evidence({
        url: 'https://example.com/advisory/final',
        modified_at: new Date(NOW + 120_000).toISOString(),
        fetched_at: new Date(NOW + 120_000).toISOString(),
      }),
    ],
    now: NOW + 120_000,
  });
  assert.equal(store.jobs().length, 1);
  assert.equal(store.jobs()[0].status, 'accepted');
  assert.equal(
    store.jobs()[0].payload,
    acceptedPayload,
    'An accepted notification retains the exact content sent',
  );
  assert.deepEqual(store.findings().find((f) => f.category === 'library').urls, [
    'https://example.com/advisory/final',
  ]);
});
