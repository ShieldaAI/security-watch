import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig } from '../dist/config.js';
import { assess, decide } from '../dist/assessment.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';
import { notificationText } from '../dist/delivery.js';

const now = Date.parse('2026-10-24T12:00:00Z');
const config = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
  models: {
    enabled: true,
    analysis: {
      provider: 'openai-compatible',
      model: 'test-model',
      api_key_env: 'NEWS_UNUSED_KEY',
      endpoint: 'http://127.0.0.1:1234',
      allow_private_endpoint: true,
    },
  },
  policy: { news: { levels: ['high', 'critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'NEWS_UNUSED_WEBHOOK' } },
});
const inventory = {
  systems: [
    {
      id: 'prod',
      name: 'Production',
      environment: 'production',
      exposure: 'internal',
      criticality: 'high',
      updated_at: new Date(now).toISOString(),
      components: [],
      products: [{ name: 'Example Database', version: '4.2', keywords: [] }],
      keywords: [],
    },
  ],
};
const quote = 'Example Database announces a new community conference with no security fixes.';
const story = {
  id: 'feed:example',
  source: 'feed:test',
  kind: 'news',
  title: 'Example Database community news',
  url: 'https://example.com/story',
  description: quote,
  aliases: [],
  severity: 'unknown',
  modified_at: new Date(now).toISOString(),
  fetched_at: new Date(now).toISOString(),
  packages: [],
  content_status: 'full',
};
const analysis = (classification = 'general_news', impact = 'not_applicable') => ({
  classification,
  impact,
  affected_products: classification === 'general_news' ? [] : ['Example Database'],
  affected_versions: classification === 'general_news' ? [] : ['4.2'],
  prerequisites: [],
  rationale: 'The quoted report describes the specific system context.',
  quotes: [{ evidence_id: story.id, quote }],
});
const reviewed = (classification, impact, overrides = {}) => ({
  ...assess(inventory, [story], config, now)[0],
  ai: { provider: 'openai-compatible', model: 'test-model', prompt_version: 'test', status: 'complete' },
  news_analysis: analysis(classification, impact),
  priority: 'high',
  ...overrides,
});

test('news classification records general mentions and excluded versions, and routes actual impacts by severity', () => {
  assert.equal(decide(reviewed('general_news', 'not_applicable'), config).action, 'record');
  assert.equal(decide(reviewed('new_vulnerability', 'not_affected'), config).action, 'record');
  for (const classification of ['new_vulnerability', 'known_vulnerability_update']) {
    assert.equal(decide(reviewed(classification, 'affected'), config).action, 'notify');
    assert.equal(decide(reviewed(classification, 'affected', { priority: 'low' }), config).action, 'record');
    assert.equal(decide(reviewed(classification, 'unknown'), config).action, 'digest');
  }
  const pending = assess(inventory, [story], config, now)[0];
  assert.equal(decide(pending, config).action, 'record');
  assert.equal(decide(pending, { ...config, models: { ...config.models, enabled: false } }).action, 'digest');
});

test('AI news claims cannot suppress authoritative criticality or configured exploitation', () => {
  assert.equal(
    decide(reviewed('general_news', 'not_applicable', { source_severity: 'critical' }), config).action,
    'notify',
  );
  assert.equal(
    decide(reviewed('general_news', 'not_applicable', { exploited: true }), config).action,
    'notify',
  );
  assert.equal(
    decide(
      reviewed('general_news', 'not_applicable', {
        news_only: false,
        category: 'product',
        applicability: 'unknown',
        source_severity: 'critical',
      }),
      { ...config, policy: { ...config.policy, product: config.policy.news } },
    ).action,
    'notify',
  );
});

test('generic products retain AI news filtering when a cited CVE is also collected', () => {
  const cve = {
    ...story,
    id: 'cve_now:CVE-2026-10001',
    source: 'cve_now',
    kind: 'advisory',
    severity: 'high',
    aliases: ['CVE-2026-10001'],
    title: 'Example Database flaw',
  };
  const finding = assess(inventory, [cve, { ...story, aliases: ['CVE-2026-10001'] }], config, now)[0];
  assert.equal(finding.category, 'product');
  assert.equal(finding.news_only, false);
  assert.equal(finding.news_candidate, true);
  const rules = { ...config, policy: { ...config.policy, product: config.policy.news } };
  const analyzed = {
    ...finding,
    ai: reviewed().ai,
    news_analysis: analysis('new_vulnerability', 'not_affected'),
  };
  assert.equal(decide(analyzed, rules).action, 'record');
  assert.equal(
    decide({ ...analyzed, news_analysis: analysis('new_vulnerability', 'affected') }, rules).action,
    'notify',
  );
});

test('multi-product news keeps each configured product even when a package is mentioned', () => {
  const configured = structuredClone(inventory);
  configured.systems[0].components = [
    { id: 'parser', ecosystem: 'npm', name: 'example-parser', version: '1.0.0' },
  ];
  const findings = assess(
    configured,
    [
      {
        ...story,
        description:
          'CVE-2026-10001 affects example-parser. Example Database also has a newly disclosed flaw.',
        aliases: ['CVE-2026-10001'],
      },
    ],
    config,
    now,
  );
  assert.deepEqual(findings.map((f) => f.component_id).sort(), ['parser', 'product:example database']);
});

test('general system news is classified before delivery and does not flap into new revisions on rescans', async (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  store.saveEvidence([story], {});
  let requests = 0;
  const http = async (_url, request) => {
    requests++;
    const input = JSON.stringify(JSON.parse(request.body));
    assert.match(input, /Example Database/);
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        choices: [
          {
            finish_reason: 'stop',
            message: {
              content: JSON.stringify({
                relevance: 'irrelevant',
                priority: 'low',
                summary: 'General conference coverage without a vulnerability.',
                evidence_ids: [story.id],
                quotes: [{ evidence_id: story.id, quote }],
                news_analysis: analysis(),
              }),
            },
          },
        ],
      }),
    };
  };
  const beforeDelivery = async () =>
    assert.equal(store.jobs().filter((j) => j.status === 'pending').length, 0);
  const report = await runScan({ config, inventory, store, http, now, onUrgent: beforeDelivery });
  const finding = report.findings.find((f) => f.category === 'news');
  assert.equal(finding.news_analysis.classification, 'general_news');
  assert.equal(finding.applicability, 'relevant', 'AI news conclusions do not claim verified safety');
  assert.equal(report.decisions[finding.id].action, 'record');
  const revisions = store.history(finding.id).length;
  await runScan({ config, inventory, store, http, now: now + 1000, onUrgent: beforeDelivery });
  const historical = await runScan({
    config,
    inventory,
    store,
    http,
    now: now + 31 * 60_000,
    onUrgent: beforeDelivery,
  });
  assert.equal(
    historical.decisions[finding.id].action,
    'record',
    'An unchanged general article does not become a vulnerability when RSS rotates',
  );
  assert.equal(requests, 1, 'Unchanged evidence uses the model cache');
  assert.equal(store.history(finding.id).length, revisions);
  assert.equal(store.jobs().length, 0);
});

test('classification and impact are material revisions and notification text makes AI provenance explicit', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const first = reviewed('new_vulnerability', 'unknown');
  store.saveAssessment(first, decide(first, config), now);
  const second = reviewed('new_vulnerability', 'affected');
  store.saveAssessment(second, decide(second, config), now + 1000);
  assert.equal(store.history(first.id).length, 2);
  const job = store.claimDue(now + 1000);
  const text = notificationText(job).text;
  assert.match(text, /AI news classification: new_vulnerability; reported system impact: affected/);
  assert.match(text, /Reported versions: 4.2/);
});

test('stale news invalidates a pending AI impact alert before the delivery callback', async (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const affectedQuote = 'Example Database version 4.2 is affected by the newly disclosed vulnerability.';
  store.saveEvidence([{ ...story, description: affectedQuote }], {});
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
              summary: 'Installed database version is reported affected.',
              evidence_ids: [story.id],
              quotes: [{ evidence_id: story.id, quote: affectedQuote }],
              news_analysis: {
                ...analysis('new_vulnerability', 'affected'),
                quotes: [{ evidence_id: story.id, quote: affectedQuote }],
              },
            }),
          },
        },
      ],
    }),
  });
  const first = await runScan({ config, inventory, store, http, now });
  const finding = first.findings.find((f) => f.category === 'news');
  assert.equal(first.decisions[finding.id].action, 'notify');
  assert.equal(store.jobs().filter((j) => j.status === 'pending').length, 1);
  const later = now + 31 * 60_000;
  const second = await runScan({
    config,
    inventory,
    store,
    http,
    now: later,
    onUrgent: async () => {
      assert.equal(
        store.claimDue(later),
        undefined,
        'An old affected conclusion must not escape before freshness review',
      );
    },
  });
  const changed = second.findings.find((f) => f.id === finding.id);
  assert.equal(changed.news_analysis.impact, 'unknown');
  assert.equal(second.decisions[finding.id].action, 'digest');
  assert.equal(store.claimDue(later), undefined, 'The new review digest waits for its configured time');
});
