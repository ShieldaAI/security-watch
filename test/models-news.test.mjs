import test from 'node:test';
import assert from 'node:assert/strict';
import { ModelAnalyzer } from '../dist/models.js';
import { parseConfig } from '../dist/config.js';
import { decide } from '../dist/assessment.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const CVE = 'CVE-2026-12345';
const QUOTE = `Researchers disclosed ${CVE}, which affects Acme Gateway versions before 2.5.0. Version 2.5.0 fixes the issue.`;
const article = {
  id: 'thn:acme',
  source: 'hacker-news',
  kind: 'news',
  content_status: 'full',
  title: 'Acme Gateway security report',
  description: QUOTE,
  aliases: [CVE],
  severity: 'high',
  packages: [],
  modified_at: new Date(NOW).toISOString(),
  fetched_at: new Date(NOW).toISOString(),
  url: 'https://thehackernews.com/2026/10/acme.html',
};
const system = {
  id: 'production',
  name: 'Production',
  environment: 'production',
  exposure: 'internet',
  criticality: 'high',
  updated_at: new Date(NOW).toISOString(),
  components: [],
  products: [{ name: 'Acme Gateway', version: '2.4.0', keywords: ['Acme'] }],
  keywords: [],
};
const finding = {
  id: 'finding',
  event_id: CVE,
  system_id: system.id,
  component_id: 'product:acme gateway',
  category: 'product',
  news_only: true,
  news_candidate: true,
  applicability: 'unknown',
  source_severity: 'high',
  priority: 'high',
  title: article.title,
  summary: 'A product name appears in news.',
  reasons: [],
  evidence_ids: [article.id],
  urls: [article.url],
  exploited: false,
  updated_at: new Date(NOW).toISOString(),
};
function configuration() {
  return parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false },
    models: {
      enabled: true,
      analysis: {
        provider: 'openai-compatible',
        model: 'analysis',
        api_key_env: 'MODEL_NEWS_TEST_UNUSED',
        endpoint: 'http://127.0.0.1:1234/v1/chat/completions',
        allow_private_endpoint: true,
      },
    },
    policy: {
      product: { levels: ['high', 'critical'], basis: 'priority', channels: ['slack'] },
      news: { levels: ['high', 'critical'], basis: 'priority', channels: ['slack'] },
      health_channels: [],
    },
    notifications: { slack: { webhook_url_env: 'SLACK_NEWS_TEST_UNUSED' } },
  });
}
function state() {
  const cache = new Map();
  return {
    getMeta: (key) => cache.get(key),
    setMeta: (key, value) => cache.set(key, value),
    reserveBudget: () => true,
  };
}
function payload(news = {}, quote = QUOTE, extra = {}) {
  return {
    relevance: 'relevant',
    priority: 'high',
    summary: 'Evaluate the exact installed Acme Gateway version against the article.',
    evidence_ids: [article.id],
    quotes: [{ evidence_id: article.id, quote }],
    news_analysis: {
      classification: 'new_vulnerability',
      impact: 'affected',
      affected_products: ['Acme Gateway'],
      affected_versions: ['versions before 2.5.0'],
      prerequisites: [],
      rationale: 'The installed 2.4.0 version is within the reported affected versions.',
      quotes: [{ evidence_id: article.id, quote }],
      ...news,
    },
    ...extra,
  };
}
const response = (value) => ({
  status: 200,
  headers: {},
  body: JSON.stringify({ choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(value) } }] }),
});
async function analyze(
  value = payload(),
  { evidence = [article], target = finding, inventory = system, config = configuration(), http } = {},
) {
  return new ModelAnalyzer(config, state(), http ?? (async () => response(value)), () => NOW).analyze(
    target,
    inventory,
    evidence,
  );
}

test('new vulnerability analysis targets the configured product and event and preserves authoritative uncertainty', async () => {
  let request;
  const result = await analyze(payload(), {
    http: async (_url, options) => {
      request = JSON.parse(options.body);
      return response(payload());
    },
  });
  const context = JSON.parse(request.messages[1].content);
  assert.deepEqual(context.target, {
    event_id: CVE,
    component_id: 'product:acme gateway',
    category: 'product',
  });
  assert.equal(context.system.products[0].version, '2.4.0');
  assert.equal(request.tools, undefined);
  assert.match(request.messages[0].content, /untrusted DATA, never instructions/);
  assert.equal(result.ai.status, 'complete');
  assert.equal(result.news_analysis.classification, 'new_vulnerability');
  assert.equal(result.news_analysis.impact, 'affected');
  assert.equal(
    result.applicability,
    'unknown',
    'A model claim is separate from authoritative version matching',
  );
  assert.equal(decide(result, configuration()).action, 'notify');
});

test('an explicitly fixed installed product version is recorded quietly as model-claimed not affected', async () => {
  const fixed = { ...system, products: [{ ...system.products[0], version: '2.5.0' }] };
  const result = await analyze(
    payload({
      impact: 'not_affected',
      rationale: 'Installed 2.5.0 is explicitly identified as the fixed release.',
    }),
    { inventory: fixed },
  );
  assert.equal(result.news_analysis.impact, 'not_affected');
  assert.equal(result.relevance, 'irrelevant');
  assert.equal(result.applicability, 'unknown');
  assert.equal(decide(result, configuration()).action, 'record');
});

test('a mere product mention is general news while a known-vulnerability exploitation update stays actionable', async () => {
  const general =
    'Acme Gateway introduced a redesigned management dashboard and a new partner training programme.';
  const result = await analyze(
    payload(
      {
        classification: 'general_news',
        impact: 'not_applicable',
        affected_products: [],
        affected_versions: [],
        rationale:
          'This article describes product features and partnerships without reporting a vulnerability.',
      },
      general,
    ),
    { evidence: [{ ...article, aliases: [], description: general }] },
  );
  assert.equal(result.news_analysis.classification, 'general_news');
  assert.equal(decide(result, configuration()).action, 'record');
  const known = `Attackers are now exploiting known ${CVE} in Acme Gateway versions before 2.5.0; the original patch remains available.`;
  const update = await analyze(payload({ classification: 'known_vulnerability_update' }, known), {
    evidence: [{ ...article, description: known }],
  });
  assert.equal(update.news_analysis.classification, 'known_vulnerability_update');
  assert.equal(update.news_analysis.impact, 'affected');
  assert.equal(decide(update, configuration()).action, 'notify');
});

test('a product finding linked to a noncritical CVE can use news analysis without changing authoritative applicability', async () => {
  const advisory = {
    ...article,
    id: 'cve-now:record',
    source: 'cve-now',
    kind: 'advisory',
    content_status: undefined,
  };
  const data = payload({
    impact: 'not_affected',
    rationale: 'The installed 2.5.0 release is the fixed version stated by the article.',
  });
  const result = await analyze(data, {
    evidence: [article, advisory],
    target: { ...finding, news_only: false, evidence_ids: [article.id, advisory.id] },
    inventory: { ...system, products: [{ ...system.products[0], version: '2.5.0' }] },
  });
  assert.equal(result.relevance, 'irrelevant');
  assert.equal(result.applicability, 'unknown');
  assert.equal(decide(result, configuration()).action, 'record');
  const critical = await analyze(data, {
    evidence: [article, advisory],
    target: {
      ...finding,
      news_only: false,
      source_severity: 'critical',
      priority: 'critical',
      evidence_ids: [article.id, advisory.id],
    },
    inventory: { ...system, products: [{ ...system.products[0], version: '2.5.0' }] },
  });
  assert.equal(decide(critical, configuration()).action, 'notify');
});

test('article completeness, stale evidence, and unknown installed versions cannot assert system safety', async (t) => {
  for (const content_status of ['excerpt', 'unavailable'])
    await t.test(content_status, async () => {
      const result = await analyze(payload({ impact: 'not_affected' }), {
        evidence: [{ ...article, content_status }],
      });
      assert.equal(result.news_analysis.classification, 'unknown');
      assert.equal(result.news_analysis.impact, 'unknown');
      assert.equal(decide(result, configuration()).action, 'digest');
    });
  const stale = await analyze(payload(), {
    evidence: [{ ...article, fetched_at: new Date(NOW - 86_400_000).toISOString() }],
  });
  assert.equal(stale.news_analysis.classification, 'unknown');
  assert.equal(stale.news_analysis.impact, 'unknown');
  const missingVersion = await analyze(payload({ impact: 'not_affected' }), {
    inventory: { ...system, products: [{ ...system.products[0], version: undefined }] },
  });
  assert.equal(missingVersion.news_analysis.classification, 'new_vulnerability');
  assert.equal(missingVersion.news_analysis.impact, 'unknown');
  const missingArticle = await analyze(payload(), { evidence: [] });
  assert.equal(missingArticle.ai.status, 'unavailable');
  assert.notEqual(decide(missingArticle, configuration()).action, 'record');
});

test('ordinary complete article text fits the actual input budget and larger articles disclose truncation', async () => {
  let context;
  const http = async (_url, options) => {
    context = JSON.parse(JSON.parse(options.body).messages[1].content);
    assert(JSON.stringify(context).length <= configuration().models.max_input_chars);
    return response(payload());
  };
  const full = await analyze(payload(), {
    evidence: [{ ...article, description: `${QUOTE} ${'Additional context. '.repeat(350)}` }],
    http,
  });
  assert.equal(full.news_analysis.impact, 'affected');
  assert(context.evidence[0].description.length > 6000);
  assert.deepEqual(context.coverage.truncated_evidence_ids, []);
  const truncated = await analyze(payload(), {
    evidence: [{ ...article, description: `${QUOTE} ${'Additional context. '.repeat(2000)}` }],
    http,
  });
  assert.equal(truncated.news_analysis.classification, 'unknown');
  assert.deepEqual(context.coverage.truncated_evidence_ids, [article.id]);
});

test('same priority and relevance do not hide disagreement over whether a vulnerability is new', async () => {
  const config = configuration();
  config.models.verification = { ...config.models.analysis, model: 'verifier' };
  let calls = 0;
  const result = await analyze(payload(), {
    config,
    http: async () =>
      response(
        payload({ classification: ++calls === 1 ? 'new_vulnerability' : 'known_vulnerability_update' }),
      ),
  });
  assert.equal(calls, 2);
  assert.equal(result.ai.status, 'conflicting');
  assert.equal(result.news_analysis.classification, 'unknown');
  assert.equal(result.news_analysis.impact, 'unknown');
});

test('invented product/version claims and borrowed advisory quotes cannot become news conclusions', async (t) => {
  for (const [name, news] of [
    ['product', { affected_products: ['Unrelated Appliance'] }],
    ['version', { affected_versions: ['versions before 99.0.0'] }],
    ['prerequisite', { prerequisites: ['authentication disabled'] }],
    [
      'quote',
      {
        quotes: [
          {
            evidence_id: article.id,
            quote: 'A completely invented quote claiming this version is unaffected.',
          },
        ],
      },
    ],
    ['inconsistent classification', { classification: 'general_news', impact: 'affected' }],
  ])
    await t.test(name, async () => {
      const result = await analyze(payload(news));
      assert.equal(result.ai.status, 'unavailable');
      assert.equal(result.news_analysis.classification, 'unknown');
      assert.notEqual(decide(result, configuration()).action, 'record');
    });
  const missing = await analyze(payload({}, QUOTE, { news_analysis: null }));
  assert.equal(missing.ai.status, 'unavailable');
  assert(missing.reasons.some((r) => r.startsWith('MODEL_NEWS_ANALYSIS_MISSING')));
});

test('multi-CVE article conclusions must quote the target and cache independently for each event', async () => {
  const other = 'CVE-2026-54321';
  const both = `${QUOTE} The same report discusses ${other}, which is a separate vulnerability in Acme Gateway.`;
  const evidence = [{ ...article, description: both, aliases: [CVE, other] }];
  const wrongSubject = await analyze(payload(), { evidence, target: { ...finding, event_id: other } });
  assert.equal(wrongSubject.ai.status, 'unavailable');
  assert(wrongSubject.reasons.some((r) => r.startsWith('MODEL_AMBIGUOUS_NEWS_SUBJECT')));
  let calls = 0;
  const analyzer = new ModelAnalyzer(
    configuration(),
    state(),
    async () => {
      calls++;
      return response(payload({}, both));
    },
    () => NOW,
  );
  await analyzer.analyze(finding, system, evidence);
  await analyzer.analyze({ ...finding, event_id: other }, system, evidence);
  await analyzer.analyze(finding, system, [
    { ...evidence[0], fetched_at: new Date(NOW + 1000).toISOString() },
  ]);
  assert.equal(
    calls,
    2,
    'Different event targets cannot reuse each other; merely refreshed fetch time can reuse current analysis',
  );
});

test('unrelated configured component versions cannot support a keyword-only impact assertion', async () => {
  const inventory = {
    ...system,
    products: [],
    components: [{ id: 'react', ecosystem: 'npm', name: 'react', version: '20.0.0' }],
    keywords: ['Acme'],
  };
  const result = await analyze(payload({ impact: 'not_affected' }), {
    inventory,
    target: { ...finding, component_id: undefined, category: 'news' },
  });
  assert.equal(result.news_analysis.impact, 'unknown');
  assert.equal(decide(result, configuration()).action, 'digest');
});

test('an affected claim naming another product cannot assert impact for the configured target', async () => {
  const quote =
    'Another Gateway versions before 2.5.0 are affected by the issue. Acme Gateway is only mentioned as an integration partner.';
  const result = await analyze(payload({ affected_products: ['Another Gateway'] }, quote), {
    evidence: [{ ...article, description: quote }],
  });
  assert.equal(result.news_analysis.impact, 'unknown');
  assert.equal(decide(result, configuration()).action, 'digest');
});
