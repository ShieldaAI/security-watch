import test from 'node:test';
import assert from 'node:assert/strict';
import { ModelAnalyzer } from '../dist/models.js';
import { parseConfig } from '../dist/config.js';
import { decide } from '../dist/assessment.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const QUOTE = 'An explicit article excerpt describes the alpha package security report.';
const source = {
  id: 'feed:alpha',
  source: 'feed:fixture',
  kind: 'news',
  content_status: 'full',
  title: 'Alpha security report',
  description: QUOTE,
  severity: 'high',
  aliases: [],
  packages: [],
  modified_at: new Date(NOW).toISOString(),
  fetched_at: new Date(NOW).toISOString(),
  url: 'https://example.com/report',
};
const system = {
  id: 'production',
  name: 'Production',
  environment: 'production',
  exposure: 'internal',
  criticality: 'high',
  updated_at: new Date(NOW).toISOString(),
  components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
  products: [],
  keywords: [],
};
const finding = {
  id: 'finding',
  event_id: source.id,
  system_id: system.id,
  category: 'news',
  applicability: 'relevant',
  source_severity: 'high',
  priority: 'high',
  title: source.title,
  summary: 'News names an installed dependency.',
  reasons: [],
  evidence_ids: [source.id],
  urls: [source.url],
  exploited: false,
  updated_at: new Date(NOW).toISOString(),
};
function configuration(provider = 'openai-compatible', extra = {}) {
  return parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false },
    models: {
      enabled: true,
      analysis: {
        provider,
        model: 'fixture',
        api_key_env: 'MODEL_SECURITY_UNUSED',
        endpoint: 'http://127.0.0.1:1234/v1/chat/completions',
        allow_private_endpoint: true,
      },
      ...extra,
    },
    policy: { news: { levels: ['high', 'critical'], channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'SLACK_UNUSED' } },
  });
}
function state() {
  const cache = new Map();
  let reservations = 0;
  return {
    getMeta: (key) => cache.get(key),
    setMeta: (key, value) => cache.set(key, value),
    reserveBudget: () => {
      reservations++;
      return true;
    },
    get reservations() {
      return reservations;
    },
  };
}
function output(extra = {}) {
  return {
    relevance: 'irrelevant',
    priority: 'low',
    summary: 'This excerpt alone does not establish applicability.',
    evidence_ids: [source.id],
    quotes: [{ evidence_id: source.id, quote: QUOTE }],
    news_analysis: {
      classification:
        extra.relevance === 'unknown'
          ? 'unknown'
          : extra.relevance === 'relevant'
            ? 'known_vulnerability_update'
            : 'general_news',
      impact: extra.relevance === 'unknown' || extra.relevance === 'relevant' ? 'unknown' : 'not_applicable',
      affected_products: [],
      affected_versions: [],
      prerequisites: [],
      rationale: 'The supplied excerpt supports this news classification.',
      quotes: [{ evidence_id: source.id, quote: QUOTE }],
    },
    ...extra,
  };
}
function response(analysis = output(), extra = {}) {
  return {
    status: 200,
    headers: {},
    body: JSON.stringify({
      choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(analysis), ...extra } }],
    }),
  };
}

test('truncated source context cannot suppress a news finding, including on cache hits', async () => {
  const cfg = configuration();
  const store = state();
  let calls = 0;
  let context;
  const long = {
    ...source,
    description: `${QUOTE} ${'Padding. '.repeat(4000)} Actually alpha 1.0.0 is affected.`,
  };
  const analyzer = new ModelAnalyzer(
    cfg,
    store,
    async (_url, request) => {
      calls++;
      context = JSON.parse(JSON.parse(request.body).messages[1].content);
      return response();
    },
    () => NOW,
  );
  for (let i = 0; i < 2; i++) {
    const result = await analyzer.analyze(finding, system, [long]);
    assert.equal(result.relevance, 'unknown');
    assert.equal(result.applicability, 'unknown');
    assert.equal(decide(result, cfg).action, 'digest');
    assert(result.reasons.some((reason) => reason.includes('bounded excerpts')));
  }
  assert.deepEqual(context.coverage.truncated_evidence_ids, [source.id]);
  assert.equal(calls, 1);
  assert.equal(store.reservations, 1);
});

test('bounded evidence selection retains authoritative records and reports omitted evidence', async () => {
  const articles = Array.from({ length: 7 }, (_, index) => ({ ...source, id: `feed:${index}` }));
  const advisory = { ...source, id: 'osv:critical', source: 'osv', kind: 'advisory', severity: 'critical' };
  const evidence = [...articles, advisory];
  let context;
  const result = await new ModelAnalyzer(
    configuration(),
    state(),
    async (_url, request) => {
      context = JSON.parse(JSON.parse(request.body).messages[1].content);
      const first = context.evidence[0];
      return response(
        output({
          evidence_ids: [first.id, 'feed:0'],
          quotes: [
            { evidence_id: first.id, quote: QUOTE },
            { evidence_id: 'feed:0', quote: QUOTE },
          ],
          news_analysis: { ...output().news_analysis, quotes: [{ evidence_id: 'feed:0', quote: QUOTE }] },
        }),
      );
    },
    () => NOW,
  ).analyze({ ...finding, evidence_ids: evidence.map((item) => item.id) }, system, evidence);
  assert.equal(context.evidence[0].id, advisory.id);
  assert.equal(context.coverage.total_evidence, 8);
  assert.equal(context.coverage.omitted_evidence, 2);
  assert.equal(result.news_analysis.classification, 'unknown');
  assert.equal(result.news_analysis.impact, 'unknown');
});

test('inventory becoming stale invalidates cached irrelevance and retains a review finding', async () => {
  let now = NOW;
  let calls = 0;
  let context;
  const store = state();
  const cfg = configuration();
  const analyzer = new ModelAnalyzer(
    cfg,
    store,
    async (_url, request) => {
      calls++;
      context = JSON.parse(JSON.parse(request.body).messages[1].content);
      return response();
    },
    () => now,
  );
  assert.equal((await analyzer.analyze(finding, system, [source])).relevance, 'irrelevant');
  now += 8 * 86_400_000;
  const stale = await analyzer.analyze({ ...finding, applicability: 'unknown' }, system, [source]);
  assert.equal(calls, 2);
  assert.equal(context.system.inventory_status, 'stale');
  assert.equal(stale.relevance, 'unknown');
  assert.equal(decide(stale, cfg).action, 'digest');
});

test('explicit model uncertainty on fresh news enters the review digest', async () => {
  const cfg = configuration();
  const result = await new ModelAnalyzer(
    cfg,
    state(),
    async () => response(output({ relevance: 'unknown' })),
    () => NOW,
  ).analyze(finding, system, [source]);
  assert.equal(result.applicability, 'unknown');
  assert.equal(decide(result, cfg).action, 'digest');
});

test('missing evidence and pre-aborted requests consume no model budget or HTTP request', async () => {
  const store = state();
  let calls = 0;
  const http = async () => {
    calls++;
    return response();
  };
  const result = await new ModelAnalyzer(configuration(), store, http, () => NOW).analyze(
    finding,
    system,
    [],
  );
  assert.equal(result.ai.status, 'unavailable');
  assert(result.reasons.some((reason) => reason.startsWith('MODEL_EVIDENCE_MISSING')));
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    new ModelAnalyzer(configuration(), store, http, () => NOW, controller.signal).analyze(finding, system, [
      source,
    ]),
    { name: 'AbortError' },
  );
  assert.equal(calls, 0);
  assert.equal(store.reservations, 0);
});

test('a refusal accompanying plausible compatible JSON is not treated as a valid assessment', async () => {
  const result = await new ModelAnalyzer(
    configuration(),
    state(),
    async () => response(output(), { refusal: 'Unable to assess this input.' }),
    () => NOW,
  ).analyze(finding, system, [source]);
  assert.equal(result.ai.status, 'unavailable');
  assert(result.reasons.some((reason) => reason.startsWith('MODEL_REFUSAL')));
  assert.equal(result.relevance, 'unknown');
});

test('a cancelled first analysis cannot begin a verification request', async () => {
  const controller = new AbortController();
  const store = state();
  let calls = 0;
  const cfg = configuration();
  cfg.models.verification = { ...cfg.models.analysis, model: 'reviewer' };
  const result = await new ModelAnalyzer(
    cfg,
    store,
    async () => {
      calls++;
      controller.abort();
      return response(output({ priority: 'critical', relevance: 'relevant' }));
    },
    () => NOW,
    controller.signal,
  ).analyze(finding, system, [source]);
  assert.equal(calls, 1);
  assert.equal(store.reservations, 1);
  assert.equal(result.ai.status, 'unavailable');
});

test('OpenAI refusal content alongside plausible JSON cannot clear a finding', async (t) => {
  const previous = process.env.MODEL_SECURITY_UNUSED;
  process.env.MODEL_SECURITY_UNUSED = 'synthetic-only';
  t.after(() => {
    if (previous === undefined) delete process.env.MODEL_SECURITY_UNUSED;
    else process.env.MODEL_SECURITY_UNUSED = previous;
  });
  const result = await new ModelAnalyzer(
    configuration('openai'),
    state(),
    async () => ({
      status: 200,
      headers: {},
      body: JSON.stringify({
        status: 'completed',
        output: [
          {
            type: 'message',
            content: [
              { type: 'refusal', refusal: 'Cannot assess.' },
              { type: 'output_text', text: JSON.stringify(output()) },
            ],
          },
        ],
      }),
    }),
    () => NOW,
  ).analyze(finding, system, [source]);
  assert.equal(result.ai.status, 'unavailable');
  assert(result.reasons.some((reason) => reason.startsWith('MODEL_REFUSAL')));
});

test('a new critical model proposal survives verifier outage and disagreement as urgent review', async (t) => {
  for (const mode of ['outage', 'disagreement', 'budget'])
    await t.test(mode, async () => {
      const cfg = configuration();
      cfg.models.verification = { ...cfg.models.analysis, model: 'reviewer' };
      const store = state();
      let calls = 0;
      if (mode === 'budget') {
        const reserve = store.reserveBudget;
        store.reserveBudget = () => store.reservations === 0 && reserve();
      }
      const result = await new ModelAnalyzer(
        cfg,
        store,
        async () => {
          calls++;
          if (calls === 1) return response(output({ relevance: 'relevant', priority: 'critical' }));
          if (mode === 'outage') throw new Error('Simulated provider outage');
          return response(output({ relevance: 'irrelevant', priority: 'low' }));
        },
        () => NOW,
      ).analyze(finding, system, [source]);
      assert.equal(result.priority, 'critical');
      assert.equal(result.source_severity, 'high');
      assert.equal(result.relevance, 'unknown');
      assert.equal(result.applicability, 'unknown');
      assert.equal(result.ai.status, mode === 'disagreement' ? 'conflicting' : 'unavailable');
      assert.equal(decide(result, cfg).action, 'notify');
      assert(
        result.reasons.some((reason) => reason.includes(QUOTE)),
        'Review retains the evidence supporting the unverified proposal',
      );
    });
});
