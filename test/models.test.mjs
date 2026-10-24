import test from 'node:test';
import assert from 'node:assert/strict';
import { ModelAnalyzer } from '../dist/models.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';
import { parseConfig } from '../dist/config.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const ID = 'GHSA-abcd-2345-efgh';
const EVIDENCE_ID = `osv:${ID}`;
const QUOTE = 'The alpha package has a confirmed vulnerability in version 1.0.0.';
const DESCRIPTION = `${QUOTE} Upgrade to version 1.0.1.`;
const system = {
  id: 'prod',
  name: 'Production',
  environment: 'production',
  exposure: 'internal',
  criticality: 'high',
  updated_at: new Date(NOW).toISOString(),
  components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
  products: [],
  keywords: [],
};
const evidence = {
  id: EVIDENCE_ID,
  source: 'osv',
  kind: 'advisory',
  title: 'Alpha advisory',
  description: DESCRIPTION,
  aliases: [ID, 'CVE-2026-12345'],
  severity: 'high',
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<1.0.1' }],
  modified_at: new Date(NOW - 3600000).toISOString(),
  fetched_at: new Date(NOW).toISOString(),
  url: 'https://example.com/advisory',
};
const assessment = {
  id: 'finding',
  event_id: ID.toUpperCase(),
  system_id: 'prod',
  component_id: 'alpha',
  category: 'library',
  applicability: 'affected',
  source_severity: 'high',
  priority: 'high',
  title: evidence.title,
  summary: 'Installed alpha version matches.',
  reasons: [],
  evidence_ids: [EVIDENCE_ID],
  urls: [evidence.url],
  exploited: false,
  updated_at: new Date(NOW).toISOString(),
};
const payload = (extra = {}) => ({
  relevance: 'relevant',
  priority: 'critical',
  summary: 'Prioritize this affected deployment.',
  evidence_ids: [EVIDENCE_ID],
  quotes: [{ evidence_id: EVIDENCE_ID, quote: QUOTE }],
  ...extra,
});
function spec(provider = 'openai-compatible', extra = {}) {
  return {
    provider,
    model: 'fixture-model',
    api_key_env: 'SECURITY_WATCH_MODEL_FIXTURE_TOKEN',
    ...(provider === 'openai-compatible'
      ? { endpoint: 'http://127.0.0.1:1234/v1/chat/completions', allow_private_endpoint: true }
      : {}),
    ...extra,
  };
}
function config(provider = 'openai-compatible', overrides = {}) {
  const base = {
    version: 1,
    sources: { osv: true, github: false, kev: false, feeds: [] },
    models: { enabled: true, analysis: spec(provider), daily_token_limit: 1000000, ...overrides.models },
    policy: {
      library: { levels: ['high', 'critical'], basis: 'priority', channels: ['slack'] },
      health_channels: [],
      ...overrides.policy,
    },
    notifications: {
      slack: { webhook_url_env: 'UNUSED_SLACK_FIXTURE' },
      email: { smtp_url_env: 'UNUSED_SMTP_FIXTURE', from: 'bot@example.com', to: ['security@example.com'] },
    },
  };
  return parseConfig(base);
}
function response(provider, analysis = payload(), extra = {}) {
  const data =
    provider === 'openai'
      ? {
          status: 'completed',
          output: [{ type: 'message', content: [{ type: 'output_text', text: JSON.stringify(analysis) }] }],
          ...extra,
        }
      : provider === 'anthropic'
        ? {
            type: 'message',
            stop_reason: 'end_turn',
            content: [{ type: 'text', text: JSON.stringify(analysis) }],
            ...extra,
          }
        : { choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(analysis) } }], ...extra };
  return { status: 200, headers: {}, body: JSON.stringify(data) };
}
function temporaryToken(t) {
  const previous = process.env.SECURITY_WATCH_MODEL_FIXTURE_TOKEN;
  process.env.SECURITY_WATCH_MODEL_FIXTURE_TOKEN = 'fixture-token-only';
  t.after(() => {
    if (previous === undefined) delete process.env.SECURITY_WATCH_MODEL_FIXTURE_TOKEN;
    else process.env.SECURITY_WATCH_MODEL_FIXTURE_TOKEN = previous;
  });
}
function memory(t) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  return store;
}
function successJobs(store, now) {
  let job;
  while ((job = store.claimDue(now))) store.completeJob(job.id, 'accepted', now);
}
function fixtureHttp(options = {}) {
  const state = {
    modelCalls: 0,
    sourceCalls: 0,
    outage: false,
    priority: 'critical',
    description: DESCRIPTION,
    modified: new Date(NOW - 3600000).toISOString(),
    withdrawn: false,
    ...options,
  };
  const client = async (url, request) => {
    if (url.endsWith('/querybatch')) {
      state.sourceCalls++;
      const queries = JSON.parse(request.body).queries;
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          results: queries.map((query) =>
            query.version === '1.0.0' && !state.withdrawn
              ? { vulns: [{ id: ID, modified: state.modified }] }
              : {},
          ),
        }),
      };
    }
    if (url.includes('/vulns/')) {
      state.sourceCalls++;
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          id: ID,
          modified: state.modified,
          published: '2026-01-01T00:00:00Z',
          summary: 'Alpha advisory',
          details: state.description,
          aliases: ['CVE-2026-12345'],
          database_specific: { severity: 'HIGH' },
          affected: [
            {
              package: { ecosystem: 'npm', name: 'alpha' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }],
            },
          ],
          ...(state.withdrawn ? { withdrawn: state.modified } : {}),
        }),
      };
    }
    state.modelCalls++;
    if (state.outage) throw new Error('Provider unavailable with redacted transport data');
    return response('openai-compatible', payload({ priority: state.priority }));
  };
  return { state, client };
}

test('OpenAI, Anthropic and compatible adapters send bounded protocol-specific requests without tools', async (t) => {
  for (const provider of ['openai', 'anthropic', 'openai-compatible'])
    await t.test(provider, async (t) => {
      temporaryToken(t);
      const store = memory(t);
      const cfg = config(provider);
      let sent;
      const result = await new ModelAnalyzer(
        cfg,
        store,
        async (url, options) => {
          sent = { url, options, body: JSON.parse(options.body) };
          return response(provider);
        },
        () => NOW,
      ).analyze(assessment, system, [evidence]);
      assert.equal(result.ai.status, 'complete');
      assert.equal(result.priority, 'critical');
      assert.equal(sent.options.method, 'POST');
      assert.equal(sent.options.redirects, 0);
      assert.equal(sent.options.maxBytes, 262144);
      assert.equal(sent.body.tools, undefined);
      assert.equal(sent.body.model, 'fixture-model');
      if (provider === 'openai') {
        assert.equal(sent.url, 'https://api.openai.com/v1/responses');
        assert.equal(sent.options.headers.authorization, 'Bearer fixture-token-only');
        assert.equal(sent.body.store, false);
        assert.equal(sent.body.text.format.strict, true);
        assert.equal(sent.body.max_output_tokens, cfg.models.max_output_tokens);
        assert.equal(JSON.parse(sent.body.input).system.components[0].name, 'alpha');
      } else if (provider === 'anthropic') {
        assert.equal(sent.url, 'https://api.anthropic.com/v1/messages');
        assert.equal(sent.options.headers['x-api-key'], 'fixture-token-only');
        assert.equal(sent.options.headers['anthropic-version'], '2023-06-01');
        assert.match(sent.body.system, /JSON schema/);
        assert.equal(sent.body.max_tokens, cfg.models.max_output_tokens);
      } else {
        assert.equal(sent.options.allowPrivate, true);
        assert.equal(sent.body.response_format.json_schema.strict, true);
        assert.equal(sent.body.max_tokens, cfg.models.max_output_tokens);
      }
      assert.equal(store.budgets()[0].requests, 1);
      assert.equal(store.budgets()[0].usd, null, 'Unconfigured pricing remains unknown');
      assert.equal(JSON.stringify(store.findings()).includes('fixture-token-only'), false);
    });
});

test('all adapters reject partial output, refusals, invented citations and unsupported quotes', async (t) => {
  for (const provider of ['openai', 'anthropic', 'openai-compatible']) {
    const partial =
      provider === 'openai'
        ? response(provider, payload(), { status: 'incomplete' })
        : provider === 'anthropic'
          ? response(provider, payload(), { stop_reason: 'max_tokens' })
          : response(provider, payload(), {
              choices: [{ finish_reason: 'length', message: { content: JSON.stringify(payload()) } }],
            });
    const refusal =
      provider === 'openai'
        ? response(provider, payload(), {
            output: [{ type: 'message', content: [{ type: 'refusal', refusal: 'Cannot assess' }] }],
          })
        : provider === 'anthropic'
          ? response(provider, payload(), {
              stop_reason: 'refusal',
              content: [{ type: 'text', text: 'Cannot assess' }],
            })
          : response(provider, payload(), {
              choices: [{ finish_reason: 'stop', message: { content: null, refusal: 'Cannot assess' } }],
            });
    for (const [name, reply] of [
      ['partial', partial],
      ['refusal', refusal],
      ['invented citation', response(provider, payload({ evidence_ids: ['invented'] }))],
      [
        'bad quote',
        response(
          provider,
          payload({
            quotes: [
              {
                evidence_id: EVIDENCE_ID,
                quote: 'This fabricated sentence is not present in the source material.',
              },
            ],
          }),
        ),
      ],
    ]) {
      await t.test(`${provider}: ${name}`, async (t) => {
        temporaryToken(t);
        const store = memory(t);
        const result = await new ModelAnalyzer(
          config(provider),
          store,
          async () => reply,
          () => NOW,
        ).analyze(assessment, system, [evidence]);
        assert.equal(result.ai.status, 'unavailable');
        assert.equal(result.applicability, 'affected');
        assert.equal(result.priority, 'high');
        assert.equal(store.budgets()[0].requests, 1);
      });
    }
  }
});

test('dollar budgets include verification and cached requests consume no additional reservation', async (t) => {
  const store = memory(t);
  const priced = spec('openai-compatible', { input_usd_per_million: 10, output_usd_per_million: 20 });
  const cfg = config('openai-compatible', {
    models: { analysis: priced, verification: { ...priced, model: 'reviewer' }, daily_budget_usd: 0.08 },
  });
  let calls = 0;
  const analyzer = new ModelAnalyzer(
    cfg,
    store,
    async () => {
      calls++;
      return response('openai-compatible');
    },
    () => NOW,
  );
  const first = await analyzer.analyze(assessment, system, [evidence]);
  const reservations = store.budgets()[0];
  assert(reservations.usd <= cfg.models.daily_budget_usd);
  assert.equal(first.ai.status, 'unavailable', 'Verification cannot exceed the remaining dollar allowance');
  assert.equal(calls, 1);
  await analyzer.analyze(assessment, system, [evidence]);
  assert.equal(calls, 1, 'Cached first analysis is reused; over-budget verification is still blocked');
  assert.equal(store.budgets()[0].requests, 1);
});

test('same evidence and AI escalation do not create new finding revisions or notifications on repeated scans', async (t) => {
  const store = memory(t);
  const cfg = config();
  const { state, client } = fixtureHttp();
  const options = { config: cfg, inventory: { systems: [system] }, store, http: client, now: NOW };
  const first = await runScan(options);
  const finding = first.findings.find((a) => a.category === 'library');
  assert.equal(finding.priority, 'critical');
  successJobs(store, NOW);
  const jobs = store.jobs().length;
  const revisions = store.history(finding.id).length;
  const second = await runScan({ ...options, now: NOW + 60000 });
  assert.equal(second.findings.find((a) => a.category === 'library').priority, 'critical');
  assert.equal(store.jobs().length, jobs);
  assert.equal(store.history(finding.id).length, revisions);
  assert.equal(state.modelCalls, 1);
});

test('a model outage must not downgrade a previous AI escalation and generate alert flapping on recovery', async (t) => {
  const store = memory(t);
  const cfg = config();
  const { state, client } = fixtureHttp();
  const options = { config: cfg, inventory: { systems: [system] }, store, http: client, now: NOW };
  const first = await runScan(options);
  const finding = first.findings.find((a) => a.category === 'library');
  successJobs(store, NOW);
  const jobsBefore = store.jobs().filter((j) => j.finding_id === finding.id).length;
  state.outage = true;
  // A new model version invalidates the old cache but does not change security evidence.
  const changedModel = config('openai-compatible', {
    models: { analysis: spec('openai-compatible', { model: 'fixture-model-v2' }) },
  });
  const unavailable = await runScan({ ...options, config: changedModel, now: NOW + 60000 });
  const degradedFinding = unavailable.findings.find((a) => a.category === 'library');
  assert.equal(degradedFinding.ai.status, 'unavailable');
  assert.equal(degradedFinding.priority, 'critical');
  assert.equal(store.jobs().filter((j) => j.finding_id === finding.id).length, jobsBefore);
  state.outage = false;
  const recovered = await runScan({ ...options, config: changedModel, now: NOW + 120000 });
  assert.equal(recovered.findings.find((a) => a.category === 'library').priority, 'critical');
  assert.equal(store.jobs().filter((j) => j.finding_id === finding.id).length, jobsBefore);
});

test('inventory updates invalidate model context and a verified fixed version is not kept affected by previous AI escalation', async (t) => {
  const store = memory(t);
  const cfg = config();
  const { state, client } = fixtureHttp();
  const options = { config: cfg, inventory: { systems: [system] }, store, http: client, now: NOW };
  await runScan(options);
  const changedSystem = { ...system, exposure: 'internet' };
  await runScan({ ...options, inventory: { systems: [changedSystem] }, now: NOW + 60000 });
  assert.equal(state.modelCalls, 2, 'Deployment context changes invalidate the analysis cache');
  const fixedSystem = { ...changedSystem, components: [{ ...system.components[0], version: '1.0.1' }] };
  const fixed = await runScan({ ...options, inventory: { systems: [fixedSystem] }, now: NOW + 120000 });
  const finding = fixed.findings.find((a) => a.category === 'library');
  assert.equal(finding.applicability, 'not_affected');
  assert.equal(fixed.decisions[finding.id].action, 'record');
  assert.equal(state.modelCalls, 2, 'Established exclusions do not require an AI opinion');
  assert.equal(store.jobs().filter((job) => job.status === 'pending').length, 0);
});

test('routing changes reuse analysis and do not resend accepted destinations', async (t) => {
  const store = memory(t);
  const cfg = config();
  const { state, client } = fixtureHttp();
  const options = { config: cfg, inventory: { systems: [system] }, store, http: client, now: NOW };
  const first = await runScan(options);
  successJobs(store, NOW);
  const finding = first.findings.find((a) => a.category === 'library');
  const acceptedSlack = store.jobs().filter((j) => j.channel === 'slack' && j.status === 'accepted').length;
  const both = config('openai-compatible', {
    policy: { library: { levels: ['high', 'critical'], basis: 'priority', channels: ['slack', 'email'] } },
  });
  await runScan({ ...options, config: both, now: NOW + 60000 });
  assert.equal(
    store.jobs().filter((j) => j.channel === 'slack' && j.status === 'accepted').length,
    acceptedSlack,
  );
  assert.equal(
    store.jobs().filter((j) => j.finding_id === finding.id && j.channel === 'slack' && j.status === 'pending')
      .length,
    0,
  );
  assert.equal(
    store.jobs().filter((j) => j.finding_id === finding.id && j.channel === 'email' && j.status === 'pending')
      .length,
    1,
  );
  assert.equal(state.modelCalls, 1);
});

test('a pending route disabled and reenabled while another route remains active is deliverable again', async (t) => {
  const store = memory(t);
  const { client } = fixtureHttp();
  const both = config('openai-compatible', {
    policy: { library: { levels: ['high', 'critical'], basis: 'priority', channels: ['slack', 'email'] } },
  });
  const emailOnly = config('openai-compatible', {
    policy: { library: { levels: ['high', 'critical'], basis: 'priority', channels: ['email'] } },
  });
  const options = { config: both, inventory: { systems: [system] }, store, http: client, now: NOW };
  await runScan(options);
  await runScan({ ...options, config: emailOnly, now: NOW + 60000 });
  assert.equal(store.jobs().filter((j) => j.channel === 'slack' && j.status === 'pending').length, 0);
  await runScan({ ...options, now: NOW + 120000 });
  assert.equal(store.jobs().filter((j) => j.channel === 'slack' && j.status === 'pending').length, 1);
  assert.equal(store.jobs().filter((j) => j.channel === 'email' && j.status === 'pending').length, 1);
});

test('production scans reserve each model request against the actual UTC day across midnight', async (t) => {
  const originalNow = Date.now;
  let current = Date.parse('2026-10-24T23:59:59Z');
  Date.now = () => current;
  t.after(() => {
    Date.now = originalNow;
  });
  const store = memory(t);
  const cfg = config('openai-compatible', {
    models: { verification: spec('openai-compatible', { model: 'reviewer' }) },
  });
  const { client, state } = fixtureHttp();
  const http = async (url, options) => {
    const reply = await client(url, options);
    if (!url.includes('osv.dev') && state.modelCalls === 1) current = Date.parse('2026-10-25T00:00:01Z');
    return reply;
  };
  const report = await runScan({ config: cfg, inventory: { systems: [system] }, store, http });
  assert.equal(report.findings.find((f) => f.category === 'library').ai.status, 'complete');
  assert.deepEqual(
    store.budgets().map((day) => ({ day: day.day, requests: day.requests })),
    [
      { day: '2026-10-24', requests: 1 },
      { day: '2026-10-25', requests: 1 },
    ],
  );
});

test('stale inventory and an AI outage cannot turn a prior critical finding into a lower-priority review', async (t) => {
  const store = memory(t);
  const cfg = config();
  const { state, client } = fixtureHttp();
  const options = { config: cfg, inventory: { systems: [system] }, store, http: client, now: NOW };
  await runScan(options);
  successJobs(store, NOW);
  state.outage = true;
  const changedModel = config('openai-compatible', {
    models: { analysis: spec('openai-compatible', { model: 'fixture-model-v2' }) },
  });
  const later = await runScan({ ...options, config: changedModel, now: NOW + 8 * 86_400_000 });
  const finding = later.findings.find((item) => item.category === 'library');
  assert.equal(finding.applicability, 'unknown');
  assert.equal(finding.ai.status, 'unavailable');
  assert.equal(finding.priority, 'critical');
  assert.equal(later.decisions[finding.id].action, 'notify');
});
