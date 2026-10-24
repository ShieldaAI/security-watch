import test from 'node:test';
import assert from 'node:assert/strict';
import { collectSources } from '../dist/sources.js';
import { parseConfig } from '../dist/config.js';
import { runScan } from '../dist/engine.js';
import { Store } from '../dist/store.js';
import { hash } from '../dist/util.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const MINUTE = 60_000;
const FEED = 'https://vendor.example/feed';
const SOURCE = `feed:${hash(FEED).slice(0, 16)}`;
const THN = 'https://feeds.feedburner.com/TheHackersNews';
const articleUrl = (id) => `https://thehackernews.com/2026/10/${id}.html`;
const date = (minutesAgo) => new Date(NOW - minutesAgo * MINUTE).toISOString();
const reply = (body, status = 200) => ({ status, headers: {}, body });
const configuration = (overrides = {}) =>
  parseConfig({
    version: 1,
    poll_interval_minutes: 30,
    news_lookback_minutes: 40,
    sources: { cve_now: false, hacker_news: false, feeds: [FEED] },
    policy: { health_channels: [] },
    ...overrides,
  });
const inventory = () => ({
  systems: [
    {
      id: 'production',
      name: 'Production',
      environment: 'production',
      exposure: 'internal',
      criticality: 'high',
      updated_at: date(0),
      components: [],
      products: [],
      keywords: ['Alpha'],
    },
  ],
});
function rss(items) {
  return `<rss><channel>${items
    .map(
      ({
        id,
        title = 'Alpha security update',
        description = 'Alpha requires investigation.',
        published,
        severity,
      }) =>
        `<item><guid>${id}</guid><title>${title}</title><description>${description}</description><link>${articleUrl(id)}</link>${published === undefined ? '' : `<pubDate>${published}</pubDate>`}${severity ? `<severity>${severity}</severity>` : ''}</item>`,
    )
    .join('')}</channel></rss>`;
}

test('the initial news window includes its exact cutoff and filters older articles before fetching', async () => {
  const seen = [];
  const result = await collectSources(
    inventory(),
    configuration({ sources: { cve_now: false, hacker_news: true } }),
    {},
    async (url) => {
      seen.push(url);
      return reply(
        url === THN
          ? rss([
              { id: 'new', published: date(5) },
              { id: 'boundary', published: date(40) },
              { id: 'old', published: new Date(NOW - 40 * MINUTE - 1).toISOString() },
            ])
          : '<article itemprop="articleBody">Alpha requires investigation. Full article details.</article>',
      );
    },
    NOW,
  );
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.evidence.map((item) => item.url).sort(), [
    articleUrl('boundary'),
    articleUrl('new'),
  ]);
  assert(!seen.includes(articleUrl('old')));
  assert.equal(result.checkpoints.hacker_news, date(0));
});

test('an Atom update inside the window includes an older publication', async () => {
  const result = await collectSources(
    inventory(),
    configuration(),
    {},
    async () =>
      reply(
        `<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>updated</id><title>Alpha patch</title><published>${date(500)}</published><updated>${date(2)}</updated><summary>Alpha patch details.</summary></entry></feed>`,
      ),
    NOW,
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.evidence.length, 1);
  assert.equal(result.evidence[0].published_at, date(500));
  assert.equal(result.evidence[0].modified_at, date(2));
});

test('overlapping polls use the configured window and stable identities', async () => {
  const body = rss([{ id: 'overlap', published: date(5) }]);
  const first = await collectSources(inventory(), configuration(), {}, async () => reply(body), NOW);
  const next = await collectSources(
    inventory(),
    configuration(),
    first.checkpoints,
    async () => reply(body),
    NOW + 30 * MINUTE,
  );
  assert.equal(next.evidence.length, 1);
  assert.equal(next.evidence[0].id, first.evidence[0].id);
  assert.equal(next.evidence[0].modified_at, first.evidence[0].modified_at);
  const expired = await collectSources(
    inventory(),
    configuration(),
    next.checkpoints,
    async () => reply(body),
    NOW + 60 * MINUTE,
  );
  assert.deepEqual(expired.evidence, []);
});

test('failed polls keep their checkpoint and catch up beyond the ordinary news window', async () => {
  const checkpoints = { [SOURCE]: date(120) };
  const failed = await collectSources(
    inventory(),
    configuration(),
    checkpoints,
    async () => reply('', 503),
    NOW,
  );
  assert.equal(failed.checkpoints[SOURCE], date(120));
  const recovered = await collectSources(
    inventory(),
    configuration(),
    failed.checkpoints,
    async () =>
      reply(
        rss([
          { id: 'outage', published: date(90) },
          { id: 'checkpoint-overlap', published: date(125) },
          { id: 'too-old', published: new Date(NOW - 125 * MINUTE - 1).toISOString() },
        ]),
      ),
    NOW,
  );
  assert.deepEqual(recovered.errors, []);
  assert.equal(recovered.evidence.length, 2);
  assert.equal(recovered.checkpoints[SOURCE], date(0));
});

test('a longer polling interval cannot leave a gap between short news windows', async () => {
  const result = await collectSources(
    inventory(),
    configuration({ poll_interval_minutes: 120, news_lookback_minutes: 10 }),
    { [SOURCE]: date(120) },
    async () => reply(rss([{ id: 'between-polls', published: date(80) }])),
    NOW,
  );
  assert.equal(result.evidence.length, 1);
});

test('known relevant stories can refresh outside discovery while unknown old stories stay out', async () => {
  const first = await collectSources(
    inventory(),
    configuration(),
    {},
    async () => reply(rss([{ id: 'known', published: date(5) }])),
    NOW,
  );
  const next = await collectSources(
    inventory(),
    configuration(),
    { [SOURCE]: new Date(NOW + 90 * MINUTE).toISOString() },
    async () =>
      reply(
        rss([
          { id: 'known', published: date(5) },
          { id: 'unknown', published: date(5) },
        ]),
      ),
    NOW + 120 * MINUTE,
    first.evidence,
  );
  assert.equal(next.evidence.length, 1);
  assert.equal(next.evidence[0].id, first.evidence[0].id);
  assert.equal(next.evidence[0].fetched_at, new Date(NOW + 120 * MINUTE).toISOString());
});

test('invalid news checkpoints fail visibly before making a request', async (t) => {
  for (const checkpoint of ['invalid', new Date(NOW + 1).toISOString()])
    await t.test(checkpoint, async () => {
      let requests = 0;
      const result = await collectSources(
        inventory(),
        configuration(),
        { [SOURCE]: checkpoint },
        async () => {
          requests++;
          return reply(rss([]));
        },
        NOW,
      );
      assert.equal(requests, 0);
      assert.equal(result.errors.length, 1);
      assert.equal(result.checkpoints[SOURCE], checkpoint);
    });
});

test('future feed dates cannot advance the checkpoint or enter evidence', async () => {
  const result = await collectSources(
    inventory(),
    configuration(),
    {},
    async () => reply(rss([{ id: 'future', published: date(-6) }])),
    NOW,
  );
  assert.equal(result.errors.length, 1);
  assert.deepEqual(result.evidence, []);
  assert.equal(result.checkpoints[SOURCE], undefined);
});

test('an invalid news checkpoint does not prevent independent advisory collection', async () => {
  const systems = inventory();
  systems.systems[0].components = [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }];
  const result = await collectSources(
    systems,
    configuration({ sources: { cve_now: false, hacker_news: false, osv: true, feeds: [FEED] } }),
    { [SOURCE]: 'invalid' },
    async (url) => {
      assert.equal(url, 'https://api.osv.dev/v1/querybatch');
      return reply(JSON.stringify({ results: [{}] }));
    },
    NOW,
  );
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].source, SOURCE);
  assert.equal(result.checkpoints.osv, date(0));
  assert.equal(result.checkpoints[SOURCE], 'invalid');
});

test('undated and invalid-date stories warn and retain their revision until content changes', async (t) => {
  for (const published of [undefined, 'not-a-date'])
    await t.test(String(published), async () => {
      const read = (description, now, checkpoints = {}, previous = []) =>
        collectSources(
          inventory(),
          configuration(),
          checkpoints,
          async () => reply(rss([{ id: 'undated', published, description }])),
          now,
          previous,
        );
      const first = await read('Alpha original content.', NOW);
      assert.equal(first.evidence.length, 1);
      assert.equal(first.errors[0].source, `${SOURCE}:timestamps`);
      assert.equal(first.checkpoints[SOURCE], date(0));
      const next = await read(
        'Alpha original content.',
        NOW + 30 * MINUTE,
        first.checkpoints,
        first.evidence,
      );
      assert.equal(next.evidence[0].modified_at, date(0));
      assert.equal(next.evidence[0].fetched_at, new Date(NOW + 30 * MINUTE).toISOString());
      const changed = await read(
        'Alpha corrected content.',
        NOW + 60 * MINUTE,
        next.checkpoints,
        next.evidence,
      );
      assert.equal(changed.evidence[0].modified_at, new Date(NOW + 60 * MINUTE).toISOString());
    });
});

test('overlapping undated article scans reuse model analysis, history and accepted delivery identity', async (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const modelKey = 'NEWS_WINDOW_TEST_MODEL_KEY';
  const slackKey = 'NEWS_WINDOW_TEST_SLACK_URL';
  process.env[modelKey] = 'fixture-only';
  process.env[slackKey] = 'https://hooks.slack.com/services/TEST/ONLY/FIXTURE';
  t.after(() => {
    delete process.env[modelKey];
    delete process.env[slackKey];
  });
  const config = configuration({
    sources: { cve_now: false, hacker_news: true },
    models: {
      enabled: true,
      analysis: {
        provider: 'openai-compatible',
        model: 'fixture',
        api_key_env: modelKey,
        endpoint: 'http://127.0.0.1:1234/v1/chat/completions',
        allow_private_endpoint: true,
      },
    },
    policy: { news: { levels: ['critical'], channels: ['slack'] }, health_channels: [] },
    notifications: { slack: { webhook_url_env: slackKey } },
  });
  let modelRequests = 0;
  const description = 'Alpha requires investigation. Full article details.';
  const http = async (url, options) => {
    if (url === THN) return reply(rss([{ id: 'undated-full', severity: 'critical' }]));
    if (url === articleUrl('undated-full'))
      return reply(`<article itemprop="articleBody">${description}</article>`);
    assert.equal(url, config.models.analysis.endpoint);
    modelRequests++;
    const context = JSON.parse(JSON.parse(options.body).messages[1].content);
    const id = context.evidence[0].id;
    const quotes = [{ evidence_id: id, quote: description }];
    return reply(
      JSON.stringify({
        choices: [
          {
            finish_reason: 'stop',
            message: {
              content: JSON.stringify({
                relevance: 'relevant',
                priority: 'critical',
                summary: 'Investigate the reported Alpha issue.',
                evidence_ids: [id],
                quotes,
                news_analysis: {
                  classification: 'unknown',
                  impact: 'unknown',
                  affected_products: [],
                  affected_versions: [],
                  prerequisites: [],
                  rationale: 'The report does not supply an affected version.',
                  quotes,
                },
              }),
            },
          },
        ],
      }),
    );
  };
  const first = await runScan({ config, inventory: inventory(), store, http, now: NOW });
  const finding = first.findings.find((item) => item.category === 'news');
  assert.equal(finding.ai.status, 'complete');
  assert.equal(modelRequests, 1);
  assert.equal(store.jobs().filter((job) => job.status === 'pending').length, 1);
  const jobCount = store.jobs().length;
  const job = store.claimDue(NOW);
  store.completeJob(job.id, 'accepted', NOW);
  const second = await runScan({ config, inventory: inventory(), store, http, now: NOW + 30 * MINUTE });
  assert.equal(modelRequests, 1);
  assert.equal(second.findings.find((item) => item.id === finding.id).ai.status, 'complete');
  assert.equal(store.jobs().length, jobCount);
  assert.equal(store.jobs().filter((job) => job.status === 'accepted').length, 1);
  assert.equal(store.jobs().filter((job) => job.status === 'pending').length, 0);
  const evidence = store.evidence()[0];
  assert.equal(evidence.modified_at, date(0));
  assert.equal(store.evidenceHistory(evidence.source, evidence.id).length, 1);
  await runScan({
    config,
    inventory: inventory(),
    store,
    http: async (url) => {
      assert.equal(url, THN);
      return reply(rss([]));
    },
    now: NOW + 60 * MINUTE,
  });
  assert.equal(store.evidence().length, 1);
  assert.notEqual(store.getFinding(finding.id).active, false);
  assert.equal(store.jobs().length, jobCount);
});
