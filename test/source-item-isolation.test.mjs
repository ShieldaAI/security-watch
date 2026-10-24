import test from 'node:test';
import assert from 'node:assert/strict';
import { collectSources } from '../dist/sources.js';
import { parseConfig } from '../dist/config.js';
import { hash } from '../dist/util.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const DATE = new Date(NOW).toISOString();
const OLD = '2026-10-24T10:00:00.000Z';
const FEED = 'https://vendor.example/security.xml?token=private-fixture';
const FEED_SOURCE = `feed:${hash(FEED).slice(0, 16)}`;
const ARTICLE = 'https://thehackernews.com/2026/10/alpha-update.html';
const inventory = { systems: [{ id: 'alpha', name: 'Alpha', components: [], keywords: ['Alpha'] }] };
const response = (value, status = 200, headers = {}) => ({
  status,
  headers,
  body: typeof value === 'string' ? value : JSON.stringify(value),
});
const config = (sources) =>
  parseConfig({
    version: 1,
    sources: {
      cve_now: false,
      hacker_news: false,
      osv: false,
      github: false,
      kev: false,
      feeds: [],
      ...sources,
    },
  });
const rssItem = (id, title = 'Alpha update', description = 'Alpha needs review.') =>
  `<item><guid>${id}</guid><title>${title}</title><description><![CDATA[${description}]]></description><link>${ARTICLE}</link><pubDate>${DATE}</pubDate></item>`;
const rss = (items) => `<rss><channel>${items.join('')}</channel></rss>`;
const github = (id, extra = {}) => ({
  ghsa_id: id,
  type: 'reviewed',
  summary: 'Alpha issue',
  updated_at: DATE,
  published_at: OLD,
  vulnerabilities: [],
  ...extra,
});
const kev = (id) => ({
  cveID: id,
  vendorProject: 'Alpha',
  product: 'Server',
  vulnerabilityName: 'Alpha issue',
  shortDescription: 'Alpha needs review.',
  requiredAction: 'Install the update.',
  dateAdded: OLD,
});
const cve = (id) => ({
  id,
  aliases: [],
  status: 'published',
  title: 'Alpha issue',
  originalDescription: 'Alpha needs review.',
  publishedAt: DATE,
  firstSeenAt: DATE,
  modifiedAt: DATE,
  affected: [],
});
const osv = (id) => ({
  id,
  summary: 'Alpha issue',
  details: 'Alpha needs review.',
  modified: DATE,
  published: OLD,
  affected: [],
});

for (const thn of [false, true])
  test(`${thn ? 'THN' : 'RSS'} skips a malformed item, keeps the following item, and recovers on a later scan`, async () => {
    let broken = true;
    let articleCalls = 0;
    const source = thn ? 'hacker_news' : FEED_SOURCE;
    const cfg = config(thn ? { hacker_news: true } : { feeds: [FEED] });
    const http = async (url) => {
      if (url === ARTICLE) {
        articleCalls++;
        return response(
          '<div class="articlebody">Alpha is affected by CVE-2026-12345. Review the installed version and update it.</div>',
        );
      }
      return response(rss([rssItem('bad', broken ? '' : 'Alpha repaired item'), rssItem('good')]));
    };
    const first = await collectSources(inventory, cfg, { [source]: OLD }, http, NOW);
    assert.equal(first.evidence.length, 1);
    assert.equal(first.checkpoints[source], OLD);
    assert(first.errors.some((error) => error.source === source && /invalid item/.test(error.message)));
    assert.doesNotMatch(JSON.stringify(first.errors), /private-fixture/);
    if (thn) {
      assert.equal(articleCalls, 1);
      assert.equal(first.evidence[0].content_status, 'full');
    }
    broken = false;
    const second = await collectSources(
      inventory,
      cfg,
      first.checkpoints,
      http,
      NOW + 60_000,
      first.evidence,
    );
    assert.equal(second.evidence.length, 2);
    assert.deepEqual(second.errors, []);
    assert.equal(second.checkpoints[source], new Date(NOW + 60_000).toISOString());
    assert(second.evidence.some((item) => item.id === first.evidence[0].id));
  });

test('a feed HTML-limit failure is isolated to its item', async () => {
  const result = await collectSources(
    inventory,
    config({ feeds: [FEED] }),
    { [FEED_SOURCE]: OLD },
    async () =>
      response(
        rss([
          rssItem('bad', 'Alpha', '<span>'.repeat(300) + 'Hidden' + '</span>'.repeat(300)),
          rssItem('good'),
        ]),
      ),
    NOW,
  );
  assert.equal(result.evidence.length, 1);
  assert.equal(result.evidence[0].description, 'Alpha needs review.');
  assert.equal(result.checkpoints[FEED_SOURCE], OLD);
  assert.equal(result.errors.length, 1);
});

test('GitHub keeps valid later items and another advisory category while a bad row remains incomplete', async () => {
  let broken = true;
  const http = async (url) => {
    if (new URL(url).searchParams.get('type') === 'malware') return response([]);
    return response([
      broken ? { private: 'not-for-diagnostics' } : github('GHSA-bbbb-bbbb-bbbb'),
      github('GHSA-aaaa-aaaa-aaaa'),
    ]);
  };
  const cfg = config({ github: true });
  const first = await collectSources(inventory, cfg, { 'github:reviewed': OLD }, http, NOW);
  assert.equal(first.evidence.length, 1);
  assert.equal(first.checkpoints['github:reviewed'], OLD);
  assert.equal(first.checkpoints['github:malware'], DATE);
  assert.doesNotMatch(JSON.stringify(first.errors), /not-for-diagnostics/);
  broken = false;
  const second = await collectSources(inventory, cfg, first.checkpoints, http, NOW + 60_000, first.evidence);
  assert.deepEqual(second.errors, []);
  assert.equal(second.evidence.length, 2);
  assert.equal(second.checkpoints['github:reviewed'], new Date(NOW + 60_000).toISOString());
});

test('future records cannot poison valid partial records or advance a checkpoint', async () => {
  const result = await collectSources(
    inventory,
    config({ github: true }),
    { 'github:reviewed': OLD },
    async (url) =>
      response(
        new URL(url).searchParams.get('type') === 'malware'
          ? []
          : [
              {},
              github('GHSA-bbbb-bbbb-bbbb', { updated_at: '2027-01-01T00:00:00Z' }),
              github('GHSA-aaaa-aaaa-aaaa'),
            ],
      ),
    NOW,
  );
  assert.deepEqual(
    result.evidence.map((item) => item.id),
    ['github:GHSA-aaaa-aaaa-aaaa'],
  );
  assert.equal(result.checkpoints['github:reviewed'], OLD);
  assert.equal(result.errors.length, 1);
});

test('a future GitHub duplicate cannot replace a valid record of the same advisory', async (t) => {
  for (const futureFirst of [false, true])
    await t.test(futureFirst ? 'future first' : 'future last', async () => {
      const id = 'GHSA-aaaa-aaaa-aaaa';
      const real = github(id, { summary: 'A valid newer revision', updated_at: DATE });
      const future = github(id, { summary: 'Untrusted future revision', updated_at: '2099-01-01T00:00:00Z' });
      const result = await collectSources(
        inventory,
        config({ github: true }),
        { 'github:reviewed': OLD },
        async (url) =>
          response(
            new URL(url).searchParams.get('type') === 'malware'
              ? []
              : [github(id, { updated_at: OLD }), ...(futureFirst ? [future, real] : [real, future])],
          ),
        NOW,
      );
      assert.equal(result.evidence.length, 1);
      assert.equal(result.evidence[0].title, 'A valid newer revision');
      assert.equal(result.evidence[0].modified_at, DATE);
      assert.equal(result.checkpoints['github:reviewed'], OLD);
      assert.equal(result.errors.length, 1);
    });
});

test('CISA KEV skips a malformed catalog row and later recovers without losing valid exploitation evidence', async () => {
  let broken = true;
  const cfg = config({ kev: true });
  const http = async () =>
    response({
      count: 2,
      dateReleased: DATE,
      vulnerabilities: [broken ? { cveID: 'bad' } : kev('CVE-2026-12346'), kev('CVE-2026-12345')],
    });
  const first = await collectSources(inventory, cfg, { kev: OLD }, http, NOW);
  assert.equal(first.evidence.length, 1);
  assert.equal(first.evidence[0].exploited, true);
  assert.equal(first.checkpoints.kev, OLD);
  broken = false;
  const second = await collectSources(inventory, cfg, first.checkpoints, http, NOW + 60_000, first.evidence);
  assert.deepEqual(second.errors, []);
  assert.equal(second.evidence.length, 2);
  assert.equal(second.checkpoints.kev, new Date(NOW + 60_000).toISOString());
});

test('cve.now skips an invalid listing item and collects following valid details before recovery', async () => {
  let broken = true;
  const cfg = config({ cve_now: true });
  const http = async (url) =>
    url.endsWith('/entries')
      ? response({
          entries: [
            broken ? { id: 'bad', publishedAt: 'invalid' } : cve('CVE-2026-12346'),
            cve('CVE-2026-12345'),
          ],
        })
      : response(cve(url.split('/').at(-1)));
  const first = await collectSources(inventory, cfg, { cve_now: OLD }, http, NOW);
  assert.equal(first.evidence.length, 1);
  assert.equal(first.checkpoints.cve_now, OLD);
  broken = false;
  const second = await collectSources(inventory, cfg, first.checkpoints, http, NOW + 60_000, first.evidence);
  assert.deepEqual(second.errors, []);
  assert.equal(second.evidence.length, 2);
});

test('cve.now retains a valid exact package match after an invalid record in the same response', async () => {
  const inv = {
    systems: [
      { id: 'alpha', components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.2.3' }] },
    ],
  };
  const good = { ...cve('CVE-2026-12345'), matched: { ecosystem: 'npm', name: 'alpha', version: '1.2.3' } };
  const result = await collectSources(
    inv,
    config({ cve_now: true }),
    { cve_now: OLD },
    async (url) =>
      url.includes('/stack?')
        ? response({
            packages: 1,
            entries: [{ ...good, id: 'CVE-2026-12346', matched: { ...good.matched, name: 'other' } }, good],
          })
        : response({ entries: [] }),
    NOW,
  );
  assert.equal(result.evidence.length, 1);
  assert.equal(result.evidence[0].id, 'cve_now:CVE-2026-12345');
  assert.deepEqual(result.evidence[0].packages[0].matched_versions, ['1.2.3']);
  assert.equal(result.checkpoints.cve_now, OLD);
  assert.equal(result.errors.length, 1);
});

test('OSV continues after a malformed query item and isolated bad detail, then recovers', async () => {
  let broken = true;
  const ids = Array.from({ length: 6 }, (_, i) => `OSV-2026-${i}`);
  const inv = {
    systems: [
      { id: 'alpha', components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.2.3' }] },
    ],
  };
  const cfg = config({ osv: true });
  const requested = [];
  const http = async (url) => {
    if (url.endsWith('/querybatch'))
      return response({ results: [{ vulns: [...(broken ? [{}] : []), ...ids.map((id) => ({ id }))] }] });
    const id = url.split('/').at(-1);
    requested.push(id);
    return response(broken && id === ids[1] ? { id } : osv(id));
  };
  const first = await collectSources(inv, cfg, { osv: OLD }, http, NOW);
  assert.deepEqual(requested, ids);
  assert.equal(first.evidence.length, 5);
  assert.equal(first.checkpoints.osv, OLD);
  assert.equal(first.errors.length, 1);
  broken = false;
  const second = await collectSources(inv, cfg, first.checkpoints, http, NOW + 60_000, first.evidence);
  assert.deepEqual(second.errors, []);
  assert.equal(second.evidence.length, 6);
  assert.equal(second.checkpoints.osv, new Date(NOW + 60_000).toISOString());
});

test('OSV stops scheduling after authentication/rate failures but settles healthy requests already in flight', async (t) => {
  for (const status of [401, 403, 429])
    await t.test(String(status), async () => {
      const ids = Array.from({ length: 9 }, (_, i) => `OSV-2026-${i}`);
      const requested = [];
      const inv = {
        systems: [
          { id: 'alpha', components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.2.3' }] },
        ],
      };
      const result = await collectSources(
        inv,
        config({ osv: true }),
        { osv: OLD },
        async (url) => {
          if (url.endsWith('/querybatch'))
            return response({ results: [{ vulns: ids.map((id) => ({ id })) }] });
          const id = url.split('/').at(-1);
          requested.push(id);
          return id === ids[0] ? response('private-error', status) : response(osv(id));
        },
        NOW,
      );
      assert.deepEqual(requested, ids.slice(0, 4));
      assert.equal(result.evidence.length, 3);
      assert.equal(result.checkpoints.osv, OLD);
      assert.doesNotMatch(JSON.stringify(result.errors), /private-error/);
    });
});

test('cancellation stops source collection and does not become a recoverable item failure', async (t) => {
  for (const stage of ['feed', 'article', 'cve-detail', 'osv-detail'])
    await t.test(stage, async () => {
      const calls = [];
      const inv =
        stage === 'osv-detail'
          ? {
              systems: [
                {
                  id: 'alpha',
                  components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.2.3' }],
                },
              ],
            }
          : inventory;
      const cfg = config({
        hacker_news: ['feed', 'article'].includes(stage),
        cve_now: stage === 'cve-detail',
        osv: stage === 'osv-detail',
        feeds: ['https://later.example/feed'],
      });
      await assert.rejects(
        collectSources(
          inv,
          cfg,
          {},
          async (url) => {
            calls.push(url);
            if (stage === 'article' && url.includes('feedburner')) return response(rss([rssItem('good')]));
            if (stage === 'cve-detail' && url.endsWith('/entries'))
              return response({ entries: [cve('CVE-2026-12345')] });
            if (stage === 'osv-detail' && url.endsWith('/querybatch'))
              return response({ results: [{ vulns: [{ id: 'OSV-2026-1' }] }] });
            if (url === 'https://later.example/feed') return response(rss([]));
            throw new DOMException('aborted', 'AbortError');
          },
          NOW,
        ),
        (error) => error.name === 'AbortError',
      );
      if (stage !== 'cve-detail') assert(calls.every((url) => url !== 'https://later.example/feed'));
    });
});
