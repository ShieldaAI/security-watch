import test from 'node:test';
import assert from 'node:assert/strict';
import { collectSources } from '../dist/sources.js';
import { assess } from '../dist/assessment.js';
import { Store } from '../dist/store.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const NOW_ISO = new Date(NOW).toISOString();
const OLD = '2026-10-24T10:00:00.000Z';
function config(sources = {}) {
  return {
    news_lookback_minutes: 1440,
    sources: {
      cve_now: false,
      hacker_news: false,
      osv: false,
      github: false,
      github_token_env: 'SECURITY_WATCH_TEST_UNUSED_TOKEN',
      kev: false,
      feeds: [],
      ...sources,
    },
  };
}
function inventory(components = [{ id: 'a', ecosystem: 'npm', name: 'alpha', version: '1.2.3' }]) {
  return { systems: [{ id: 'prod', components }] };
}
const response = (value, headers = {}) => ({ status: 200, headers, body: JSON.stringify(value) });
const xml = (body) => ({ status: 200, headers: {}, body });
function osvAdvisory(id, extra = {}) {
  return {
    id,
    modified: OLD,
    published: '2026-01-01T00:00:00Z',
    summary: 'Example advisory',
    details: 'Package vulnerability details.',
    aliases: ['CVE-2026-12345'],
    affected: [
      {
        package: { ecosystem: 'npm', name: 'alpha' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.4' }] }],
      },
    ],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    ...extra,
  };
}
function githubAdvisory(id = 'GHSA-abcd-2345-efgh', extra = {}) {
  return {
    ghsa_id: id,
    cve_id: 'CVE-2026-12345',
    type: 'reviewed',
    summary: 'Example advisory',
    description: 'Affected package.',
    severity: 'critical',
    updated_at: OLD,
    published_at: '2026-01-01T00:00:00Z',
    withdrawn_at: null,
    vulnerabilities: [
      {
        package: { ecosystem: 'npm', name: 'alpha' },
        vulnerable_version_range: '<1.2.4',
        first_patched_version: '1.2.4',
      },
    ],
    ...extra,
  };
}

test('OSV batches deduplicated exact versions and follows each query pagination independently', async () => {
  const calls = [];
  const inv = inventory([
    { id: 'a', ecosystem: 'npm', name: 'alpha', version: '1.2.3' },
    { id: 'duplicate', ecosystem: 'npm', name: 'alpha', version: '1.2.3' },
    { id: 'b', ecosystem: 'npm', name: 'beta', version: '2.0.0' },
    { id: 'unknown', ecosystem: 'npm', name: 'unknown' },
  ]);
  const result = await collectSources(
    inv,
    config({ osv: true }),
    {},
    async (url, options) => {
      calls.push([url, options]);
      if (url.endsWith('/querybatch')) {
        const queries = JSON.parse(options.body).queries;
        if (queries.length === 3) {
          assert.deepEqual(
            queries.map((q) => q.package.name),
            ['alpha', 'beta', 'unknown'],
          );
          assert.equal('version' in queries[2], false);
          return response({
            results: [{ vulns: [{ id: 'GHSA-aaaa-aaaa-aaaa' }], next_page_token: 'alpha-page-2' }, {}, {}],
          });
        }
        assert.equal(queries.length, 1);
        assert.equal(queries[0].package.name, 'alpha');
        assert.equal(queries[0].page_token, 'alpha-page-2');
        return response({ results: [{ vulns: [{ id: 'GHSA-bbbb-bbbb-bbbb' }] }] });
      }
      return response(osvAdvisory(decodeURIComponent(url.split('/').at(-1))));
    },
    NOW,
  );
  assert.deepEqual(result.errors, []);
  assert.equal(calls.length, 4);
  assert.equal(result.evidence.length, 2);
  for (const evidence of result.evidence) {
    assert.deepEqual(evidence.packages[0].matched_versions, ['1.2.3']);
    assert.equal(evidence.packages[0].range, '<1.2.4');
    assert.equal(evidence.packages[0].fixed, '1.2.4');
    assert.equal(evidence.severity, 'critical');
  }
  assert.equal(result.checkpoints.osv, NOW_ISO);
});

test('OSV splits inventories into batches of at most 100 and no matches create no safe assertions', async () => {
  const components = Array.from({ length: 101 }, (_, index) => ({
    id: String(index),
    ecosystem: 'npm',
    name: `package-${index}`,
    version: '1.0.0',
  }));
  const counts = [];
  const result = await collectSources(
    inventory(components),
    config({ osv: true }),
    {},
    async (_, options) => {
      const queries = JSON.parse(options.body).queries;
      counts.push(queries.length);
      return response({ results: queries.map(() => ({})) });
    },
    NOW,
  );
  assert.deepEqual(counts, [100, 1]);
  assert.deepEqual(result.evidence, []);
  assert.deepEqual(result.errors, []);
});

test('historical OSV IDs refresh after disappearing from query results so withdrawals are observed', async () => {
  const previous = [{ id: 'osv:GHSA-aaaa-aaaa-aaaa', source: 'osv' }];
  let fullReads = 0;
  const result = await collectSources(
    inventory(),
    config({ osv: true }),
    { osv: OLD },
    async (url) => {
      if (url.endsWith('/querybatch')) return response({ results: [{}] });
      fullReads++;
      return response(osvAdvisory('GHSA-aaaa-aaaa-aaaa', { withdrawn: '2026-10-24T11:00:00Z' }));
    },
    NOW,
    previous,
  );
  assert.equal(fullReads, 1);
  assert.equal(result.evidence[0].withdrawn, true);
  assert.equal(result.evidence[0].packages[0].matched_versions, undefined);
});

test('OSV incomplete batches, repeated cursors and mismatched full records preserve old checkpoints', async (t) => {
  for (const failure of ['count', 'cursor', 'id', 'missing-date'])
    await t.test(failure, async () => {
      const result = await collectSources(
        inventory(),
        config({ osv: true }),
        { osv: OLD },
        async (url) => {
          if (url.endsWith('/querybatch')) {
            if (failure === 'count') return response({ results: [] });
            if (failure === 'cursor') return response({ results: [{ next_page_token: 'repeated' }] });
            return response({ results: [{ vulns: [{ id: 'GHSA-aaaa-aaaa-aaaa' }] }] });
          }
          return response(
            osvAdvisory(
              failure === 'id' ? 'GHSA-bbbb-bbbb-bbbb' : 'GHSA-aaaa-aaaa-aaaa',
              failure === 'missing-date' ? { modified: undefined } : {},
            ),
          );
        },
        NOW,
      );
      assert.equal(result.errors.length, 1);
      assert.equal(result.checkpoints.osv, OLD);
      assert.deepEqual(result.evidence, []);
    });
});

test('OSV supports disjoint semver intervals and leaves unsupported ranges without exclusion claims', async () => {
  const result = await collectSources(
    inventory(),
    config({ osv: true }),
    {},
    async (url) => {
      if (url.endsWith('/querybatch')) return response({ results: [{ vulns: [{ id: 'OSV-test' }] }] });
      return response(
        osvAdvisory('OSV-test', {
          affected: [
            {
              package: { ecosystem: 'npm', name: 'alpha' },
              ranges: [
                {
                  type: 'SEMVER',
                  events: [
                    { introduced: '0' },
                    { fixed: '1.0.0' },
                    { introduced: '2.0.0' },
                    { last_affected: '2.3.0' },
                  ],
                },
              ],
            },
            {
              package: { ecosystem: 'npm', name: 'beta' },
              ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: 'release-2' }] }],
            },
          ],
        }),
      );
    },
    NOW,
  );
  assert.equal(result.evidence[0].packages[0].range, '<1.0.0 || >=2.0.0 <=2.3.0');
  assert.equal(result.evidence[0].packages[1].range, undefined);
});

test('valid unsorted OSV events and independent limit events preserve version-boundary outcomes', async (t) => {
  const cases = [
    {
      name: 'unsorted intervals',
      events: [{ fixed: '3.0.0' }, { introduced: '2.0.0' }, { fixed: '1.0.0' }, { introduced: '0' }],
      expected: ['affected', 'not_affected', 'affected', 'not_affected'],
    },
    {
      name: 'multiple independent limits',
      events: [{ introduced: '0' }, { limit: '1.0.0' }, { limit: '3.0.0' }],
      expected: ['affected', 'affected', 'affected', 'not_affected'],
    },
    {
      name: 'limit after fixed',
      events: [{ introduced: '0' }, { fixed: '1.0.0' }, { limit: '3.0.0' }],
      expected: ['affected', 'not_affected', 'not_affected', 'not_affected'],
    },
    {
      name: 'infinite limit',
      events: [{ limit: '*' }, { introduced: '0' }],
      expected: ['affected', 'affected', 'affected', 'affected'],
    },
  ];
  for (const scenario of cases)
    await t.test(scenario.name, async () => {
      const result = await collectSources(
        inventory(),
        config({ osv: true }),
        {},
        async (url) => {
          if (url.endsWith('/querybatch')) return response({ results: [{}] });
          return response(
            osvAdvisory('OSV-boundary', {
              affected: [
                {
                  package: { ecosystem: 'npm', name: 'alpha' },
                  ranges: [{ type: 'SEMVER', events: scenario.events }],
                },
              ],
            }),
          );
        },
        NOW,
        [{ id: 'osv:OSV-boundary', source: 'osv' }],
      );
      assert.deepEqual(result.errors, []);
      const actual = ['0.5.0', '1.0.0', '2.0.0', '3.0.0'].map((version) => {
        const inv = {
          systems: [
            {
              id: 'prod',
              name: 'prod',
              updated_at: NOW_ISO,
              exposure: 'internal',
              criticality: 'high',
              components: [{ id: 'dep', ecosystem: 'npm', name: 'alpha', version }],
              products: [],
              keywords: [],
            },
          ],
        };
        return assess(inv, result.evidence, { inventory_stale_days: 7 }, NOW)[0].applicability;
      });
      assert.deepEqual(actual, scenario.expected);
    });
});

test('GitHub collects reviewed and malware separately and follows trusted cursor links with checkpoint overlap', async () => {
  const calls = [];
  const next = 'https://api.github.com/advisories?type=reviewed&after=cursor-2';
  const result = await collectSources(
    inventory(),
    config({ github: true }),
    { 'github:reviewed': OLD, 'github:malware': OLD },
    async (url) => {
      calls.push(url);
      const parsed = new URL(url);
      if (parsed.searchParams.get('type') === 'malware')
        return response([
          githubAdvisory('GHSA-mmmm-mmmm-mmmm', { type: 'malware', severity: 'unknown', cve_id: null }),
        ]);
      if (parsed.searchParams.has('after'))
        return response([githubAdvisory('GHSA-bbbb-bbbb-bbbb', { withdrawn_at: '2026-10-24T11:00:00Z' })]);
      assert.equal(parsed.searchParams.get('modified'), '2026-10-24T09:00:00Z..2026-10-24T12:00:00Z');
      assert.equal(parsed.searchParams.get('per_page'), '100');
      return response([githubAdvisory()], { Link: `<${next}>; rel="next"` });
    },
    NOW,
  );
  assert.deepEqual(result.errors, []);
  assert.equal(calls.length, 3);
  assert.equal(result.evidence.length, 3);
  assert.equal(result.evidence.find((item) => item.source === 'github:malware').malware, true);
  assert.equal(result.evidence.find((item) => item.id.endsWith('bbbb-bbbb-bbbb')).withdrawn, true);
  assert.equal(result.checkpoints['github:reviewed'], NOW_ISO);
  assert.equal(result.evidence[0].packages[0].range, '<1.2.4');
});

test('GitHub failure midway retains valid records without advancing its checkpoint while other sources complete', async () => {
  const result = await collectSources(
    inventory(),
    config({ github: true }),
    { 'github:reviewed': OLD },
    async (url) => {
      const parsed = new URL(url);
      if (parsed.searchParams.get('type') === 'malware') return response([]);
      if (parsed.searchParams.has('after')) return { status: 429, headers: {}, body: 'limited' };
      return response([githubAdvisory()], {
        link: '<https://api.github.com/advisories?after=second>; rel="next"',
      });
    },
    NOW,
  );
  assert.equal(result.checkpoints['github:reviewed'], OLD);
  assert.equal(result.checkpoints['github:malware'], NOW_ISO);
  assert.deepEqual(
    result.evidence.map((item) => item.id),
    ['github:GHSA-abcd-2345-efgh'],
  );
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].source, 'github:reviewed');
  assert.match(result.errors[0].message, /HTTP 429.*Valid records were retained/);
});

test('GitHub pagination cannot send authentication to an attacker or loop indefinitely', async (t) => {
  for (const next of [
    'https://attacker.example/advisories',
    'https://api.github.com/user',
    'https://api.github.com@attacker.example/advisories',
  ])
    await t.test(next, async () => {
      let calls = 0;
      const result = await collectSources(
        inventory(),
        config({ github: true }),
        {},
        async (url) => {
          calls++;
          if (new URL(url).searchParams.get('type') === 'malware') return response([]);
          return response([githubAdvisory()], { link: `<${next}>; rel="next"` });
        },
        NOW,
      );
      assert.equal(calls, 2);
      assert.equal(result.errors.length, 1);
      assert.equal(result.checkpoints['github:reviewed'], undefined);
    });
});

test('GitHub invalid schema and exhausted pagination cap do not silently mark a source complete', async (t) => {
  await t.test('schema', async () => {
    const result = await collectSources(
      inventory(),
      config({ github: true }),
      {},
      async () => response({ message: 'Not an advisory list' }),
      NOW,
    );
    assert.equal(result.errors.length, 2);
    assert.deepEqual(result.checkpoints, {});
  });
  await t.test('cap', async () => {
    let page = 0;
    const result = await collectSources(
      inventory(),
      config({ github: true }),
      {},
      async (url) => {
        if (new URL(url).searchParams.get('type') === 'malware') return response([]);
        page++;
        return response([githubAdvisory()], {
          link: `<https://api.github.com/advisories?after=${page}>; rel="next"`,
        });
      },
      NOW,
    );
    assert.equal(page, 50);
    assert.match(result.errors[0].message, /limit/);
    assert.equal(result.checkpoints['github:reviewed'], undefined);
    assert.equal(result.checkpoints['github:malware'], NOW_ISO);
  });
});

test('KEV preserves exploitation evidence without inventing severity or affected versions', async () => {
  const result = await collectSources(
    inventory(),
    config({ kev: true }),
    {},
    async () =>
      response({
        count: 1,
        dateReleased: OLD,
        vulnerabilities: [
          {
            cveID: 'CVE-2026-12345',
            vendorProject: 'Vendor',
            product: 'Service',
            vulnerabilityName: 'Example exploit',
            dateAdded: '2026-10-20',
            shortDescription: 'Exploitation observed.',
            requiredAction: 'Apply vendor mitigation.',
          },
        ],
      }),
    NOW,
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.evidence[0].exploited, true);
  assert.equal(result.evidence[0].severity, 'unknown');
  assert.deepEqual(result.evidence[0].packages, []);
  assert.deepEqual(result.evidence[0].aliases, ['CVE-2026-12345']);
});

test('KEV count mismatch is an incomplete-source error', async () => {
  const result = await collectSources(
    inventory(),
    config({ kev: true }),
    { kev: OLD },
    async () => response({ count: 100, dateReleased: OLD, vulnerabilities: [] }),
    NOW,
  );
  assert.equal(result.errors.length, 1);
  assert.equal(result.checkpoints.kev, OLD);
});

test('KEV catalog releases only revise changed entries while every refresh remains current', async () => {
  const entry = {
    cveID: 'CVE-2026-12345',
    vendorProject: 'Acme',
    product: 'Widget',
    vulnerabilityName: 'Widget issue',
    shortDescription: 'A vulnerability.',
    requiredAction: 'Apply updates.',
    dateAdded: '2026-10-20',
  };
  const first = await collectSources(
    inventory(),
    config({ kev: true }),
    {},
    async () => response({ count: 1, dateReleased: OLD, vulnerabilities: [entry] }),
    NOW,
  );
  const nextTime = NOW + 3_600_000;
  const release = new Date(NOW).toISOString();
  const unchanged = await collectSources(
    inventory(),
    config({ kev: true }),
    first.checkpoints,
    async () => response({ count: 1, dateReleased: release, vulnerabilities: [entry] }),
    nextTime,
    first.evidence,
  );
  assert.deepEqual(unchanged.errors, []);
  assert.equal(unchanged.evidence[0].modified_at, first.evidence[0].modified_at);
  assert.equal(unchanged.evidence[0].fetched_at, new Date(nextTime).toISOString());
  assert.equal(unchanged.checkpoints.kev, new Date(nextTime).toISOString());
  const changed = await collectSources(
    inventory(),
    config({ kev: true }),
    first.checkpoints,
    async () =>
      response({
        count: 1,
        dateReleased: release,
        vulnerabilities: [{ ...entry, requiredAction: 'Disconnect affected instances.' }],
      }),
    nextTime,
    first.evidence,
  );
  assert.equal(changed.evidence[0].modified_at, release);
  assert.match(changed.evidence[0].description, /Disconnect affected instances/);
  const store = new Store(':memory:');
  try {
    store.saveEvidence(first.evidence, first.checkpoints);
    store.saveEvidence(unchanged.evidence, unchanged.checkpoints);
    assert.equal(store.evidenceHistory('kev', first.evidence[0].id).length, 1);
    store.saveEvidence(changed.evidence, changed.checkpoints);
    assert.equal(store.evidenceHistory('kev', first.evidence[0].id).length, 2);
  } finally {
    store.close();
  }
});

test('duplicate GitHub and feed revisions preserve the most recently modified content', async () => {
  const newer = new Date(NOW - 60_000).toISOString();
  const github = await collectSources(
    inventory(),
    config({ github: true }),
    {},
    async (url) => {
      if (new URL(url).searchParams.get('type') === 'malware') return response([]);
      return response([
        githubAdvisory(undefined, { updated_at: newer, summary: 'Latest correction', severity: 'critical' }),
        githubAdvisory(undefined, { summary: 'Older story', severity: 'low' }),
      ]);
    },
    NOW,
  );
  assert.equal(github.evidence[0].title, 'Latest correction');
  const feed = await collectSources(
    inventory(),
    config({ feeds: ['https://example.com/feed'] }),
    {},
    async () =>
      xml(
        `<rss><channel><item><guid>same</guid><title>Latest correction</title><pubDate>${newer}</pubDate></item><item><guid>same</guid><title>Older story</title><pubDate>${OLD}</pubDate></item></channel></rss>`,
      ),
    NOW,
  );
  assert.equal(feed.evidence[0].title, 'Latest correction');
});

test('far-future source revisions cannot poison stored evidence or advance checkpoints', async () => {
  const result = await collectSources(
    inventory(),
    config({ osv: true }),
    { osv: OLD },
    async (url) => {
      if (url.endsWith('/querybatch')) return response({ results: [{ vulns: [{ id: 'OSV-future' }] }] });
      return response(osvAdvisory('OSV-future', { modified: '2099-01-01T00:00:00Z' }));
    },
    NOW,
  );
  assert.deepEqual(result.evidence, []);
  assert.equal(result.checkpoints.osv, OLD);
  assert.match(result.errors[0].message, /future/i);
});

test('bounded source clock skew is accepted and GitHub page size is enforced', async () => {
  const current = await collectSources(
    inventory(),
    config({ github: true }),
    {},
    async (url) => {
      if (new URL(url).searchParams.get('type') === 'malware') return response([]);
      return response([githubAdvisory(undefined, { updated_at: new Date(NOW + 4 * 60_000).toISOString() })]);
    },
    NOW,
  );
  assert.deepEqual(current.errors, []);
  assert.equal(current.evidence.length, 1);
  const oversized = await collectSources(
    inventory(),
    config({ github: true }),
    {},
    async (url) => {
      if (new URL(url).searchParams.get('type') === 'malware') return response([]);
      return response(Array.from({ length: 101 }, () => githubAdvisory()));
    },
    NOW,
  );
  assert.deepEqual(oversized.evidence, []);
  assert.match(oversized.errors[0].message, /page limit/);
  assert.equal(oversized.checkpoints['github:reviewed'], undefined);
});

test('RSS and Atom normalize text and aliases without fetching article links', async () => {
  const calls = [];
  const result = await collectSources(
    inventory(),
    config({ feeds: ['https://vendor.example/rss?token=secret', 'https://vendor.example/atom'] }),
    {},
    async (url) => {
      calls.push(url);
      if (url.includes('/rss'))
        return xml(
          '<rss version="2.0"><channel><title>Updates</title><item><guid>vendor-123</guid><title>Critical CVE-2026-12345</title><link>https://vendor.example/advisory/123</link><description><![CDATA[<p>Use <b>fixed</b> version.</p><script>evil()</script>]]></description><pubDate>Fri, 23 Oct 2026 12:00:00 GMT</pubDate><severity>critical</severity></item></channel></rss>',
        );
      return xml(
        '<feed xmlns="http://www.w3.org/2005/Atom"><title>Updates</title><entry><id>urn:uuid:123</id><title>GHSA-abcd-2345-efgh update</title><link rel="self" href="https://vendor.example/api/123"/><link rel="alternate" href="/advisory/123"/><summary>Details &amp; fixes.</summary><updated>2026-10-23T13:00:00Z</updated></entry></feed>',
      );
    },
    NOW,
  );
  assert.deepEqual(result.errors, []);
  assert.equal(calls.length, 2);
  assert.equal(result.evidence.length, 2);
  assert.equal(result.evidence[0].description, 'Use fixed version.');
  assert.equal(result.evidence[0].severity, 'critical');
  assert.deepEqual(result.evidence[0].aliases, ['CVE-2026-12345']);
  assert.equal(result.evidence[1].url, 'https://vendor.example/advisory/123');
  assert.equal(result.evidence[1].description, 'Details & fixes.');
  assert.equal(JSON.stringify(result.evidence).includes('secret'), false);
});

test('feed IDs stay stable across title changes and separate different feeds', async () => {
  const read = (title) =>
    collectSources(
      inventory(),
      config({ feeds: ['https://a.example/feed', 'https://b.example/feed'] }),
      {},
      async () =>
        xml(`<rss><channel><item><guid>same-id</guid><title>${title}</title></item></channel></rss>`),
      NOW,
    );
  const first = await read('Original');
  const second = await read('Revised');
  assert.equal(first.evidence[0].id, second.evidence[0].id);
  assert.notEqual(first.evidence[0].id, first.evidence[1].id);
});

test('XML entities, malformed feeds and missing stable entry identities fail visibly', async (t) => {
  for (const body of [
    '<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&xxe;</title></item></channel></rss>',
    '<!ENTITY expansion "payload"><rss/>',
    '<rss><channel><item></rss>',
    '<html><body>Not a feed</body></html>',
    '<rss><channel><item><title>No stable identity</title></item></channel></rss>',
  ])
    await t.test(body.slice(0, 40), async () => {
      const result = await collectSources(
        inventory(),
        config({ feeds: ['https://example.com/feed?secret=private'] }),
        {},
        async () => xml(body),
        NOW,
      );
      assert.equal(result.errors.length, 1);
      assert.deepEqual(result.evidence, []);
      assert.deepEqual(result.checkpoints, {});
      assert.equal(JSON.stringify(result.errors).includes('private'), false);
    });
});

test('transport exceptions redact secrets and preserve unrelated successful sources', async () => {
  const result = await collectSources(
    inventory(),
    config({ osv: true, feeds: ['https://example.com/feed?token=PRIVATE_TOKEN'] }),
    { osv: OLD },
    async (url) => {
      if (url.includes('osv.dev')) return response({ results: [{}] });
      throw new Error(
        'Request https://example.com/feed?token=PRIVATE_TOKEN with Authorization: secret failed',
      );
    },
    NOW,
  );
  assert.equal(result.checkpoints.osv, NOW_ISO);
  assert.equal(result.errors.length, 1);
  assert.equal(JSON.stringify(result).includes('PRIVATE_TOKEN'), false);
  assert.equal(JSON.stringify(result).includes('Authorization'), false);
});

test('OSV uses supplied database severity and CVSS base scores while unsupported vectors remain unknown', async (t) => {
  const cases = [
    ['database', { database_specific: { severity: 'HIGH' }, severity: [] }, 'high'],
    ['moderate-label', { database_specific: { severity: 'MODERATE' }, severity: [] }, 'medium'],
    ['critical', { severity: [{ score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }, 'critical'],
    ['high', { severity: [{ score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }] }, 'high'],
    ['medium', { severity: [{ score: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' }] }, 'medium'],
    ['low', { severity: [{ score: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N' }] }, 'low'],
    ['scope-changed', { severity: [{ score: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H' }] }, 'high'],
    ['invalid', { severity: [{ score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:INVALID/I:H/A:H' }] }, 'unknown'],
    [
      'unsupported',
      { severity: [{ score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }] },
      'unknown',
    ],
  ];
  for (const [name, extra, expected] of cases)
    await t.test(name, async () => {
      const result = await collectSources(
        inventory(),
        config({ osv: true }),
        {},
        async (url) => {
          if (url.endsWith('/querybatch')) return response({ results: [{ vulns: [{ id: 'OSV-score' }] }] });
          return response(osvAdvisory('OSV-score', extra));
        },
        NOW,
      );
      assert.deepEqual(result.errors, []);
      assert.equal(result.evidence[0].severity, expected);
    });
});

test('OSV query matches remain complete when upstream omits affected metadata for multiple installed versions', async () => {
  const result = await collectSources(
    inventory([
      { id: 'a', ecosystem: 'npm', name: 'alpha', version: '1.0.0' },
      { id: 'b', ecosystem: 'npm', name: 'alpha', version: '2.0.0' },
    ]),
    config({ osv: true }),
    {},
    async (url) => {
      if (url.endsWith('/querybatch'))
        return response({
          results: [{ vulns: [{ id: 'OSV-query-match' }] }, { vulns: [{ id: 'OSV-query-match' }] }],
        });
      return response(osvAdvisory('OSV-query-match', { affected: [] }));
    },
    NOW,
  );
  assert.deepEqual(result.evidence[0].packages[0].matched_versions, ['1.0.0', '2.0.0']);
});
