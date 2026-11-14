import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { collectSources } from '../dist/sources.js';
import { evidenceRelevant } from '../dist/cve-now.js';
import { assess } from '../dist/assessment.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const config = (sources) => ({
  news_lookback_minutes: 40,
  poll_interval_minutes: 30,
  inventory_stale_days: 30,
  policy: {},
  sources: {
    cve_now: false,
    hacker_news: false,
    osv: false,
    github: false,
    github_token_env: 'LIVENESS_UNUSED',
    kev: false,
    feeds: [],
    ...sources,
  },
});
const inventory = (components, extra = {}) => ({
  systems: [
    { id: 'prod', name: 'prod', updated_at: iso(NOW), products: [], keywords: [], components, ...extra },
  ],
});
const npm = (name, version = '1.0.0') => ({ id: `lock:${name}`, ecosystem: 'npm', name, version });
const json = (value, headers = {}) => ({ status: 200, headers, body: JSON.stringify(value) });
const lockfileSlice = ['debug', 'send', 'buffer', 'request', 'events', 'process', 'open', 'path'].map(
  (name) => npm(name),
);
const unrelated = [
  'A heap-based buffer overflow in the Acme router firmware allows remote attackers to execute arbitrary code.',
  'Improper access control in ExampleCMS allows an authenticated user to send a crafted request and read arbitrary files.',
  'A vulnerability in the web management interface could allow an attacker to open a privileged session.',
  'The plugin does not sanitise a parameter, leading to stored XSS when the admin views the events page.',
  'Out-of-bounds read in the image parser allows a denial of service when a crafted file is opened by a process.',
];
const cveRecord = (number, description, extra = {}) => ({
  id: `cve_now:CVE-2026-${number}`,
  source: 'cve_now',
  kind: 'advisory',
  title: `CVE-2026-${number}`,
  url: 'https://cve.now/x',
  description,
  aliases: [`CVE-2026-${number}`],
  severity: 'high',
  modified_at: iso(NOW - 10 * DAY),
  fetched_at: iso(NOW - HOUR - number),
  packages: [],
  ...extra,
});
const cveNowHttp =
  (state, listing = []) =>
  async (url) => {
    const { pathname, searchParams } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries') {
      const offset = Number(searchParams.get('cursor') ?? 0);
      const entries = listing.slice(offset, offset + 100);
      return json({
        entries,
        ...(offset + 100 < listing.length ? { nextCursor: String(offset + 100) } : {}),
      });
    }
    const id = decodeURIComponent(pathname.split('/').pop());
    state.details.push(id);
    return json({
      id,
      status: 'published',
      title: id,
      originalDescription: 'unchanged',
      publishedAt: iso(NOW - 10 * DAY),
      modifiedAt: iso(NOW - 10 * DAY),
    });
  };

test('everyday words that are also package names do not make unrelated records relevant', () => {
  const inv = inventory(lockfileSlice);
  for (const description of unrelated) {
    assert.equal(evidenceRelevant(cveRecord(1, description), inv), false, description);
    const story = {
      ...cveRecord(2, description),
      id: 'hacker_news:entry:1',
      source: 'hacker_news',
      kind: 'news',
    };
    assert.equal(evidenceRelevant(story, inv), false, description);
    assert.deepEqual(assess(inv, [story], config({}), NOW), [], description);
  }
  // A story about packages still matches a plain-word name, and a distinctive name needs no context.
  const story = (description) => ({
    ...cveRecord(30003, description),
    id: 'hacker_news:entry:2',
    source: 'hacker_news',
    kind: 'news',
  });
  const about = story('A malicious release of the request npm package steals tokens (CVE-2026-30003).');
  assert.equal(evidenceRelevant(about, inv), true);
  assert.deepEqual(
    assess(inv, [about], config({}), NOW).map((finding) => finding.component_id),
    ['lock:request'],
  );
  const distinctive = inventory([npm('qrlib-pad'), npm('@acme/sdk'), npm('lodash4')]);
  for (const name of ['qrlib-pad', '@acme/sdk', 'lodash4'])
    assert.equal(evidenceRelevant(story(`Attackers abuse ${name} in the wild.`), distinctive), true, name);
  // Terms the operator declared always count, in advisories and in news.
  const declared = inventory([], {
    keywords: ['Acme router'],
    products: [{ name: 'ExampleCMS', keywords: [] }],
  });
  assert.equal(evidenceRelevant(cveRecord(4, unrelated[0]), declared), true);
  assert.equal(evidenceRelevant(cveRecord(5, unrelated[1]), declared), true);
  // A structured claim is a match whatever the text says.
  const claimed = cveRecord(6, 'No names here.', { packages: [{ ecosystem: 'npm', name: 'send' }] });
  assert.equal(evidenceRelevant(claimed, inv), true);
});

test('stored cve.now records cost a bounded number of requests per poll and take turns', async () => {
  const inv = inventory([npm('alpha')], { keywords: ['Acme router'] });
  const stored = [
    ...Array.from({ length: 1200 }, (_, index) => cveRecord(20000 + index, unrelated[0])),
    ...Array.from({ length: 3 }, (_, index) =>
      cveRecord(40000 + index, 'Package claim.', { packages: [{ ecosystem: 'npm', name: 'alpha' }] }),
    ),
    ...Array.from({ length: 4000 }, (_, index) => cveRecord(50000 + index, unrelated[1])),
  ];
  const state = { details: [] };
  const result = await collectSources(
    inv,
    config({ cve_now: true }),
    { cve_now: iso(NOW - 30 * 60_000) },
    cveNowHttp(state),
    NOW,
    stored,
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.checkpoints.cve_now, iso(NOW));
  // Every package-matched record, plus 200 keyword-matched ones; none of the 4,000 unrelated ones.
  assert.equal(state.details.length, 203);
  for (const index of [0, 1, 2]) assert.ok(state.details.includes(`CVE-2026-${40000 + index}`));
  assert.ok(state.details.every((id) => !id.startsWith('CVE-2026-5')));
  // The records read least recently go first, so repeated polls work through all of them.
  const oldest = stored
    .filter((item) => item.id.startsWith('cve_now:CVE-2026-2'))
    .sort((a, b) => Date.parse(a.fetched_at) - Date.parse(b.fetched_at))
    .slice(0, 200)
    .map((item) => item.id.slice(8));
  assert.deepEqual(state.details.filter((id) => id.startsWith('CVE-2026-2')).sort(), oldest.sort());
});

test('a cve.now backlog larger than one poll is collected oldest first and resumes', async () => {
  const inv = inventory([npm('alpha')]);
  const total = 5200;
  // Newest first, one record a minute.
  const listing = Array.from({ length: total }, (_, index) => ({
    id: `CVE-2026-${String(90000 - index)}`,
    publishedAt: iso(NOW - HOUR - index * 60_000),
  }));
  const state = { details: [] };
  const first = await collectSources(
    inv,
    config({ cve_now: true }),
    { cve_now: iso(NOW - 40 * DAY) },
    cveNowHttp(state, listing),
    NOW,
    [],
  );
  assert.equal(state.details.length, 5000);
  assert.match(first.errors[0].message, /200 more new record\(s\).*continues from there/);
  assert.equal(first.evidence.length, 5000);
  // The oldest 5,000 were read; the checkpoint points just past the newest of them.
  const reached = NOW - HOUR - 200 * 60_000;
  assert.equal(first.checkpoints.cve_now, iso(reached + HOUR));
  assert.ok(!state.details.includes('CVE-2026-90000'));

  state.details = [];
  const second = await collectSources(
    inv,
    config({ cve_now: true }),
    first.checkpoints,
    cveNowHttp(state, listing),
    NOW,
    [],
  );
  assert.deepEqual(second.errors, []);
  assert.equal(second.checkpoints.cve_now, iso(NOW));
  assert.ok(state.details.includes('CVE-2026-90000'));
  assert.ok(state.details.length <= 202);
});

test('a GitHub backlog larger than the page limit drains over consecutive runs', async () => {
  const inv = inventory([npm('alpha', '1.2.3')]);
  const total = 6000;
  const updated = (number) => NOW - 5 * HOUR + number * 1000;
  const record = (number) => ({
    ghsa_id: `GHSA-${String(number).padStart(4, '0')}-aaaa-bbbb`,
    type: 'reviewed',
    summary: 's',
    description: 'd',
    severity: 'critical',
    updated_at: iso(updated(number)),
    published_at: '2026-01-01T00:00:00Z',
    withdrawn_at: null,
    vulnerabilities: [
      {
        package: { ecosystem: 'npm', name: number === 5500 ? 'alpha' : 'other-pkg' },
        vulnerable_version_range: '< 9.0.0',
        first_patched_version: null,
      },
    ],
  });
  const http = async (url) => {
    const address = new URL(url);
    if (address.searchParams.get('type') === 'malware') return json([]);
    const [from] = address.searchParams.get('modified').split('..');
    const matching = [];
    for (let number = 0; number < total; number++)
      if (updated(number) >= Date.parse(from)) matching.push(number);
    const page = Number(address.searchParams.get('page') ?? 0);
    const next = new URL(url);
    next.searchParams.set('page', String(page + 1));
    return json(
      matching.slice(page * 100, page * 100 + 100).map(record),
      (page + 1) * 100 < matching.length ? { link: `<${next.href}>; rel="next"` } : {},
    );
  };
  let checkpoints = { 'github:reviewed': iso(NOW - 6 * HOUR), 'github:malware': iso(NOW - 6 * HOUR) };
  const first = await collectSources(inv, config({ github: true }), checkpoints, http, NOW, []);
  assert.equal(first.evidence.length, 5000);
  assert.match(first.errors[0].message, /continues from there/);
  assert.equal(first.checkpoints['github:reviewed'], iso(updated(4999) + HOUR));
  assert.ok(!first.evidence.some((item) => item.id === 'github:GHSA-5500-aaaa-bbbb'));
  checkpoints = first.checkpoints;
  const second = await collectSources(inv, config({ github: true }), checkpoints, http, NOW + 60_000, []);
  assert.deepEqual(second.errors, []);
  assert.ok(second.evidence.some((item) => item.id === 'github:GHSA-5500-aaaa-bbbb'));
  assert.equal(second.checkpoints['github:reviewed'], iso(NOW + 60_000));
});

test('one package name this application cannot normalise does not discard its advisory', async () => {
  const inv = inventory([npm('alpha', '1.2.3')]);
  const good = {
    ghsa_id: 'GHSA-aaaa-aaaa-aaaa',
    type: 'reviewed',
    summary: 's',
    description: 'd',
    severity: 'critical',
    updated_at: iso(NOW - HOUR),
    published_at: '2026-01-01T00:00:00Z',
    withdrawn_at: null,
    vulnerabilities: [
      { package: { ecosystem: 'npm', name: 'alpha' }, vulnerable_version_range: '< 9.0.0' },
      { package: { ecosystem: 'npm', name: 'Bad Name!' }, vulnerable_version_range: '< 9.0.0' },
    ],
  };
  const github = await collectSources(
    inv,
    config({ github: true }),
    { 'github:reviewed': iso(NOW - HOUR) },
    async (url) => (new URL(url).searchParams.get('type') === 'malware' ? json([]) : json([good])),
    NOW,
    [],
  );
  assert.deepEqual(github.errors, []);
  assert.equal(github.checkpoints['github:reviewed'], iso(NOW));
  assert.equal(assess(inv, github.evidence, config({}), NOW)[0].applicability, 'affected');

  const osv = await collectSources(
    inv,
    config({ osv: true }),
    {},
    async (url) =>
      url.endsWith('/querybatch')
        ? json({ results: [{ vulns: [{ id: 'GHSA-aaaa-bbbb-cccc', modified: iso(NOW - HOUR) }] }] })
        : json({
            id: 'GHSA-aaaa-bbbb-cccc',
            summary: 's',
            details: 'd',
            modified: iso(NOW - HOUR),
            affected: [
              {
                package: { ecosystem: 'npm', name: 'alpha' },
                ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.0.0' }] }],
              },
              {
                package: { ecosystem: 'Packagist', name: 'Bad Vendor/Bad Bundle' },
                ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }],
              },
            ],
          }),
    NOW,
    [],
  );
  assert.deepEqual(osv.errors, []);
  assert.equal(assess(inv, osv.evidence, config({}), NOW).length, 1);
});

test('stored OSV records that no longer exist do not stop the refresh of later ones', async () => {
  const inv = inventory([npm('alpha', '1.2.3')]);
  const stored = (id) => ({
    id: `osv:${id}`,
    source: 'osv',
    kind: 'advisory',
    title: 't',
    url: 'u',
    description: 'd',
    aliases: [],
    severity: 'high',
    modified_at: iso(NOW - HOUR),
    fetched_at: iso(NOW - HOUR),
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '<9.0.0' }],
  });
  const previous = [
    ...Array.from({ length: 9 }, (_, index) => stored(`GHSA-gone-0000-000${index}`)),
    stored('GHSA-live-0000-0000'),
  ];
  const asked = [];
  const http = async (url) => {
    if (url.endsWith('/querybatch')) return json({ results: [{}] });
    asked.push(url.split('/').pop());
    if (url.includes('gone')) return { status: 404, headers: {}, body: '{}' };
    return json({
      id: 'GHSA-live-0000-0000',
      summary: 's',
      details: 'd',
      modified: iso(NOW - 60_000),
      withdrawn: iso(NOW - 60_000),
      affected: [
        {
          package: { ecosystem: 'npm', name: 'alpha' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
        },
      ],
    });
  };
  const result = await collectSources(inv, config({ osv: true }), {}, http, NOW, previous);
  assert.equal(asked.length, 10);
  assert.deepEqual(result.errors, []);
  assert.equal(result.evidence.length, 1);
  assert.equal(result.evidence[0].withdrawn, true);

  // A missing record that the current query still names is a real failure.
  const named = await collectSources(
    inv,
    config({ osv: true }),
    {},
    async (url) =>
      url.endsWith('/querybatch')
        ? json({ results: [{ vulns: [{ id: 'GHSA-gone-0000-0000', modified: iso(NOW - HOUR) }] }] })
        : { status: 404, headers: {}, body: '{}' },
    NOW,
    [],
  );
  assert.match(named.errors[0].message, /failed/);
});

test('a feed entry that appears after its own timestamp is collected, and an old one stays out', async () => {
  const feedUrl = 'https://vendor.example/feed.xml';
  const item = (title, time) =>
    `<item><title>${title}</title><link>https://vendor.example/${title}</link><guid>${title}</guid>` +
    `<pubDate>${new Date(time).toUTCString()}</pubDate><description>alpha advisory</description></item>`;
  const feed =
    (...items) =>
    async () => ({
      status: 200,
      headers: {},
      body: `<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>${items.join('')}</channel></rss>`,
    });
  const inv = inventory([npm('alpha')]);
  const settings = config({ feeds: [feedUrl] });
  const titles = (result) => result.evidence.map((entry) => entry.title).sort();

  // First run: only the configured window counts; the older entry is seen and left out.
  const first = await collectSources(
    inv,
    settings,
    {},
    feed(item('recent', NOW - 10 * 60_000), item('old', NOW - 3 * HOUR)),
    NOW,
    [],
  );
  assert.deepEqual(titles(first), ['recent']);

  // Second run: two entries are listed for the first time with stamps older than the window.
  const later = NOW + 30 * 60_000;
  const second = await collectSources(
    inv,
    settings,
    first.checkpoints,
    feed(
      item('fresh', later - 5 * 60_000),
      item('late-appearing', later - 75 * 60_000),
      item('midnight-stamped', Date.parse('2026-10-24T00:00:00Z')),
      item('ancient', later - 9 * DAY),
      item('recent', NOW - 10 * 60_000),
      item('old', NOW - 3 * HOUR),
    ),
    later,
    first.evidence,
  );
  assert.deepEqual(second.errors, []);
  assert.deepEqual(titles(second), ['fresh', 'late-appearing', 'midnight-stamped', 'recent']);

  // Third run: nothing is new, so nothing outside the window returns.
  const third = await collectSources(
    inv,
    settings,
    second.checkpoints,
    feed(
      item('late-appearing', later - 75 * 60_000),
      item('midnight-stamped', Date.parse('2026-10-24T00:00:00Z')),
      item('old', NOW - 3 * HOUR),
    ),
    later + 30 * 60_000,
    [],
  );
  assert.deepEqual(titles(third), []);
});

test('a large inventory is compared with a large evidence store without blocking for seconds', () => {
  const components = Array.from({ length: 1500 }, (_, index) => npm(`package-${index}`));
  const inv = inventory(components);
  const records = Array.from({ length: 10_000 }, (_, index) =>
    cveRecord(100000 + index, unrelated[index % unrelated.length], {
      id: `osv:GHSA-${index}`,
      source: 'osv',
      aliases: [],
      fetched_at: iso(NOW),
      packages: [{ ecosystem: 'npm', name: `other-${index}`, range: '<2.0.0' }],
    }),
  );
  const started = performance.now();
  assert.equal(records.filter((item) => evidenceRelevant(item, inv)).length, 0);
  assert.deepEqual(assess(inv, records, config({}), NOW), []);
  // 23.9 s and 5.0 s before the index; the bound is generous for slow CI hosts.
  assert.ok(performance.now() - started < 5_000);
});

test('the response formats cve.now served on 2026-11-13 are collected', async () => {
  const live = JSON.parse(
    readFileSync(new URL('./fixtures/cve-now-live-2026-11-13.json', import.meta.url), 'utf8'),
  );
  const recorded = Date.parse('2026-11-13T19:00:00Z');
  const inv = {
    systems: [
      {
        id: 'prod',
        name: 'prod',
        updated_at: iso(recorded),
        products: [],
        keywords: [],
        components: [npm('lodash', '4.17.20'), npm('express', '4.21.2')],
      },
    ],
  };
  const older = { ...live.listing.entries[1], id: 'CVE-2026-90001', publishedAt: iso(recorded - 2 * HOUR) };
  const asked = [];
  const http = async (url) => {
    const { pathname, searchParams } = new URL(url);
    asked.push(pathname + (searchParams.get('cursor') ? '?cursor' : ''));
    if (pathname === '/stack')
      // The package lookup is a JSON Feed: matches for lodash, an empty feed for express.
      return json(
        searchParams.get('p').startsWith('npm:lodash@') ? live.stack : { ...live.stack, items: [] },
      );
    if (pathname === '/api/v1/entries')
      return searchParams.get('cursor')
        ? json({ items: [older], entries: [older] })
        : json({ ...live.listing, next_cursor: 'page-two' });
    const id = decodeURIComponent(pathname.split('/').pop());
    return id === live.detail.id
      ? json(live.detail)
      : json({ ...live.detail, id, feedId: id, aliases: [], affected: [], title: id });
  };
  const result = await collectSources(
    inv,
    config({ cve_now: true }),
    { cve_now: iso(recorded - 3 * HOUR) },
    http,
    recorded,
    [],
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.checkpoints.cve_now, iso(recorded));
  // The paging key is next_cursor: the second page must be read.
  assert.ok(asked.includes('/api/v1/entries?cursor'));
  assert.ok(result.evidence.some((item) => item.id === 'cve_now:CVE-2026-90001'));
  const matched = result.evidence.find((item) => item.id === `cve_now:${live.detail.id}`);
  const claim = matched.packages.find((item) => item.ecosystem === 'npm' && item.name === 'lodash');
  assert.deepEqual(claim.matched_versions, ['4.17.20']);
  assert.equal(claim.range, '<4.18.0');
  const findings = assess(inv, result.evidence, config({}), recorded);
  assert.deepEqual(
    findings.map((finding) => [finding.component_id, finding.applicability]),
    [['lock:lodash', 'affected']],
  );

  // A match for a package that was not asked about is rejected, not trusted.
  const forged = structuredClone(live.stack);
  forged.items[0]._cve_now.matched.name = 'left-pad';
  const refused = await collectSources(
    inv,
    config({ cve_now: true }),
    { cve_now: iso(recorded - HOUR) },
    async (url) => (new URL(url).pathname === '/stack' ? json(forged) : json({ entries: [] })),
    recorded,
    [],
  );
  assert.match(refused.errors[0].message, /unrequested package match/);
});

test('a cve.now record stamped ahead of the clock is collected with its earlier stamp', async () => {
  const inv = inventory([npm('alpha')], { keywords: ['Acme router'] });
  const future = iso(NOW + 3 * DAY);
  const published = iso(NOW - 2 * HOUR);
  const listing = [
    // Scheduled publication: listed now, stamped in the future.
    { id: 'CVE-2026-70001', publishedAt: future, firstSeenAt: iso(NOW - 10 * 60_000) },
    { id: 'CVE-2026-70002', publishedAt: iso(NOW - 30 * 60_000) },
    { id: 'CVE-2026-70003', publishedAt: future },
    { id: 'CVE-2026-70004', publishedAt: iso(NOW - 40 * 60_000) },
  ];
  const detail = (id) => ({
    id,
    status: 'published',
    title: id,
    originalDescription: 'A flaw in the Acme router firmware.',
    firstSeenAt: published,
    publishedAt: id === 'CVE-2026-70003' ? future : published,
    modifiedAt: id === 'CVE-2026-70004' ? published : future,
  });
  const result = await collectSources(
    inv,
    config({ cve_now: true }),
    { cve_now: iso(NOW - HOUR) },
    async (url) => {
      const { pathname } = new URL(url);
      if (pathname === '/stack') return json({ packages: 1, entries: [] });
      if (pathname === '/api/v1/entries') return json({ entries: listing });
      return json(detail(decodeURIComponent(pathname.split('/').pop())));
    },
    NOW,
    [],
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.checkpoints.cve_now, iso(NOW));
  assert.equal(result.coverage[0].status, 'complete');
  assert.deepEqual(result.evidence.map((item) => item.id).sort(), [
    'cve_now:CVE-2026-70001',
    'cve_now:CVE-2026-70002',
    'cve_now:CVE-2026-70003',
    'cve_now:CVE-2026-70004',
  ]);
  // No stored stamp is ahead of the clock, so a later revision can still take precedence.
  for (const item of result.evidence) {
    assert.ok(Date.parse(item.modified_at) <= NOW, item.id);
    assert.ok(item.published_at === undefined || Date.parse(item.published_at) <= NOW, item.id);
  }
  assert.equal(result.evidence.find((item) => item.id.endsWith('70003')).published_at, undefined);
  // The same record read again keeps the same stamp: no new revision on every scan.
  const again = await collectSources(
    inv,
    config({ cve_now: true }),
    result.checkpoints,
    async (url) => {
      const { pathname } = new URL(url);
      if (pathname === '/stack') return json({ packages: 1, entries: [] });
      if (pathname === '/api/v1/entries') return json({ entries: [] });
      return json(detail(decodeURIComponent(pathname.split('/').pop())));
    },
    NOW + 30 * 60_000,
    result.evidence,
  );
  const stamp = (set, id) => set.find((item) => item.id === id).modified_at;
  assert.equal(
    stamp(again.evidence, 'cve_now:CVE-2026-70001'),
    stamp(result.evidence, 'cve_now:CVE-2026-70001'),
  );
});

test('the first cve.now scan of a new installation looks back one day', async () => {
  const listing = [
    { id: 'CVE-2026-80001', publishedAt: iso(NOW - 2 * HOUR) },
    { id: 'CVE-2026-80002', publishedAt: iso(NOW - 23 * HOUR) },
    { id: 'CVE-2026-80003', publishedAt: iso(NOW - 26 * HOUR) },
    { id: 'CVE-2026-80004', publishedAt: iso(NOW - 6 * DAY) },
  ];
  const state = { details: [] };
  const result = await collectSources(
    inventory([npm('alpha')]),
    config({ cve_now: true }),
    {},
    cveNowHttp(state, listing),
    NOW,
    [],
  );
  assert.deepEqual(result.errors, []);
  // One day plus the usual hour of overlap; older records are left to exact package queries.
  assert.deepEqual(state.details.sort(), ['CVE-2026-80001', 'CVE-2026-80002']);
  assert.equal(result.checkpoints.cve_now, iso(NOW));
});
