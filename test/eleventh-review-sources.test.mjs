// Regressions from the eleventh review of collection: GitHub records confirmed as current, stale
// exclusions and the overrides, the room kept for the cve.now listing, the attempt rule for owed
// records, lookups retried first, OSV history, merged events and smaller matching guards.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assess, decide } from '../dist/assessment.js';
import { inventoryMatcher, packageMentioned } from '../dist/matching.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });
const failing = (status) => ({ status, headers: {}, body: '' });

const inventory = (components) => ({
  systems: [
    {
      id: 'prod',
      name: 'prod',
      updated_at: iso(NOW),
      products: [],
      keywords: [],
      components: components.map(([name, version]) => ({ id: `c:${name}`, ecosystem: 'npm', name, version })),
    },
  ],
});
const rule = { levels: ['critical'], basis: 'source_severity', channels: ['slack'] };
const config = (sources) => ({
  news_lookback_minutes: 40,
  poll_interval_minutes: 30,
  inventory_stale_days: 30,
  models: { enabled: false },
  policy: {
    library: rule,
    product: rule,
    news: rule,
    health_channels: ['slack'],
    urgent_unknown: true,
    exploited_override: true,
    malware_override: true,
  },
  sources: {
    cve_now: false,
    hacker_news: false,
    osv: false,
    github: false,
    github_token_env: 'ELEVENTH_SOURCES_UNUSED',
    kev: false,
    feeds: [],
    ...sources,
  },
});

// ---- GitHub ----------------------------------------------------------------------------------------

const ghsa = (id, name, range, modified, extra = {}) => ({
  ghsa_id: id,
  cve_id: null,
  type: 'reviewed',
  summary: `${name} flaw`,
  description: `A flaw in ${name}.`,
  severity: 'critical',
  updated_at: iso(modified),
  published_at: iso(NOW - 10 * DAY),
  withdrawn_at: null,
  vulnerabilities: [
    { package: { ecosystem: 'npm', name }, vulnerable_version_range: range, first_patched_version: null },
  ],
  ...extra,
});
async function githubPolls(answers, start = {}) {
  const store = new Store(':memory:');
  store.saveEvidence([], start);
  const inv = inventory([['alpha', '3.0.0']]);
  const settings = config({ github: true });
  const rounds = [];
  for (const [poll, answer] of answers.entries()) {
    const now = NOW + poll * 30 * MINUTE;
    const urls = [];
    const http = async (url) => {
      urls.push(url);
      return new URL(url).searchParams.get('type') === 'malware' ? json([]) : json(answer(now));
    };
    const result = await collectSources(inv, settings, store.checkpoints(), http, now, store.evidence());
    store.saveEvidence(result.evidence, result.checkpoints);
    const [finding] = assess(inv, store.evidence(), settings, now);
    rounds.push({ result, urls, finding, decision: finding && decide(finding, settings) });
  }
  return rounds;
}

test('an unchanged GitHub record for an inventory package stays current while GitHub answers', async () => {
  const rounds = await githubPolls([
    () => [
      ghsa('GHSA-aaaa-bbbb-0001', 'alpha', '< 2.0.0', NOW - HOUR),
      ghsa('GHSA-aaaa-bbbb-0002', 'zeta', '< 1.0.0', NOW - HOUR),
    ],
    () => [],
    () => [],
    () => [],
  ]);
  for (const { finding, decision } of rounds) {
    assert.equal(finding.applicability, 'not_affected');
    assert.equal(decision.action, 'record');
  }
  // Only records for the inventory's packages are confirmed.
  assert.deepEqual(
    rounds[3].result.evidence.map((item) => item.id),
    ['github:GHSA-aaaa-bbbb-0001'],
  );
  assert.equal(rounds[3].result.evidence[0].fetched_at, iso(NOW + 90 * MINUTE));
});

test('a GitHub record read again with a wider range is not replaced by the stored copy', async () => {
  const rounds = await githubPolls([
    () => [ghsa('GHSA-aaaa-bbbb-0003', 'alpha', '< 2.0.0', NOW - HOUR)],
    (now) => [ghsa('GHSA-aaaa-bbbb-0003', 'alpha', '< 4.0.0', now - MINUTE)],
  ]);
  assert.equal(rounds[0].finding.applicability, 'not_affected');
  assert.equal(rounds[1].finding.applicability, 'affected');
  assert.equal(rounds[1].decision.action, 'notify');
});

test('a stored GitHub record whose new version could not be read is not confirmed; others are', async () => {
  const rounds = await githubPolls([
    () => [
      ghsa('GHSA-aaaa-bbbb-0004', 'alpha', '< 2.0.0', NOW - HOUR),
      ghsa('GHSA-aaaa-bbbb-0005', 'alpha', '< 1.0.0', NOW - HOUR),
    ],
    (now) => [{ ghsa_id: 'GHSA-aaaa-bbbb-0004', updated_at: iso(now - MINUTE) }],
  ]);
  assert.ok(rounds[1].result.errors.length > 0);
  const ids = rounds[1].result.evidence.map((item) => item.id);
  assert.ok(!ids.includes('github:GHSA-aaaa-bbbb-0004'), 'the record whose update could not be read');
  assert.ok(ids.includes('github:GHSA-aaaa-bbbb-0005'), 'an unrelated record is still confirmed');
  // A row with no identifier could be any record: nothing is confirmed.
  const anonymous = await githubPolls([
    () => [ghsa('GHSA-aaaa-bbbb-0004', 'alpha', '< 2.0.0', NOW - HOUR)],
    (now) => [{ updated_at: iso(now - MINUTE) }],
  ]);
  assert.ok(!anonymous[1].result.evidence.some((item) => item.id === 'github:GHSA-aaaa-bbbb-0004'));
});

test('a GitHub record is confirmed only when the scans since it was read cover every change', async () => {
  const stored = {
    id: 'github:GHSA-AAAA-BBBB-0006',
    source: 'github:reviewed',
    kind: 'advisory',
    title: 'alpha flaw',
    url: 'https://github.com/advisories/GHSA-AAAA-BBBB-0006',
    description: 'A flaw in alpha.',
    aliases: ['GHSA-AAAA-BBBB-0006'],
    severity: 'critical',
    modified_at: iso(NOW - DAY),
    fetched_at: iso(NOW - 3 * HOUR),
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
  };
  const run = async (checkpoints) => {
    const http = async () => json([]);
    return collectSources(inventory([['alpha', '3.0.0']]), config({ github: true }), checkpoints, http, NOW, [
      stored,
    ]);
  };
  const confirmed = (result) => result.evidence.some((item) => item.id === stored.id);
  // The window starts after the record was read: a change in between could have been missed.
  assert.equal(
    confirmed(await run({ 'github:reviewed': iso(NOW - 30 * MINUTE), 'github:malware': iso(NOW) })),
    false,
  );
  // A catch-up that began before it was read covers that time.
  const chained = await run({
    'github:reviewed': iso(NOW - 30 * MINUTE),
    'github:reviewed:since': iso(NOW - 4 * HOUR),
    'github:malware': iso(NOW),
  });
  assert.equal(confirmed(chained), true);
  // A complete scan ends the catch-up.
  assert.equal(chained.checkpoints['github:reviewed:since'], '');
});

test('a GitHub checkpoint ahead of the clock starts over instead of stopping the source', async () => {
  const urls = [];
  const result = await collectSources(
    inventory([['alpha', '3.0.0']]),
    config({ github: true }),
    { 'github:reviewed': iso(NOW + DAY), 'github:malware': iso(NOW) },
    async (url) => {
      urls.push(url);
      return json([]);
    },
    NOW,
    [],
  );
  assert.deepEqual(result.errors, []);
  const window = new URL(urls.find((url) => url.includes('type=reviewed'))).searchParams.get('modified');
  assert.equal(window.split('..')[0], iso(NOW - 7 * DAY - HOUR).replace(/\.\d{3}Z$/, 'Z'));
});

// ---- Stale exclusions and the overrides ----------------------------------------------------------

test('a stale exclusion goes to the digest even for an exploited or malicious advisory', () => {
  const settings = config({});
  const inv = inventory([['alpha', '3.0.0']]);
  const advisory = (extra) => ({
    id: 'osv:GHSA-aaaa-bbbb-0007',
    source: 'osv',
    kind: 'advisory',
    title: 'alpha flaw',
    url: 'https://example.com/a',
    description: '',
    aliases: ['GHSA-aaaa-bbbb-0007'],
    severity: 'critical',
    modified_at: iso(NOW - DAY),
    fetched_at: iso(NOW - 90 * MINUTE),
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
    ...extra,
  });
  for (const extra of [{ exploited: true }, { malware: true }, {}]) {
    const [finding] = assess(inv, [advisory(extra)], settings, NOW);
    assert.equal(finding.stale_exclusion, true, JSON.stringify(extra));
    assert.equal(decide(finding, settings).action, 'digest', JSON.stringify(extra));
  }
});

// ---- cve.now ---------------------------------------------------------------------------------------

const record = (id, name = 'alpha') =>
  json({
    id,
    status: 'published',
    title: `${id} flaw`,
    originalDescription: `A flaw in ${name}.`,
    severity: { cvss: 9.8 },
    affected: [{ ecosystem: 'npm', package: name, ranges: [{ introduced: '0', fixed: '2.0.0' }] }],
    publishedAt: iso(NOW - 10 * DAY),
    modifiedAt: iso(NOW - 10 * DAY),
  });
const storedRecord = (id, fetched) => ({
  id: `cve_now:${id}`,
  source: 'cve_now',
  kind: 'advisory',
  title: id,
  url: 'https://cve.now/x',
  description: 'A flaw in alpha.',
  aliases: [id],
  severity: 'critical',
  modified_at: iso(NOW - 10 * DAY),
  fetched_at: iso(fetched),
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
});

test('records named by the lookups do not take the room kept for the listing', async () => {
  // 5,000 stored records for alpha, 2,000 of them named by the lookup; one new record is listed.
  const ids = Array.from({ length: 5_000 }, (_, index) => `CVE-2025-${100_000 + index}`);
  const stored = ids.map((id, index) => storedRecord(id, NOW - HOUR - index));
  const fresh = 'CVE-2026-99999';
  const details = [];
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack')
      return json({
        items: ids.slice(0, 2_000).map((id) => ({
          id,
          _cve_now: { matched: { ecosystem: 'npm', name: 'alpha', version: '3.0.0' } },
        })),
      });
    if (pathname === '/api/v1/entries')
      return json({ entries: [{ id: fresh, publishedAt: iso(NOW - 10 * MINUTE) }] });
    const id = decodeURIComponent(pathname.split('/').at(-1));
    details.push(id);
    return record(id);
  };
  const result = await collectSources(
    inventory([['alpha', '3.0.0']]),
    config({ cve_now: true }),
    { cve_now: iso(NOW - HOUR) },
    http,
    NOW,
    stored,
  );
  assert.ok(details.includes(fresh), 'the new record is read');
  assert.equal(details.length, 4_001);
  assert.equal(result.checkpoints.cve_now, iso(NOW));
  assert.match(result.errors[0]?.message ?? '', /1000 requested record\(s\) were not read/);
});

/** One poll with an owed record and a readable new one; the owed record's request always fails. */
async function owedPoll(attempts, { blockFirst = false } = {}) {
  const owed = 'CVE-2026-90901';
  // Four readable records come first, one batch; the owed record is in the next batch.
  const readable = ['CVE-2026-90902', 'CVE-2026-90903', 'CVE-2026-90904', 'CVE-2026-90905'];
  const asked = [];
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries')
      return json({ entries: readable.map((id) => ({ id, publishedAt: iso(NOW - 10 * MINUTE) })) });
    const id = decodeURIComponent(pathname.split('/').at(-1));
    asked.push(id);
    if (blockFirst && id === readable[0]) return failing(429);
    return id === owed ? failing(500) : record(id);
  };
  const result = await collectSources(
    inventory([['alpha', '3.0.0']]),
    config({ cve_now: true }),
    {
      cve_now: iso(NOW - HOUR),
      'cve_now:owed': JSON.stringify([[owed, NOW - 100 * HOUR, NOW - 100 * HOUR, attempts]]),
      'cve_now:troubled': JSON.stringify([owed]),
    },
    http,
    NOW,
    [],
  );
  return { result, asked, owed: JSON.parse(result.checkpoints['cve_now:owed'] ?? '[]') };
}

test('an owed record is given up on only after three failed requests, however long it waited', async () => {
  // Three days have passed; this is its second failed request.
  const second = await owedPoll(1);
  assert.deepEqual(
    second.owed.map(([id, , , attempts]) => [id, attempts]),
    [['CVE-2026-90901', 2]],
  );
  assert.doesNotMatch(second.result.errors[0].message, /given up on/);
  // The third failed request gives it up, with a report.
  const third = await owedPoll(2);
  assert.deepEqual(third.owed, []);
  assert.match(third.result.errors[0].message, /could not be read for three days and were given up on/);
  // A poll that ends before its request is sent does not count as an attempt.
  const unsent = await owedPoll(2, { blockFirst: true });
  assert.ok(!unsent.asked.includes('CVE-2026-90901'));
  // The record refused with "too many requests" is owed too, after its first attempt.
  assert.deepEqual(
    unsent.owed.find(([id]) => id === 'CVE-2026-90901'),
    ['CVE-2026-90901', NOW - 100 * HOUR, NOW - 100 * HOUR, 2],
  );
});

test('the lookup that named a record that could not be read is sent first on the next poll', async () => {
  const names = Array.from({ length: 1_500 }, (_, index) => [
    `pkg-${String(index).padStart(5, '0')}`,
    '1.0.0',
  ]);
  const named = 'npm:pkg-00990@1.0.0';
  let checkpoints = { cve_now: iso(NOW - HOUR) };
  const rounds = [];
  for (let poll = 0; poll < 2; poll++) {
    const asked = [];
    const http = async (url) => {
      const { pathname, searchParams } = new URL(url);
      if (pathname === '/stack') {
        asked.push(searchParams.get('p'));
        return searchParams.get('p') === named && poll === 0
          ? json({
              items: [
                {
                  id: 'CVE-2026-90950',
                  _cve_now: { matched: { ecosystem: 'npm', name: 'pkg-00990', version: '1.0.0' } },
                },
              ],
            })
          : json({ packages: 1, entries: [] });
      }
      if (pathname === '/api/v1/entries') return json({ entries: [] });
      return failing(503);
    };
    const result = await collectSources(
      inventory(names),
      config({ cve_now: true }),
      checkpoints,
      http,
      NOW + poll * 30 * MINUTE,
      [],
    );
    checkpoints = result.checkpoints;
    rounds.push(asked);
  }
  assert.ok(rounds[0].includes(named));
  assert.equal(rounds[1][0], named);
});

// ---- OSV -------------------------------------------------------------------------------------------

test('stored OSV records for packages no longer in the inventory are not read again', async () => {
  const stored = (id, name) => ({
    id: `osv:${id}`,
    source: 'osv',
    kind: 'advisory',
    title: id,
    url: 'https://osv.dev/x',
    description: '',
    aliases: [id],
    severity: 'high',
    modified_at: iso(NOW - DAY),
    fetched_at: iso(NOW - HOUR),
    packages: [{ ecosystem: 'npm', name, range: '<2.0.0' }],
  });
  const read = [];
  await collectSources(
    inventory([['alpha', '3.0.0']]),
    config({ osv: true }),
    {},
    async (url) => {
      if (url.endsWith('/querybatch')) return json({ results: [{}] });
      read.push(url.split('/').at(-1));
      return failing(404);
    },
    NOW,
    [stored('GHSA-aaaa-bbbb-0010', 'alpha'), stored('GHSA-aaaa-bbbb-0011', 'removed-package')],
  );
  assert.deepEqual(read, ['GHSA-aaaa-bbbb-0010']);
});

// ---- Merged events ---------------------------------------------------------------------------------

test('two events reported for two components keep their identifiers when one advisory merges them', () => {
  const inv = inventory([
    ['alpha', '1.0.0'],
    ['beta', '1.0.0'],
  ]);
  const settings = config({});
  const advisory = (id, aliases, names, source = 'cve_now') => ({
    id: `${source}:${id}`,
    source,
    kind: 'advisory',
    title: id,
    url: 'https://example.com/a',
    description: '',
    aliases,
    severity: 'high',
    modified_at: iso(NOW - 1000),
    fetched_at: iso(NOW),
    packages: names.map((name) => ({ ecosystem: 'npm', name, range: '<2.0.0' })),
  });
  const separate = [
    advisory('CVE-2026-0001', ['CVE-2026-0001'], ['alpha']),
    advisory('CVE-2026-0002', ['CVE-2026-0002'], ['beta']),
  ];
  const before = assess(inv, separate, settings, NOW);
  const merged = [
    ...separate,
    advisory(
      'GHSA-aaaa-bbbb-cccc',
      ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-0001', 'CVE-2026-0002'],
      ['alpha', 'beta'],
      'osv',
    ),
  ];
  const after = assess(
    inv,
    merged,
    settings,
    NOW,
    NOW,
    new Set(before.map((finding) => finding.event_id)),
    new Set(before.map((finding) => finding.id)),
  );
  const ids = (findings) =>
    findings.map((finding) => [finding.component_id, finding.id, finding.event_id]).sort();
  assert.deepEqual(ids(after), ids(before));
});

// ---- Matching guards -------------------------------------------------------------------------------

test('matching: the "js" form passes the word check, and the Maven artifact and currency guards hold', () => {
  const matcher = inventoryMatcher(inventory([['express', '4.21.2']]));
  assert.equal(matcher.packageNamed('ExpressJS 4.21.2 fixes an open redirect.'), true);
  const maven = (name, text) => packageMentioned(text, { ecosystem: 'Maven', name });
  // Too short to stand alone, or an English word: the artifact alone is not the library.
  assert.equal(maven('com.example:zqxw', 'A zqxw flaw was found in the parser.'), false);
  // An English word written as a name would count for a package named so; not for a Maven artifact.
  assert.equal(maven('org.example:scheduler', 'A flaw in Scheduler lets attackers run jobs.'), false);
  assert.equal(maven('org.example:zqxwvut', 'A zqxwvut flaw was found in the parser.'), true);
  for (const unit of ['GBP', 'JPY', 'euros', 'XMR', 'bitcoin'])
    assert.equal(
      packageMentioned(`Send 2.5 ${unit} to the wallet below.`, { ecosystem: 'npm', name: 'send' }),
      false,
      unit,
    );
});
