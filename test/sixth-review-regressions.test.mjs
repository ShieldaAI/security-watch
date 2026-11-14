// Regressions from the sixth review: a held checkpoint that made a backlog read the same records
// again and again, exclusions withdrawn for a record that has nothing to do with packages, and
// ordinary words next to "package" or "library".
import test from 'node:test';
import assert from 'node:assert/strict';
import { assess } from '../dist/assessment.js';
import { inventoryMatcher, packageMentioned } from '../dist/matching.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });
const sources = {
  news_lookback_minutes: 40,
  poll_interval_minutes: 30,
  inventory_stale_days: 30,
  policy: {},
  sources: {
    cve_now: true,
    hacker_news: false,
    osv: false,
    github: false,
    github_token_env: 'SIXTH_REVIEW_UNUSED',
    kev: false,
    feeds: [],
  },
};
const inventory = (extra = {}) => ({
  systems: [
    {
      id: 'prod',
      name: 'prod',
      updated_at: iso(NOW),
      products: [],
      keywords: [],
      components: [{ id: 'lock:alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
      ...extra,
    },
  ],
});
const record = (id, extra = {}) => ({
  id,
  status: 'published',
  title: id,
  originalDescription: 'unchanged',
  publishedAt: iso(NOW - 10 * DAY),
  modifiedAt: iso(NOW - 10 * DAY),
  ...extra,
});
const stored = (id, extra = {}) => ({
  id: `cve_now:${id}`,
  source: 'cve_now',
  kind: 'advisory',
  title: id,
  url: 'https://cve.now/x',
  description: 'alpha flaw',
  aliases: [id],
  severity: 'critical',
  modified_at: iso(NOW - 10 * DAY),
  fetched_at: iso(NOW - HOUR),
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<0.9.0' }],
  ...extra,
});
const failing = (status) => ({ status, headers: {}, body: '' });
/** A stub of the service. `detail` may count requests to model a limit per poll. */
const service = (state, { listing = () => [], detail = () => undefined } = {}, now = NOW) => {
  return async (url) => {
    const { pathname, searchParams } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries') {
      const all = listing(now);
      const offset = Number(searchParams.get('cursor') ?? 0);
      return json({
        entries: all.slice(offset, offset + 100),
        ...(offset + 100 < all.length ? { next_cursor: String(offset + 100) } : {}),
      });
    }
    const id = decodeURIComponent(pathname.split('/').pop());
    (state.details ??= []).push(id);
    const answer = detail(id, state.details.length);
    if (!answer) (state.read ??= []).push(id);
    return answer ?? json(record(id));
  };
};
/** `count` records over `days`, newest first, ending ten minutes before `now`. */
const backlog = (count, days, now = NOW) =>
  Array.from({ length: count }, (_, index) => ({
    id: `CVE-2026-${200000 + count - index}`,
    publishedAt: iso(now - 600_000 - Math.floor((index * days * DAY) / count)),
  }));

// ---- A backlog is never read twice ------------------------------------------------------------------

test('a backlog is worked through even when the service allows only so many requests per poll', async () => {
  // Five days of records, and "too many requests" after 1,000 detail requests in each poll.
  const listing = backlog(3000, 5);
  const world = { listing: () => listing, detail: (_id, count) => (count > 1000 ? failing(429) : undefined) };
  let checkpoints = { cve_now: iso(NOW - 5 * DAY - HOUR) };
  const everRead = new Set();
  const reads = [];
  for (let poll = 0; poll < 5; poll++) {
    const now = NOW + poll * 30 * 60_000;
    const state = {};
    const result = await collectSources(
      inventory(),
      sources,
      checkpoints,
      service(state, world, now),
      now,
      [],
    );
    assert.ok(
      Date.parse(result.checkpoints.cve_now) > Date.parse(checkpoints.cve_now) || !result.errors.length,
      `poll ${poll}: the checkpoint moves`,
    );
    // Records of the last hour are read again on every poll (the checkpoint's overlap); nothing
    // older than that is.
    for (const id of state.read ?? []) {
      const published = Date.parse(listing.find((entry) => entry.id === id).publishedAt);
      assert.ok(
        !everRead.has(id) || published >= now - 2 * HOUR,
        `poll ${poll}: ${id} is read a second time`,
      );
      everRead.add(id);
    }
    reads.push((state.read ?? []).length);
    checkpoints = result.checkpoints;
  }
  assert.deepEqual(reads.slice(0, 3), [1000, 1000, 1000]);
  assert.equal(everRead.size, 3000, 'every record is read once');
  assert.equal(checkpoints['cve_now:owed'], '[]');
});

test('occasional failures in a large first scan do not hold the checkpoint', async () => {
  // A new installation reads a day of records; every hundredth request fails once.
  const listing = backlog(600, 0.95);
  const failed = new Set();
  const world = {
    listing: () => listing,
    detail: (id, count) => {
      if (count % 100 !== 0 || failed.has(id)) return undefined;
      failed.add(id);
      return failing(503);
    },
  };
  const first = {};
  const one = await collectSources(inventory(), sources, {}, service(first, world), NOW, []);
  assert.equal(first.read.length, 594);
  assert.equal(one.checkpoints.cve_now, iso(NOW), 'the checkpoint is set on the first poll');
  assert.equal(JSON.parse(one.checkpoints['cve_now:owed']).length, 6);
  // The next poll asks for the six, and for nothing it has already read.
  const later = NOW + 30 * 60_000;
  const second = {};
  const two = await collectSources(
    inventory(),
    sources,
    one.checkpoints,
    service(second, world, later),
    later,
    [],
  );
  // Besides those, only the records of the checkpoint's one-hour overlap are asked for again.
  for (const id of failed) assert.ok(second.details.includes(id), id);
  assert.ok(second.details.length <= failed.size + 40, `${second.details.length} requests`);
  assert.deepEqual(two.errors, []);
});

test('more unread records than are remembered are found again through the listing, and none is lost', async () => {
  // 4,000 records; the service stops answering after 1,000 requests on the first poll only.
  const listing = backlog(4000, 6);
  let limited = true;
  const world = {
    listing: () => listing,
    detail: (_id, count) => (limited && count > 1000 ? failing(429) : undefined),
  };
  const first = {};
  const start = { cve_now: iso(NOW - 6 * DAY - HOUR) };
  const one = await collectSources(inventory(), sources, start, service(first, world), NOW, []);
  const owed = JSON.parse(one.checkpoints['cve_now:owed']);
  assert.equal(owed.length, 2000, 'the oldest unread records are remembered');
  assert.match(one.errors[0].message, /1000 more new record\(s\) are left for the next poll/);
  // The checkpoint stops just before the first record that is not remembered.
  assert.ok(Date.parse(one.checkpoints.cve_now) < NOW - DAY);
  limited = false;
  const later = NOW + 30 * 60_000;
  const second = {};
  const two = await collectSources(
    inventory(),
    sources,
    one.checkpoints,
    service(second, world, later),
    later,
    [],
  );
  const all = new Set([...first.read, ...second.read]);
  assert.equal(all.size, 4000);
  assert.ok(first.read.length + second.read.length <= 4000 + 40, 'and almost none of them twice');
  assert.deepEqual(two.errors, []);
});

test('owed records that a full poll has no room to ask for stay owed', async () => {
  const owed = ['CVE-2026-71001', 'CVE-2026-71002', 'CVE-2026-71003'].map((id) => [
    id,
    NOW - 2 * HOUR,
    NOW - 3 * HOUR,
  ]);
  const listing = backlog(6000, 9);
  const state = {};
  const result = await collectSources(
    inventory(),
    sources,
    { cve_now: iso(NOW - 9 * DAY - HOUR), 'cve_now:owed': JSON.stringify(owed) },
    service(state, { listing: () => listing }),
    NOW,
    [],
  );
  assert.equal(state.details.length, 5000);
  const kept = JSON.parse(result.checkpoints['cve_now:owed']).map(([id]) => id);
  for (const [id] of owed)
    assert.ok(state.details.includes(id) || kept.includes(id), `${id} is asked for or kept`);
});

test('a first-failure time ahead of the clock does not keep a record owed for ever', async () => {
  const id = 'CVE-2026-72001';
  const result = await collectSources(
    inventory(),
    sources,
    { cve_now: iso(NOW - HOUR), 'cve_now:owed': JSON.stringify([[id, NOW + 30 * DAY, NOW - 2 * HOUR]]) },
    service({}, { detail: (wanted) => (wanted === id ? failing(404) : undefined) }),
    NOW + 26 * HOUR,
    [],
  );
  // The time is taken as "now" when it was read: a day later the record is given up on.
  const next = await collectSources(
    inventory(),
    sources,
    result.checkpoints,
    service({}, { detail: (wanted) => (wanted === id ? failing(404) : undefined) }),
    NOW + 52 * HOUR,
    [],
  );
  assert.match(next.errors[0].message, /could not be used and were skipped/);
  assert.equal(next.checkpoints['cve_now:owed'], '[]');
});

// ---- Package results --------------------------------------------------------------------------------

test('a failed request for a record kept for a keyword does not touch the package results', async () => {
  const inv = inventory({ products: [{ name: 'nginx', version: '1.25.0', keywords: [] }] });
  const previous = [
    stored('CVE-2026-73001'),
    stored('CVE-2026-73002', { description: 'A flaw in nginx request parsing.', packages: [] }),
  ];
  const state = {};
  const result = await collectSources(
    inv,
    sources,
    { cve_now: iso(NOW - HOUR) },
    service(state, { detail: (id) => (id === 'CVE-2026-73002' ? failing(503) : undefined) }),
    NOW,
    previous,
  );
  assert.deepEqual([...state.details].sort(), ['CVE-2026-73001', 'CVE-2026-73002']);
  assert.match(result.errors[0].message, /1 advisory detail request\(s\) failed/);
  assert.equal(result.coverage[0].status, 'partial');
  // The package record was read; what failed is a record about a product.
  assert.equal(result.coverage[0].package_results, 'complete');
});

test('package records that were never sent leave the package results incomplete, also when other records were read', async () => {
  const tracked = [stored('CVE-2026-74001'), stored('CVE-2026-74002')];
  // Four new records that can be read, then eight that fail; the stored package records failed on
  // the poll before, so they come last and are never reached.
  const listing = [
    ...Array.from({ length: 8 }, (_, index) => ({
      id: `CVE-2026-75${100 + index}`,
      publishedAt: iso(NOW - 10 * 60_000 - index * 1000),
    })),
    ...Array.from({ length: 4 }, (_, index) => ({
      id: `CVE-2026-76${100 + index}`,
      publishedAt: iso(NOW - 20 * 60_000 - index * 1000),
    })),
  ];
  const state = {};
  const result = await collectSources(
    inventory(),
    sources,
    { cve_now: iso(NOW - HOUR), 'cve_now:troubled': JSON.stringify(['CVE-2026-74001', 'CVE-2026-74002']) },
    service(state, {
      listing: () => listing,
      detail: (id) => (id.startsWith('CVE-2026-75') ? failing(503) : undefined),
    }),
    NOW,
    tracked,
  );
  assert.equal(result.evidence.length, 4, 'some records were read');
  assert.ok(!state.details.some((id) => id.startsWith('CVE-2026-74')), 'the package records were not sent');
  assert.equal(result.coverage[0].status, 'partial');
  assert.equal(result.coverage[0].package_results, undefined);
});

test('a stored record that the service now files under another identifier is kept current under both', async () => {
  const old = 'GHSA-aaaa-bbbb-cccc';
  const store = new Store(':memory:');
  store.saveEvidence([stored(old, { aliases: [old] })], {});
  // The same record, now with a CVE identifier and a wider range.
  const detail = () =>
    json(
      record('CVE-2026-77001', {
        aliases: [old],
        modifiedAt: iso(NOW - HOUR),
        affected: [{ ecosystem: 'npm', package: 'alpha', ranges: [{ introduced: '0', fixed: '2.0.0' }] }],
      }),
    );
  for (const hours of [0, 2, 26]) {
    const now = NOW + hours * HOUR;
    const result = await collectSources(
      inventory(),
      sources,
      store.checkpoints(),
      service({}, { detail }, now),
      now,
      store.evidence(),
    );
    assert.deepEqual(result.errors, [], `${hours} h`);
    store.saveEvidence(result.evidence, result.checkpoints);
    const copies = store.evidence().filter((item) => item.source === 'cve_now');
    assert.deepEqual(
      copies.map((item) => item.id).sort(),
      ['cve_now:CVE-2026-77001', `cve_now:${old}`].sort(),
    );
    for (const copy of copies) {
      assert.equal(copy.fetched_at, iso(now), `${hours} h: ${copy.id} is current`);
      assert.equal(copy.packages[0].range, '<2.0.0');
    }
    const findings = assess(inventory(), store.evidence(), sources, now);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].applicability, 'affected', `${hours} h`);
  }
});

// ---- Matching ------------------------------------------------------------------------------------------

const mentioned = (ecosystem, name, text) => packageMentioned(text, { ecosystem, name });

test('an ordinary word next to "packages" or "library" is not the package of that name', () => {
  for (const [ecosystem, name, text] of [
    ['npm', 'which', 'A package named fabrice, which imitates fabric, steals AWS keys.'],
    ['npm', 'which', 'The packages, which deliver a loader, were removed from npm.'],
    ['npm', 'which', 'It declared a dependency called flatmap-stream, which contained the payload.'],
    ['npm', 'which', 'The Python package certifi, which ships the trust store, removed the root.'],
    ['npm', 'three', 'Researchers at Socket found three packages that typosquat popular libraries.'],
    ['npm', 'six', 'The actor published six npm packages over two days.'],
    ['npm', 'buffer', 'A heap-based buffer overflow in the syslog function of the GNU C Library gives root.'],
    ['npm', 'buffer', 'The heap buffer overflow in the libwebp library is exploited in the wild.'],
    ['npm', 'request', 'ws WebSocket Library Lets One Request Crash the Server'],
    ['npm', 'request', 'The npm package ejs passes options from the request to the template compiler.'],
    ['npm', 'accepts', 'The JavaScript cryptography library accepts malformed signatures.'],
    ['npm', 'long', 'The semver package takes a long time to parse crafted ranges.'],
    ['npm', 'malicious', 'Malicious npm packages posing as SDKs steal keys.'],
    ['npm', 'popular', 'The attacker targeted popular npm packages with millions of downloads.'],
    ['npm', 'send', 'The stealer uses the package manager to install tools and send data out.'],
  ])
    assert.equal(mentioned(ecosystem, name, text), false, `${name}: ${text}`);
});

test('a word is the package when the text names it as one', () => {
  for (const [ecosystem, name, text] of [
    ['npm', 'request', 'The request package has been deprecated since 2020.'],
    ['npm', 'request', 'The "request" npm package has been deprecated since 2020.'],
    ['PyPI', 'requests', 'Maintainers of the requests library fixed a credential leak.'],
    ['npm', 'next', 'The npm package next is affected by a cache poisoning bug.'],
    ['npm', 'which', 'A dependency called which was republished with a backdoor.'],
    ['npm', 'once', 'A package named once was hijacked.'],
    ['npm', 'send', 'Run npm install send@latest to get the fix.'],
    ['npm', 'send', 'Run npm install --save send to get the fix.'],
    ['PyPI', 'requests', 'Run pip install requests to get the fix.'],
    ['npm', 'debug', 'The advisory lists npm:debug among the affected packages.'],
    // A registry, the kind in the plural, and a short list.
    ['npm', 'chalk', 'Chalk and Debug npm Packages Hijacked in Phishing Attack on Maintainer'],
    ['npm', 'debug', 'Chalk and Debug npm Packages Hijacked in Phishing Attack on Maintainer'],
    [
      'npm',
      'colors',
      'Developer sabotages his own npm libraries colors and faker, breaking thousands of apps',
    ],
    ['npm', 'colors', 'The npm packages chalk, colors and debug were republished.'],
    // The language, what the software is, the name with a capital.
    [
      'PyPI',
      'tornado',
      'The multipart parser of the Python framework Tornado logs a warning for every part.',
    ],
    ['PyPI', 'black', 'A crafted file makes the Python formatter Black spend minutes in one expression.'],
    ['RubyGems', 'rack', 'The Ruby web server interface library Rack reads files outside the root.'],
  ])
    assert.equal(mentioned(ecosystem, name, text), true, `${name}: ${text}`);
  // The language alone, or the name in lower case after it, is not enough.
  assert.equal(mentioned('PyPI', 'black', 'The Python tool black lists every file it changes.'), false);
  assert.equal(mentioned('PyPI', 'requests', 'The Python backdoor sends requests to its C2.'), false);
});

test('a story about a flaw in a C library does not become a finding for an npm package named like a word in it', () => {
  const inv = inventory({
    components: ['buffer', 'which', 'three', 'request'].map((name) => ({
      id: `c:${name}`,
      ecosystem: 'npm',
      name,
      version: '1.0.0',
    })),
  });
  const story = {
    id: 'feed:x:entry:7',
    source: 'feed:x',
    kind: 'news',
    title: 'Critical WebP flaw exploited in the wild',
    url: 'https://example.com/webp',
    description:
      'The heap buffer overflow in the libwebp library, tracked as CVE-2023-5129, is exploited in the wild. Researchers found three packages that bundle the vulnerable code, which a single request with a crafted image can trigger.',
    aliases: ['CVE-2023-5129'],
    severity: 'unknown',
    modified_at: iso(NOW),
    fetched_at: iso(NOW),
    packages: [],
    content_status: 'full',
  };
  const advisory = stored('CVE-2023-5129', {
    description: 'Heap buffer overflow in libwebp.',
    packages: [],
    exploited: true,
    fetched_at: iso(NOW),
  });
  assert.equal(inventoryMatcher(inv).packageNamed(`${story.title}\n${story.description}`), false);
  assert.deepEqual(assess(inv, [story, advisory], sources, NOW), []);
});
