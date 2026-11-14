// Regressions from the third review: one record must never hold the cve.now checkpoint for ever, a
// stored record the service stops serving must not turn into a silent alert, long downtime must
// recover, single-line cleaning must be linear, and a quantity or a verb is not a package release.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig } from '../dist/config.js';
import { runScan } from '../dist/engine.js';
import { loadInventory } from '../dist/inventory.js';
import { inventoryMatcher, packageMentioned } from '../dist/matching.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';
import { singleLine } from '../dist/util.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const config = {
  news_lookback_minutes: 40,
  poll_interval_minutes: 30,
  inventory_stale_days: 30,
  policy: {},
  sources: {
    cve_now: true,
    hacker_news: false,
    osv: false,
    github: false,
    github_token_env: 'THIRD_REVIEW_UNUSED',
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
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });
const record = (id) => ({
  id,
  status: 'published',
  title: id,
  originalDescription: 'unchanged',
  publishedAt: iso(NOW - 10 * DAY),
  modifiedAt: iso(NOW - 10 * DAY),
});
/** A stub of the service: a listing served 100 per page, and a detail record for every identifier. */
const service =
  (state, listing = [], detail = () => undefined) =>
  async (url) => {
    const { pathname, searchParams } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries') {
      state.pages = (state.pages ?? 0) + 1;
      const offset = Number(searchParams.get('cursor') ?? 0);
      return json({
        entries: listing.slice(offset, offset + 100),
        ...(offset + 100 < listing.length ? { next_cursor: String(offset + 100) } : {}),
      });
    }
    const id = decodeURIComponent(pathname.split('/').pop());
    (state.details ??= []).push(id);
    return detail(id) ?? json(record(id));
  };
const checkpoint = { cve_now: iso(NOW - 30 * 60_000) };
const poll = (listing, detail, now, state = {}, checkpoints = checkpoint, previous = [], inv = inventory()) =>
  collectSources(inv, config, checkpoints, service(state, listing, detail), now, previous);
const listedAt = (id, age) => ({ id, publishedAt: iso(NOW - age) });

test('a listing entry that cannot be read holds the checkpoint for a day, not for ever', async () => {
  // Refused outright: the identifier is not one. Its place is next to the record listed before it.
  const listing = [listedAt('CVE-2026-81001', 5 * 60_000), { id: 'X1', publishedAt: iso(NOW - 600_000) }];
  const young = await poll(listing, undefined, NOW);
  assert.match(young.errors[0].message, /1 invalid item\(s\) were skipped/);
  assert.match(young.errors[0].message, /checkpoint was not advanced/);
  assert.equal(young.checkpoints.cve_now, checkpoint.cve_now);
  assert.equal(young.evidence.length, 1, 'the readable record is kept');
  // A day of polls later the entry is still there. It is reported once more and passed over.
  const later = NOW + 25 * HOUR;
  const aged = await poll(listing, undefined, later);
  assert.match(aged.errors[0].message, /1 invalid item\(s\) were skipped/);
  assert.doesNotMatch(aged.errors[0].message, /checkpoint was not advanced/);
  assert.equal(aged.coverage[0].status, 'partial');
  assert.equal(aged.checkpoints.cve_now, iso(later));
  // With the checkpoint past it, the entry is no longer in the window and the source is complete.
  const after = await poll(listing, undefined, later + 2 * HOUR, {}, aged.checkpoints);
  assert.deepEqual(after.errors, []);
  assert.equal(after.coverage[0].status, 'complete');
});

test('a listed record whose detail is refused for good is passed over after a day', async () => {
  const listing = [listedAt('CVE-2026-81002', 5 * 60_000), listedAt('CVE-2026-81003', 600_000)];
  const gone = (id) => (id === 'CVE-2026-81003' ? { status: 404, headers: {}, body: '' } : undefined);
  const young = await poll(listing, gone, NOW);
  assert.match(young.errors[0].message, /1 advisory detail request\(s\) failed.*HTTP 404/);
  assert.equal(young.checkpoints.cve_now, checkpoint.cve_now);
  const later = NOW + 25 * HOUR;
  const aged = await poll(listing, gone, later);
  assert.match(aged.errors[0].message, /1 advisory record\(s\) could not be used and were skipped.*HTTP 404/);
  assert.equal(aged.checkpoints.cve_now, iso(later));
});

test('a listed record that keeps failing with HTTP 503 is held for three days, then passed over', async () => {
  const listing = [listedAt('CVE-2026-81004', 5 * 60_000), listedAt('CVE-2026-81005', 600_000)];
  const failing = (id) => (id === 'CVE-2026-81005' ? { status: 503, headers: {}, body: '' } : undefined);
  for (const hours of [0, 25, 71]) {
    const result = await poll(listing, failing, NOW + hours * HOUR);
    assert.match(result.errors[0].message, /1 advisory detail request\(s\) failed/, `${hours} h`);
    assert.equal(result.checkpoints.cve_now, checkpoint.cve_now, `${hours} h`);
  }
  const later = NOW + 73 * HOUR;
  const aged = await poll(listing, failing, later);
  assert.match(aged.errors[0].message, /could not be used and were skipped.*HTTP 503/);
  assert.equal(aged.checkpoints.cve_now, iso(later));
});

test('nothing is given up on while the service is failing every request', async () => {
  // Five old listed records, all answering 503: an outage, not five bad records.
  const listing = Array.from({ length: 5 }, (_, index) => listedAt(`CVE-2026-8200${index}`, 600_000 + index));
  const down = () => ({ status: 503, headers: {}, body: '' });
  const state = {};
  const result = await poll(listing, down, NOW + 80 * HOUR, state);
  assert.equal(state.details.length, 4, 'the first failed batch stops the requests');
  assert.match(result.errors[0].message, /advisory detail request\(s\) failed/);
  assert.doesNotMatch(result.errors[0].message, /were skipped/);
  assert.equal(result.checkpoints.cve_now, checkpoint.cve_now);
});

test('a record stamped ahead of the clock with an unusable detail does not hold the checkpoint for ever', async () => {
  const listing = [
    { id: 'CVE-2026-81006', publishedAt: iso(NOW + 30 * DAY), firstSeenAt: iso(NOW - 600_000) },
    listedAt('CVE-2026-81007', 5 * 60_000),
  ];
  const reserved = (id) =>
    id === 'CVE-2026-81006' ? json({ id, status: 'reserved', title: id }) : undefined;
  const young = await poll(listing, reserved, NOW);
  assert.equal(young.checkpoints.cve_now, checkpoint.cve_now);
  const later = NOW + 25 * HOUR;
  const aged = await poll(listing, reserved, later);
  assert.match(aged.errors[0].message, /could not be used and were skipped/);
  assert.equal(aged.checkpoints.cve_now, iso(later));
});

test('four adjacent unusable new records do not stop the records after them from being read', async () => {
  const listing = [
    ...Array.from({ length: 40 }, (_, index) => listedAt(`CVE-2026-830${10 + index}`, 60_000 + index * 1000)),
    ...Array.from({ length: 4 }, (_, index) => listedAt(`CVE-2026-8400${index}`, 20 * 60_000 + index * 1000)),
  ];
  const reserved = (id) =>
    id.startsWith('CVE-2026-8400') ? json({ id, status: 'reserved', title: id }) : undefined;
  const state = {};
  const result = await poll(listing, reserved, NOW, state);
  assert.equal(state.details.length, 44);
  assert.equal(result.evidence.length, 40, 'every ordinary record is read on the same poll');
  assert.match(result.errors[0].message, /4 advisory detail request\(s\) failed/);
});

// A record about an inventory package that is gone keeps its last content. So does a record kept
// for a declared keyword when the service serves it in a form that cannot be used.
for (const [name, answer, packages, inv] of [
  [
    'no longer serves',
    () => ({ status: 404, headers: {}, body: '' }),
    [{ ecosystem: 'npm', name: 'alpha', range: '<0.9.0' }],
    inventory(),
  ],
  [
    'serves in a form that cannot be used, and that is not about an inventory package,',
    (id) => json({ id, status: 'reserved', title: id }),
    [],
    inventory({ keywords: ['alpha flaw'] }),
  ],
])
  test(`a stored record the service ${name} keeps its last content and stays current`, async () => {
    const id = 'CVE-2026-85000';
    const kept = {
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
      packages,
    };
    const state = {};
    const result = await poll(
      [],
      (wanted) => (wanted === id ? answer(wanted) : undefined),
      NOW,
      state,
      checkpoint,
      [kept],
      inv,
    );
    assert.deepEqual(state.details, [id], 'the service was asked');
    assert.deepEqual(result.errors, []);
    assert.equal(result.coverage[0].status, 'complete');
    const current = result.evidence.find((item) => item.id === kept.id);
    // Checked now: a result that rests on this record must not drift to "unknown" as stale evidence,
    // and the record must not stay first in the refresh order on every later poll.
    assert.equal(current.fetched_at, iso(NOW));
    assert.deepEqual(current.packages, kept.packages);
    assert.equal(current.modified_at, kept.modified_at);
  });

test('a stored record about an inventory package that is served in an unusable form is reported', async () => {
  // The service still has the record but in a status this application does not know. Its ranges
  // may have changed, so the stored ones must not go on counting as current.
  const id = 'CVE-2026-85002';
  const kept = {
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
  };
  const other = listedAt('CVE-2026-85003', 5 * 60_000);
  const result = await poll(
    [other],
    (wanted) => (wanted === id ? json({ id, status: 'superseded', title: id }) : undefined),
    NOW,
    {},
    checkpoint,
    [kept],
  );
  assert.match(
    result.errors[0].message,
    /1 advisory detail request\(s\) failed.*unsupported advisory status/,
  );
  assert.equal(result.coverage[0].status, 'partial');
  assert.equal(
    result.coverage[0].package_results,
    undefined,
    'exclusions from this source are not supported',
  );
  assert.equal(
    result.evidence.find((item) => item.id === kept.id),
    undefined,
    'no refreshed copy is made up',
  );
  // It does not hold the checkpoint: it was not found through the listing.
  assert.equal(result.checkpoints.cve_now, iso(NOW));
});

test('a stored record that fails with a server error is still reported', async () => {
  const id = 'CVE-2026-85001';
  const kept = {
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
  };
  const result = await poll([], () => ({ status: 503, headers: {}, body: '' }), NOW, {}, checkpoint, [kept]);
  assert.match(result.errors[0].message, /1 advisory detail request\(s\) failed.*HTTP 503/);
  assert.notEqual(result.coverage[0].status, 'complete');
  assert.equal(
    result.evidence.find((item) => item.id === kept.id),
    undefined,
    'no refreshed copy is made up',
  );
});

test('a record without a publication date does not end paging early', async () => {
  // 250 recent records over three pages; the last entry of page one has no publication date and an
  // old first-seen time. A late arrival sits on page three.
  const recent = Array.from({ length: 250 }, (_, index) =>
    listedAt(`CVE-2026-${90000 - index}`, 60_000 + index * 5000),
  );
  recent[99] = { id: 'CVE-2026-70010', publishedAt: null, firstSeenAt: iso(NOW - 9 * DAY) };
  recent.push({ id: 'CVE-2026-70011', publishedAt: iso(NOW - 3 * DAY), firstSeenAt: iso(NOW - 10 * 60_000) });
  const state = {};
  const result = await poll(recent, undefined, NOW, state);
  assert.equal(state.pages, 3);
  assert.ok(state.details.includes('CVE-2026-70011'), 'the late arrival on the last page is read');
  assert.deepEqual(result.errors, []);
});

test('a listing of first-seen times only still stops at the horizon', async () => {
  const old = Array.from({ length: 300 }, (_, index) => ({
    id: `CVE-2026-${60000 + index}`,
    firstSeenAt: iso(NOW - 8 * DAY - index * 60_000),
  }));
  const state = {};
  const result = await poll(
    [{ id: 'CVE-2026-70020', firstSeenAt: iso(NOW - 60_000) }, ...old],
    undefined,
    NOW,
    state,
  );
  assert.equal(state.pages, 1);
  assert.deepEqual(state.details, ['CVE-2026-70020']);
  assert.deepEqual(result.errors, []);
});

test('a checkpoint older than one poll can page through is reported and recovers, instead of failing for ever', async () => {
  // 60,500 records since a checkpoint 120 days back: more than 600 pages of 100.
  const total = 60_500;
  const span = 119 * DAY;
  const listing = Array.from({ length: total }, (_, index) =>
    listedAt(`CVE-2026-${200000 - index}`, 60_000 + Math.floor((index * span) / total)),
  );
  let checkpoints = { cve_now: iso(NOW - 120 * DAY) };
  const first = {};
  const one = await poll(listing, undefined, NOW, first, checkpoints);
  assert.equal(first.pages, 600);
  assert.equal(first.details.length, 5000);
  assert.equal(one.coverage[0].status, 'partial');
  assert.match(
    one.errors[0].message,
    /more records since the last complete poll than one poll pages through/,
  );
  assert.match(
    one.errors[0].message,
    /records published before \d{4}-\d\d-\d\dT[\d:.]+Z and after the last checkpoint were not read/,
  );
  assert.ok(Date.parse(one.checkpoints.cve_now) > Date.parse(checkpoints.cve_now), 'the checkpoint moves');
  // Later polls work through the rest, oldest first, and reach the newest record.
  let polls = 1;
  let newest = false;
  let now = NOW;
  checkpoints = one.checkpoints;
  while (!newest && polls < 20) {
    now += 30 * 60_000;
    const state = {};
    const next = await poll(listing, undefined, now, state, checkpoints);
    assert.ok(
      Date.parse(next.checkpoints.cve_now) > Date.parse(checkpoints.cve_now),
      `poll ${polls} moves on`,
    );
    checkpoints = next.checkpoints;
    newest = (state.details ?? []).includes('CVE-2026-200000');
    polls++;
  }
  assert.ok(newest, `the newest record is read after ${polls} polls`);
});

test('single-line cleaning takes time proportional to the input', () => {
  const lf = String.fromCharCode(10);
  const ls = String.fromCharCode(0x2028);
  const started = Date.now();
  assert.equal(singleLine(`2.0.0${' '.repeat(4_000_000)}x`, 100), '2.0.0');
  assert.equal(singleLine(`2.0.0${` ${lf}`.repeat(2_000_000)}x`, 100), '2.0.0 x');
  assert.equal(singleLine(`${' '.repeat(4_000_000)}${lf}`, 100), '');
  assert.equal(singleLine(`a${' '.repeat(4_000_000)}${ls}b`, 100), 'a b');
  // The earlier pattern needed minutes for each of these. Seconds would already mean a regression.
  assert.ok(Date.now() - started < 3000, `took ${Date.now() - started} ms`);
});

test('single-line cleaning joins every run of separators and the spaces around it into one space', () => {
  const c = String.fromCharCode;
  assert.equal(singleLine(`a ${c(10)} ${c(0x2028)}  b`), 'a b');
  assert.equal(singleLine(`a${c(0x85)} ${c(13)}${c(10)}b`), 'a b');
  assert.equal(singleLine(`${c(10)} a  b ${c(9)}`), 'a  b');
  assert.equal(singleLine(`ab ${c(10)} cd`, 3), 'ab');
  assert.equal(singleLine(`ab${c(10)}cd`, 4), 'ab c');
  assert.equal(singleLine('plain  text  '), 'plain  text');
  assert.equal(singleLine(''), '');
});

const mentioned = (ecosystem, name, text) => packageMentioned(text, { ecosystem, name });

test('a quantity after an everyday word is not a release of the package with that name', () => {
  for (const [ecosystem, name, text] of [
    ['npm', 'send', 'Botnet can send 1.5 million requests per second, CVE-2026-11111 exploited in routers'],
    ['npm', 'request', 'Attackers stole request 2.5 million customer records via CVE-2026-11111'],
    [
      'npm',
      'next',
      'Ransomware payments to reach $265 billion over the next 5.5 years; CVE-2026-11111 abused',
    ],
    ['npm', 'next', 'Patch within the next 15.5 hours, agency says of CVE-2026-11111'],
    ['PyPI', 'requests', 'Flood of requests 3.5 times larger than the last record hits CDN (CVE-2026-11111)'],
    ['npm', 'debug', 'Vendor ships debug 2.0 firmware build with hardcoded password CVE-2026-11111'],
  ])
    assert.equal(mentioned(ecosystem, name, text), false, text);
  for (const [ecosystem, name, text] of [
    ['npm', 'send', 'send@0.19.0 fixes a template injection (CVE-2026-11111)'],
    ['npm', 'debug', 'Malicious debug v4.4 was live for two hours (CVE-2026-11111)'],
    ['PyPI', 'requests', 'Requests 2.32.0 fixes a credential leak (CVE-2026-11111)'],
    ['npm', 'next', 'Next.js 15 middleware bypass CVE-2026-11111'],
    ['npm', 'request', 'The request package is deprecated and affected by CVE-2026-11111'],
  ])
    assert.equal(mentioned(ecosystem, name, text), true, text);
});

test('software named with an everyday word counts when it is written as a name', () => {
  for (const [ecosystem, name, text] of [
    ['npm', 'express', 'Researchers express concern as Citrix NetScaler flaw CVE-2026-11111 is exploited'],
    [
      'npm',
      'express',
      'Fortinet warns of FortiOS flaw CVE-2026-11111; customers express 10.0 severity concern',
    ],
    ['npm', 'express', 'Researchers Express Concern Over Citrix NetScaler Flaw CVE-2026-11111'],
    ['npm', 'react', 'Vendors react slowly to CVE-2026-11111 in edge routers'],
    ['PyPI', 'flask', 'Whisky flask maker breached through CVE-2026-11111'],
    ['RubyGems', 'rails', 'Attack derails metro: signalling on the rails stopped by CVE-2026-11111'],
    ['npm', 'figures', 'New figures show CVE-2026-11111 exploited at 400 companies'],
    ['npm', 'async', 'An async callback race in a router kernel, CVE-2026-11111'],
  ])
    assert.equal(mentioned(ecosystem, name, text), false, text);
  for (const [ecosystem, name, text] of [
    ['npm', 'express', 'A flaw in Express lets attackers bypass route guards (CVE-2026-11111)'],
    ['npm', 'express', 'Express fixes open redirect CVE-2026-11111 in res.location'],
    ['npm', 'express', 'Express.js open redirect CVE-2026-11111'],
    ['npm', 'react', 'Critical bug in React Server Components, CVE-2026-11111'],
    ['PyPI', 'flask', 'Maintainers of the Flask framework fix CVE-2026-11111'],
    ['RubyGems', 'rails', 'Rails releases patches for Active Storage flaw CVE-2026-11111'],
    ['RubyGems', 'rails', 'Ruby on Rails deserialisation bug CVE-2026-11111'],
  ])
    assert.equal(mentioned(ecosystem, name, text), true, text);
});

test('the inventory matcher applies the same rules as the single-name check', () => {
  const inv = inventory({
    components: ['express', 'send', 'next', 'figures'].map((name) => ({
      id: `c:${name}`,
      ecosystem: 'npm',
      name,
      version: '1.0.0',
    })),
  });
  const { packageNamed } = inventoryMatcher(inv);
  assert.equal(packageNamed('Researchers express concern as botnets send 1.5 million requests'), false);
  assert.equal(packageNamed('New figures for the next 5.5 years'), false);
  assert.equal(packageNamed('A flaw in Express lets attackers bypass route guards'), true);
  assert.equal(packageNamed('send@0.19.0 fixes a template injection'), true);
});

test('a capitalised npm name is a notice: the scan is not degraded and nothing is queued', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'sw-names-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  writeFileSync(
    join(directory, 'systems.json'),
    JSON.stringify({
      systems: [
        {
          id: 'api',
          name: 'API',
          updated_at: iso(NOW),
          libraries: [
            'npm:MD5@1.3.0',
            'npm:CSSselect@0.4.1',
            'npm:Base64@1.0.0',
            'npm:JSONStream@1.3.5',
            'npm:JSONPath@0.11.2',
            'npm:JSONSelect@0.4.0',
          ],
        },
      ],
    }),
  );
  const loaded = loadInventory(join(directory, 'systems.json'));
  assert.equal(loaded.import_warnings, undefined);
  // The four names known to be published with capitals are not mentioned at all.
  assert.equal(loaded.name_notices.length, 2);
  assert.match(loaded.name_notices.join(' '), /MD5/);
  assert.match(loaded.name_notices.join(' '), /CSSselect/);
  const store = new Store(':memory:');
  const report = await runScan({
    config: parseConfig({
      version: 1,
      sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
    }),
    inventory: loaded,
    store,
    http: async () => {
      throw new Error('no request is expected');
    },
    now: NOW,
    // Evidence supplied directly: no source is contacted, and none is reported as disabled.
    fixture: [],
  });
  assert.equal(report.degraded, false);
  assert.deepEqual(report.errors, []);
  assert.equal(report.notices.filter((notice) => /contains capital letters/.test(notice)).length, 2);
  assert.equal(report.findings.filter((finding) => finding.category === 'health').length, 0);
  assert.equal(store.jobs().length, 0);
});
