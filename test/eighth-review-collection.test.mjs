// Regressions from the eighth review of collection and matching: version ranges read as releases,
// names written after their ecosystem, package lookups that fail, and guards without a test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assess } from '../dist/assessment.js';
import { packageMentioned } from '../dist/matching.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });
const failing = (status) => ({ status, headers: {}, body: '' });
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
    github_token_env: 'EIGHTH_COLLECTION_UNUSED',
    kev: false,
    feeds: [],
  },
};
const inventory = (names = ['alpha']) => ({
  systems: [
    {
      id: 'prod',
      name: 'prod',
      updated_at: iso(NOW),
      products: [],
      keywords: [],
      components: names.map((name) => ({ id: `c:${name}`, ecosystem: 'npm', name, version: '1.0.0' })),
    },
  ],
});
const mentioned = (ecosystem, name, text) => packageMentioned(text, { ecosystem, name });

// ---- Matching ------------------------------------------------------------------------------------------

test('a version range in prose is not a release of a package named like the word before it', () => {
  for (const [name, text] of [
    ['through', 'Fortinet fixed FortiOS versions 7.0.0 through 7.0.16 (CVE-2026-11111).'],
    ['through', 'Next.js 11.1.4 through 15.2.2 are affected by the middleware bypass.'],
    ['from', 'Upgrade from 16.1.0 to 16.1.3 to fix the flaw.'],
    ['after', 'Versions after 3.2.1 are not affected.'],
    ['until', 'The flaw was present until 4.1.2 was released.'],
    ['to', 'Upgrade to 2.4.1 now.'],
    ['through', 'Through 7.0.16 the appliance accepts the crafted request.'],
  ])
    assert.equal(mentioned('npm', name, text), false, `${name}: ${text}`);
  for (const [name, text] of [
    ['through', 'Pin through@2.3.8 in the lockfile.'],
    ['through', 'The through v2.3 stream helper was republished.'],
    ['through', 'The through npm package was republished.'],
  ])
    assert.equal(mentioned('npm', name, text), true, `${name}: ${text}`);
});

test('a library written after its ecosystem is the package', () => {
  assert.equal(mentioned('npm', 'tar', 'node-tar arbitrary file creation flaw fixed in 6.2.1'), true);
  assert.equal(mentioned('PyPI', 'markdown', 'Python-Markdown ReDoS in the footnotes extension'), true);
  // Only for its own ecosystem.
  assert.equal(mentioned('PyPI', 'tar', 'node-tar arbitrary file creation flaw'), false);
});

test('the stop words of the list rule keep connecting words out of a list of names', () => {
  // A comma and "and" are there, but the entries are not names.
  for (const text of [
    'The npm packages that, which and once were installed ran a script.',
    'Researchers found npm packages, which and that once worked.',
  ])
    assert.equal(mentioned('npm', 'once', text), false, text);
});

// ---- Package lookups -----------------------------------------------------------------------------

test('a failed package lookup does not take back what an earlier lookup matched', async () => {
  // The record's npm claim has no usable range: only the lookup says the installed version matches.
  const id = 'CVE-2026-89001';
  const detail = json({
    id,
    status: 'published',
    title: 'alpha flaw',
    originalDescription: 'A flaw in alpha.',
    severity: { cvss: 9.8 },
    affected: [{ ecosystem: 'npm', package: 'alpha' }],
    publishedAt: iso(NOW - 2 * DAY),
    modifiedAt: iso(NOW - 2 * DAY),
  });
  const store = new Store(':memory:');
  let lookupFails = false;
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack')
      return lookupFails
        ? failing(503)
        : json({
            items: [{ id, _cve_now: { matched: { ecosystem: 'npm', name: 'alpha', version: '1.0.0' } } }],
          });
    if (pathname === '/api/v1/entries') return json({ entries: [] });
    return detail;
  };
  const applicability = [];
  for (const [index, fails] of [false, true, false].entries()) {
    lookupFails = fails;
    const now = NOW + index * 30 * 60_000;
    const result = await collectSources(
      inventory(),
      sources,
      store.checkpoints(),
      http,
      now,
      store.evidence(),
    );
    store.saveEvidence(result.evidence, result.checkpoints);
    const [finding] = assess(inventory(), store.evidence(), sources, now);
    applicability.push(finding.applicability);
  }
  assert.deepEqual(applicability, ['affected', 'affected', 'affected']);
});

test('package lookups that keep failing are sent after the others', async () => {
  const names = Array.from({ length: 12 }, (_, index) => `pkg${String(index).padStart(2, '0')}`);
  const broken = new Set(['npm:pkg00@1.0.0', 'npm:pkg01@1.0.0', 'npm:pkg02@1.0.0', 'npm:pkg03@1.0.0']);
  const run = async (checkpoints, now) => {
    const lookups = [];
    const http = async (url) => {
      const { pathname, searchParams } = new URL(url);
      if (pathname === '/stack') {
        lookups.push(searchParams.get('p'));
        return broken.has(searchParams.get('p')) ? failing(500) : json({ packages: 1, entries: [] });
      }
      if (pathname === '/api/v1/entries') return json({ entries: [] });
      return failing(404);
    };
    const result = await collectSources(inventory(names), sources, checkpoints, http, now, []);
    return { result, lookups };
  };
  // The four that fail come first in order and end the lookups at once.
  const first = await run({ cve_now: iso(NOW - HOUR) }, NOW);
  assert.equal(first.lookups.length, 4);
  // Next time they go last: every other package is looked up.
  const second = await run(first.result.checkpoints, NOW + 30 * 60_000);
  assert.equal(second.lookups.length, 12);
  assert.deepEqual(second.lookups.slice(-4).sort(), [...broken].sort());
});

// ---- Guards ----------------------------------------------------------------------------------------

test('a stored record whose request times out (408) is reported, not counted as checked', async () => {
  const id = 'CVE-2026-89101';
  const stored = {
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
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries') return json({ entries: [] });
    return failing(408);
  };
  const result = await collectSources(inventory(), sources, { cve_now: iso(NOW - HOUR) }, http, NOW, [
    stored,
  ]);
  assert.match(result.errors[0].message, /1 advisory detail request\(s\) failed.*HTTP 408/);
  assert.equal(
    result.evidence.find((item) => item.id === stored.id),
    undefined,
    'no fresh copy is made up',
  );
});
