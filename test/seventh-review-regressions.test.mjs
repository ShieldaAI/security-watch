// Regressions from the seventh review: a failed package lookup, exclusions that flipped on any gap
// in a source, list rules that took any five words, and hyphenated English names.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig } from '../dist/config.js';
import { runScan } from '../dist/engine.js';
import { dictionaryName } from '../dist/everyday-words.js';
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
    github_token_env: 'SEVENTH_REVIEW_UNUSED',
    kev: false,
    feeds: [],
  },
};
const components = (names) =>
  names.map((name) => ({ id: `c:${name}`, ecosystem: 'npm', name, version: '1.0.0' }));
const inventory = (names = ['alpha']) => ({
  systems: [
    {
      id: 'prod',
      name: 'Production',
      environment: 'production',
      exposure: 'internet',
      criticality: 'critical',
      updated_at: iso(NOW),
      products: [],
      keywords: [],
      components: components(names),
    },
  ],
});

// ---- The package lookup ----------------------------------------------------------------------------

test('one failed package lookup is reported, and the rest of the poll goes on', async () => {
  const names = Array.from({ length: 12 }, (_, index) => `pkg${index}`);
  const state = { lookups: 0, details: [] };
  const http = async (url) => {
    const { pathname, searchParams } = new URL(url);
    if (pathname === '/stack') {
      state.lookups++;
      return searchParams.get('p') === 'npm:pkg3@1.0.0' ? failing(500) : json({ packages: 1, entries: [] });
    }
    if (pathname === '/api/v1/entries')
      return json({ entries: [{ id: 'CVE-2026-80001', publishedAt: iso(NOW - 600_000) }] });
    const id = decodeURIComponent(pathname.split('/').pop());
    state.details.push(id);
    return json({
      id,
      status: 'published',
      title: id,
      originalDescription: 'x',
      publishedAt: iso(NOW - 600_000),
      modifiedAt: iso(NOW - 600_000),
    });
  };
  const result = await collectSources(inventory(names), sources, { cve_now: iso(NOW - HOUR) }, http, NOW, []);
  assert.equal(state.lookups, 12, 'every package is looked up');
  assert.deepEqual(state.details, ['CVE-2026-80001'], 'the listing and the records are read');
  assert.equal(result.evidence.length, 1);
  assert.match(result.errors[0].message, /1 package lookup request\(s\) failed or were not sent/);
  assert.equal(result.coverage[0].status, 'partial');
  assert.equal(result.coverage[0].package_results, undefined);
  assert.equal(result.checkpoints.cve_now, iso(NOW), 'a lookup does not hold the checkpoint');
});

test('repeated lookup failures end the lookups for that poll, but not the poll', async () => {
  const names = Array.from({ length: 40 }, (_, index) => `pkg${index}`);
  let lookups = 0;
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack') {
      lookups++;
      return failing(503);
    }
    if (pathname === '/api/v1/entries') return json({ entries: [] });
    return failing(404);
  };
  const result = await collectSources(inventory(names), sources, { cve_now: iso(NOW - HOUR) }, http, NOW, []);
  assert.equal(lookups, 4, 'the first batch that fails entirely stops the lookups');
  assert.match(result.errors[0].message, /40 package lookup request\(s\) failed or were not sent/);
  assert.equal(result.checkpoints.cve_now, iso(NOW));
});

// ---- Exclusions ------------------------------------------------------------------------------------

process.env.SEVENTH_HOOK = 'https://hooks.slack.com/services/T/B/x';
const scanConfig = parseConfig({
  version: 1,
  poll_interval_minutes: 30,
  sources: { cve_now: true, hacker_news: false, osv: false, github: false, kev: false },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'SEVENTH_HOOK' } },
});
const record = (id, name, fixed) => ({
  id,
  status: 'published',
  title: `${name} flaw`,
  originalDescription: `A flaw in ${name}.`,
  severity: { cvss: 9.8 },
  affected: [{ ecosystem: 'npm', package: name, ranges: [{ introduced: '0', fixed }] }],
  publishedAt: iso(NOW - 2 * DAY),
  modifiedAt: iso(NOW - 2 * DAY),
});

test('single transient failures do not flip exclusions or send alerts', async () => {
  const store = new Store(':memory:');
  const inv = {
    systems: [
      {
        ...inventory().systems[0],
        components: components(['alpha', 'beta']).map((c) => ({ ...c, version: '2.0.0' })),
      },
    ],
  };
  const records = {
    'CVE-2026-81001': record('CVE-2026-81001', 'alpha', '1.5.0'),
    'CVE-2026-81002': record('CVE-2026-81002', 'beta', '1.5.0'),
  };
  // Seven polls; on three of them one request fails once: a detail, a lookup, a detail.
  const failures = { 1: 'detail:CVE-2026-81001', 3: 'lookup:beta', 5: 'detail:CVE-2026-81002' };
  for (let poll = 0; poll < 7; poll++) {
    const now = NOW + poll * 30 * 60_000;
    const http = async (url) => {
      const { pathname, searchParams } = new URL(url);
      if (pathname === '/stack') {
        const name = searchParams.get('p').slice(4).split('@')[0];
        if (failures[poll] === `lookup:${name}`) return failing(503);
        // The lookup names only advisories that affect the installed version: none here.
        return json({ items: [] });
      }
      // Both advisories are new on the first poll; later they are stored and re-read each poll.
      if (pathname === '/api/v1/entries')
        return json({
          entries:
            poll === 0 ? Object.keys(records).map((id) => ({ id, publishedAt: iso(now - 600_000) })) : [],
        });
      const id = decodeURIComponent(pathname.split('/').pop());
      if (failures[poll] === `detail:${id}`) return failing(503);
      return json(records[id]);
    };
    await runScan({ config: scanConfig, inventory: inv, store, now, http });
    const library = store.findings().filter((finding) => finding.category === 'library');
    assert.equal(library.length, 2, `poll ${poll}`);
    for (const finding of library)
      assert.equal(finding.applicability, 'not_affected', `poll ${poll}: ${finding.component_id}`);
  }
  for (const finding of store.findings().filter((item) => item.category === 'library'))
    assert.equal(store.history(finding.id).length, 1, 'no new revision');
  assert.deepEqual(
    store
      .jobs()
      .filter((job) => job.finding_id.length && store.getFinding(job.finding_id)?.category === 'library'),
    [],
    'no alert',
  );
});

// ---- Re-read records do not hold the checkpoint --------------------------------------------------

test('a listed record that is already stored is not read again, and is not owed', async () => {
  const id = 'CVE-2026-82001';
  const stored = {
    id: `cve_now:${id}`,
    source: 'cve_now',
    kind: 'advisory',
    title: id,
    url: 'https://cve.now/x',
    description: 'x',
    aliases: [id],
    severity: 'high',
    modified_at: iso(NOW - HOUR),
    fetched_at: iso(NOW - 30 * 60_000),
    packages: [],
  };
  const details = [];
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries')
      return json({ entries: [{ id, publishedAt: iso(NOW - 40 * 60_000) }] });
    details.push(pathname);
    return failing(503);
  };
  const result = await collectSources(inventory(), sources, { cve_now: iso(NOW - 30 * 60_000) }, http, NOW, [
    stored,
  ]);
  // It was read on the poll that listed it first; the checkpoint's overlap does not spend a request.
  assert.deepEqual(details, []);
  assert.deepEqual(result.errors, []);
  assert.equal(result.checkpoints.cve_now, iso(NOW), 'the checkpoint is not held');
  assert.equal(result.checkpoints['cve_now:owed'], '[]');
});

// ---- Matching ------------------------------------------------------------------------------------------

const mentioned = (name, text) => packageMentioned(text, { ecosystem: 'npm', name });

test('one word after "npm packages" is not a list of package names', () => {
  for (const [name, text] of [
    ['send', 'Researchers found malicious npm packages that send stolen tokens to Telegram.'],
    ['which', 'The malicious npm packages which steal wallets were removed.'],
    ['open', 'The npm packages that open a reverse shell were downloaded 3,000 times.'],
    ['once', 'The npm packages that once worked were taken over.'],
    ['process', 'The npm packages designed to process images were trojanized.'],
    ['ignore', 'The npm packages that ignore lockfiles were abused.'],
    ['once', 'Once the malicious npm packages are installed, they run a script.'],
    ['send', 'The maintainer did not send malicious npm packages to the registry.'],
  ])
    assert.equal(mentioned(name, text), false, `${name}: ${text}`);
  for (const [name, text] of [
    ['chalk', 'Chalk and Debug npm Packages Hijacked in Phishing Attack'],
    ['debug', 'Chalk and Debug npm Packages Hijacked in Phishing Attack'],
    ['colors', 'The maintainer sabotaged the npm libraries colors and faker.'],
    ['colors', 'The npm packages chalk, colors and debug were republished.'],
    ['debug', 'The npm packages chalk, colors and debug were republished.'],
    ['chalk', 'The npm packages chalk, colors and debug were republished.'],
  ])
    assert.equal(mentioned(name, text), true, `${name}: ${text}`);
});

test('a compound that prose writes with a hyphen needs the same context as an English word', () => {
  for (const name of [
    'one-time',
    'stack-trace',
    'content-disposition',
    'side-channel',
    'set-cookie',
    'websockets',
  ])
    assert.equal(dictionaryName(name), true, name);
  // A library's compound is hardly ever prose: it is the package wherever it is written.
  for (const name of [
    'lodash-es',
    'left-pad',
    'body-parser',
    'tough-cookie',
    'cross-spawn',
    'node-fetch',
    'socket.io',
    '@acme/sdk',
  ])
    assert.equal(dictionaryName(name), false, name);
  for (const [name, text] of [
    ['one-time', 'Attackers abuse one-time links in a Chrome zero-day campaign.'],
    ['one-time', 'Enter the one-time password sent by SMS.'],
    ['stack-trace', 'The appliance leaks a stack-trace with internal paths.'],
    ['content-disposition', 'A crafted Content-Disposition header bypasses the filter.'],
  ])
    assert.equal(mentioned(name, text), false, `${name}: ${text}`);
  for (const [name, text] of [
    ['one-time', 'The one-time package, a dependency of winston, was hijacked.'],
    ['left-pad', 'Attackers abuse left-pad in the wild.'],
    ['body-parser', 'body-parser denial of service when URL encoding is enabled'],
    ['node-fetch', 'node-fetch forwards secure headers to untrusted sites'],
    ['lodash-es', 'Attackers abuse lodash-es in the wild.'],
  ])
    assert.equal(mentioned(name, text), true, `${name}: ${text}`);
});
