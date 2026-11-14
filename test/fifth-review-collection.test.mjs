// Regressions from the fifth review of collection and matching: text from a feed that fails the
// whole source, records that keep failing, the remembered list of unread records, package context
// that must stand near the name, and the release command's environment.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assess } from '../dist/assessment.js';
import { parseConfig } from '../dist/config.js';
import { runScan } from '../dist/engine.js';
import { inventoryMatcher, packageMentioned } from '../dist/matching.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';
import { releaseEnvironmentProblem, releaseOptions, untrackedPackedFiles } from '../scripts/release-tag.mjs';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });
const sources = (extra = {}) => ({
  news_lookback_minutes: 40,
  poll_interval_minutes: 30,
  inventory_stale_days: 30,
  policy: {},
  sources: {
    cve_now: true,
    hacker_news: false,
    osv: false,
    github: false,
    github_token_env: 'FIFTH_REVIEW_UNUSED',
    kev: false,
    feeds: [],
    ...extra,
  },
});
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
/** A stub of the service. `listing` is a function of the time, so that it can grow between polls. */
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
    return detail(id) ?? json(record(id));
  };
};
const failing = (status) => ({ status, headers: {}, body: '' });
/** Polls at the given hours after NOW, each starting from the state the one before left. */
async function sequence(
  world,
  hours,
  { previous = [], inv = inventory(), start = { cve_now: iso(NOW - 30 * 60_000) } } = {},
) {
  let checkpoints = start;
  const results = [];
  for (const hour of hours) {
    const now = NOW + hour * HOUR;
    const state = {};
    const result = await collectSources(
      inv,
      sources(),
      checkpoints,
      service(state, world, now),
      now,
      previous,
    );
    checkpoints = result.checkpoints;
    results.push({ hour, now, result, asked: state.details ?? [] });
  }
  return results;
}
/** One new record every ten minutes, newest first, as the listing serves them. */
const steady = (now, from = NOW - HOUR) => {
  const entries = [];
  for (let time = from; time <= now; time += 10 * 60_000)
    entries.push({ id: `CVE-2026-${70000 + Math.round((time - from) / 600_000)}`, publishedAt: iso(time) });
  return entries.reverse();
};

// ---- Text from a feed --------------------------------------------------------------------------------

test('an over-long number after CVE- in a story is not an identifier and fails nothing', async () => {
  const story = (description) => ({
    id: 'feed:x:entry:1',
    source: 'feed:x',
    kind: 'news',
    title: 'A flaw in lodash',
    url: 'https://example.com/x',
    description,
    // As an earlier release, or another collector, may have stored it.
    aliases: [`CVE-2026-${'9'.repeat(130)}`, 'CVE-2026-12345'],
    severity: 'unknown',
    modified_at: iso(NOW - DAY),
    fetched_at: iso(NOW - DAY),
    packages: [],
    content_status: 'full',
  });
  const inv = inventory({
    components: [{ id: 'lodash', ecosystem: 'npm', name: 'lodash', version: '4.17.21' }],
  });
  const state = {};
  const result = await collectSources(inv, sources(), { cve_now: iso(NOW - HOUR) }, service(state), NOW, [
    story('A flaw in lodash lets attackers pollute prototypes.'),
  ]);
  assert.deepEqual(result.errors, []);
  assert.equal(result.coverage[0].status, 'complete');
  assert.deepEqual(state.details, ['CVE-2026-12345'], 'the readable identifier is still followed');
});

test('a story is linked to the first hundred identifiers it cites, each of a bounded length', async () => {
  const ids = Array.from({ length: 150 }, (_, index) => `CVE-2026-${10000 + index}`);
  const item = `<item><title>Roundup of lodash flaws</title><link>https://example.com/roundup</link><guid>g1</guid><pubDate>${new Date(NOW - 600_000).toUTCString()}</pubDate><description>${ids.join(' ')} CVE-2026-${'7'.repeat(40)} GHSA-aaaa-bbbb-cccc</description></item>`;
  const result = await collectSources(
    inventory(),
    sources({ cve_now: false, feeds: ['https://example.com/feed.xml'] }),
    {},
    async () => ({
      status: 200,
      headers: {},
      body: `<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>${item}</channel></rss>`,
    }),
    NOW,
    [],
  );
  const [story] = result.evidence;
  assert.equal(story.aliases.length, 100);
  assert.deepEqual(story.aliases.slice(0, 2), ['CVE-2026-10000', 'CVE-2026-10001']);
  assert.ok(story.aliases.every((id) => id.length <= 28));
});

// ---- Records that keep failing ------------------------------------------------------------------------

test('a dozen new records that always fail do not hold the checkpoint or hide the records after them', async () => {
  const bad = Array.from({ length: 12 }, (_, index) => ({
    id: `CVE-2026-6${100 + index}`,
    publishedAt: iso(NOW - 20 * 60_000 - index * 1000),
  }));
  const isBad = (id) => bad.some((entry) => entry.id === id);
  const world = {
    listing: (now) =>
      [...steady(now), ...bad].sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt)),
    detail: (id) => (isBad(id) ? failing(500) : undefined),
  };
  const hours = Array.from({ length: 17 }, (_, index) => index * 6);
  const polls = await sequence(world, hours);
  // A poll ends at the first batch that fails entirely, so it takes three polls to meet all twelve.
  // From then on they are asked for last, and the checkpoint keeps up with the clock on every poll.
  const settled = polls.slice(4);
  for (const { hour, now, result } of settled)
    assert.equal(result.checkpoints.cve_now, iso(now), `${hour} h: the checkpoint is at the poll time`);
  // The newest record of each poll is read, and no poll asks for more than the new records plus
  // the twelve that fail: nothing listed before is read again.
  for (const { hour, now, asked } of settled) {
    const newest = steady(now)[0].id;
    assert.ok(asked.includes(newest), `${hour} h: the newest record is read`);
    assert.ok(asked.length <= 37 + 12, `${hour} h: ${asked.length} requests`);
  }
  // While they fail they are reported; three days after the first failure they are given up on.
  assert.match(polls[5].result.errors[0].message, /advisory detail request\(s\) failed/);
  assert.match(polls[5].result.errors[0].message, /12 new record\(s\) are still to be read/);
  const given = polls.filter(({ result }) =>
    /could not be read for three days and were given up on/.test(result.errors[0]?.message ?? ''),
  );
  assert.ok(given.length >= 1 && given[0].hour > 72, `given up on at ${given.map(({ hour }) => hour)} h`);
  const last = polls.at(-1);
  assert.deepEqual(last.result.errors, []);
  assert.equal(last.result.coverage[0].status, 'complete');
  assert.equal(last.result.checkpoints['cve_now:owed'], '[]');
  assert.ok(!last.asked.some(isBad), 'they are not asked for any more');
});

test('two new records that always answer "too many requests" are asked for last, both of them', async () => {
  const bad = ['CVE-2026-62001', 'CVE-2026-62002'];
  const world = {
    listing: (now) =>
      [
        ...steady(now),
        { id: bad[0], publishedAt: iso(NOW - 50 * 60_000) },
        { id: bad[1], publishedAt: iso(NOW - 5 * 60_000) },
      ].sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt)),
    detail: (id) => (bad.includes(id) ? failing(429) : undefined),
  };
  const polls = await sequence(world, [0, 2, 8, 14, 20]);
  // The first poll meets one of them, the second the other; after that both are known.
  for (const { hour, now, result, asked } of polls.slice(2)) {
    assert.equal(result.checkpoints.cve_now, iso(now), `${hour} h`);
    assert.ok(asked.includes(steady(now)[0].id), `${hour} h: the newest record is read`);
    // The poll ends at the first of the two; neither comes before a record that can be read.
    const firstBad = asked.findIndex((id) => bad.includes(id));
    assert.ok(firstBad === asked.length - 1, `${hour} h: asked in order ${asked.slice(-3)}`);
    assert.deepEqual(JSON.parse(result.checkpoints['cve_now:troubled']).sort(), bad, `${hour} h`);
  }
});

test('new records left unasked when a poll ends early are remembered and read later', async () => {
  // Thirty records in one poll; the eight oldest fail, and the first batch of four ends that poll.
  const entries = Array.from({ length: 30 }, (_, index) => ({
    id: `CVE-2026-63${100 + index}`,
    publishedAt: iso(NOW - 40 * 60_000 + index * 60_000),
  }));
  const firstEight = new Set(entries.slice(0, 8).map((entry) => entry.id));
  let broken = true;
  const world = {
    listing: () => [...entries].reverse(),
    detail: (id) => (broken && firstEight.has(id) ? failing(503) : undefined),
  };
  const [first] = await sequence(world, [0]);
  assert.equal(first.asked.length, 4);
  assert.equal(JSON.parse(first.result.checkpoints['cve_now:owed']).length, 30, 'failed and unasked alike');
  // Two hours later the service is well and the listing has moved on: none of the thirty is in
  // the window any more, and all of them are read by name.
  broken = false;
  const later = NOW + 2 * HOUR;
  const state = {};
  const second = await collectSources(
    inventory(),
    sources(),
    { ...first.result.checkpoints, cve_now: iso(later - 30 * 60_000) },
    service(state, { listing: () => [] }, later),
    later,
    [],
  );
  assert.equal(state.details.length, 30);
  assert.equal(second.evidence.length, 30);
  assert.deepEqual(second.errors, []);
  assert.equal(second.checkpoints['cve_now:owed'], '[]');
});

test('a listing entry without an identifier above every dated record is reported for a day, not for ever', async () => {
  const world = {
    listing: (now) => [{ id: 'X1', publishedAt: iso(NOW + 400 * DAY) }, ...steady(now)],
  };
  const polls = await sequence(world, [0, 12, 23, 26, 48]);
  for (const { hour, result } of polls.slice(0, 3)) {
    assert.match(result.errors[0].message, /1 invalid item\(s\) were skipped/, `${hour} h`);
    assert.equal(result.coverage[0].status, 'partial', `${hour} h`);
  }
  for (const { hour, now, result } of polls.slice(3)) {
    assert.deepEqual(result.errors, [], `${hour} h`);
    assert.equal(result.checkpoints.cve_now, iso(now), `${hour} h`);
  }
});

test('a checkpoint ahead of the clock is treated like a new installation, not as a reason to fail', async () => {
  const state = {};
  const result = await collectSources(
    inventory(),
    sources(),
    { cve_now: iso(NOW + 3 * HOUR) },
    service(state, { listing: () => [{ id: 'CVE-2026-64001', publishedAt: iso(NOW - 20 * HOUR) }] }),
    NOW,
    [],
  );
  assert.deepEqual(result.errors, []);
  assert.deepEqual(state.details, ['CVE-2026-64001'], 'one day back is read');
  assert.equal(result.checkpoints.cve_now, iso(NOW));
});

test('what the service serves now replaces the stored record even with an earlier modification time', async () => {
  const id = 'CVE-2026-65001';
  const store = new Store(':memory:');
  store.saveEvidence([stored(id, { modified_at: iso(NOW - 2 * DAY) })], {});
  const detail = () =>
    json(
      record(id, {
        modifiedAt: iso(NOW - 5 * DAY),
        affected: [{ ecosystem: 'npm', package: 'alpha', ranges: [{ introduced: '0', fixed: '1.1.0' }] }],
      }),
    );
  const result = await collectSources(
    inventory(),
    sources(),
    { cve_now: iso(NOW - HOUR) },
    service({}, { detail }),
    NOW,
    store.evidence(),
  );
  store.saveEvidence(result.evidence, result.checkpoints);
  assert.equal(store.evidence().find((item) => item.id === `cve_now:${id}`).packages[0].range, '<1.1.0');
  const [finding] = assess(inventory(), store.evidence(), sources(), NOW);
  assert.equal(finding.applicability, 'affected');
});

test('a cited CVE that is stored under another identifier is not asked for again by its cited name', async () => {
  const inv = inventory({ keywords: ['Acme router'], components: [] });
  const story = {
    id: 'feed:x:entry:2',
    source: 'feed:x',
    kind: 'news',
    title: 'Acme router flaw',
    url: 'https://example.com/x',
    description: 'Acme router bug CVE-2026-66001',
    aliases: ['CVE-2026-66001'],
    severity: 'unknown',
    modified_at: iso(NOW - DAY),
    fetched_at: iso(NOW - DAY),
    packages: [],
    content_status: 'full',
  };
  // The service files the record under a GHSA identifier, with the CVE as an alias.
  const kept = stored('GHSA-aaaa-bbbb-cccc', {
    aliases: ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-66001'],
    description: 'Acme router flaw',
    packages: [],
  });
  const state = {};
  await collectSources(inv, sources(), { cve_now: iso(NOW - HOUR) }, service(state), NOW, [story, kept]);
  assert.ok(!(state.details ?? []).includes('CVE-2026-66001'));
});

test('package requests that were never sent leave the package results incomplete', async () => {
  // Eight new records fail, and the first batch of four ends the poll. The stored package records are asked for last here
  // (they failed on the poll before), so they are never reached: no request for them failed, and
  // none was sent.
  const tracked = [stored('CVE-2026-67001'), stored('CVE-2026-67002')];
  const listing = Array.from({ length: 8 }, (_, index) => ({
    id: `CVE-2026-68${100 + index}`,
    publishedAt: iso(NOW - 10 * 60_000 - index * 1000),
  }));
  const state = {};
  const result = await collectSources(
    inventory(),
    sources(),
    { cve_now: iso(NOW - HOUR), 'cve_now:troubled': JSON.stringify(['CVE-2026-67001', 'CVE-2026-67002']) },
    service(state, {
      listing: () => listing,
      detail: (id) => (id.startsWith('CVE-2026-68') ? failing(503) : undefined),
    }),
    NOW,
    tracked,
  );
  assert.equal(state.details.length, 4);
  assert.ok(!state.details.some((id) => id.startsWith('CVE-2026-67')));
  assert.equal(result.coverage[0].package_results, undefined);
});

test('a vendor feed without a model gets the notice that news is matched without AI', async () => {
  const report = await runScan({
    config: parseConfig({
      version: 1,
      sources: {
        cve_now: false,
        hacker_news: false,
        osv: false,
        github: false,
        kev: false,
        vendor_feeds: ['nodejs'],
      },
    }),
    inventory: inventory(),
    store: new Store(':memory:'),
    now: NOW,
    http: async () => ({
      status: 200,
      headers: {},
      body: '<?xml version="1.0"?><rss version="2.0"><channel><title>x</title></channel></rss>',
    }),
  });
  assert.ok(report.notices.some((notice) => /AI is disabled/.test(notice)));
});

// ---- Matching ------------------------------------------------------------------------------------------

const mentioned = (ecosystem, name, text) => packageMentioned(text, { ecosystem, name });

test('an English word matches only where the text calls it a package', () => {
  for (const [ecosystem, name, text] of [
    [
      'npm',
      'send',
      'Malicious npm packages posing as Flashbots SDKs were found. They steal wallet keys and send them to a Telegram bot.',
    ],
    [
      'npm',
      'next',
      'The group sideloads a malicious DLL library through a signed binary, then waits several days before it fetches the next stage.',
    ],
    [
      'npm',
      'enabled',
      'The Magecart group injects malicious JavaScript into checkout pages of online shops. The skimmer is enabled only when a card form is shown.',
    ],
    [
      'npm',
      'prompts',
      'The MSI package installs a remote access tool on the machine silently and completely without any prompts.',
    ],
    [
      'npm',
      'once',
      'A Python package bundled in the installer drops the payload. It runs once the user signs in.',
    ],
    ['PyPI', 'requests', 'The Python backdoor sends requests to its C2 every minute.'],
    // The word "package" or "library" right next to an ordinary word is still ordinary prose.
    ['npm', 'which', 'A package named fabrice, which imitates fabric, steals AWS keys.'],
    ['npm', 'which', 'The packages, which deliver a loader, were removed from npm.'],
    ['npm', 'three', 'Researchers at Socket found three packages that typosquat popular libraries.'],
    ['npm', 'buffer', 'A heap-based buffer overflow in the syslog function of the GNU C Library gives root.'],
    ['npm', 'request', 'The npm package ejs passes options from the request to the template compiler.'],
    ['npm', 'accepts', 'The JavaScript cryptography library accepts malformed signatures.'],
    ['npm', 'long', 'The semver package takes a long time to parse crafted ranges.'],
    ['npm', 'enabled', 'The JavaScript helper enabled, used by debug, was hijacked.'],
    ['PyPI', 'coverage', 'A Python tool, coverage, executes code from a crafted config file.'],
  ])
    assert.equal(mentioned(ecosystem, name, text), false, `${name}: ${text}`);
  for (const [ecosystem, name, text] of [
    ['npm', 'send', 'A flaw in the send npm package lets attackers read files.'],
    ['npm', 'next', 'The npm package next is affected by a cache poisoning bug.'],
    ['npm', 'prompts', 'A compromised release of the prompts library was published to npm.'],
    ['npm', 'enabled', 'The npm package enabled, used by debug, was hijacked.'],
    ['npm', 'which', 'A dependency called which was republished with a backdoor.'],
    ['PyPI', 'requests', 'Run pip install requests==2.32.0 to get the fix.'],
    ['PyPI', 'requests', 'Maintainers of the "requests" library fixed a credential leak.'],
    ['npm', 'entities', 'The entities package on npm was compromised.'],
  ])
    assert.equal(mentioned(ecosystem, name, text), true, `${name}: ${text}`);
});

test('a well-known library is named as the second word of a sentence, and a release may have two parts', () => {
  for (const [ecosystem, name, text] of [
    ['RubyGems', 'rails', 'Critical Rails flaw allows remote code execution'],
    ['npm', 'react', 'The React team disclosed an unauthenticated remote code execution bug.'],
    ['npm', 'express', 'New Express vulnerability lets attackers bypass route guards'],
    ['npm', 'electron', 'Critical Electron bug affects desktop chat apps'],
    ['PyPI', 'flask', 'Popular Flask extension leaks session cookies'],
    // A two-part version after a capitalised English word, also for the commonest words.
    ['PyPI', 'salt', 'Salt 3007.1 fixes an authentication bypass'],
    ['PyPI', 'tornado', 'Tornado 6.5 fixes a denial of service in multipart parsing'],
    ['PyPI', 'requests', 'Requests 2.32 fixes a proxy credential leak'],
    ['npm', 'next', 'Next 15.2 fixes a middleware bypass'],
    ['npm', 'debug', 'Debug 4.4 was published with a clipper'],
    // Lower-case ".js" for a word that is not among the commonest.
    ['npm', 'validator', 'validator.js URL check can be bypassed, CERT warns'],
    // Two characters: as name@version, or right next to "package", "library" or "module".
    ['npm', 'ws', 'A flaw in ws crashes servers; upgrade to ws@8.17.1.'],
    ['npm', 'ws', 'DoS flaw in ws WebSocket library crashes Node.js servers'],
    ['npm', 'qs', 'The npm package qs is vulnerable to prototype pollution.'],
    ['npm', 'ip', 'Developer archives the ip package over a disputed CVE'],
  ])
    assert.equal(mentioned(ecosystem, name, text), true, `${name}: ${text}`);
  for (const [ecosystem, name, text] of [
    ['npm', 'express', 'The story was first reported by the Indian Express on Monday.'],
    ['npm', 'express', 'Customers Express 10.0 Severity Concern'],
    ['npm', 'next', 'Patch Within the Next 2.5 Weeks, Agency Says'],
    ['npm', 'send', 'Botnets Send 1.5 Million Requests per Second'],
    ['npm', 'config', 'The stealer reads wp-config.php and config.js from the web root.'],
    ['npm', 'ip', 'The IP address of the package server was leaked.'],
    ['npm', 'ip', 'An ip address in the library logs gave the attacker away.'],
    ['npm', 'ws', 'The WS-Security module accepts unsigned messages.'],
    ['npm', 'offline', 'The hospital took its systems offline after the attack.'],
    ['npm', 'website', 'The gang defaced the company website and leaked data.'],
    ['npm', 'metadata', 'The attacker read the instance metadata to steal cloud credentials.'],
  ])
    assert.equal(mentioned(ecosystem, name, text), false, `${name}: ${text}`);
});

test('the inventory matcher agrees with the single-name check on every rule', () => {
  const names = {
    npm: [
      'send',
      'next',
      'express',
      'entities',
      'validator',
      'config',
      'ws',
      'ip',
      'lodash',
      'offline',
      'which',
      'three',
    ],
    PyPI: ['requests', 'salt', 'flask', 'coverage'],
  };
  const components = Object.entries(names).flatMap(([ecosystem, list]) =>
    list.map((name) => ({ id: `${ecosystem}:${name}`, ecosystem, name, version: '1.0.0' })),
  );
  const inv = inventory({ components });
  const { packageNamed } = inventoryMatcher(inv);
  for (const text of [
    'The Python backdoor sends requests to its C2 every minute.',
    'Malicious npm packages were found. They steal wallet keys and send them to a Telegram bot.',
    'Researchers express concern as botnets send 1.5 million requests per second.',
    'The stealer reads wp-config.php and config.js from the web root.',
    'The IP address of the package server was leaked.',
    'The hospital took its systems offline after the attack.',
    'Maintainers of the requests library fixed a credential leak.',
    'A flaw in the send package lets attackers read files.',
    'Salt 3007.1 fixes an authentication bypass',
    'Critical Flask flaw leaks session cookies',
    'validator.js URL check can be bypassed, CERT warns',
    'Developer archives the ip package over a disputed CVE',
    'upgrade to ws@8.17.1',
    'a flaw in lodash lets attackers pollute prototypes',
    'A Python tool, coverage, executes code from a crafted config file.',
    'The packages, which deliver a loader, were removed from npm.',
    'Researchers found three packages that typosquat popular libraries.',
    'A dependency called which was republished with a backdoor.',
  ]) {
    const single = components.some((component) => packageMentioned(text, component));
    assert.equal(packageNamed(text), single, text);
  }
});

// ---- The release command -------------------------------------------------------------------------------

test('a release is refused when npm is set to ignore scripts or to use another registry', () => {
  assert.equal(releaseEnvironmentProblem({}), undefined);
  assert.equal(releaseEnvironmentProblem({ PATH: '/bin', npm_config_ignore_scripts: '' }), undefined);
  assert.equal(releaseEnvironmentProblem({ npm_config_ignore_scripts: 'false' }), undefined);
  assert.equal(releaseEnvironmentProblem({ npm_config_registry: 'https://registry.npmjs.org/' }), undefined);
  assert.equal(releaseEnvironmentProblem({ npm_config_registry: 'https://registry.npmjs.org' }), undefined);
  // `npm run release --ignore-scripts`, without the `--`: npm keeps the option for itself.
  for (const env of [
    { npm_config_ignore_scripts: 'true' },
    { NPM_CONFIG_IGNORE_SCRIPTS: 'true' },
    { npm_config_ignore_scripts: '1' },
  ])
    assert.match(releaseEnvironmentProblem(env), /ignore scripts/, JSON.stringify(env));
  for (const env of [
    { npm_config_registry: 'https://example.com/' },
    { NPM_CONFIG_REGISTRY: 'http://localhost:4873/' },
    { npm_config_registry: 'https://registry.npmjs.org.example.com/' },
  ])
    assert.match(
      releaseEnvironmentProblem(env),
      /releases go to https:\/\/registry\.npmjs\.org/,
      JSON.stringify(env),
    );
});

test('the release options and the packed-file check are exact, not prefixes or fragments', () => {
  // A one-time code is the whole option, not the end of another one.
  for (const option of [
    '--tag=x--otp=123456',
    'x--otp=123456',
    '--otp=123456 --tag=latest',
    '--otp=12345',
    '--dry-run=false',
  ])
    assert.throws(() => releaseOptions([option]), /accepts only --dry-run and --otp=CODE/, option);
  assert.deepEqual(releaseOptions(['--otp=12345678']), ['--otp=12345678']);
  // Only the build output at the top of the package is exempt from being tracked.
  assert.deepEqual(untrackedPackedFiles(['dist/a.js', 'docs/dist/notes.txt', 'examples/dist/x.js'], []), [
    'docs/dist/notes.txt',
    'examples/dist/x.js',
  ]);
});
