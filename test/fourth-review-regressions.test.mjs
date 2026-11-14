// Regressions from the fourth review: English words as package names, cve.now records that keep
// failing, a failed listing, a stamp ahead of the clock, the guards behind `package_results`,
// version citations, model identity, message cuts and notices.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assess, decide } from '../dist/assessment.js';
import { parseConfig } from '../dist/config.js';
import { deliverPending, notificationText } from '../dist/delivery.js';
import { runScan } from '../dist/engine.js';
import { dictionaryName, everydayWord } from '../dist/everyday-words.js';
import { isPublicAddress, NetworkError } from '../dist/http.js';
import { loadInventory } from '../dist/inventory.js';
import { inventoryMatcher, packageMentioned } from '../dist/matching.js';
import { validateAnalysis } from '../dist/models.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';
import { cut } from '../dist/util.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });
const character = String.fromCharCode;
const mentioned = (ecosystem, name, text) => packageMentioned(text, { ecosystem, name });

// ---- English words as package names ----------------------------------------------------------------

test('an English word in its ordinary sense is not the package of that name', () => {
  for (const [ecosystem, name, text] of [
    [
      'npm',
      'entities',
      'Federal Civilian Executive Branch entities are required to apply the fixes by December 5.',
    ],
    ['npm', 'immediate', 'CISA urged administrators to take immediate action.'],
    [
      'npm',
      'scheduler',
      'The backdoor registers itself with the Windows Task Scheduler to survive a reboot.',
    ],
    ['npm', 'side-channel', 'New Side-Channel Attack Leaks Secrets From Intel CPUs'],
    ['npm', 'underscore', 'The intrusions underscore the need to patch edge devices quickly.'],
    ['npm', 'immutable', 'The ransomware crew also wiped the immutable backups.'],
    ['npm', 'validator', 'Attackers stole validator keys from the bridge operator and drained $80 million.'],
    ['npm', 'compression', 'The archive uses a custom compression scheme to evade scanners.'],
    ['npm', 'prompts', 'Hidden prompts in the email made the assistant leak the inbox.'],
    ['npm', 'xss', 'Stored XSS Flaw in WordPress Plugin Affects 200,000 Sites'],
    ['npm', 'cors', 'A CORS misconfiguration exposed the billing API.'],
    ['npm', 'rollup', 'Microsoft shipped the fix in the November cumulative rollup.'],
    ['npm', 'cron', 'The miner adds a cron job to keep itself running.'],
    ['PyPI', 'executing', 'A remote attacker can end up executing arbitrary commands as root.'],
    ['PyPI', 'deprecated', 'The appliance still enables the deprecated TLS 1.0 protocol.'],
    ['PyPI', 'coverage', 'The insurer denied coverage after the breach.'],
    ['PyPI', 'rsa', 'The firmware ships a hard-coded RSA private key.'],
    ['Hex', 'telemetry', 'ESET telemetry shows most victims are in Brazil.'],
    ['Hex', 'jason', '"We patched within hours," said Jason Miller, the company CISO.'],
    ['RubyGems', 'prime', 'Hospitals remain a prime target for extortion.'],
    ['RubyGems', 'base64', 'The payload is a Base64 string decoded at run time.'],
    // A capital after a lower-case word, but part of another name.
    [
      'npm',
      'ghost',
      'CISA warned that the Ghost ransomware group has breached organizations in 70 countries.',
    ],
    ['PyPI', 'tornado', 'The stolen funds were laundered through the Tornado Cash mixer.'],
    ['PyPI', 'salt', 'The carrier intrusions were attributed to Salt Typhoon.'],
    ['npm', 'morgan', 'Morgan Stanley fined over disposal of unwiped hard drives.'],
    // Title case shows nothing.
    ['npm', 'react', 'How to React When Ransomware Hits Your Company'],
    ['npm', 'express', 'Users Take to Social Media to Express Anger Over Breach'],
    // An address is not a release, a file is not a library, a language is not a registry.
    ['npm', 'address', 'The requests came from IP address 203.0.113.7 and were blocked.'],
    ['npm', 'config', 'The stealer reads wp-config.php and config.js from the web root.'],
    ['PyPI', 'requests', 'The Python backdoor sends requests to its C2 every minute.'],
    ['npm', 'buffer', 'A buffer overflow in the kernel module lets a local user gain root.'],
    // A unit or a rating after the number.
    ['npm', 'next', 'Patch Within the Next 2.5 Weeks, Agency Says'],
    ['npm', 'address', 'Admins Urged to Address 9.8 CVSS Bug'],
    ['npm', 'express', 'Customers Express 10.0 Severity Concern'],
  ])
    assert.equal(mentioned(ecosystem, name, text), false, `${name}: ${text}`);
});

test('a story about the package still matches an English-word name', () => {
  for (const [ecosystem, name, text] of [
    // The registry, or the word "package", "library" or "dependency".
    ['npm', 'entities', 'The entities package on npm was compromised (CVE-2026-11111).'],
    ['npm', 'request', 'A malicious release of the request npm package steals tokens.'],
    ['PyPI', 'requests', 'A flaw in the requests PyPI library leaks proxy credentials.'],
    // Named as a package: an install command, a registry prefix, "called".
    ['PyPI', 'coverage', 'Run pip install coverage only from the official index.'],
    ['npm', 'send', 'The advisory covers npm:send before 0.19.0.'],
    ['npm', 'once', 'A dependency called once is pulled in by the tool.'],
    // A release.
    ['npm', 'send', 'Upgrade to send@0.19.0 to fix template injection.'],
    ['npm', 'debug', 'Malicious debug v4.4 was live for two hours.'],
    ['PyPI', 'requests', 'Requests 2.32.0 fixes a credential leak.'],
    ['npm', 'next', 'Critical Next.js middleware bypass under active exploitation'],
    ['npm', 'express', 'ExpressJS Maintainers Patch Open Redirect Bug'],
    ['npm', 'next', 'NextJS Middleware Bypass Under Active Exploitation'],
    ['RubyGems', 'rails', 'Rails 7.2 Fixes SQL Injection in Active Record'],
    ['PyPI', 'flask', `Flask Session Cookie Flaw Disclosed${character(10)}Flask 3.1 is affected.`],
    // Written as a name.
    ['npm', 'express', 'A flaw in Express lets attackers bypass route guards.'],
    ['npm', 'scheduler', 'Researchers found that the Scheduler module mishandles timers.'],
    ['RubyGems', 'rails', 'Rails releases patches for an Active Storage flaw.'],
    ['npm', 'electron', 'Electron fixes a sandbox escape in the renderer.'],
    [
      'RubyGems',
      'rack',
      `Rack Flaw Lets Attackers Read Arbitrary Files${character(10)}Rack's static file handler does not normalise paths.`,
    ],
    ['npm', 'react', 'Critical bug in React Server Components allows remote code execution.'],
    // Not English: the name is the package wherever it is written.
    ['npm', 'lodash', 'a flaw in lodash lets attackers pollute prototypes'],
    ['npm', 'axios', 'Axios 1.8.2 fixes SSRF'],
    ['npm', 'qrlib-pad', 'Attackers abuse qrlib-pad in the wild.'],
    ['npm', '@acme/sdk', 'Attackers abuse @acme/sdk in the wild.'],
  ])
    assert.equal(mentioned(ecosystem, name, text), true, `${name}: ${text}`);
});

test('well-known library names are told apart from English words', () => {
  // Not English: these match wherever they are written.
  for (const name of `axios lodash webpack django vite langchain numpy vue jquery sequelize prisma fastify
tensorflow pytorch keras laravel symfony nokogiri sidekiq tokio serde actix eslint semver dotenv
jszip rimraf minimist mkdirp execa zod nuxt graphql knex esbuild vitest pinia vuex mobx zustand rxjs
ramda dayjs luxon ajv jsdom undici boto3 urllib3 certifi pyyaml jinja2 werkzeug sqlalchemy gunicorn
uvicorn fastapi pydantic httpx aiohttp scipy matplotlib nltk pytest mypy pylint rspec rubocop sinatra
hapi multer chokidar nanoid redux spacy`.split(/\s+/))
    assert.equal(dictionaryName(name), false, name);
  // English, or a term of security writing: these need more than the word.
  for (const name of `entities scheduler immediate address underscore immutable validator compression
prompts coverage safety telemetry prime express react flask rails electron angular spring xss cors
rollup punycode base64 jason morgan side-channel zero-day`.split(/\s+/))
    assert.equal(dictionaryName(name), true, name);
  // The commonest words do not even count when written as a name.
  for (const name of ['send', 'buffer', 'request', 'next', 'address', 'ghost', 'salt', 'xss'])
    assert.equal(everydayWord(name), true, name);
  for (const name of ['express', 'react', 'entities', 'scheduler'])
    assert.equal(everydayWord(name), false, name);
});

test('the inventory matcher follows the same rules and stays fast for a large inventory', () => {
  const names = [
    'express',
    'entities',
    'scheduler',
    'send',
    'address',
    'config',
    'lodash',
    ...Array.from({ length: 3000 }, (_, index) => `pkg-${index}-lib`),
  ];
  const inventory = {
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
  };
  const started = Date.now();
  const { packageNamed } = inventoryMatcher(inventory);
  for (const text of [
    'Federal entities must apply the fixes; the Windows Task Scheduler keeps the implant alive.',
    'The requests came from IP address 203.0.113.7; the stealer reads config.js.',
    'Researchers express concern as botnets send 1.5 million requests per second.',
  ])
    assert.equal(packageNamed(text), false, text);
  for (const text of [
    'A flaw in Express lets attackers bypass route guards.',
    'The entities package on npm was compromised.',
    'send@0.19.0 fixes a template injection.',
    'a flaw in lodash lets attackers pollute prototypes',
    'pkg-2999-lib was hijacked.',
  ])
    assert.equal(packageNamed(text), true, text);
  // One story compared with every component, again for each of 300 advisories it cites.
  const story = `Roundup of flaws. ${'Nothing here names a package. '.repeat(400)}`;
  for (let advisory = 0; advisory < 100; advisory++)
    for (const component of inventory.systems[0].components) packageMentioned(story, component);
  // Without the cache this takes minutes. The limit is wide because test machines are often busy.
  assert.ok(Date.now() - started < 30_000, `took ${Date.now() - started} ms`);
});

// ---- cve.now ---------------------------------------------------------------------------------------

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
    github_token_env: 'FOURTH_REVIEW_UNUSED',
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
/** A stub of the service. `lookup` answers the package lookup; `listing` may be a response itself. */
const service =
  (state, { listing = [], detail = () => undefined, lookup = { packages: 1, entries: [] } } = {}) =>
  async (url) => {
    const { pathname, searchParams } = new URL(url);
    if (pathname === '/stack') return json(lookup);
    if (pathname === '/api/v1/entries') {
      if (!Array.isArray(listing)) return listing;
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
const listedAt = (id, age) => ({ id, publishedAt: iso(NOW - age) });
const failing = { status: 500, headers: {}, body: '' };

test('records whose requests keep failing are asked for last, so the others are still read', async () => {
  // Four stored records about an inventory package answer HTTP 500 for ever. They are first in
  // the order, and a batch that fails entirely ends a poll.
  const broken = ['CVE-2026-91001', 'CVE-2026-91002', 'CVE-2026-91003', 'CVE-2026-91004'];
  const previous = broken.map((id) => stored(id));
  const listing = Array.from({ length: 20 }, (_, index) =>
    listedAt(`CVE-2026-92${100 + index}`, 60_000 + index * 1000),
  );
  const detail = (id) => (broken.includes(id) ? failing : undefined);
  const first = {};
  const one = await collectSources(
    inventory(),
    sources,
    checkpoint,
    service(first, { listing, detail }),
    NOW,
    previous,
  );
  assert.deepEqual(first.details, broken, 'the first poll stops at the failed batch');
  assert.deepEqual(JSON.parse(one.checkpoints['cve_now:troubled']).sort(), broken);
  // The next poll asks for the new records first, and for the failing ones at the end.
  const second = {};
  const two = await collectSources(
    inventory(),
    sources,
    one.checkpoints,
    service(second, { listing, detail }),
    NOW + 30 * 60_000,
    previous,
  );
  assert.deepEqual(second.details.slice(-4).sort(), broken);
  assert.equal(two.evidence.length, 20, 'every new record is read');
  assert.match(two.errors[0].message, /4 advisory detail request\(s\) failed/);
  // Not found through the listing: they do not hold the checkpoint.
  assert.equal(two.checkpoints.cve_now, iso(NOW + 30 * 60_000));
  // A record that answers "too many requests" is put last in the same way.
  const limited = { status: 429, headers: {}, body: '' };
  const third = {};
  const blocked = (id) => (id === broken[0] ? limited : undefined);
  const three = await collectSources(
    inventory(),
    sources,
    checkpoint,
    service({}, { listing, detail: blocked }),
    NOW,
    previous,
  );
  await collectSources(
    inventory(),
    sources,
    three.checkpoints,
    service(third, { listing, detail: blocked }),
    NOW + 30 * 60_000,
    previous,
  );
  assert.equal(third.details.at(-1), broken[0]);
  assert.equal(third.details.length, 24, 'nothing is left unasked');
});

test('a failed listing request does not discard what the package lookup found', async () => {
  // The current lookup format names the matched records; their content is read afterwards.
  const lookup = {
    items: [
      {
        id: 'CVE-2026-93001',
        _cve_now: { matched: { ecosystem: 'npm', name: 'alpha', version: '1.0.0' } },
      },
    ],
  };
  const state = {};
  const result = await collectSources(
    inventory(),
    sources,
    checkpoint,
    service(state, { listing: failing, lookup }),
    NOW,
    [],
  );
  assert.deepEqual(state.details, ['CVE-2026-93001']);
  assert.equal(result.evidence.length, 1);
  assert.deepEqual(result.evidence[0].packages[0].matched_versions, ['1.0.0']);
  assert.equal(result.coverage[0].status, 'partial');
  assert.match(result.errors[0].message, /HTTP 500/);
  assert.equal(result.checkpoints.cve_now, checkpoint.cve_now, 'the checkpoint stays');
  // The listing only finds new records. The package lookup and what it named were read, so version
  // exclusions drawn from this source still hold: a failed listing must not withdraw them.
  assert.equal(result.coverage[0].package_results, 'complete');
});

test('a stored record whose new revision is stamped ahead of the clock is still updated', async () => {
  const id = 'CVE-2026-94001';
  // Stored two days ago with a narrow range; installed 1.0.0 is outside it.
  const old = stored(id, {
    modified_at: iso(NOW - 2 * DAY),
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '<0.5.0' }],
  });
  const store = new Store(':memory:');
  store.saveEvidence([old], {});
  // The service widens the range and stamps the change two hours ahead; its publication date is older
  // than the stored revision.
  const detail = () =>
    json(
      record(id, {
        publishedAt: iso(NOW - 30 * DAY),
        modifiedAt: iso(NOW + 2 * HOUR),
        affected: [{ ecosystem: 'npm', package: 'alpha', ranges: [{ introduced: '0', fixed: '2.0.0' }] }],
      }),
    );
  const result = await collectSources(
    inventory(),
    sources,
    checkpoint,
    service({}, { detail }),
    NOW,
    store.evidence(),
  );
  assert.deepEqual(result.errors, []);
  const collected = result.evidence.find((item) => item.id === old.id);
  assert.equal(collected.packages[0].range, '<2.0.0');
  assert.equal(collected.modified_at, old.modified_at, 'not older than the stored revision');
  store.saveEvidence(result.evidence, result.checkpoints);
  assert.equal(store.evidence().find((item) => item.id === old.id).packages[0].range, '<2.0.0');
  const [finding] = assess(inventory(), store.evidence(), sources, NOW);
  assert.equal(finding.applicability, 'affected');
});

test('a cited identifier the service cannot serve in any way is asked for once a day, without an error', async () => {
  const inv = inventory({ keywords: ['Acme router'], components: [] });
  const story = (id) => ({
    id: `hacker_news:entry:${id}`,
    source: 'hacker_news',
    kind: 'news',
    title: 'Acme router flaw',
    url: 'https://example.com/x',
    description: `Acme router bug ${id}`,
    aliases: [id],
    severity: 'unknown',
    modified_at: iso(NOW - 3 * DAY),
    fetched_at: iso(NOW - 3 * DAY),
    packages: [],
    content_status: 'full',
  });
  const stories = [story('CVE-2025-30001'), story('CVE-2025-30002')];
  const detail = (id) =>
    id === 'CVE-2025-30001'
      ? { status: 410, headers: {}, body: '' }
      : json({ id, status: 'reserved', title: id });
  let checkpoints = checkpoint;
  const requests = [];
  for (const minutes of [0, 30, 60, 23 * 60, 25 * 60]) {
    const state = {};
    const result = await collectSources(
      inv,
      sources,
      checkpoints,
      service(state, { detail }),
      NOW + minutes * 60_000,
      stories,
    );
    assert.deepEqual(result.errors, [], `${minutes} min`);
    checkpoints = result.checkpoints;
    requests.push((state.details ?? []).length);
  }
  assert.deepEqual(requests, [2, 0, 0, 0, 2]);
});

test('the remembered list of missing identifiers survives a clock that moved back, and is bounded', async () => {
  const inv = inventory({ keywords: ['Acme router'], components: [] });
  const ids = Array.from({ length: 5200 }, (_, index) => `CVE-2025-${40000 + index}`);
  const stories = [
    ...ids.map((id, index) => ({
      id: `hacker_news:entry:${index}`,
      source: 'hacker_news',
      kind: 'news',
      title: 'Acme router flaw',
      url: 'https://example.com/x',
      description: `Acme router bug ${id}`,
      aliases: [id],
      severity: 'unknown',
      modified_at: iso(NOW - 3 * DAY),
      fetched_at: iso(NOW - 3 * DAY),
      packages: [],
      content_status: 'full',
    })),
  ];
  const gone = () => ({ status: 404, headers: {}, body: '' });
  const first = {};
  const one = await collectSources(inv, sources, checkpoint, service(first, { detail: gone }), NOW, stories);
  assert.equal(first.details.length, 5000, 'one poll asks for at most 5,000 records');
  assert.ok(JSON.parse(one.checkpoints['cve_now:missing']).length <= 5000);
  // Asked "in the future": the clock was moved back. The entry is not trusted, and is asked for again.
  const later = { ...checkpoint, 'cve_now:missing': JSON.stringify([[ids[0], NOW + 5 * DAY]]) };
  const second = {};
  await collectSources(inv, sources, later, service(second, { detail: gone }), NOW, stories.slice(0, 1));
  assert.deepEqual(second.details, [ids[0]]);
});

// What clears `package_results`: every case in which a record for an inventory package may be unread.
test('an incomplete scan claims complete package results only when every package record was read', async () => {
  const receipt = (result) => result.coverage.find((item) => item.source === 'cve_now');
  const odd = [listedAt('CVE-2026-95001', 5 * 60_000)];
  const reserved = (id) =>
    id === 'CVE-2026-95001' ? json({ id, status: 'reserved', title: id }) : undefined;
  // Control: only an unrelated new record is unreadable.
  const control = await collectSources(
    inventory(),
    sources,
    checkpoint,
    service({}, { listing: odd, detail: reserved }),
    NOW,
    [stored('CVE-2026-95010')],
  );
  assert.equal(receipt(control).status, 'partial');
  assert.equal(receipt(control).package_results, 'complete');

  // A bad item in the package lookup.
  const badLookup = {
    packages: 1,
    entries: [
      { ...record('CVE-2026-95020'), matched: { ecosystem: 'npm', name: 'other', version: '9.9.9' } },
    ],
  };
  const lookup = await collectSources(
    inventory(),
    sources,
    checkpoint,
    service({}, { lookup: badLookup }),
    NOW,
    [stored('CVE-2026-95010')],
  );
  assert.equal(receipt(lookup).status, 'partial');
  assert.equal(receipt(lookup).package_results, undefined);

  // Requests for package records that were never sent, because the poll stopped early.
  const many = Array.from({ length: 12 }, (_, index) => stored(`CVE-2026-96${100 + index}`));
  const firstFour = new Set(many.slice(0, 4).map((item) => item.aliases[0]));
  const stopped = await collectSources(
    inventory(),
    sources,
    checkpoint,
    service({}, { detail: (id) => (firstFour.has(id) ? { status: 429, headers: {}, body: '' } : undefined) }),
    NOW,
    many,
  );
  assert.notEqual(receipt(stopped).status, 'complete');
  assert.equal(receipt(stopped).package_results, undefined);

  // Requests left out by the limit of 5,000 records per poll.
  const tracked = Array.from({ length: 5001 }, (_, index) =>
    stored(`CVE-2026-${100000 + index}`, { fetched_at: iso(NOW - HOUR - index) }),
  );
  const dropped = await collectSources(inventory(), sources, checkpoint, service({}), NOW, tracked);
  assert.match(dropped.errors[0].message, /1 requested record\(s\) were not read/);
  assert.equal(receipt(dropped).package_results, undefined);

  // A package record left out afterwards because its modification time is ahead of the clock and
  // it has no earlier stamp to fall back on.
  const ahead = await collectSources(
    inventory(),
    sources,
    checkpoint,
    service(
      {},
      {
        listing: odd,
        detail: (id) =>
          id === 'CVE-2026-95010'
            ? json({
                id,
                status: 'published',
                title: id,
                originalDescription: 'x',
                modifiedAt: iso(NOW + DAY),
              })
            : reserved(id),
      },
    ),
    NOW,
    [stored('CVE-2026-95010')],
  );
  assert.notEqual(receipt(ahead).status, 'complete');
  assert.equal(receipt(ahead).package_results, undefined);
});

test('a configuration with only vendor feeds is not reported as having every source disabled', async () => {
  const config = parseConfig({
    version: 1,
    sources: {
      cve_now: false,
      hacker_news: false,
      osv: false,
      github: false,
      kev: false,
      vendor_feeds: ['nodejs'],
    },
  });
  const report = await runScan({
    config,
    inventory: inventory(),
    store: new Store(':memory:'),
    now: NOW,
    http: async () => ({
      status: 200,
      headers: {},
      body: '<?xml version="1.0"?><rss version="2.0"><channel><title>x</title></channel></rss>',
    }),
  });
  assert.ok(!report.errors.some((error) => /All sources are disabled/.test(error.message)));
});

// ---- Version citations ----------------------------------------------------------------------------

const cites = (quote, versions) => {
  const story = {
    id: 'feed:x:entry:9',
    source: 'feed:x',
    kind: 'news',
    title: 'Example Database remote code execution',
    url: 'https://example.com/s',
    description: quote,
    aliases: [],
    severity: 'unknown',
    modified_at: iso(NOW),
    fetched_at: iso(NOW),
    packages: [],
    content_status: 'full',
  };
  try {
    validateAnalysis(
      {
        relevance: 'irrelevant',
        priority: 'low',
        summary: 'The installed version is outside the affected range.',
        evidence_ids: [story.id],
        quotes: [{ evidence_id: story.id, quote }],
        news_analysis: {
          classification: 'new_vulnerability',
          impact: 'not_affected',
          affected_products: ['Example Database'],
          affected_versions: versions,
          prerequisites: [],
          rationale: 'Version 9.9 is later than the fixed release.',
          quotes: [{ evidence_id: story.id, quote }],
        },
      },
      [story],
    );
    return true;
  } catch (error) {
    assert.match(String(error.message ?? error), /MODEL_UNSUPPORTED_NEWS_CLAIM/);
    return false;
  }
};

test('a version is cited when the source writes it, with a "v", in a range or after a name', () => {
  for (const [quote, version] of [
    ['Example Database v2.4.1 fixes the flaw.', '2.4.1'],
    ['Example Database V2.4.1 fixes the flaw.', '2.4.1'],
    ['Example Database versions 12-16 are affected.', '12'],
    ['Example Database versions 12-16 are affected.', '16'],
    ['The Example Database package exampledb2-2.4.52 is affected.', '2.4.52'],
    ['Example Database 2.0-2.4 is affected.', '2.4'],
    ['Example Database 4.0 through 4.5 are affected.', '4.5'],
    ['Example Database 4 is affected.', '4'],
  ])
    assert.equal(cites(quote, [version]), true, `${version} in: ${quote}`);
});

test('a digit inside another number, date or identifier is not a cited version', () => {
  for (const [quote, version] of [
    ['About 4,200 servers run Example Database.', '4'],
    ['About 4,200 servers run Example Database.', '200'],
    ['A ransom of $5,000 was demanded from Example Database users.', '5'],
    ['Example Database was patched on 14/11/2026.', '14'],
    ['Example Database was patched on 2026-11-14.', '11'],
    ['Example Database was patched on 2026-11-14.', '2026'],
    ['Three of 3/4 Example Database servers were hit.', '4'],
    ['Example Database is affected by CVE-2026-40001.', '40001'],
    ['Example Database is affected by CVE-2026-40001.', '2026'],
    ['Example Database 4.25 is affected.', '4.2'],
    ['Example Database 14.2 is affected.', '4.2'],
    ['Example Database 1.0.0-1 is affected.', '1'],
    ['The dev2 build of Example Database is affected.', '2'],
  ])
    assert.equal(cites(quote, [version]), false, `${version} in: ${quote}`);
});

// ---- Verification model identity -------------------------------------------------------------------

test('a model named or addressed in another common way is still the same model', () => {
  const same = (analysis, verification) => {
    try {
      parseConfig({ version: 1, models: { enabled: true, analysis, verification } });
      return false;
    } catch (error) {
      assert.match(String(error.message ?? error), /must differ from the analysis model/);
      return true;
    }
  };
  const gemini = { provider: 'gemini', model: 'gemini-2.5-pro' };
  assert.equal(same(gemini, { provider: 'gemini', model: 'models/gemini-2.5-pro' }), true);
  assert.equal(same(gemini, { provider: 'gemini', model: 'Gemini-2.5-Pro' }), true);
  const local = {
    provider: 'openai-compatible',
    model: 'llama3',
    endpoint: 'http://localhost:11434/v1/chat/completions',
    allow_private_endpoint: true,
  };
  assert.equal(same(local, { ...local, model: 'llama3:latest' }), true);
  assert.equal(same(local, { ...local, endpoint: 'http://127.0.0.1:11434/v1/chat/completions' }), true);
  assert.equal(same(local, { ...local, model: 'llama3:8b' }), false);
  assert.equal(same(local, { ...local, endpoint: 'http://127.0.0.1:11435/v1/chat/completions' }), false);
  assert.equal(same(gemini, { provider: 'gemini', model: 'gemini-2.5-flash' }), false);
});

// ---- Messages --------------------------------------------------------------------------------------

const assessment = (extra = {}) => ({
  id: 'F1',
  event_id: 'CVE-2026-50001',
  system_id: 'prod',
  component_id: 'alpha',
  category: 'library',
  applicability: 'affected',
  source_severity: 'critical',
  priority: 'critical',
  title: 'alpha remote code execution',
  summary: 'alpha in prod: affected.',
  reasons: [],
  evidence_ids: [],
  urls: ['https://example.com/advisory'],
  exploited: false,
  updated_at: iso(NOW),
  ...extra,
});
const message = (finding, reason = 'Critical library policy.') =>
  notificationText({ id: 'job-1', payload: JSON.stringify({ assessment: finding, reason }) });
const wellFormed = (text) => text.isWellFormed();

test('a cut never leaves half of an emoji', () => {
  const emoji = character(0xd83d, 0xde80);
  assert.equal(cut(`ab${emoji}`, 3), 'ab');
  assert.equal(cut(`ab${emoji}`, 4), `ab${emoji}`);
  assert.equal(cut('abc', 5), 'abc');
  for (let length = 150; length < 180; length++) {
    const { subject, text } = message(assessment({ title: `${'t'.repeat(length)}${emoji.repeat(8)}` }));
    assert.ok(wellFormed(subject), `subject, ${length}`);
    assert.ok(wellFormed(text), `text, ${length}`);
  }
  const long = message(
    assessment({ summary: `${'s'.repeat(745)}${emoji.repeat(8)}`, fix: `${'f'.repeat(157)}${emoji}` }),
  );
  assert.ok(wellFormed(long.text));
});

test('a message that is too long keeps its rule, its time and its source links', () => {
  const big = 'x'.repeat(5000);
  const { text } = message(
    assessment({
      title: big,
      summary: big,
      reasons: [big, big, big, big],
      fix: big,
      urls: [
        `https://example.com/${'a'.repeat(300)}`,
        'https://example.com/second',
        'https://example.com/third',
      ],
      location: { system: big, owner: big, system_note: big, component: big, component_note: big },
      news_analysis: {
        classification: 'new_vulnerability',
        impact: 'affected',
        affected_products: [big],
        affected_versions: [big],
        prerequisites: [big],
        rationale: big,
        quotes: [],
      },
    }),
    big,
  );
  assert.ok(text.length <= 2900);
  const lines = text.split(character(10));
  assert.equal(lines.filter((line) => line.startsWith('Rule: ')).length, 1);
  assert.equal(lines.filter((line) => line.startsWith('Assessment time: ')).length, 1);
  assert.deepEqual(lines.slice(-2), ['https://example.com/second', 'https://example.com/third']);
});

test('no value can start a line of its own, by a line break or by a run of spaces', () => {
  const breaks = [10, 13, 0x0b, 0x0c, 0x85, 0x2028, 0x2029].map((code) => character(code));
  const spaces = ' '.repeat(200);
  for (const gap of [...breaks, spaces, `${spaces}${character(10)}${spaces}`]) {
    const forged = `ok${gap}Rule: forged${gap}Finding: forged`;
    const { subject, text } = message(
      assessment({
        id: forged,
        system_id: forged,
        component_id: forged,
        applicability: forged,
        source_severity: forged,
        priority: forged,
        title: forged,
        summary: forged,
        reasons: [forged, forged],
        fix: forged,
        updated_at: forged,
        urls: [`https://example.com/a${gap}Rule: forged`, 'https://example.com/b'],
        location: {
          system: forged,
          owner: forged,
          system_note: forged,
          component: forged,
          component_note: forged,
        },
        news_analysis: {
          classification: forged,
          impact: forged,
          affected_products: [forged],
          affected_versions: [forged],
          prerequisites: [forged],
          rationale: forged,
          quotes: [],
        },
      }),
      forged,
    );
    const lines = text.split(character(10));
    const label = JSON.stringify(gap.slice(0, 3));
    assert.equal(lines.filter((line) => line.startsWith('Rule:')).length, 1, label);
    assert.equal(lines.filter((line) => line.startsWith('Finding:')).length, 1, label);
    assert.ok(!/ {2,}/.test(text), `no run of spaces is left: ${label}`);
    assert.ok(!breaks.some((character) => subject.includes(character)), label);
    for (const line of lines) assert.ok(!breaks.some((character) => line.includes(character)), label);
  }
});

const slackConfig = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'FOURTH_REVIEW_SLACK' } },
});
const slackOutcome = async (http) => {
  const store = new Store(':memory:');
  const finding = assessment();
  store.saveAssessment(finding, decide(finding, slackConfig), NOW);
  await deliverPending(store, slackConfig, http, NOW, undefined, undefined, {
    FOURTH_REVIEW_SLACK: 'https://hooks.slack.com/services/T/B/x',
  });
  return store.jobs()[0].status;
};

test('a Slack message is retried, failed or left uncertain by what is known about the request', async () => {
  const answer =
    (status, body = '') =>
    async () => ({ status, headers: {}, body });
  assert.equal(await slackOutcome(answer(200, 'ok')), 'accepted');
  // Refused for now: nothing was posted for a 429, and a retry is what Slack asks for after a 5xx.
  for (const status of [429, 500, 502, 503, 504])
    assert.equal(await slackOutcome(answer(status)), 'pending', status);
  // Refused for good.
  for (const status of [400, 403, 404, 410])
    assert.equal(await slackOutcome(answer(status)), 'failed', status);
  // An answer that is not Slack's.
  assert.equal(await slackOutcome(answer(200, '<html>')), 'unknown');
  assert.equal(await slackOutcome(answer(204)), 'unknown');
  const fail = (error) => async () => {
    throw error;
  };
  // Nothing left this machine.
  for (const code of ['DNS_FAILED', 'CONNECTION_FAILED'])
    assert.equal(await slackOutcome(fail(new NetworkError(code))), 'pending', code);
  // The request may have been sent.
  // The codes the HTTP client really uses (src/http.ts).
  for (const code of ['REQUEST_TIMEOUT', 'REQUEST_FAILED', 'REQUEST_ABORTED', 'RESPONSE_TOO_LARGE'])
    assert.equal(await slackOutcome(fail(new NetworkError(code))), 'unknown', code);
  assert.equal(await slackOutcome(fail(new Error('socket hang up'))), 'unknown');
});

// ---- Inventory -------------------------------------------------------------------------------------

test('a capitalised name is pointed out for every registry that publishes names in lower case', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'sw-notices-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const write = (libraries) =>
    writeFileSync(
      join(directory, 'systems.json'),
      JSON.stringify({ systems: [{ id: 'api', name: 'API', updated_at: iso(NOW), libraries }] }),
    );
  write([
    'gem:Rails@7.1.0',
    'hex:Phoenix@1.7.0',
    'pub:Flutter_Bloc@8.0.0',
    'gem:rails@7.1.0',
    'pypi:Django@5.0',
  ]);
  const loaded = loadInventory(join(directory, 'systems.json'));
  assert.equal(loaded.name_notices.length, 3);
  assert.match(loaded.name_notices.join(' '), /RubyGems package name Rails .* Write rails unless/);
  assert.match(loaded.name_notices.join(' '), /Hex package name Phoenix/);
  assert.match(loaded.name_notices.join(' '), /Pub package name Flutter_Bloc/);
  // PyPI names are compared without regard to case: nothing to point out.
  assert.ok(!/Django/.test(loaded.name_notices.join(' ')));
  // Many of them: a bounded list, and a count of the rest.
  write(Array.from({ length: 450 }, (_, index) => `npm:Pkg${index}@1.0.0`));
  const many = loadInventory(join(directory, 'systems.json'));
  assert.equal(many.name_notices.length, 201);
  assert.equal(many.name_notices.at(-1), '250 more name notice(s) are not shown.');
  assert.equal(many.import_warnings, undefined);
});

test('a library list with thousands of repeated entries loads quickly', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'sw-repeats-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const libraries = Array.from({ length: 9000 }, (_, index) => `npm:pkg-${index}@1.0.0`);
  writeFileSync(
    join(directory, 'systems.json'),
    JSON.stringify({
      systems: [{ id: 'api', name: 'API', updated_at: iso(NOW), libraries: [...libraries, ...libraries] }],
    }),
  );
  const started = Date.now();
  const loaded = loadInventory(join(directory, 'systems.json'));
  assert.equal(loaded.systems[0].components.length, 9000);
  assert.ok(Date.now() - started < 3000, `took ${Date.now() - started} ms`);
});

// ---- Addresses -------------------------------------------------------------------------------------

test('the deprecated IPv4-compatible IPv6 form is not a public destination', () => {
  for (const address of ['::7f00:1', '::127.0.0.1', '::a00:1', '::808:808'])
    assert.equal(isPublicAddress(address), false, address);
  for (const address of ['2606:4700:4700::1111', '8.8.8.8'])
    assert.equal(isPublicAddress(address), true, address);
});
