// Regressions from the ninth release review: package lookups that failed are sent after the
// others, what earlier lookups matched stays when a lookup is not sent, the stale-evidence window,
// connector words, the fix line and shortening, and the release checks run before a publish.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assess } from '../dist/assessment.js';
import { notificationText, smtpTranscript } from '../dist/delivery.js';
import { validateAnalysis } from '../dist/models.js';
import { packageMentioned } from '../dist/matching.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';
import { releaseChecks, releaseTag } from '../scripts/release-tag.mjs';

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
    github_token_env: 'TENTH_REVIEW_UNUSED',
    kev: false,
    feeds: [],
  },
};
const inventory = (names) => ({
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
const numbered = (count) =>
  Array.from({ length: count }, (_, index) => `pkg-${String(index).padStart(5, '0')}`);

/** Polls 30 minutes apart; `answer(key, poll)` returns a lookup response or nothing for "no match". */
async function polls(names, times, answer = () => undefined, start = {}) {
  let checkpoints = { cve_now: iso(NOW - HOUR), ...start };
  const rounds = [];
  for (let poll = 0; poll < times; poll++) {
    const asked = [];
    const http = async (url) => {
      const { pathname, searchParams } = new URL(url);
      if (pathname === '/stack') {
        const key = searchParams.get('p');
        asked.push(key);
        return answer(key, poll) ?? json({ packages: 1, entries: [] });
      }
      if (pathname === '/api/v1/entries') return json({ entries: [] });
      return { status: 404, headers: {}, body: '' };
    };
    const result = await collectSources(
      inventory(names),
      sources,
      checkpoints,
      http,
      NOW + poll * 1_800_000,
      [],
    );
    checkpoints = result.checkpoints;
    rounds.push({ asked, result });
  }
  return rounds;
}

// ---- Lookup order ----------------------------------------------------------------------------------

test('a lookup that failed is sent after the others on the next poll', async () => {
  const names = ['alpha', 'bravo', 'charlie', 'delta', 'echo'];
  const rounds = await polls(names, 2, (key, poll) =>
    key === 'npm:bravo@1.0.0' && poll === 0 ? { status: 500, headers: {}, body: '' } : undefined,
  );
  assert.equal(rounds[0].asked[1], 'npm:bravo@1.0.0');
  assert.equal(rounds[1].asked.at(-1), 'npm:bravo@1.0.0', 'bravo goes last after failing');
});

test('lookups that keep failing never keep the others from being looked up', async () => {
  // The four first by name fail on every poll, a whole batch at once, which ends a poll's lookups.
  const names = ['alpha', 'bravo', 'charlie', 'delta', ...numbered(8)];
  const broken = new Set(names.slice(0, 4).map((name) => `npm:${name}@1.0.0`));
  const rounds = await polls(names, 4, (key) =>
    broken.has(key) ? { status: 500, headers: {}, body: '' } : undefined,
  );
  assert.equal(rounds[0].asked.length, 4, 'the first poll stops at them');
  for (const { asked } of rounds.slice(1)) {
    assert.equal(asked.length, names.length, 'every later poll looks up all of them');
    assert.deepEqual(new Set(asked.slice(-4)), broken, 'the failing ones last');
  }
});

test('a version never looked up goes first, and a last-tried time ahead of the clock counts as now', async () => {
  const names = numbered(1_001);
  const history = names.map((name, index) => [`${name}@1.0.0`, index === 0 ? NOW + 1e12 : NOW - 1_000]);
  const rounds = await polls([...names, 'zz-new'], 2, undefined, {
    'cve_now:lookups': JSON.stringify(history),
  });
  assert.equal(rounds[0].asked[0], 'npm:zz-new@1.0.0', 'the new version first');
  assert.ok(!rounds[0].asked.includes('npm:pkg-00000@1.0.0'), 'the one stamped "now" waits');
  assert.ok(rounds[1].asked.includes('npm:pkg-00000@1.0.0'), 'and has its turn on the next poll');
});

test('eight failed lookups end the lookups of a poll', async () => {
  // One in every batch of four fails, so no batch fails as a whole.
  const names = numbered(60);
  const rounds = await polls(names, 1, (key) =>
    Number(key.slice(8, 13)) % 4 === 0 ? { status: 500, headers: {}, body: '' } : undefined,
  );
  assert.equal(rounds[0].asked.length, 32);
  // Eight failed and the 28 after them were not sent.
  assert.match(rounds[0].result.errors[0].message, /36 package lookup request\(s\) failed or were not sent/);
});

test('package results are not complete while some lookups were not sent', async () => {
  const [round] = await polls(numbered(1_001), 1);
  assert.equal(round.asked.length, 1_000);
  const receipt = round.result.coverage.find((item) => item.source === 'cve_now');
  assert.equal(receipt.package_results, undefined);
  assert.notEqual(receipt.status, 'complete');
  // With every lookup sent the poll is complete (a partial poll with every lookup sent is marked
  // in test/fourth-review-regressions.test.mjs).
  const [small] = await polls(numbered(3), 1);
  assert.equal(small.result.coverage.find((item) => item.source === 'cve_now').status, 'complete');
});

// ---- What earlier lookups matched -----------------------------------------------------------------

test('what an earlier lookup matched stays when that lookup is not sent this poll', async () => {
  // alpha is looked up on the first poll and matched to two records: one whose affected list names
  // alpha without a usable range, one that does not name it at all. On the second poll the 1,000
  // versions never tried are looked up and alpha is not.
  const names = ['alpha', ...numbered(2_000)];
  const record = (id, affected) =>
    json({
      id,
      status: 'published',
      title: `${id} flaw`,
      originalDescription: 'A flaw.',
      severity: { cvss: 9.8 },
      affected,
      publishedAt: iso(NOW - 2 * DAY),
      modifiedAt: iso(NOW - 2 * DAY),
    });
  const records = {
    'CVE-2026-90001': record('CVE-2026-90001', [{ ecosystem: 'npm', package: 'alpha' }]),
    'CVE-2026-90002': record('CVE-2026-90002', [{ ecosystem: 'npm', package: 'other' }]),
  };
  const store = new Store(':memory:');
  const results = [];
  for (const poll of [0, 1]) {
    const now = NOW + poll * 1_800_000;
    const asked = [];
    const http = async (url) => {
      const { pathname, searchParams } = new URL(url);
      if (pathname === '/stack') {
        asked.push(searchParams.get('p'));
        return searchParams.get('p') === 'npm:alpha@1.0.0'
          ? json({
              items: Object.keys(records).map((id) => ({
                id,
                _cve_now: { matched: { ecosystem: 'npm', name: 'alpha', version: '1.0.0' } },
              })),
            })
          : json({ packages: 1, entries: [] });
      }
      if (pathname === '/api/v1/entries') return json({ entries: [] });
      return (
        records[decodeURIComponent(pathname.split('/').at(-1))] ?? { status: 404, headers: {}, body: '' }
      );
    };
    const result = await collectSources(
      inventory(names),
      sources,
      store.checkpoints(),
      http,
      now,
      store.evidence(),
    );
    store.saveEvidence(result.evidence, result.checkpoints);
    results.push({
      alphaAsked: asked.includes('npm:alpha@1.0.0'),
      findings: assess(inventory(names), store.evidence(), sources, now)
        .filter((finding) => finding.component_id === 'c:alpha')
        .map((finding) => finding.applicability)
        .sort(),
    });
  }
  assert.deepEqual(results, [
    { alphaAsked: true, findings: ['affected', 'affected'] },
    { alphaAsked: false, findings: ['affected', 'affected'] },
  ]);
});

// ---- Stale evidence ----------------------------------------------------------------------------------

test('evidence counts as stale after two poll intervals, not one and not three', () => {
  const inv = inventory(['dep']);
  inv.systems[0].components[0].version = '2.0.0';
  const advisory = (age) => ({
    id: 'CVE-2026-90100',
    source: 'osv',
    kind: 'advisory',
    title: 'Synthetic advisory',
    url: 'https://example.com/advisory',
    description: '',
    aliases: [],
    severity: 'high',
    fetched_at: iso(NOW - age),
    modified_at: iso(NOW - DAY),
    packages: [{ ecosystem: 'npm', name: 'dep', range: '<2.0.0', fixed: '2.0.0' }],
  });
  const config = { ...sources, poll_interval_minutes: 30 };
  const applicability = (age) => assess(inv, [advisory(age)], config, NOW)[0].applicability;
  assert.equal(applicability(45 * 60_000), 'not_affected', 'one and a half intervals');
  assert.equal(applicability(59 * 60_000), 'not_affected', 'just under two intervals');
  assert.equal(applicability(61 * 60_000), 'unknown', 'just over two intervals');
  assert.equal(applicability(89 * 60_000), 'unknown', 'under three intervals');
});

// ---- Matching ----------------------------------------------------------------------------------------

test('a connector word before a short version is not a release of a package named like it', () => {
  const mentioned = (name, text) => packageMentioned(text, { ecosystem: 'npm', name });
  for (const [name, text] of [
    ['until', 'Until 4.2 ships, administrators should disable the feature.'],
    ['from', 'From 2.1 on, the option is removed.'],
    ['after', 'After 3.4 the flag is gone.'],
    ['through', 'Through 7.0 the appliance accepts the request.'],
  ])
    assert.equal(mentioned(name, text), false, `${name}: ${text}`);
  // A name that is not a connector word still takes the form.
  assert.equal(mentioned('lodash', 'Lodash 4.17 fixes a prototype pollution flaw.'), true);
});

// ---- Message ---------------------------------------------------------------------------------------

const assessment = (extra = {}) => ({
  id: 'finding-1',
  system_id: 'prod',
  component_id: 'c:dep',
  title: 'dep flaw',
  priority: 'high',
  applicability: 'affected',
  source_severity: 'high',
  summary: 'A flaw in dep.',
  reasons: [],
  urls: [],
  updated_at: iso(NOW),
  ...extra,
});
const message = (a, reason = 'new finding') =>
  notificationText({ id: 'delivery-1', payload: JSON.stringify({ assessment: a, reason }) }).text;

test('a fixed version too long to show does not hide the short ones after it', () => {
  const text = message(assessment({ fix: `${'9'.repeat(130)}, 1.2.3` }));
  assert.match(text, /^Fix: 1\.2\.3; and 1 more \(run explain for all\)$/m);
  assert.match(message(assessment({ fix: '9'.repeat(130) })), /^Fix: 1 version\(s\) too long to show/m);
});

test('a long message keeps the lines every message has, leaving out links and notes first', () => {
  const url = (index) => `https://example.com/${String(index).repeat(300).slice(0, 300)}`;
  const longest = (extra = {}) =>
    assessment({
      title: 'T'.repeat(400),
      id: 'F'.repeat(200),
      system_id: 'S'.repeat(200),
      component_id: 'C'.repeat(200),
      location: {
        system: 'W'.repeat(120),
        owner: 'O'.repeat(80),
        system_note: 'N'.repeat(300),
        component: 'I'.repeat(160),
        component_note: 'M'.repeat(300),
      },
      exploited: true,
      summary: 'Y'.repeat(750),
      reasons: Array.from({ length: 20 }, (_, index) => `reason ${index} ${'r'.repeat(170)}`),
      fix: Array.from({ length: 30 }, (_, index) => `${index}.${'0'.repeat(100)}`).join(', '),
      urls: [url(1), url(2), url(3)],
      ...extra,
    });
  // Every field at its longest: the links and then the notes are left out, the summary stays whole.
  const text = message(longest(), 'R'.repeat(180));
  assert.ok(text.length <= 2900, `${text.length} characters`);
  assert.doesNotMatch(text, /^https:/m);
  assert.doesNotMatch(text, /NNN|MMM/);
  assert.match(text, new RegExp(`^Summary: ${'Y'.repeat(750)}$`, 'm'));
  for (const label of [
    'Finding:',
    'Delivery:',
    'System:',
    'Where to look:',
    'Affected item:',
    'Applicability:',
    'Summary:',
    'Fix:',
    'Rule:',
    'Assessment time:',
  ])
    assert.match(text, new RegExp(`^${label}`, 'm'), label);
  assert.match(text, /^\(Message shortened; run explain for the full finding\.\)$/m);
  // A shorter summary and fix leave room for the notes and the first link, not the other two.
  const some = message(longest({ summary: 'Y'.repeat(100), fix: '1.2.3' }), 'R'.repeat(180));
  assert.ok(some.length <= 2900, `${some.length} characters`);
  assert.deepEqual(some.match(/^https:.*$/gm), [url(1)]);
  assert.match(some, new RegExp(`N{300}`));
  assert.match(some, new RegExp(`M{300}`));
  // Short inputs keep everything, with no note.
  const short = message(assessment({ reasons: ['one'], urls: ['https://example.com/a'] }));
  assert.doesNotMatch(short, /Message shortened/);
  assert.match(short, /^https:\/\/example\.com\/a$/m);
});

test('reasons give way before links do', () => {
  const text = message(
    assessment({
      summary: 'Y'.repeat(750),
      reasons: Array.from({ length: 30 }, (_, index) => `reason ${index} ${'r'.repeat(170)}`),
      urls: ['https://example.com/a', 'https://example.com/b'],
    }),
  );
  assert.ok(text.length <= 2900);
  assert.match(text, /Message shortened/);
  assert.match(text, /^https:\/\/example\.com\/a$/m);
  assert.match(text, /^https:\/\/example\.com\/b$/m);
});

// ---- Release -----------------------------------------------------------------------------------------

test('every prerelease form goes to the next tag', () => {
  for (const version of ['1.0.0-rc.1', '1.0.0-beta.2', '1.0.0-alpha', '2.0.0-0', '1.1.0-next.3'])
    assert.equal(releaseTag(version), 'next', version);
  for (const version of ['1.0.0', '2.3.4']) assert.equal(releaseTag(version), 'latest', version);
});

/** A stand-in for git and npm that records each command and answers as the case needs. */
function releaseRun(overrides = {}) {
  const calls = [];
  const answers = {
    status: [''],
    registry: 'https://registry.npmjs.org/',
    scoped: 'undefined',
    packed: ['package.json', 'README.md', 'dist/index.js'],
    tracked: ['package.json', 'README.md'],
    ...overrides,
  };
  let statuses = 0;
  const run = (command, args, options) => {
    calls.push({ command, args, options });
    if (command === 'git' && args[0] === 'status')
      return answers.status[Math.min(statuses++, answers.status.length - 1)];
    if (command === 'git' && args[0] === 'ls-files') return answers.tracked.join('\0');
    const [, ...npm] = args;
    if (npm[0] === 'config') return `${npm[2] === 'registry' ? answers.registry : answers.scoped}\n`;
    if (npm[0] === 'run') return null;
    if (npm[0] === 'pack') return JSON.stringify([{ files: answers.packed.map((path) => ({ path })) }]);
    throw new Error(`unexpected ${command} ${args.join(' ')}`);
  };
  return { run, calls };
}
const releaseEnv = (extra = {}) => ({
  npm_execpath: '/npm-cli.js',
  SECURITY_WATCH_RELEASE_TAG: 'next',
  npm_config_dry_run: 'true',
  npm_config_tag: 'next',
  NPM_CONFIG_OTP: '123456',
  PATH: '/bin',
  ...extra,
});
const manifest = { version: '1.0.0-rc.1', publishConfig: { tag: 'next' } };
const check = (run, env = releaseEnv(), m = manifest) =>
  releaseChecks({ root: '/repo', env, manifest: m, run });

test('the release checks pass a clean, tracked, official-registry publish and run the full check', () => {
  const { run, calls } = releaseRun();
  assert.equal(check(run), '/repo');
  const npmRun = calls.find((call) => call.args[1] === 'run');
  assert.deepEqual(npmRun.args, ['/npm-cli.js', 'run', 'check']);
  assert.equal(npmRun.options.stdio, 'inherit');
  // The publish's own options are not passed on to the checks.
  for (const key of ['npm_config_dry_run', 'npm_config_tag', 'NPM_CONFIG_OTP'])
    assert.equal(npmRun.options.env[key], undefined, key);
  assert.equal(npmRun.options.env.PATH, '/bin');
  const pack = calls.find((call) => call.args[1] === 'pack');
  assert.deepEqual(pack.args.slice(1), ['pack', '--dry-run', '--json', '--ignore-scripts']);
  assert.equal(pack.options.env.npm_config_dry_run, undefined);
  assert.deepEqual(
    calls.filter((call) => call.args[1] === 'config').map((call) => call.args[3]),
    ['registry', '@shieldaai:registry'],
  );
  // The tree is checked before and after.
  assert.equal(calls.filter((call) => call.command === 'git' && call.args[0] === 'status').length, 2);
});

test('the release checks refuse each unsafe publish', () => {
  const refused = (overrides, env, m, pattern) => {
    const { run, calls } = releaseRun(overrides);
    assert.throws(() => check(run, env, m), pattern);
    return calls;
  };
  const dirty = refused({ status: [' M src/index.ts'] }, undefined, undefined, /clean committed checkout/);
  assert.equal(dirty.length, 1, 'nothing else runs');
  refused({}, releaseEnv({ npm_execpath: '' }), undefined, /Run through npm run release/);
  refused({}, releaseEnv({ npm_config_ignore_scripts: 'true' }), undefined, /ignore scripts/);
  refused({ registry: 'https://npm.example.com/' }, undefined, undefined, /npm\.example\.com/);
  refused({ scoped: 'https://scoped.example.com/' }, undefined, undefined, /scoped\.example\.com/);
  refused({}, releaseEnv({ SECURITY_WATCH_RELEASE_TAG: undefined }), undefined, /npm run release/);
  refused({}, undefined, { version: '1.0.0-beta.1', publishConfig: { tag: 'latest' } }, /must be next/);
  const beforeCheck = refused({ registry: 'https://npm.example.com/' }, undefined, undefined, /npm\.example/);
  assert.ok(!beforeCheck.some((call) => call.args[1] === 'run'), 'refused before the full check runs');
  refused(
    { packed: ['package.json', 'docs/secret.md', 'dist/index.js'] },
    undefined,
    undefined,
    /not in git: docs\/secret\.md/,
  );
  refused({ status: ['', '?? dist-new.txt'] }, undefined, undefined, /Release checks changed source/);
});

test('a failing full check stops the release', () => {
  const { run } = releaseRun();
  const failing = (command, args, options) => {
    if (args[1] === 'run') throw new Error('Command failed: npm run check');
    return run(command, args, options);
  };
  assert.throws(() => check(failing), /npm run check/);
});

// ---- Smaller guards the ninth release review found untested ------------------------------------

test('the package name rules depend on the ecosystem asked about', () => {
  const mentioned = (ecosystem, name, text) => packageMentioned(text, { ecosystem, name });
  const text = 'node-tar arbitrary file creation flaw fixed in 6.2.1';
  // The same text, asked for npm and then for other ecosystems: no answer is reused.
  assert.equal(mentioned('npm', 'tar', text), true);
  assert.equal(mentioned('Go', 'tar', text), false);
  assert.equal(mentioned('Maven', 'tar', text), false);
  assert.equal(mentioned('PyPI', 'tar', text), false);
});

test('a quoted common word before "package" is the package; "that" is never a list entry', () => {
  const mentioned = (name, text) => packageMentioned(text, { ecosystem: 'npm', name });
  assert.equal(mentioned('once', 'The "once" package was taken over and republished.'), true);
  assert.equal(mentioned('that', 'The npm packages qrlib-pad, that and xlsx-parser ran a script.'), false);
});

const cites = (quote, version) => {
  const story = {
    id: 'feed:x:entry:10',
    source: 'feed:x',
    kind: 'news',
    title: 'Example server remote code execution',
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
          affected_products: ['Example server'],
          affected_versions: [version],
          prerequisites: [],
          rationale: 'The installed version is later than the fixed release.',
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

test('version citations: invisible marks, chained hyphens, thousands, plus signs and dated qualifiers', () => {
  // Any character that shows as nothing is dropped, not only the zero-width space.
  for (const mark of [0x2060, 0x00ad, 0x200d, 0xfeff])
    assert.equal(cites(`Example server 2.4${String.fromCharCode(mark)}.1 is affected.`, '2.4.1'), true, mark);
  for (const [text, version] of [
    // A third part joined by a hyphen makes one identifier, on either side.
    ['Example server 1.0-1.2-2.3 is affected.', '2.3'],
    ['Example server build-node-18 is affected.', '18'],
    // A number before a version with no letter in it is not a name.
    ['Example server 2026-2.4.1 is affected.', '2.4.1'],
    // A thousands separator, a sum, a dated release.
    ["Example server 4'200 users are affected.", '200'],
    ['Example server sum 1+2 is affected.', '2'],
    ['Example server 9.4.51.v202302 is affected.', '9.4.51'],
  ])
    assert.equal(cites(text, version), false, `${version} in ${text}`);
  assert.equal(cites('Example server node-18 is affected.', '18'), true);
  assert.equal(cites('Example server openssl-3.0.7 is affected.', '3.0.7'), true);
});

test('list entries of the news analysis are shown whole', () => {
  const product = `Example ${'p'.repeat(100)} server`;
  const text = message(
    assessment({
      news_analysis: {
        classification: 'new_vulnerability',
        impact: 'affected',
        affected_products: [product],
        affected_versions: ['2.4.1'],
        prerequisites: [],
        rationale: 'Named product.',
      },
    }),
  );
  assert.ok(text.includes(`Affected products: ${product}`));
});

test('group mentions are broken whatever their case, and longer words are left alone', () => {
  const ZWSP = String.fromCharCode(0x200b);
  const text = message(assessment({ summary: 'Ping @Channel and @HERE; see @heretic and @everyones.' }));
  assert.ok(text.includes(`@${ZWSP}Channel`));
  assert.ok(text.includes(`@${ZWSP}HERE`));
  assert.ok(text.includes('@heretic'));
  assert.ok(text.includes('@everyones'));
});

test('only the first server line decides whether the service speaks SMTP', () => {
  const smtp = smtpTranscript();
  smtp.observe({ tnx: 'server' }, '220 mail.example ESMTP');
  smtp.observe({ tnx: 'server' }, 'unexpected text');
  assert.equal(smtp.nothingHandedOver(), false);
  const other = smtpTranscript();
  other.observe({ tnx: 'server' }, '2200 ready');
  assert.equal(other.nothingHandedOver(), true, 'four digits are not an SMTP reply code');
});
