// Regressions from the tenth reviews of delivery and of collection: a group mention made by
// cutting a value, model claims that are fragments of a word, the order in which a long message
// gives way, Slack pauses, and the guards of the stale rule and package lookups.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assess, decide } from '../dist/assessment.js';
import { deliverPending, notificationText } from '../dist/delivery.js';
import { packageMentioned } from '../dist/matching.js';
import { validateAnalysis } from '../dist/models.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });
const ZWSP = String.fromCharCode(0x200b);

const assessment = (extra = {}) => ({
  id: 'finding-1',
  event_id: 'CVE-2026-91001',
  system_id: 'prod',
  component_id: 'c:dep',
  category: 'library',
  title: 'dep flaw',
  priority: 'critical',
  applicability: 'affected',
  source_severity: 'critical',
  summary: 'A flaw in dep.',
  reasons: [],
  evidence_ids: [],
  urls: [],
  exploited: false,
  updated_at: iso(NOW),
  ...extra,
});
const render = (a, id = 'delivery-1', reason = 'new finding') =>
  notificationText({ id, payload: JSON.stringify({ assessment: a, reason }) });

// ---- Message text ----------------------------------------------------------------------------------

test('cutting a value never leaves a bare group mention', () => {
  const { subject, text } = render(
    assessment({
      title: `${'t'.repeat(162)} @heresy`,
      system_id: `${'s'.repeat(190)} @channelsxyz`,
      summary: `${'y'.repeat(739)} @everyoneelse`,
    }),
  );
  for (const value of [subject, text])
    assert.doesNotMatch(value, /@(?:channel|here|everyone)(?![\p{L}\p{N}_])/u, value.slice(-40));
  assert.ok(subject.includes(`@${ZWSP}here…`), subject.slice(-20));
  assert.ok(text.includes(`@${ZWSP}channel…`));
  assert.ok(text.includes(`@${ZWSP}everyone…`));
});

test('a source link with a group mention in it is left out, and @group is guarded', () => {
  const { text } = render(
    assessment({
      summary: 'Ping @group and @GROUP.',
      urls: ['https://example.com/@channel', 'https://example.com/a', 'https://example.com/@Here/x'],
    }),
  );
  assert.ok(text.includes(`@${ZWSP}group`) && text.includes(`@${ZWSP}GROUP`));
  assert.deepEqual(text.match(/^https:.*$/gm), ['https://example.com/a']);
});

test('a model list entry longer than its line is counted, not shown', () => {
  const { text } = render(
    assessment({
      news_analysis: {
        classification: 'new_vulnerability',
        impact: 'affected',
        affected_products: [`Example ${'p'.repeat(200)}`, 'Example server'],
        affected_versions: ['2.4.1'],
        prerequisites: [],
        rationale: 'Named product.',
      },
    }),
  );
  assert.match(text, /^Affected products: and 2 more$/m);
});

const url = (index) => `https://example.com/${String(index).repeat(300).slice(0, 300)}`;
const longest = (extra = {}) =>
  assessment({
    title: 'T'.repeat(400),
    id: 'F'.repeat(200),
    system_id: 'S'.repeat(200),
    component_id: 'C'.repeat(200),
    applicability: 'a'.repeat(40),
    source_severity: 'b'.repeat(40),
    priority: 'c'.repeat(40),
    location: {
      system: 'W'.repeat(120),
      owner: 'O'.repeat(80),
      system_note: 'N'.repeat(300),
      component: 'I'.repeat(160),
      component_note: 'M'.repeat(300),
    },
    exploited: true,
    summary: 'Y'.repeat(750),
    reasons: ['r'.repeat(170)],
    fix: Array.from({ length: 30 }, (_, index) => `${index}.${'0'.repeat(100)}`).join(', '),
    urls: [url(1), url(2), url(3)],
    ...extra,
  });

test('once the notes give way no link comes back', () => {
  // The notes do not fit with any link, and would with one link once the notes are gone.
  const { text } = render(
    longest({ summary: 'Y'.repeat(400), fix: '1.2.3' }),
    'D'.repeat(200),
    'R'.repeat(180),
  );
  assert.ok(text.length <= 2900, `${text.length}`);
  if (!/N{300}/.test(text)) assert.doesNotMatch(text, /^https:/m, 'links went before the notes');
});

test('every field at its limit, the internal ones included, still fits one Slack section', () => {
  const { text } = render(longest(), 'D'.repeat(200), 'R'.repeat(180));
  assert.ok(text.length <= 2900, `${text.length}`);
  for (const label of [
    'Finding:',
    'System:',
    'Where to look:',
    'Affected item:',
    'Summary:',
    'Fix:',
    'Rule:',
  ])
    assert.match(text, new RegExp(`^${label}`, 'm'), label);
  assert.match(text, /^Summary: Y+…$/m, 'only then is the summary cut');
  const mentions = render(longest({ summary: '@here '.repeat(125) }), 'D'.repeat(200), 'R'.repeat(180)).text;
  assert.ok(mentions.length <= 2900, `${mentions.length} with mention breaks`);
});

// ---- Model claims ----------------------------------------------------------------------------------

const story = (quote) => ({
  id: 'feed:x:entry:11',
  source: 'feed:x',
  kind: 'news',
  title: 'Example remote code execution',
  url: 'https://example.com/s',
  description: quote,
  aliases: [],
  severity: 'unknown',
  modified_at: iso(NOW),
  fetched_at: iso(NOW),
  packages: [],
  content_status: 'full',
});
const analysis = (quote, news) => {
  const item = story(quote);
  try {
    validateAnalysis(
      {
        relevance: 'irrelevant',
        priority: 'low',
        summary: 'Checked.',
        evidence_ids: [item.id],
        quotes: [{ evidence_id: item.id, quote }],
        news_analysis: {
          classification: 'new_vulnerability',
          impact: 'not_affected',
          affected_products: ['Example server'],
          affected_versions: ['4.17.1'],
          prerequisites: [],
          rationale: 'Checked.',
          quotes: [{ evidence_id: item.id, quote }],
          ...news,
        },
      },
      [item],
    );
    return 'accepted';
  } catch (error) {
    return String(error.message ?? error);
  }
};

test('a product or prerequisite claim must be whole words of the quote', () => {
  const quote =
    'Example server and expressive-forms 4.17.1 are affected for unauthenticated users of Node.js.';
  for (const news of [
    { affected_products: ['express'] },
    { affected_products: ['forms 4'] },
    { affected_products: ['Node'] },
    { prerequisites: ['authenticated'] },
  ])
    assert.equal(analysis(quote, news), 'MODEL_UNSUPPORTED_NEWS_CLAIM', JSON.stringify(news));
  for (const news of [
    { affected_products: ['Example server'] },
    { affected_products: ['expressive-forms'] },
    { affected_products: ['EXAMPLE  server'] },
    { affected_products: ['Node.js'] },
    { prerequisites: ['unauthenticated users'] },
  ])
    assert.equal(analysis(quote, news), 'accepted', JSON.stringify(news));
});

test('an unknown classification cannot carry a decisive impact', () => {
  const quote = 'Example server 4.17.1 is affected.';
  assert.equal(
    analysis(quote, { classification: 'unknown', impact: 'affected' }),
    'MODEL_INCONSISTENT_NEWS_ANALYSIS',
  );
  assert.equal(analysis(quote, { classification: 'unknown', impact: 'unknown' }), 'accepted');
});

// ---- Slack pauses ----------------------------------------------------------------------------------

const deliveryConfig = {
  digest_interval_hours: 24,
  policy: {
    library: { levels: ['critical'], basis: 'source_severity', channels: ['slack'] },
    product: { levels: ['critical'], basis: 'source_severity', channels: ['slack'] },
    news: { levels: ['critical'], basis: 'source_severity', channels: ['slack'] },
    health_channels: ['slack'],
    urgent_unknown: true,
    exploited_override: true,
    malware_override: true,
  },
  notifications: { max_attempts: 3, slack: { webhook_url_env: 'TENTH_FOLLOWUP_SLACK' } },
};
function slackStore(t, findings) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  process.env.TENTH_FOLLOWUP_SLACK = 'https://hooks.slack.com/services/T/B/secret';
  t.after(() => delete process.env.TENTH_FOLLOWUP_SLACK);
  for (const id of findings)
    store.saveAssessment(
      assessment({ id }),
      { action: 'notify', channels: ['slack'], reason: 'critical' },
      1000,
    );
  return store;
}

test('a Slack rate limit pauses every Slack job, not only the one refused', async (t) => {
  const store = slackStore(t, ['finding-1', 'finding-2']);
  let calls = 0;
  const http = async () => {
    calls++;
    return calls === 1
      ? { status: 429, body: 'limited', headers: { 'Retry-After': '20' } }
      : { status: 200, body: 'ok', headers: {} };
  };
  await deliverPending(store, deliveryConfig, http, 1000);
  assert.equal(calls, 1);
  // Pacing alone would allow the other job a second later; the pause does not.
  await deliverPending(store, deliveryConfig, http, 5000);
  assert.equal(calls, 1);
  await deliverPending(store, deliveryConfig, http, 21000);
  assert.equal(calls, 2);
});

test('Retry-After: 0 still waits a second', async (t) => {
  const store = slackStore(t, ['finding-1']);
  await deliverPending(
    store,
    deliveryConfig,
    async () => ({ status: 429, body: 'limited', headers: { 'Retry-After': '0' } }),
    1000,
  );
  assert.equal(store.jobs()[0].available_at, 2000);
  assert.equal(store.jobs()[0].status, 'pending');
});

// ---- Stale rule ------------------------------------------------------------------------------------

const inventory = (names) => ({
  systems: [
    {
      id: 'prod',
      name: 'prod',
      updated_at: iso(NOW),
      products: [],
      keywords: [],
      components: names.map((name) => ({ id: `c:${name}`, ecosystem: 'npm', name, version: '2.0.0' })),
    },
  ],
});
const advisory = (id, fetched) => ({
  id,
  source: 'osv',
  kind: 'advisory',
  title: 'Synthetic advisory',
  url: 'https://example.com/advisory',
  description: '',
  aliases: [id],
  severity: 'high',
  fetched_at: iso(fetched),
  modified_at: iso(NOW - DAY),
  packages: [{ ecosystem: 'npm', name: 'dep', range: '<2.0.0', fixed: '2.0.0' }],
});
const config = {
  news_lookback_minutes: 40,
  poll_interval_minutes: 30,
  inventory_stale_days: 30,
  policy: {},
};

test('one stale record among fresh ones withdraws the exclusion, and so does a fetch time ahead of the clock', () => {
  const applicability = (items) => assess(inventory(['dep']), items, config, NOW)[0].applicability;
  assert.equal(applicability([advisory('CVE-2026-91101', NOW)]), 'not_affected');
  assert.equal(
    applicability([
      advisory('CVE-2026-91101', NOW),
      { ...advisory('CVE-2026-91101', NOW - 3 * HOUR), id: 'github:x' },
    ]),
    'unknown',
  );
  assert.equal(applicability([advisory('CVE-2026-91101', NOW + HOUR)]), 'unknown');
  assert.equal(
    applicability([advisory('CVE-2026-91101', NOW + 60_000)]),
    'not_affected',
    'clock skew of a minute',
  );
});

// ---- Package lookups -------------------------------------------------------------------------------

const sources = {
  ...config,
  sources: {
    cve_now: true,
    hacker_news: false,
    osv: false,
    github: false,
    github_token_env: 'TENTH_FOLLOWUP_UNUSED',
    kev: false,
    feeds: [],
  },
};
const numbered = (count) =>
  Array.from({ length: count }, (_, index) => `pkg-${String(index).padStart(5, '0')}`);

test('a version not sent this poll keeps the mark that its last lookup failed', async () => {
  // pkg-00999 fails on the first poll only, is not sent on the second, and on the third, when its
  // turn comes again, goes after the others.
  let checkpoints = { cve_now: iso(NOW - HOUR) };
  const rounds = [];
  for (let poll = 0; poll < 3; poll++) {
    const asked = [];
    const http = async (address) => {
      const { pathname, searchParams } = new URL(address);
      if (pathname === '/stack') {
        asked.push(searchParams.get('p'));
        return searchParams.get('p') === 'npm:pkg-00999@2.0.0' && poll === 0
          ? { status: 500, headers: {}, body: '' }
          : json({ packages: 1, entries: [] });
      }
      if (pathname === '/api/v1/entries') return json({ entries: [] });
      return { status: 404, headers: {}, body: '' };
    };
    const result = await collectSources(
      inventory(numbered(1_500)),
      sources,
      checkpoints,
      http,
      NOW + poll * 1_800_000,
      [],
    );
    checkpoints = result.checkpoints;
    rounds.push(asked);
  }
  assert.ok(rounds[0].includes('npm:pkg-00999@2.0.0'));
  assert.ok(!rounds[1].includes('npm:pkg-00999@2.0.0'));
  assert.equal(rounds[2].at(-1), 'npm:pkg-00999@2.0.0');
});

test('what a lookup matched is not kept once the lookup answers without it', async () => {
  const id = 'CVE-2026-91201';
  const detail = json({
    id,
    status: 'published',
    title: 'dep flaw',
    originalDescription: 'A flaw in dep.',
    severity: { cvss: 9.8 },
    affected: [{ ecosystem: 'npm', package: 'dep' }],
    publishedAt: iso(NOW - 2 * DAY),
    modifiedAt: iso(NOW - 2 * DAY),
  });
  const store = new Store(':memory:');
  const results = [];
  for (const [poll, matches] of [true, false].entries()) {
    const now = NOW + poll * 1_800_000;
    const http = async (address) => {
      const { pathname } = new URL(address);
      if (pathname === '/stack')
        return matches
          ? json({
              items: [{ id, _cve_now: { matched: { ecosystem: 'npm', name: 'dep', version: '2.0.0' } } }],
            })
          : json({ items: [] });
      if (pathname === '/api/v1/entries') return json({ entries: [] });
      return detail;
    };
    const result = await collectSources(
      inventory(['dep']),
      sources,
      store.checkpoints(),
      http,
      now,
      store.evidence(),
    );
    store.saveEvidence(result.evidence, result.checkpoints);
    results.push(assess(inventory(['dep']), store.evidence(), sources, now)[0].applicability);
  }
  assert.equal(results[0], 'affected');
  assert.notEqual(results[1], 'affected');
});

test('a record named by a lookup that cannot be read leaves package results incomplete', async () => {
  const id = 'CVE-2026-91301';
  const http = async (address) => {
    const { pathname } = new URL(address);
    if (pathname === '/stack')
      return json({
        items: [{ id, _cve_now: { matched: { ecosystem: 'npm', name: 'dep', version: '2.0.0' } } }],
      });
    if (pathname === '/api/v1/entries') return json({ entries: [] });
    return { status: 503, headers: {}, body: '' };
  };
  const result = await collectSources(
    inventory(['dep']),
    sources,
    { cve_now: iso(NOW - HOUR) },
    http,
    NOW,
    [],
  );
  const receipt = result.coverage.find((item) => item.source === 'cve_now');
  assert.notEqual(receipt.status, 'complete');
  assert.equal(receipt.package_results, undefined);
});

// ---- Matching --------------------------------------------------------------------------------------

test('a quoted joining word is a list entry whatever its case; unquoted it never is', () => {
  const mentioned = (name, text) => packageMentioned(text, { ecosystem: 'npm', name });
  assert.equal(mentioned('that', 'The npm packages qrlib-pad, "that" and xlsx-parser ran a script.'), true);
  assert.equal(mentioned('that', 'The npm packages qrlib-pad, That and xlsx-parser ran a script.'), false);
});

// ---- Event identity --------------------------------------------------------------------------------

test('a record that gains a GHSA alias stays the same finding', async () => {
  const { parseConfig, runScan } = await import('../dist/index.js');
  const scanConfig = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
  });
  const store = new Store(':memory:');
  const inv = inventory(['dep']);
  inv.systems[0].components[0].version = '1.0.0';
  const cve = 'CVE-2026-91401';
  const ghsa = 'GHSA-abcd-2345-wxyz';
  const base = {
    kind: 'advisory',
    title: 'dep flaw',
    url: 'https://example.com/a',
    description: 'A flaw in dep.',
    severity: 'critical',
    modified_at: iso(NOW - DAY),
    fetched_at: iso(NOW),
    packages: [{ ecosystem: 'npm', name: 'dep', range: '<2.0.0', fixed: '2.0.0' }],
  };
  const first = await runScan({
    config: scanConfig,
    inventory: inv,
    store,
    fixture: [{ ...base, id: `osv:${cve}`, source: 'osv', aliases: [cve] }],
    now: NOW,
  });
  const later = NOW + 60_000;
  const second = await runScan({
    config: scanConfig,
    inventory: inv,
    store,
    fixture: [
      { ...base, id: `osv:${cve}`, source: 'osv', aliases: [cve], fetched_at: iso(later) },
      {
        ...base,
        id: `github:${ghsa}`,
        source: 'github:reviewed',
        aliases: [ghsa, cve],
        fetched_at: iso(later),
      },
    ],
    now: later,
  });
  const library = (report) => report.findings.filter((finding) => finding.category === 'library');
  assert.equal(library(first).length, 1);
  assert.deepEqual(
    library(second).map((finding) => [finding.id, finding.event_id]),
    library(first).map((finding) => [finding.id, finding.event_id]),
  );
  assert.equal(store.findings().filter((finding) => finding.active === false).length, 0, 'nothing retired');
  // A new installation, with no earlier finding, takes the GHSA identifier as before.
  const fresh = await runScan({
    config: scanConfig,
    inventory: inv,
    store: new Store(':memory:'),
    fixture: [{ ...base, id: `github:${ghsa}`, source: 'github:reviewed', aliases: [ghsa, cve] }],
    now: NOW,
  });
  assert.equal(library(fresh)[0].event_id, ghsa.toUpperCase());
});

test('an exclusion withdrawn only because its evidence is old goes to the digest, not an urgent alert', () => {
  const critical = { ...advisory('CVE-2026-91501', NOW - 3 * HOUR), severity: 'critical' };
  const policyConfig = {
    ...config,
    models: { enabled: false },
    policy: {
      library: { levels: ['critical'], basis: 'source_severity', channels: ['slack'] },
      product: { levels: ['critical'], basis: 'source_severity', channels: ['slack'] },
      news: { levels: ['critical'], basis: 'source_severity', channels: ['slack'] },
      health_channels: ['slack'],
      urgent_unknown: true,
      exploited_override: true,
      malware_override: true,
    },
  };
  const [stale] = assess(inventory(['dep']), [critical], policyConfig, NOW);
  assert.equal(stale.applicability, 'unknown');
  assert.equal(stale.stale_exclusion, true);
  assert.equal(decide(stale, policyConfig).action, 'digest');
  // An installed version inside the range stays urgent however old the evidence is.
  const vulnerable = inventory(['dep']);
  vulnerable.systems[0].components[0].version = '1.0.0';
  const [affected] = assess(vulnerable, [critical], policyConfig, NOW);
  assert.equal(affected.stale_exclusion, undefined);
  assert.equal(decide(affected, policyConfig).action, 'notify');
  // A fresh exclusion is simply recorded.
  const [fresh] = assess(inventory(['dep']), [{ ...critical, fetched_at: iso(NOW) }], policyConfig, NOW);
  assert.equal(decide(fresh, policyConfig).action, 'record');
});

test('matching: "N other npm packages", amounts of currency, -y words and Maven artifacts', () => {
  const mentioned = (ecosystem, name, text) => packageMentioned(text, { ecosystem, name });
  assert.equal(mentioned('npm', 'debug', 'The worm compromised debug and 16 other npm packages.'), true);
  assert.equal(
    mentioned('npm', 'chalk', 'Attackers backdoored chalk, debug and 17 other npm packages.'),
    true,
  );
  assert.equal(mentioned('npm', 'that', 'They compromised that and 16 other npm packages.'), false);
  assert.equal(mentioned('npm', 'send', 'Send 2.5 BTC to the wallet below to recover your files.'), false);
  assert.equal(mentioned('npm', 'send', 'Send 0.19.0 fixes a template injection flaw.'), true);
  // An English word with -ied, -ier or -iest is an English word.
  assert.equal(mentioned('npm', 'prettier', 'The phishing kit shows a prettier login page.'), false);
  assert.equal(mentioned('npm', 'prettier', 'A flaw in prettier@3.3.2 runs plugins from the project.'), true);
  // A Maven library is named by its artifact when that is not an English word.
  const maven = (name, text) => mentioned('Maven', name, text);
  assert.equal(
    maven('com.fasterxml.jackson.core:jackson-databind', 'jackson-databind has another gadget.'),
    true,
  );
  assert.equal(maven('org.yaml:snakeyaml', "SnakeYAML's Constructor allows arbitrary types."), true);
  assert.equal(
    maven('org.apache.commons:commons-text', 'The commons text of the treaty was published.'),
    false,
  );
});

test('a message of exactly 2,900 characters is sent whole; one more character shortens it', () => {
  const reasons = Array.from({ length: 15 }, (_, index) => `reason ${index} ${'r'.repeat(160)}`);
  const base = render(assessment({ reasons })).text.length;
  const room = 2900 - base - '\n• '.length;
  assert.ok(room > 0 && room <= 180, `room ${room}`);
  const exact = render(assessment({ reasons: [...reasons, 'q'.repeat(room)] })).text;
  assert.equal(exact.length, 2900);
  assert.doesNotMatch(exact, /Message shortened/);
  const over = render(assessment({ reasons: [...reasons, 'q'.repeat(room + 1)] })).text;
  assert.match(over, /Message shortened/);
  assert.ok(over.length <= 2900);
  assert.doesNotMatch(over, /q{10}/, 'the last reason is the one left out');
});
