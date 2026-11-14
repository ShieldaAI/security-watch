// Regressions from the eighth review: lookup timeouts, records owed through an outage, the fix line
// with comma-separated versions, "module" and the commonest words, install commands, cut values,
// links, version citations, and guards that had no test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { decide } from '../dist/assessment.js';
import { evidenceRelevant } from '../dist/cve-now.js';
import { parseConfig } from '../dist/config.js';
import { deliverPending, notificationText } from '../dist/delivery.js';
import { NetworkError } from '../dist/http.js';
import { packageMentioned } from '../dist/matching.js';
import { validateAnalysis } from '../dist/models.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });
const failing = (status) => ({ status, headers: {}, body: '' });
const LF = String.fromCharCode(10);
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
    github_token_env: 'EIGHTH_REVIEW_UNUSED',
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
const record = (id, extra = {}) => ({
  id,
  status: 'published',
  title: id,
  originalDescription: 'unchanged',
  publishedAt: iso(NOW - 2 * DAY),
  modifiedAt: iso(NOW - 2 * DAY),
  ...extra,
});

// ---- cve.now ---------------------------------------------------------------------------------------

test('a lookup that times out or loses its connection does not end the poll', async () => {
  for (const error of [
    new NetworkError('TIMEOUT'),
    new NetworkError('RESPONSE_FAILED'),
    new Error('socket hang up'),
  ]) {
    const details = [];
    const http = async (url) => {
      const { pathname, searchParams } = new URL(url);
      if (pathname === '/stack') {
        if (searchParams.get('p') === 'npm:beta@1.0.0') throw error;
        return json({ packages: 1, entries: [] });
      }
      if (pathname === '/api/v1/entries')
        return json({ entries: [{ id: 'CVE-2026-83001', publishedAt: iso(NOW - 600_000) }] });
      const id = decodeURIComponent(pathname.split('/').pop());
      details.push(id);
      return json(record(id, { publishedAt: iso(NOW - 600_000), modifiedAt: iso(NOW - 600_000) }));
    };
    const result = await collectSources(
      inventory(['alpha', 'beta']),
      sources,
      { cve_now: iso(NOW - HOUR) },
      http,
      NOW,
      [],
    );
    assert.deepEqual(details, ['CVE-2026-83001'], error.message);
    assert.match(result.errors[0].message, /1 package lookup request\(s\) failed/, error.message);
    assert.equal(result.checkpoints.cve_now, iso(NOW), error.message);
  }
});

test('records owed through a long outage are neither given up nor lost', async () => {
  const id = 'CVE-2026-84001';
  let checkpoints = { cve_now: iso(NOW - HOUR) };
  let down = false;
  let listingDown = false;
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries') {
      if (listingDown) return failing(503);
      return json({ entries: [{ id, publishedAt: iso(NOW - 600_000) }] });
    }
    return down ? failing(500) : json(record(decodeURIComponent(pathname.split('/').pop())));
  };
  // The record fails on its first poll, and then the whole service is down for four days.
  down = true;
  const first = await collectSources(inventory(), sources, checkpoints, http, NOW, []);
  checkpoints = first.checkpoints;
  listingDown = true;
  for (const hours of [2, 30, 74, 96]) {
    const result = await collectSources(inventory(), sources, checkpoints, http, NOW + hours * HOUR, []);
    checkpoints = result.checkpoints;
    assert.doesNotMatch(result.errors[0].message, /were skipped/, `${hours} h`);
    assert.deepEqual(
      JSON.parse(checkpoints['cve_now:owed']).map(([owed]) => owed),
      [id],
      `${hours} h: still owed`,
    );
  }
  // The service comes back: the record is read.
  down = false;
  listingDown = false;
  const back = await collectSources(inventory(), sources, checkpoints, http, NOW + 97 * HOUR, []);
  assert.ok(back.evidence.some((item) => item.id === `cve_now:${id}`));
  assert.equal(back.checkpoints['cve_now:owed'], '[]');
});

test('a record that only fails, in a poll whose last batch failed, is not given up on', async () => {
  // Two owed records, both failing, and nothing else to read: the poll is not cut short (the
  // failing batch is the last one), but no record was read either.
  const owed = ['CVE-2026-85001', 'CVE-2026-85002'].map((id) => [id, NOW - 80 * HOUR, NOW - 81 * HOUR]);
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries') return json({ entries: [] });
    return failing(500);
  };
  const result = await collectSources(
    inventory(),
    sources,
    { cve_now: iso(NOW - HOUR), 'cve_now:owed': JSON.stringify(owed) },
    http,
    NOW,
    [],
  );
  assert.doesNotMatch(result.errors[0].message, /were skipped/);
  assert.equal(JSON.parse(result.checkpoints['cve_now:owed']).length, 2);
});

test('an owed record that was refused is asked for after the others', async () => {
  const asked = [];
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries')
      return json({
        entries: [
          { id: 'CVE-2026-86002', publishedAt: iso(NOW - 600_000) },
          { id: 'CVE-2026-86001', publishedAt: iso(NOW - 700_000) },
        ],
      });
    const id = decodeURIComponent(pathname.split('/').pop());
    asked.push(id);
    return id === 'CVE-2026-86001' ? failing(404) : json(record(id));
  };
  const first = await collectSources(inventory(), sources, { cve_now: iso(NOW - HOUR) }, http, NOW, []);
  asked.length = 0;
  await collectSources(inventory(), sources, first.checkpoints, http, NOW + 2 * HOUR, []);
  assert.equal(asked.at(-1), 'CVE-2026-86001');
});

test('repeated refusals of the package lookup end the lookups for that poll', async () => {
  for (const status of [401, 429]) {
    let lookups = 0;
    const http = async (url) => {
      const { pathname } = new URL(url);
      if (pathname === '/stack') {
        lookups++;
        return lookups === 1 ? failing(status) : json({ packages: 1, entries: [] });
      }
      if (pathname === '/api/v1/entries') return json({ entries: [] });
      return failing(404);
    };
    const names = Array.from({ length: 20 }, (_, index) => `pkg${index}`);
    const result = await collectSources(
      inventory(names),
      sources,
      { cve_now: iso(NOW - HOUR) },
      http,
      NOW,
      [],
    );
    assert.equal(lookups, 4, `${status}: the batch in flight finishes, no more are sent`);
    assert.match(
      result.errors[0].message,
      // One refused, the other three of its batch answered, the sixteen after it not sent.
      /17 package lookup request\(s\) failed or were not sent/,
      String(status),
    );
  }
});

test('a record is kept with a package name this application cannot read, and refused without any time', async () => {
  const http = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/stack') return json({ packages: 1, entries: [] });
    if (pathname === '/api/v1/entries')
      return json({
        entries: [
          { id: 'CVE-2026-87001', publishedAt: iso(NOW - 600_000) },
          { id: 'CVE-2026-87002', publishedAt: iso(NOW - 600_000) },
        ],
      });
    const id = decodeURIComponent(pathname.split('/').pop());
    if (id === 'CVE-2026-87001')
      return json(
        record(id, {
          affected: [
            { ecosystem: 'PyPI', package: 'not a valid name!' },
            { ecosystem: 'npm', package: 'alpha', ranges: [{ introduced: '0', fixed: '2.0.0' }] },
          ],
        }),
      );
    return json({ id, status: 'published', title: id, originalDescription: 'x' });
  };
  const result = await collectSources(inventory(), sources, { cve_now: iso(NOW - HOUR) }, http, NOW, []);
  const kept = result.evidence.find((item) => item.id === 'cve_now:CVE-2026-87001');
  assert.deepEqual(
    kept.packages.map((claim) => claim.name),
    ['not a valid name!', 'alpha'],
  );
  assert.ok(!result.evidence.some((item) => item.id === 'cve_now:CVE-2026-87002'), 'no usable time: refused');
  assert.match(result.errors[0].message, /1 advisory detail request\(s\) failed/);
});

test('package names in advisory text do not make an advisory relevant', () => {
  const advisory = {
    id: 'cve_now:CVE-2026-88001',
    source: 'cve_now',
    kind: 'advisory',
    title: 'Router firmware lets attackers send a crafted request',
    url: 'https://cve.now/x',
    description: 'A buffer overflow lets attackers send the next request. See the express notice.',
    aliases: ['CVE-2026-88001'],
    severity: 'critical',
    modified_at: iso(NOW),
    fetched_at: iso(NOW),
    packages: [],
  };
  assert.equal(
    evidenceRelevant(advisory, inventory(['send', 'next', 'express', 'buffer', 'request'])),
    false,
  );
});

// ---- Matching ------------------------------------------------------------------------------------------

const mentioned = (ecosystem, name, text) => packageMentioned(text, { ecosystem, name });

test('"module", the commonest words before "package", and another ecosystem\'s install command do not name a package', () => {
  for (const [ecosystem, name, text] of [
    ['npm', 'scheduler', 'A flaw in the kernel scheduler module lets local users gain root.'],
    ['npm', 'proxy', 'The Apache proxy module forwards requests to internal hosts.'],
    ['npm', 'session', 'The PAM session module was modified by the attackers.'],
    ['npm', 'rewrite', 'An IIS rewrite module flaw exposes source code.'],
    ['npm', 'which', 'It is unclear which package was affected.'],
    ['npm', 'next', 'The fix ships in the next package update.'],
    ['npm', 'standard', 'The flaw is in the standard library of the language.'],
    ['npm', 'security', 'Install a security plugin to block the attack.'],
    ['npm', 'express', 'Run pip install express to reproduce the Python proof of concept.'],
    ['PyPI', 'requests', 'Run npm install requests to pull the typosquat.'],
  ])
    assert.equal(mentioned(ecosystem, name, text), false, `${name}: ${text}`);
  for (const [ecosystem, name, text] of [
    ['npm', 'express', 'Run npm install express@4.21.2 to get the fix.'],
    ['PyPI', 'requests', 'Run pip install requests to get the fix.'],
    ['npm', 'next', "The 'next' package is affected."],
    ['npm', 'next', 'The next npm package is affected.'],
    ['npm', 'scheduler', 'A flaw in the scheduler package lets attackers block the event loop.'],
  ])
    assert.equal(mentioned(ecosystem, name, text), true, `${name}: ${text}`);
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
const message = (finding) =>
  notificationText({
    id: 'job-1',
    payload: JSON.stringify({ assessment: finding, reason: 'Critical library policy.' }),
  });
const lineOf = (text, label) => text.split(LF).find((line) => line.startsWith(label));

test('a fix list of one advisory, joined with commas, is shown as whole versions', () => {
  const versions = Array.from({ length: 40 }, (_, index) => `1.${index}.10`);
  const line = lineOf(message(assessment({ fix: versions.join(', ') })).text, 'Fix: ');
  const shown = line
    .slice('Fix: '.length)
    .replace(/; and \d+ more \(run explain for all\)$/, '')
    .split('; ');
  for (const version of shown) assert.ok(versions.includes(version), `"${version}" is a whole version`);
  assert.match(line, new RegExp(`and ${versions.length - shown.length} more \\(run explain for all\\)$`));
});

test('a value that does not fit is marked, and a list shows whole entries', () => {
  const ranges = ['Server', 'Router', 'Shell', 'Workbench', 'Cluster', 'Enterprise Backup'].flatMap(
    (part) => [`MySQL ${part} 8.0.0 to 8.0.39`, `MySQL ${part} 8.4.0 to 8.4.2`],
  );
  const { text } = message(
    assessment({
      summary: 's'.repeat(800),
      news_analysis: {
        classification: 'new_vulnerability',
        impact: 'affected',
        affected_products: ['MySQL'],
        affected_versions: ranges,
        prerequisites: [],
        rationale: 'w'.repeat(500),
        quotes: [],
      },
    }),
  );
  const versions = lineOf(text, 'Reported versions: ').slice('Reported versions: '.length);
  const shown = versions.replace(/(?:; )?and \d+ more$/, '').split('; ');
  for (const entry of shown) assert.ok(ranges.includes(entry), `"${entry}" is a whole entry`);
  assert.match(versions, /and \d+ more$/);
  assert.ok(lineOf(text, 'Summary: ').endsWith('…'));
  assert.ok(lineOf(text, 'Impact reasoning: ').endsWith('…'));
});

test('every reason is shown, unless the message is too long, and then the note says so', () => {
  const reasons = Array.from({ length: 8 }, (_, index) => `Reason ${index + 1}.`);
  const short = message(assessment({ reasons })).text;
  for (const reason of reasons) assert.ok(short.includes(`• ${reason}`), reason);
  assert.ok(!short.includes('(Message shortened'));
  const many = Array.from({ length: 16 }, (_, index) => `${'r'.repeat(170)} ${index}`);
  const long = message(assessment({ reasons: many, summary: 's'.repeat(700) })).text;
  assert.ok(long.includes('(Message shortened'));
});

test('a link with an invisible character is left out, not shown as another address', () => {
  const soft = String.fromCharCode(0xad);
  const zero = String.fromCharCode(0x200b);
  const { text } = message(
    assessment({
      urls: [`https://example.com/a${soft}b`, `https://example.com/c${zero}d`, 'https://example.com/ok'],
    }),
  );
  const lines = text.split(LF);
  assert.ok(
    !lines.some(
      (line) => line.startsWith('https://example.com/ab') || line.startsWith('https://example.com/cd'),
    ),
  );
  assert.ok(lines.includes('https://example.com/ok'));
});

test('a Slack Retry-After is never followed for more than a day', async () => {
  const config = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false },
    policy: { library: { levels: ['critical'], channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'EIGHTH_SLACK' } },
  });
  for (const retryAfter of ['999999999', new Date(NOW + 400 * DAY).toUTCString()]) {
    const store = new Store(':memory:');
    const finding = assessment();
    store.saveAssessment(finding, decide(finding, config), NOW);
    await deliverPending(
      store,
      config,
      async () => ({ status: 429, headers: { 'retry-after': retryAfter }, body: '' }),
      NOW,
      undefined,
      undefined,
      { EIGHTH_SLACK: 'https://hooks.slack.com/services/T/B/x' },
    );
    const [job] = store.jobs();
    assert.equal(job.status, 'pending', retryAfter);
    assert.ok(job.available_at <= NOW + DAY, `${retryAfter}: ${job.available_at - NOW} ms`);
  }
});

// ---- Version citations -----------------------------------------------------------------------------

const cites = (quote, version) => {
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
          affected_versions: [version],
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

test('a version copied with typographic dashes or spaces is the version the quote states', () => {
  const enDash = String.fromCharCode(0x2013);
  const nbsp = String.fromCharCode(0xa0);
  const zero = String.fromCharCode(0x200b);
  for (const [quote, version] of [
    [`Example Database versions 2.0${enDash}2.4 are affected.`, `2.0${enDash}2.4`],
    [`Example Database versions 2.0 ${enDash} 2.4 are affected.`, `2.0 ${enDash} 2.4`],
    [`Example Database before${nbsp}2.4.1 is affected.`, `before${nbsp}2.4.1`],
    [`Example Database before${nbsp}2.4.1 is affected.`, 'before 2.4.1'],
  ])
    assert.equal(cites(quote, version), true, version);
  for (const [quote, version] of [
    [`Example Database is used by 45${nbsp}% of hosts.`, '45'],
    ['Example Database is used by 45\t% of hosts.', '45'],
    ['Example Database is used by 45  % of hosts.', '45'],
    [`Example Database 2.4.1${zero}.1 is affected.`, '2.4.1'],
  ])
    assert.equal(cites(quote, version), false, JSON.stringify(quote));
});
