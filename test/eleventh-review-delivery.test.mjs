// Regressions from the eleventh review of delivery: model claims that are part of a longer name,
// values padded with invisible characters, the order in which a long message gives way, and a job
// taken back while it was being sent.
import test from 'node:test';
import assert from 'node:assert/strict';
import { deliverPending, notificationText } from '../dist/delivery.js';
import { validateAnalysis } from '../dist/models.js';
import { singleLine } from '../dist/util.js';
import { Store } from '../dist/store.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const ZWSP = String.fromCharCode(0x200b);

// ---- Model claims ----------------------------------------------------------------------------------

const claim = (quote, products, prerequisites = []) => {
  const story = {
    id: 'feed:x:entry:12',
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
  };
  try {
    validateAnalysis(
      {
        relevance: 'relevant',
        priority: 'high',
        summary: 'Checked.',
        evidence_ids: [story.id],
        quotes: [{ evidence_id: story.id, quote }],
        news_analysis: {
          classification: 'new_vulnerability',
          impact: 'affected',
          affected_products: products,
          affected_versions: ['8.6'],
          prerequisites,
          rationale: 'Checked.',
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

test('a claimed product that is part of a longer name is refused', () => {
  for (const [quote, product] of [
    ['Notepad++ 8.6 runs a plugin from the profile.', 'Notepad'],
    ['The @angular/core 8.6 template compiler is affected.', 'core'],
    ['The @angular/core 8.6 template compiler is affected.', 'angular'],
    ['ASP.NET 8.6 accepts the crafted header.', '.NET'],
    ['The express#2 fork 8.6 is affected.', 'express'],
    ['C++ 8.6 builds are affected.', 'C'],
    ['C# 8.6 builds are affected.', 'C'],
    // A decomposed accent is the same letter as a composed one.
    ['Café server 8.6 is affected.', 'Cafe'],
  ])
    assert.equal(claim(quote, [product]), false, `${product} in ${quote}`);
});

test('a claimed product written with punctuation, or next to text without spaces, is accepted', () => {
  for (const [quote, product] of [
    ['Notepad++ 8.6 runs a plugin from the profile.', 'Notepad++'],
    ['The @angular/core 8.6 template compiler is affected.', '@angular/core'],
    ['The .NET 8.6 runtime is affected.', '.NET'],
    ['C++ 8.6 builds are affected.', 'C++'],
    ['Node.js 8.6 is affected.', 'Node.js'],
    ["Notepad's 8.6 release is affected.", 'Notepad'],
    ['Café server 8.6 is affected.', 'Café server'],
    // Japanese runs a name into the next word.
    ['Example Databaseで、バージョン 8.6 に脆弱性があります。', 'Example Database'],
    // A later whole-word occurrence counts when an earlier one is part of a longer word.
    ['The expressive forms and express 8.6 are affected.', 'express'],
  ])
    assert.equal(claim(quote, [product]), true, `${product} in ${quote}`);
  // Invisible characters and spacing in the claim do not matter.
  assert.equal(claim('Example  Server 8.6 is affected.', [`Example${ZWSP} Server `]), true);
  assert.equal(claim('Example Server 8.6 is affected.', ['   ']), false);
});

// ---- Invisible padding -----------------------------------------------------------------------------

test('characters that show as nothing do not count against a length limit', () => {
  const padded = `${ZWSP.repeat(3_995)}8.0.39`;
  assert.equal(singleLine(padded), '8.0.39');
  assert.equal(singleLine(`a${'ㅤ'.repeat(3)}b`), 'a   b', 'a filler is a space, not nothing');
  const text = notificationText({
    id: 'delivery-1',
    payload: JSON.stringify({
      reason: 'new finding',
      assessment: {
        id: 'finding-1',
        event_id: 'CVE-2026-92001',
        system_id: 'prod',
        category: 'library',
        title: 'dep flaw',
        priority: 'critical',
        applicability: 'affected',
        source_severity: 'critical',
        summary: `${ZWSP.repeat(3_995)}Upgrade to 8.0.39.`,
        reasons: [],
        evidence_ids: [],
        urls: [],
        exploited: false,
        fix: padded,
        updated_at: iso(NOW),
      },
    }),
  }).text;
  assert.match(text, /^Fix: 8\.0\.39$/m);
  assert.match(text, /^Summary: Upgrade to 8\.0\.39\.$/m);
});

// ---- Shortening order ------------------------------------------------------------------------------

const longest = (extra = {}) => ({
  id: 'F'.repeat(200),
  event_id: 'CVE-2026-92002',
  system_id: 'S'.repeat(200),
  component_id: 'C'.repeat(200),
  category: 'library',
  title: 'T'.repeat(400),
  priority: 'critical',
  applicability: 'affected',
  source_severity: 'critical',
  summary: 'Y'.repeat(750),
  reasons: ['r'.repeat(170)],
  evidence_ids: [],
  urls: [],
  exploited: true,
  updated_at: iso(NOW),
  location: {
    system: 'W'.repeat(120),
    owner: 'O'.repeat(80),
    system_note: 'N'.repeat(300),
    component: 'I'.repeat(160),
    component_note: 'M'.repeat(300),
  },
  fix: '1.2.3',
  ...extra,
});
const render = (a) =>
  notificationText({
    id: 'D'.repeat(200),
    payload: JSON.stringify({ assessment: a, reason: 'R'.repeat(180) }),
  }).text;

test('the notes give way before the summary is cut', () => {
  const text = render(longest({ summary: 'Y'.repeat(500) }));
  assert.ok(text.length <= 2900, `${text.length}`);
  assert.doesNotMatch(text, /N{300}|M{300}/, 'the notes are left out');
  assert.match(text, /^Summary: Y{500}$/m, 'the summary is whole');
  assert.match(text, /^Where to look: W+ \(owner: O+\)$/m);
  // Shorter still, the notes stay.
  const notes = render(longest({ summary: 'Y'.repeat(300) }));
  assert.match(notes, /N{300}/);
});

test('when only cutting the summary is left, the notes are gone first and mention breaks are counted as shown', () => {
  const fix = Array.from({ length: 30 }, (_, index) => `${index}.${'0'.repeat(100)}`).join(', ');
  const text = render(
    longest({
      fix,
      applicability: 'a'.repeat(40),
      source_severity: 'b'.repeat(40),
      priority: 'c'.repeat(40),
    }),
  );
  assert.ok(text.length <= 2900, `${text.length}`);
  assert.doesNotMatch(text, /N{300}|M{300}/);
  assert.match(text, /^Summary: Y+…$/m);
  // A summary full of "@here" past the part shown keeps as much as fits.
  const mentions = render(
    longest({
      fix,
      applicability: 'a'.repeat(40),
      source_severity: 'b'.repeat(40),
      priority: 'c'.repeat(40),
      summary: `${'Y'.repeat(600)}${' @here'.repeat(150)}`,
    }),
  );
  assert.ok(mentions.length <= 2900, `${mentions.length}`);
  const summary = mentions.match(/^Summary: .*$/m)[0];
  assert.ok(summary.length > 500, `${summary.length}`);
  assert.ok(mentions.length > 2850, `${mentions.length}: the room is used`);
});

test('a later shorter reason does not take the place of one that did not fit', () => {
  const reasons = Array.from({ length: 15 }, (_, index) => `reason ${index} ${'r'.repeat(160)}`);
  const base = notificationText({
    id: 'delivery-1',
    payload: JSON.stringify({
      assessment: longest({
        location: undefined,
        title: 't',
        id: 'f',
        system_id: 's',
        component_id: 'c',
        summary: 's',
        reasons,
        exploited: false,
      }),
      reason: 'r',
    }),
  }).text.length;
  const room = 2900 - base - '\n• '.length;
  assert.ok(room > 10 && room <= 170, `room ${room}`);
  const text = notificationText({
    id: 'delivery-1',
    payload: JSON.stringify({
      assessment: longest({
        location: undefined,
        title: 't',
        id: 'f',
        system_id: 's',
        component_id: 'c',
        summary: 's',
        reasons: [...reasons, 'q'.repeat(room + 1), 'short'],
        exploited: false,
      }),
      reason: 'r',
    }),
  }).text;
  assert.match(text, /Message shortened/);
  assert.doesNotMatch(text, /^• short$/m, 'reasons are left out from the first that does not fit');
});

test('a source link is at most 320 characters', () => {
  const at = (length) => `https://example.com/${'a'.repeat(length - 'https://example.com/'.length)}`;
  const text = notificationText({
    id: 'delivery-1',
    payload: JSON.stringify({
      assessment: longest({
        location: undefined,
        title: 't',
        summary: 's',
        reasons: [],
        urls: [at(320), at(321)],
      }),
      reason: 'r',
    }),
  }).text;
  assert.doesNotMatch(text, /Message shortened/);
  assert.ok(text.includes(at(320)));
  assert.ok(!text.includes(at(321)));
});

// ---- A job taken back while it was being sent ---------------------------------------------------

test('a job taken back while it was being sent is marked uncertain, not sent again', async (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  process.env.ELEVENTH_DELIVERY_SLACK = 'https://hooks.slack.com/services/T/B/secret';
  t.after(() => delete process.env.ELEVENTH_DELIVERY_SLACK);
  const rule = { levels: ['critical'], basis: 'source_severity', channels: ['slack'] };
  const config = {
    digest_interval_hours: 24,
    policy: {
      library: rule,
      product: rule,
      news: rule,
      health_channels: ['slack'],
      urgent_unknown: true,
      exploited_override: true,
      malware_override: true,
    },
    notifications: { max_attempts: 3, slack: { webhook_url_env: 'ELEVENTH_DELIVERY_SLACK' } },
  };
  store.saveAssessment(
    longest({ id: 'finding-1', location: undefined }),
    { action: 'notify', channels: ['slack'], reason: 'critical' },
    1000,
  );
  let calls = 0;
  const result = await deliverPending(
    store,
    config,
    async () => {
      calls++;
      // Another process recovers the job as interrupted and an operator queues it again.
      const [job] = store.jobs();
      store.recoverSending(1000);
      store.retryJob(job.id, 1000);
      return { status: 200, body: 'ok', headers: {} };
    },
    1000,
  );
  assert.equal(calls, 1);
  assert.equal(result.unknown, 1);
  assert.equal(store.jobs()[0].status, 'unknown', 'not left pending, where it would be sent again');
});
