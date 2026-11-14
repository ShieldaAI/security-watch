// Regressions from the fifth review: how a long message is shortened, blank characters that act as
// line breaks, source links, version citations, lockfile warnings and model identity.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../dist/assessment.js';
import { parseConfig } from '../dist/config.js';
import { deliverPending, notificationText, slackProblem } from '../dist/delivery.js';
import { NetworkError } from '../dist/http.js';
import { loadInventory } from '../dist/inventory.js';
import { validateAnalysis } from '../dist/models.js';
import { Store } from '../dist/store.js';
import { singleLine } from '../dist/util.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const character = String.fromCharCode;
const LF = character(10);
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
const linesOf = (text) => text.split(LF);

// ---- Shortening ------------------------------------------------------------------------------------

test('a message that is too long loses whole lines, says so, and never shows a cut fix version', () => {
  const links = [1, 2, 3].map((n) => `https://example.com/${'advisory-'.repeat(14)}${n}`);
  const base = {
    fix: '4.17.21',
    urls: links,
    reasons: ['r'.repeat(170), 'r'.repeat(170), 'r'.repeat(170), 'r'.repeat(170)],
    location: {
      system: 'Checkout',
      owner: 'Payments',
      system_note: 'n'.repeat(280),
      component: 'lodash',
      component_note: 'n'.repeat(280),
    },
    news_analysis: {
      classification: 'new_vulnerability',
      impact: 'affected',
      affected_products: ['p'.repeat(170)],
      affected_versions: ['4.17.20'],
      prerequisites: ['q'.repeat(230)],
      rationale: 'w'.repeat(390),
      quotes: [],
    },
  };
  let shortened = 0;
  for (let length = 0; length <= 750; length++) {
    const { text } = message(assessment({ ...base, summary: 's'.repeat(length) }));
    assert.ok(text.length <= 2900, `length ${length}`);
    const lines = linesOf(text);
    // The fix is shown whole.
    assert.deepEqual(
      lines.filter((line) => line.startsWith('Fix:')),
      ['Fix: 4.17.21'],
      `summary of ${length}`,
    );
    assert.equal(lines.filter((line) => line.startsWith('Rule: ')).length, 1);
    assert.deepEqual(lines.slice(-3), links);
    // No line is a fragment: each is one the message would have had in full.
    const full = linesOf(message(assessment({ ...base, summary: 's'.repeat(length), reasons: [] })).text);
    const note = lines.filter((line) => line.startsWith('(Message shortened'));
    if (note.length) {
      shortened++;
      assert.equal(note.length, 1);
      for (const line of lines)
        assert.ok(
          line.startsWith('(Message shortened') || line.startsWith('• ') || full.includes(line),
          `a cut line at ${length}: ${line.slice(0, 60)}`,
        );
    }
  }
  assert.ok(shortened > 0, 'the case does exceed the limit for some lengths');
  // A short message says nothing about shortening.
  assert.ok(!message(assessment({ fix: '4.17.21' })).text.includes('Message shortened'));
});

// ---- Blank characters -------------------------------------------------------------------------------

test('blank and invisible characters cannot move a value to what looks like a new line', () => {
  const gaps = [
    ' '.repeat(120),
    // Spaces separated by a mark that is removed.
    ` ${character(0x200e)}`.repeat(60),
    ` ${character(0x202e)}`.repeat(60),
    ` ${character(0x200b)}`.repeat(60),
    ` ${character(0xad)}`.repeat(60),
    // Characters that show as a blank but are not spaces.
    character(0x2800).repeat(120),
    character(0x3164).repeat(120),
    character(0xffa0).repeat(120),
    character(0x115f).repeat(120),
    // Every Unicode space.
    [0xa0, 0x1680, 0x2000, 0x2003, 0x2009, 0x200a, 0x202f, 0x205f, 0x3000]
      .map((code) => character(code))
      .join('')
      .repeat(14),
  ];
  for (const gap of gaps) {
    const forged = `alpha flaw${gap}Rule: forged by the advisory`;
    const { subject, text } = message(
      assessment({ title: forged, summary: forged, reasons: [forged], fix: forged, system_id: forged }),
      forged,
    );
    const label = [...gap.slice(0, 2)].map((item) => item.charCodeAt(0).toString(16)).join(' ');
    for (const value of [subject, ...linesOf(text)]) {
      assert.ok(!/[^\S]{2,}/u.test(value), `a run of spaces is left: ${label}`);
      assert.ok(!/[ᅟᅠ⠀ㅤﾠ]/u.test(value), `a blank filler is left: ${label}`);
      assert.ok(value.includes('alpha flaw Rule: forged') || !value.includes('forged'), label);
    }
    assert.equal(linesOf(text).filter((line) => line.startsWith('Rule:')).length, 1, label);
  }
});

test('a value that begins like a label still sits behind the label of its own line', () => {
  const { text } = message(
    assessment({ summary: 'Rule: forged', title: 'Finding: forged', fix: 'Rule: forged' }),
  );
  const lines = linesOf(text);
  assert.ok(lines.includes('Summary: Rule: forged'));
  assert.equal(lines.filter((line) => line.startsWith('Rule:')).length, 1);
  assert.equal(lines.filter((line) => line.startsWith('Finding:')).length, 1);
});

test('half of a surrogate pair never reaches a message', () => {
  const half = character(0xd83d);
  const { subject, text } = message(
    assessment({ title: `alpha ${half} flaw`, summary: `x${half}`, fix: half }),
  );
  assert.ok(subject.isWellFormed());
  assert.ok(text.isWellFormed());
  // The one-line helper stops before a pair it has no room for.
  const emoji = character(0xd83d, 0xde00);
  for (const max of [1, 2, 3, 4])
    assert.ok(singleLine(` ${emoji}${emoji}`, max).isWellFormed(), `max ${max}`);
  assert.equal(singleLine(` ${emoji}`, 1), '');
  assert.equal(singleLine(` ${emoji}`, 2), emoji);
  // A value made of characters that are widened is still cut to its limit, on a whole character.
  const mentions = message(assessment({ fix: `${'@'.repeat(200)}${emoji}` })).text;
  const fix = linesOf(mentions).find((line) => line.startsWith('Fix: '));
  assert.ok(fix.length <= 'Fix: '.length + 160);
  assert.ok(fix.isWellFormed());
});

// ---- Links -----------------------------------------------------------------------------------------

test('a source link is shown exactly as it is, or not at all', () => {
  const scoped = 'https://www.npmjs.com/package/@angular/core';
  const long = `https://example.com/${'a'.repeat(400)}`;
  const { text } = message(
    assessment({ urls: [scoped, long, 'https://example.com/ok', 'javascript:alert(1)'] }),
  );
  const lines = linesOf(text);
  assert.ok(lines.includes(scoped), 'nothing is inserted after the @');
  assert.ok(lines.includes('https://example.com/ok'));
  assert.ok(!lines.some((line) => line.startsWith('https://example.com/aaa')), 'a link is never shortened');
  assert.ok(!text.includes('javascript:'));
  // Elsewhere an @ is still kept from becoming a mention.
  const mention = message(assessment({ summary: 'ask @channel' })).text;
  assert.ok(mention.includes(`@${character(0x200b)}channel`));
});

// ---- Slack -----------------------------------------------------------------------------------------

test('a Slack request that was refused before any connection is retried', async () => {
  const config = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false },
    policy: { library: { levels: ['critical'], channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'FIFTH_REVIEW_SLACK' } },
  });
  const outcome = async (code) => {
    const store = new Store(':memory:');
    const finding = assessment();
    store.saveAssessment(finding, decide(finding, config), NOW);
    await deliverPending(
      store,
      config,
      async () => {
        throw new NetworkError(code);
      },
      NOW,
      undefined,
      undefined,
      { FIFTH_REVIEW_SLACK: 'https://hooks.slack.com/services/T/B/x' },
    );
    return store.jobs()[0].status;
  };
  // The resolver answered with a private address: the request never left this machine.
  assert.equal(await outcome('DESTINATION_DENIED'), 'pending');
  // A redirect was answered: the request was sent.
  assert.equal(await outcome('REDIRECT_DENIED'), 'unknown');
});

test('an address that is not a Slack webhook is named as a problem', () => {
  assert.equal(slackProblem('https://hooks.slack.com/services/T000/B000/abc'), undefined);
  for (const address of [
    'http://hooks.slack.com/services/T/B/x',
    'https://example.com/hook',
    'https://hooks.slack.com/other',
    'https://user:pw@hooks.slack.com/services/T/B/x',
    'https://hooks.slack.com:8443/services/T/B/x',
    'https://hooks.slack.com/services/T/B/x?a=1',
    'not a url',
  ]) {
    const problem = slackProblem(address);
    assert.match(problem, /Slack webhook/, address);
    assert.ok(!problem.includes(address), 'the address is not repeated');
  }
});

// ---- Version citations ----------------------------------------------------------------------------

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

test('a number that is part of a longer version, an amount, a time or a protocol is not cited', () => {
  for (const [text, version] of [
    ['2.4.1-rc.1', '2.4.1'],
    ['2.4.1-beta', '2.4.1'],
    ['2.4.1+build.5', '2.4.1'],
    ['2.4.1~rc1', '2.4.1'],
    ['2.4.1_p1', '2.4.1'],
    ['a_2.4.1', '2.4.1'],
    ['1.2.x', '1.2'],
    ['2.4.*', '2.4'],
    ['1.0-2.0-3.0', '2.0'],
    ['3-alpha', '3'],
    ['10:30', '10'],
    ['10:30', '30'],
    ['10.0.0.1:8080', '8080'],
    ['45%', '45'],
    ['4.5%', '4.5'],
    ['$5', '5'],
    ['$4.99', '4.99'],
    ['555-0100', '555'],
    ['555-0100', '0100'],
    ['#4521', '4521'],
    ['HTTP/2', '2'],
    ['HTTP/1.1', '1.1'],
    ['a change of -5', '5'],
    ['::ffff:1.2.3.4', '1.2.3.4'],
    ['12-16.2', '12'],
    ['1.0.0-1', '1.0.0'],
    ['about 12345-67890 units', '12345'],
  ])
    assert.equal(cites(`Example Database ${text} is mentioned.`, version), false, `${version} in ${text}`);
});

test('a version in a list, a range or after a name is cited', () => {
  for (const [text, version] of [
    ['2.4.1/2.4.2', '2.4.1'],
    ['2.4.1/2.4.2', '2.4.2'],
    ['2.4.1,2.4.2', '2.4.1'],
    ['2.4.1, 2.4.2 and 2.4.3', '2.4.2'],
    ['node-18', '18'],
    ['RHEL-9', '9'],
    ['alpha-1', '1'],
    ['2.4.1-rc.1', '2.4.1-rc.1'],
    ['versions 12-16', '12'],
    ['versions 12-16', '16'],
    ['2.0-2.4', '2.0'],
    ['v2.4.1', '2.4.1'],
    ['(2.4.1)', '2.4.1'],
    ['2.4.1.', '2.4.1'],
    ['port 8080', '8080'],
  ])
    assert.equal(cites(`Example Database ${text} is mentioned.`, version), true, `${version} in ${text}`);
});

// ---- Inventory -------------------------------------------------------------------------------------

test('lockfile entries that are left out are counted like any other import warning', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'sw-lockfile-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const packages = { '': {} };
  for (let index = 0; index < 1000; index++)
    packages[`node_modules/bad-${index}`] = { name: `not a name ${index}`, version: '1.0.0' };
  packages['node_modules/good'] = { version: '1.0.0' };
  writeFileSync(join(directory, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }));
  writeFileSync(
    join(directory, 'systems.json'),
    JSON.stringify({
      systems: [{ id: 'api', name: 'API', updated_at: iso(NOW), lockfile: './package-lock.json' }],
    }),
  );
  const inventory = loadInventory(join(directory, 'systems.json'));
  assert.deepEqual(
    inventory.systems[0].components.map((component) => component.name),
    ['good'],
  );
  assert.equal(inventory.import_warnings.length, 201);
  assert.equal(inventory.import_warnings.at(-1), '800 more import warning(s) are not shown.');
});

// ---- Verification model identity -------------------------------------------------------------------

test('every way of writing this machine is one address, and a registry prefix is not another model', () => {
  const same = (analysis, verification) => {
    try {
      parseConfig({ version: 1, models: { enabled: true, analysis, verification } });
      return false;
    } catch (error) {
      assert.match(String(error.message ?? error), /must differ from the analysis model/);
      return true;
    }
  };
  const local = (host, model = 'llama3') => ({
    provider: 'openai-compatible',
    model,
    endpoint: `http://${host}:11434/v1/chat/completions`,
    allow_private_endpoint: true,
  });
  for (const host of ['127.0.0.1', '127.0.0.2', '[::1]', '0.0.0.0', '[::ffff:127.0.0.1]', 'ollama.localhost'])
    assert.equal(same(local('localhost'), local(host)), true, host);
  assert.equal(same(local('localhost'), local('localhost', 'library/llama3')), true);
  assert.equal(same(local('localhost'), local('localhost', 'llama3:latest')), true);
  // Another machine, another port or another tag is another model.
  assert.equal(same(local('localhost'), local('192.168.1.20')), false);
  assert.equal(same(local('localhost'), local('localhost', 'llama3:8b')), false);
  assert.equal(same(local('localhost'), local('localhost', 'other/llama3')), false);
});
