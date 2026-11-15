// Regressions from the fifteenth review of delivery and guards: quotes the model writes itself are
// widened over the text as it is read (look-alike and invisible joiners included), package revisions
// and letter releases after a version, trailing dots, news quotes that must come from the evidence,
// the first-scan health grace and fixture previews.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { catchingUpFrom, checkHealth } from '../dist/health.js';
import { validateDestination } from '../dist/http.js';
import { excerptsFor, validateAnalysis } from '../dist/models.js';
import { parseConfig } from '../dist/config.js';
import { Store } from '../dist/store.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();

/** Whether the claims are accepted, with every quote given as written. */
function accepts(
  text,
  quotes,
  { products = [], versions = [], classification = 'new_vulnerability', impact = 'unknown' } = {},
) {
  const evidence = [
    {
      id: 'n1',
      kind: 'news',
      title: 'News',
      description: text,
      aliases: [],
      source: 'feed:x',
      url: 'https://example.com',
      severity: 'unknown',
      modified_at: iso(NOW),
      fetched_at: iso(NOW),
      packages: [],
    },
  ];
  const qs = quotes.map((quote) => ({ evidence_id: 'n1', quote }));
  try {
    validateAnalysis(
      {
        relevance: 'relevant',
        priority: 'high',
        summary: 'Checked.',
        evidence_ids: ['n1'],
        quotes: qs,
        news_analysis: {
          classification,
          impact,
          rationale: 'Checked.',
          quotes: qs,
          affected_products: products,
          affected_versions: versions,
          prerequisites: [],
        },
      },
      evidence,
    );
    return true;
  } catch {
    return false;
  }
}

test('a quote cut at a look-alike or invisible joiner supports no fragment', () => {
  const left = 'The advisory published today says ';
  for (const [joined, claim, kind] of [
    ['Confluence‑Cloud', 'Confluence', 'p'],
    ['Confluence­Cloud', 'Confluence', 'p'],
    ['Confluence＋plugin', 'Confluence', 'p'],
    ['Confluence​Cloud', 'Confluence', 'p'],
    ['2.4․' + '1', '2.4', 'v'],
    ['2.4​.1', '2.4', 'v'],
    ['2.4．1', '2.4', 'v'],
    ['1­2.4.1', '2.4.1', 'v'],
  ]) {
    const text = `${left}${joined} is affected in this release cycle.`;
    const at = text.indexOf(claim);
    const quotes = [text.slice(0, at + claim.length), text.slice(at)].filter((quote) => quote.length >= 20);
    for (const quote of quotes)
      assert.equal(
        accepts(text, [quote], kind === 'p' ? { products: [claim] } : { versions: [claim] }),
        false,
        `${claim} from ${JSON.stringify(quote)}`,
      );
  }
});

test('property: a claim a cut quote supports is supported by the whole text too', () => {
  let seed = 12345;
  const random = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  const pick = (list) => list[Math.floor(random() * list.length)];
  const joiners = [
    '-',
    '‐',
    '‑',
    '−',
    '­',
    '​',
    '‍',
    '⁠',
    '﻿',
    '/',
    '∕',
    '\\',
    '@',
    '﹫',
    '＠',
    '.',
    '·',
    '․',
    '．',
    '+',
    '＋',
    '#',
    '＃',
    ':',
    '~',
    '_',
    '＿',
    'x',
    'ｘ',
    '𝐗',
    '́',
    ' ',
    ', ',
    '1',
    '１',
    '.1',
    '%',
    ' %',
    '\u00b0',
    '\u20ac',
    '\u00b1',
    '\u2019',
    '\u2236',
    '\u33b3',
    '\u2116',
    '\ufe52',
    '\ufe62',
    '\u2795',
    '\u2216',
  ];
  let checked = 0;
  for (let index = 0; index < 4000; index++) {
    const product = random() < 0.5;
    const claim = product ? 'Struts' : '2.4';
    const pre = random() < 0.5 ? pick(joiners) : '';
    const post =
      random() < 0.7 ? pick(joiners) + (random() < 0.5 ? pick(['ware', '1', 'x', 'Cloud']) : '') : '';
    const left = 'The advisory published today says ';
    const text = `${left}Ab${pre}${claim}${post} is affected in this release cycle.`;
    const start = left.length + 2 + pre.length;
    const quote = random() < 0.5 ? text.slice(0, start + claim.length) : text.slice(start);
    if (quote.length < 20) continue;
    const claims = product ? { products: [claim] } : { versions: [claim] };
    if (accepts(text, [quote], claims))
      assert.equal(accepts(text, [text], claims), true, JSON.stringify({ text, quote }));
    checked++;
  }
  assert.ok(checked > 3000);
});

test('a version may be followed by a known revision, a letter release or ".x", not by another name', () => {
  const text = (body) => `Advisory: ${body} is affected in this release cycle.`;
  for (const [body, product] of [
    ['openssl-1.1.1w', 'openssl'],
    ['openssl@1.1.1w', 'openssl'],
    ['lodash@4.x', 'lodash'],
    ['node-18.x', 'node'],
    ['nginx-1.25.3-1~jammy', 'nginx'],
    ['glibc-2.35-0ubuntu3', 'glibc'],
  ])
    assert.equal(accepts(text(body), [text(body)], { products: [product] }), true, body);
  for (const [body, product] of [
    ['express-4-1evil', 'express'],
    ['express-4-1.evil.example', 'express'],
    ['vue-3-3d', 'vue'],
    ['node-7z', 'node'],
  ])
    assert.equal(accepts(text(body), [text(body)], { products: [product] }), false, body);
});

test('a news quote must come from the evidence even when it supports no claim', () => {
  const text = 'A general report about the conference schedule and the new venue.';
  assert.equal(accepts(text, [text], { classification: 'general_news', impact: 'not_applicable' }), true);
  assert.equal(
    accepts(text, ['An invented quote that the article never says.'], {
      classification: 'general_news',
      impact: 'not_applicable',
    }),
    false,
  );
});

test('a quote with the small commercial at reads as "@"', () => {
  const text = 'The express﹫evil fork 8.6 is affected in this release cycle.';
  assert.equal(accepts(text, [text], { products: ['express'] }), false);
});

test('any number of trailing dots names the same host', () => {
  for (const host of ['localhost.', 'localhost..', 'foo.localhost...'])
    assert.throws(() => validateDestination(`https://${host}/ping`), /./, host);
});

test('a worker that says it started in the future gets no first-scan grace', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const config = parseConfig({ version: 1 });
  store.setMeta(
    'worker',
    JSON.stringify({ status: 'running', started_at: iso(NOW + 60_000), heartbeat_at: iso(NOW) }),
  );
  assert.equal(checkHealth(store, config, NOW).ok, false);
  store.setMeta(
    'worker',
    JSON.stringify({ status: 'running', started_at: iso(NOW - 30 * 60_000), heartbeat_at: iso(NOW) }),
  );
  assert.equal(checkHealth(store, config, NOW).ok, true);
});

test('a fixture preview treats its records as read now, whatever date the file carries', () => {
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const examples = fileURLToPath(new URL('../examples/', import.meta.url));
  const result = spawnSync(
    process.execPath,
    [
      cli,
      'scan',
      '--config',
      `${examples}security-watch.example.yaml`,
      '--fixture',
      `${examples}advisories.json`,
      '--dry-run',
    ],
    { encoding: 'utf8', timeout: 30_000 },
  );
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  // The staging system runs a version the fictional advisory excludes: not "unknown" from old evidence.
  assert.ok(report.findings.some((finding) => finding.applicability === 'not_affected'));
  assert.ok(
    !report.findings.some((finding) => finding.reasons.some((reason) => /evidence is stale/.test(reason))),
  );
});

test('a version cut from the start of a word is refused even when another quote supports the product', () => {
  const text = 'Example Server is affected. Example Server 12.4.1 lets unauthenticated users upload files.';
  assert.equal(
    accepts(text, ['Example Server is affected.', '2.4.1 lets unauthenticated users'], {
      products: ['Example Server'],
      versions: ['2.4.1'],
    }),
    false,
  );
  assert.equal(
    accepts(text, ['Example Server is affected.', '12.4.1 lets unauthenticated users'], {
      products: ['Example Server'],
      versions: ['12.4.1'],
    }),
    true,
  );
});

test('every occurrence of a free quote is widened: one whole occurrence is enough', () => {
  const text = 'Example Server 12.4.1 is old. Example Server 2.4.1 is affected by the flaw.';
  assert.equal(accepts(text, ['2.4.1 is affected by the flaw.'], { versions: ['2.4.1'] }), true);
});

test('a version after a label colon or at either end of a tilde range is cited', () => {
  const chinese = 'Apache Struts 2.0.0~2.5.32 存在远程代码执行漏洞，请尽快升级。';
  assert.equal(accepts(chinese, [chinese], { versions: ['2.5.32'] }), true);
  assert.equal(accepts(chinese, [chinese], { versions: ['2.0.0'] }), true);
  const label = 'Affected Version:2.5.32 and earlier releases are vulnerable.';
  assert.equal(
    accepts(label, ['2.5.32 and earlier releases are vulnerable.'], { versions: ['2.5.32'] }),
    true,
  );
  for (const text of [
    'Scores CVSS:3.1 for the flaw in this release cycle.',
    'It listens on example.com:443 in this cycle.',
  ])
    assert.equal(accepts(text, [text], { versions: [text.includes('CVSS') ? '3.1' : '443'] }), false, text);
});

test('a product cut from the end of a longer word is refused', () => {
  const text = 'The advisory says MyExpress 4.0 is affected in this release cycle.';
  assert.equal(
    accepts(text, ['Express 4.0 is affected in this release cycle.'], { products: ['Express'] }),
    false,
  );
  const whole = 'The advisory says Express 4.0 is affected in this release cycle.';
  assert.equal(
    accepts(whole, ['Express 4.0 is affected in this release cycle.'], { products: ['Express'] }),
    true,
  );
});

test('the catch-up grace survives restarts until a scan is recorded, and is reported as starting', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const config = parseConfig({ version: 1 });
  const worker = (startedAgo, since) =>
    store.setMeta(
      'worker',
      JSON.stringify({
        status: 'running',
        started_at: iso(NOW - startedAgo),
        catching_up_since: iso(NOW - since),
        heartbeat_at: iso(NOW),
      }),
    );
  const scan = (ago) =>
    store.setMeta('last_scan', JSON.stringify({ at: iso(NOW - ago), degraded: false, errors: [] }));
  // A restart after eight hours of downtime: the full hour to catch up, reported as starting.
  scan(8 * 3_600_000);
  worker(10 * 60_000, 10 * 60_000);
  const catching = checkHealth(store, config, NOW);
  assert.equal(catching.ok, true);
  assert.equal(catching.status, 'starting', 'no success ping while catching up');
  // Restarted ten minutes ago, but catching up for three hours across restarts: a crash loop.
  worker(10 * 60_000, 3 * 3_600_000);
  assert.equal(checkHealth(store, config, NOW).ok, false);
  // The same on a new installation that never recorded a scan.
  store.setMeta('last_scan', 'null');
  assert.equal(checkHealth(store, config, NOW).ok, false);
  worker(10 * 60_000, 30 * 60_000);
  assert.equal(checkHealth(store, config, NOW).ok, true);
  // Without a worker check (--scan-only), no grace applies.
  scan(50 * 60_000);
  assert.equal(checkHealth(store, config, NOW, false).ok, false);
});

test('a restarted worker keeps the catch-up start until a scan is recorded', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  store.setMeta('last_scan', JSON.stringify({ at: iso(NOW - 3 * 3_600_000), degraded: false, errors: [] }));
  // First start after the scan: a fresh start.
  assert.equal(catchingUpFrom(store, iso(NOW - 2 * 3_600_000)), iso(NOW - 2 * 3_600_000));
  store.setMeta('worker', JSON.stringify({ status: 'running', catching_up_since: iso(NOW - 2 * 3_600_000) }));
  // Restarted without a scan since: the earlier start stands.
  assert.equal(catchingUpFrom(store, iso(NOW)), iso(NOW - 2 * 3_600_000));
  // A scan was recorded since: the next start is fresh.
  store.setMeta('last_scan', JSON.stringify({ at: iso(NOW - 60_000), degraded: false, errors: [] }));
  assert.equal(catchingUpFrom(store, iso(NOW)), iso(NOW));
  // An unreadable record starts afresh.
  store.setMeta('worker', 'not JSON');
  assert.equal(catchingUpFrom(store, iso(NOW)), iso(NOW));
});
test('the demo shows one affected and one excluded system whatever date its files carry', () => {
  const demo = fileURLToPath(new URL('../scripts/demo.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [demo], { encoding: 'utf8', timeout: 30_000 });
  assert.equal(result.status, 0, result.stderr);
  const applicability = JSON.parse(result.stdout)
    .findings.map((finding) => finding.applicability)
    .sort();
  assert.deepEqual(applicability, ['affected', 'not_affected']);
});

test('a claim is checked in the evidence: amounts and units around a cut quote count', () => {
  for (const [text, version] of [
    ['The update cut memory use by 45% in this release cycle.', '45'],
    ['The update cut memory use by 45 % in this release cycle.', '45'],
    ['The sensor reads 20° in this release cycle.', '20'],
    ['The fee was €5 in this release cycle.', '5'],
    ['Over 4’200 users are affected in this cycle.', '200'],
    ['Latency is 8.0.3㎳ in this release cycle.', '8.0.3'],
  ]) {
    const at = text.indexOf(version, text.search(/\d/));
    for (const quote of [text.slice(0, at + version.length), text.slice(at)].filter((q) => q.length >= 20))
      assert.equal(
        accepts(text, [quote], { versions: [version] }),
        false,
        `${version} from ${JSON.stringify(quote)}`,
      );
  }
});

test('a claim outside every quote is not supported, even next to one', () => {
  const text = 'Upgrade the package lodash@4.17.20 now. Affected Version 2.5.32 here.';
  assert.equal(accepts(text, ['Upgrade the package lodash'], { versions: ['4.17.20'] }), false);
  assert.equal(accepts(text, ['Upgrade the package lodash@4.17.20 now.'], { versions: ['4.17.20'] }), true);
});

test('small forms and other look-alike marks join a name or a version', () => {
  const sentence = (body) => `The advisory says ${body} is affected in this release cycle.`;
  for (const [body, product] of [
    ['Notepad﹢﹢', 'Notepad'],
    ['Notepad➕➕', 'Notepad'],
    ['apache﹨struts', 'struts'],
    ['apache∖struts', 'struts'],
    ['Node﹒js', 'Node'],
    ['Node⸱js', 'Node'],
    ['Struts∶evil', 'Struts'],
  ])
    assert.equal(accepts(sentence(body), [sentence(body)], { products: [product] }), false, body);
  for (const [body, version] of [
    ['2.4﹒1', '2.4'],
    ['2.4・1', '2.4'],
    ['2.4.1﹢build5', '2.4.1'],
  ])
    assert.equal(accepts(sentence(body), [sentence(body)], { versions: [version] }), false, body);
});

test('labels in other languages, Docker tags and RHEL or Fedora revisions', () => {
  const sentence = (body) => `The advisory says ${body} is affected in this release cycle.`;
  for (const body of [
    '版本:2.5.32',
    'バージョン：2.5.32',
    '버전:2.5.32',
    'Versión:2.5.32',
    'fixed in:2.5.32',
    'ver:2.5.32',
  ])
    assert.equal(accepts(sentence(body), [sentence(body)], { versions: ['2.5.32'] }), true, body);
  for (const body of ['x-affected:2.5.32', 'subversion:2.5.32'])
    assert.equal(accepts(sentence(body), [sentence(body)], { versions: ['2.5.32'] }), false, body);
  for (const [body, product] of [
    ['nginx:1.25.3', 'nginx'],
    ['node:18-alpine', 'node'],
    ['openssl-1.1.1k-12.el8_9', 'openssl'],
    ['nginx-1.24.0-2.fc39', 'nginx'],
    ['openssh-8.7p1-34.el9', 'openssh'],
    ['nginx-1.25.3-1+deb12u5', 'nginx'],
  ])
    assert.equal(accepts(sentence(body), [sentence(body)], { products: [product] }), true, body);
  for (const [body, product] of [
    ['express-4-1+evil.example', 'express'],
    ['express-4-1~evil', 'express'],
    ['express-4-1build', 'express'],
    ['express-4-1deb', 'express'],
  ])
    assert.equal(accepts(sentence(body), [sentence(body)], { products: [product] }), false, body);
  // A tilde range needs a dotted version on both sides.
  assert.equal(accepts(sentence('2~5'), [sentence('2~5')], { versions: ['5'] }), false);
});

test('a news quote is checked against the evidence on its own, and every occurrence of a quote counts', () => {
  const text = 'A general report about the conference schedule and the new venue.';
  const evidence = [
    {
      id: 'n1',
      kind: 'news',
      title: 'News',
      description: text,
      aliases: [],
      source: 'feed:x',
      url: 'https://example.com',
      severity: 'unknown',
      modified_at: iso(NOW),
      fetched_at: iso(NOW),
      packages: [],
    },
  ];
  assert.throws(
    () =>
      validateAnalysis(
        {
          relevance: 'irrelevant',
          priority: 'low',
          summary: 'Checked.',
          evidence_ids: ['n1'],
          quotes: [{ evidence_id: 'n1', quote: text }],
          news_analysis: {
            classification: 'general_news',
            impact: 'not_applicable',
            rationale: 'Checked.',
            quotes: [{ evidence_id: 'n1', quote: 'An invented quote that the article never says.' }],
            affected_products: [],
            affected_versions: [],
            prerequisites: [],
          },
        },
        evidence,
      ),
    /MODEL_UNSUPPORTED_NEWS_QUOTE/,
  );
  // The quote occurs twice; only its second occurrence holds the whole version.
  const twice = 'Example 12.4.1 is affected by it. Example 2.4.1 is affected by it.';
  assert.equal(accepts(twice, ['2.4.1 is affected by it.'], { versions: ['2.4.1'] }), true);
});

test('a CJK label straight after other CJK text still labels the version', () => {
  const text = '受影响版本:2.5.32 存在远程代码执行漏洞。';
  assert.equal(accepts(text, [text], { versions: ['2.5.32'] }), true);
});

test('any other mark written between a name and more of a word joins it; sentence punctuation does not', () => {
  const sentence = (body) => `The advisory says ${body} is affected in this release cycle.`;
  for (const body of ['Notepad§x', 'Notepad★x', 'Notepad%x', 'Notepad©x'])
    assert.equal(accepts(sentence(body), [sentence(body)], { products: ['Notepad'] }), false, body);
  for (const body of ['Notepad, x', 'Notepad; x', 'Notepad (x)', 'Notepad™', 'Notepad®'])
    assert.equal(accepts(sentence(body), [sentence(body)], { products: ['Notepad'] }), true, body);
});

test('a claim that runs past the end of its quote is not supported by it', () => {
  const text = 'The advisory says Example Server 2.4.1 is affected in this release cycle.';
  assert.equal(accepts(text, ['The advisory says Example Ser'], { products: ['Example Server'] }), false);
  assert.equal(accepts(text, ['The advisory says Example Server 2.4'], { versions: ['2.4.1'] }), false);
  assert.equal(accepts(text, ['The advisory says Example Server 2.4.1'], { versions: ['2.4.1'] }), true);
});

test('a port, a vector and an image tag do not cite a version; a label with spaces does', () => {
  const sentence = (body) => `The advisory says ${body} is affected in this release cycle.`;
  // An image tag cannot be told from "timeout:2.5.32" by its spelling: it is refused, and the
  // analysis goes to review.
  assert.equal(
    accepts(sentence('nginx:1.25.3'), [sentence('nginx:1.25.3')], { versions: ['1.25.3'] }),
    false,
  );
  assert.equal(
    accepts(sentence('timeout:2.5.32'), [sentence('timeout:2.5.32')], { versions: ['2.5.32'] }),
    false,
  );
  assert.equal(
    accepts(sentence('example.com:443'), [sentence('example.com:443')], { versions: ['443'] }),
    false,
  );
  assert.equal(accepts(sentence('CVSS:3.1'), [sentence('CVSS:3.1')], { versions: ['3.1'] }), false);
  assert.equal(
    accepts(sentence('Version : 2.5.32'), [sentence('Version : 2.5.32')], { versions: ['2.5.32'] }),
    true,
  );
});
test('a fixture scan that saves its results does not mark the inventory as current', (t) => {
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const examples = fileURLToPath(new URL('../examples/', import.meta.url));
  const directory = mkdtempSync(join(tmpdir(), 'sw-fixture-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  writeFileSync(
    join(directory, 'security-watch.yaml'),
    [
      `version: 1`,
      `inventory: ${examples}systems.example.yaml`,
      `database: ${join(directory, 'watch.db')}`,
    ].join('\n'),
  );
  const result = spawnSync(
    process.execPath,
    [
      cli,
      'scan',
      '--config',
      join(directory, 'security-watch.yaml'),
      '--fixture',
      `${examples}advisories.json`,
    ],
    { encoding: 'utf8', timeout: 30_000 },
  );
  const report = JSON.parse(result.stdout);
  // The example inventory is dated 2026-10-23: without --dry-run it counts as stale when it is.
  if (Date.now() - Date.parse('2026-10-23T00:00:00Z') > 7 * 86_400_000)
    assert.ok(
      report.findings.some((finding) => finding.reasons.some((reason) => /Inventory is stale/.test(reason))),
    );
});

test('reading the evidence twice changes nothing: invisible marks before combining marks do not shift positions', () => {
  // A full-width letter or an invisible mark between a base letter and a combining mark composes
  // only once the mark is gone.
  for (const unit of ['e​́', 'Ａ́', 'a­̈', 'o⁠̂']) {
    const prefix = unit.repeat(40);
    const outside = `${prefix} The report covers several items in this cycle. Struts 2.5.32 is affected now.`;
    assert.equal(
      accepts(outside, ['The report covers several items in this cycle.'], {
        products: ['Struts'],
        versions: ['2.5.32'],
      }),
      false,
      'a claim after the quote',
    );
    const inside = `${prefix} The report covers Struts 2.5.32 in this cycle. End of the report text.`;
    assert.equal(
      accepts(inside, ['The report covers Struts 2.5.32 in this cycle.'], {
        products: ['Struts'],
        versions: ['2.5.32'],
      }),
      true,
      'a claim inside the quote',
    );
  }
});

test('quotes that meet in the evidence form one stretch, and a claim across them is inside', () => {
  const text = 'The advisory says Example Server 2.4.1 is affected in this release cycle.';
  const cut = text.indexOf('Server') + 3;
  assert.equal(
    accepts(text, [text.slice(0, cut), text.slice(cut)], {
      products: ['Example Server'],
      versions: ['2.4.1'],
    }),
    true,
  );
  assert.equal(accepts(text, [text.slice(0, cut)], { products: ['Example Server'] }), false);
});

test('more label languages, left-side joiners, apostrophes and a tilde after a version', () => {
  const sentence = (body) => `The advisory says ${body} is affected in this release cycle.`;
  // Two-part versions: only the label makes them a citation.
  for (const body of [
    'Versionen:2.5',
    'Vers\u00e3o:2.5',
    'Vers\u00f5es:2.5',
    '\u0412\u0435\u0440\u0441\u0438\u044f:2.5',
    '\u0412\u0435\u0440\u0441\u0438\u0438:2.5',
    'Versiones:2.5',
  ])
    assert.equal(accepts(sentence(body), [sentence(body)], { versions: ['2.5'] }), true, body);
  for (const [body, product] of [
    ['evil:express', 'express'],
    ['x~express', 'express'],
    ["express'forms", 'express'],
    ['express\u2019forms', 'express'],
    ["Notepad'sx", 'Notepad'],
    ['x\u00a9Struts', 'Struts'],
  ])
    assert.equal(accepts(sentence(body), [sentence(body)], { products: [product] }), false, body);
  for (const [body, product] of [
    ["Notepad's", 'Notepad'],
    ["Struts' x", 'Struts'],
    [':Struts', 'Struts'],
    ['Struts( and', 'Struts'],
    ['express\u2014forms', 'express'],
    // Brackets and an ellipsis after a name are ordinary prose ("Intel(R)", "Java(TM)", a Chinese
    // advisory's full-width bracket), not part of the name.
    ['Intel(R) Xeon(R)', 'Intel'],
    ['Oracle Java(TM) SE', 'Java'],
    ['Apache Struts\uff08CVE-2026-1234\uff09', 'Apache Struts'],
    ['Struts\u2026and Spring', 'Struts'],
  ])
    assert.equal(accepts(sentence(body), [sentence(body)], { products: [product] }), true, body);
  assert.equal(accepts(sentence('2.4.1~1'), [sentence('2.4.1~1')], { versions: ['2.4.1'] }), false);
  assert.equal(accepts(sentence('1~2.4.1'), [sentence('1~2.4.1')], { versions: ['2.4.1'] }), false);
  assert.equal(accepts(sentence('2.0.0~2.4.1'), [sentence('2.0.0~2.4.1')], { versions: ['2.0.0'] }), true);
});
test('product claims and claims before the quote are checked against the quote too', () => {
  const text = 'Struts is mentioned first. The report covers several items in this cycle today.';
  assert.equal(
    accepts(text, ['The report covers several items in this cycle today.'], { products: ['Struts'] }),
    false,
  );
  assert.equal(accepts(text, ['Struts is mentioned first. The report'], { products: ['Struts'] }), true);
});

test('property: reading the text twice changes nothing, for every letter followed by combining marks', () => {
  // The positions found in one reading must hold in the next: lowering the case can produce a
  // pair that composes ("T" and a diaeresis).
  for (const prefix of ['T\u0308', '\u03aa\u0301', '\u0386\u0345', '\u0130\u0301']) {
    const outside = `${prefix.repeat(40)} The report covers several items in this cycle. Struts 2.5.32 is affected now.`;
    assert.equal(
      accepts(outside, ['The report covers several items in this cycle.'], {
        products: ['Struts'],
        versions: ['2.5.32'],
      }),
      false,
      prefix,
    );
    const inside = `${prefix.repeat(40)} The report covers Struts 2.5.32 in this cycle. End of the report text.`;
    assert.equal(
      accepts(inside, ['The report covers Struts 2.5.32 in this cycle.'], {
        products: ['Struts'],
        versions: ['2.5.32'],
      }),
      true,
      prefix,
    );
  }
});

test('merged spans: quotes out of order, one inside another, and one character apart', () => {
  const text = 'The advisory says Example Server 2.4.1 is affected in this release cycle.';
  const at = text.indexOf('Server');
  // Out of order and meeting: one stretch.
  assert.equal(
    accepts(text, [text.slice(at + 3), text.slice(0, at + 3)], { products: ['Example Server'] }),
    true,
  );
  // One inside the other: the outer one stands.
  assert.equal(accepts(text, [text, text.slice(at, at + 25)], { versions: ['2.4.1'] }), true);
  // One character apart: not one stretch.
  assert.equal(
    accepts(text, [text.slice(0, at + 3), text.slice(at + 4)], { products: ['Example Server'] }),
    false,
  );
});

test('a catch-up start ahead of the clock (a clock set back) is not kept', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  store.setMeta('worker', JSON.stringify({ status: 'running', catching_up_since: iso(NOW + 3_600_000) }));
  assert.equal(catchingUpFrom(store, iso(NOW)), iso(NOW));
  // In health, a catch-up start after the worker's own start counts from the start.
  const config = parseConfig({ version: 1 });
  store.setMeta(
    'worker',
    JSON.stringify({
      status: 'running',
      started_at: iso(NOW - 2 * 3_600_000),
      catching_up_since: iso(NOW - 10 * 60_000),
      heartbeat_at: iso(NOW),
    }),
  );
  store.setMeta('last_scan', 'null');
  assert.equal(checkHealth(store, config, NOW).ok, false, 'two hours since the start, not ten minutes');
});

test('only running time counts against the catch-up grace: the time stopped moves its start', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const since = iso(NOW - 3 * 3_600_000);
  const seenAgo = (ago, field = 'heartbeat_at') =>
    store.setMeta(
      'worker',
      JSON.stringify({ status: 'stopped', catching_up_since: since, [field]: iso(NOW - ago) }),
    );
  // Catching up began three hours ago: whatever the stop, only the time running is used.
  for (const ago of [5_000, 59 * 60_000, 3_600_000, 61 * 60_000, 2 * 3_600_000]) {
    seenAgo(ago);
    const kept = Date.parse(catchingUpFrom(store, iso(NOW)));
    assert.equal(NOW - kept, Date.parse(iso(NOW - ago)) - Date.parse(since), String(ago));
  }
  // A clean stop seconds ago moves it by those seconds.
  seenAgo(5_000);
  assert.equal(catchingUpFrom(store, iso(NOW)), iso(NOW - 3 * 3_600_000 + 5_000));
  seenAgo(61 * 60_000, 'started_at');
  assert.equal(
    catchingUpFrom(store, iso(NOW)),
    iso(NOW - 3 * 3_600_000 + 61 * 60_000),
    'the start without a heartbeat',
  );
  // The later of the two counts.
  store.setMeta(
    'worker',
    JSON.stringify({
      status: 'stopped',
      catching_up_since: since,
      started_at: since,
      heartbeat_at: iso(NOW - 5 * 60_000),
    }),
  );
  assert.equal(catchingUpFrom(store, iso(NOW)), iso(NOW - 3 * 3_600_000 + 5 * 60_000));
  // A worker that died (still "running") may have run a minute past its last heartbeat.
  for (const status of ['running', 'stopping', undefined]) {
    store.setMeta(
      'worker',
      JSON.stringify({ status, catching_up_since: since, heartbeat_at: iso(NOW - 5 * 60_000) }),
    );
    assert.equal(catchingUpFrom(store, iso(NOW)), iso(NOW - 3 * 3_600_000 + 4 * 60_000), String(status));
    store.setMeta(
      'worker',
      JSON.stringify({ status, catching_up_since: since, heartbeat_at: iso(NOW - 30_000) }),
    );
    assert.equal(catchingUpFrom(store, iso(NOW)), since, String(status));
  }
  // A last sign of life before the catch-up start or after this start moves nothing.
  store.setMeta(
    'worker',
    JSON.stringify({ catching_up_since: since, heartbeat_at: iso(NOW - 4 * 3_600_000) }),
  );
  assert.equal(catchingUpFrom(store, iso(NOW)), since);
  store.setMeta('worker', JSON.stringify({ catching_up_since: since, heartbeat_at: iso(NOW + 60_000) }));
  assert.equal(catchingUpFrom(store, iso(NOW)), since);
  // A scan recorded at the very instant catching up began ends it.
  store.setMeta('worker', JSON.stringify({ catching_up_since: since }));
  store.setMeta('last_scan', JSON.stringify({ at: since, degraded: false, errors: [] }));
  assert.equal(catchingUpFrom(store, iso(NOW)), iso(NOW));
});

test('a catch-up start that is not a time string starts the grace afresh', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  for (const since of [0, 946_684_800_000, null, ['2026-01-01']]) {
    store.setMeta('worker', JSON.stringify({ status: 'running', catching_up_since: since }));
    assert.equal(catchingUpFrom(store, iso(NOW)), iso(NOW), JSON.stringify(since));
  }
});

test('a heartbeat more than five seconds ahead of the clock is not a live worker', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const config = parseConfig({ version: 1 });
  store.setMeta('last_scan', JSON.stringify({ at: iso(NOW - 60_000), degraded: false, errors: [] }));
  const beat = (ahead) =>
    store.setMeta(
      'worker',
      JSON.stringify({ status: 'running', started_at: iso(NOW - 3_600_000), heartbeat_at: iso(NOW + ahead) }),
    );
  beat(4_000);
  assert.equal(checkHealth(store, config, NOW).ok, true);
  beat(6_000);
  assert.equal(checkHealth(store, config, NOW).ok, false);
});

test('a claim whose own letters compose only after lowering the case is read like the quote', () => {
  for (const name of ['T̈ool', 'Ϊ́on Server', 'Άͅlpha']) {
    const text = `The vendor reports that ${name} 2.4.1 lets remote users run code without signing in.`;
    assert.equal(accepts(text, [text], { products: [name], versions: ['2.4.1'] }), true, name);
  }
});

test('brackets and quotation marks of any script do not join a name', () => {
  for (const [open, close] of [
    '【】',
    '〔〕',
    '「」',
    '『』',
    '〈〉',
    '《》',
    '‹›',
    '〖〗',
    '⟨⟩',
    '（）',
    '()',
    '[]',
  ]) {
    const text = `The vendor says Apache Struts${open}CVE-2026-1234${close} lets remote users run code at once.`;
    assert.equal(accepts(text, [text], { products: ['Apache Struts'] }), true, open);
  }
  // Other marks written straight between a name and more of a word still join.
  const text = 'The vendor says x©Struts lets remote users run code without signing in at all.';
  assert.equal(accepts(text, [text], { products: ['Struts'] }), false);
});

test('a quote with letters that compose only after lowering the case inside it keeps its place', () => {
  const text = 'Intro text. The ÄT̈X tool and Apache Struts 2.5.32 are affected now. Outro text here.';
  const quote = 'The ÄT̈X tool and Apache Struts 2.5.32 are affected now.';
  assert.equal(accepts(text, [quote], { products: ['Apache Struts'], versions: ['2.5.32'] }), true);
  assert.equal(accepts(text, [quote], { products: ['ÄT̈X tool'] }), true);
});

test('excerpts are cut between whole characters, and a Greek word cut after a sigma is still found', () => {
  const filler = 'Le correctif concerne Apache Struts 2.5.32 et les versions antérieures du produit. ';
  let checked = 0;
  for (let pad = 0; pad < 80; pad++) {
    const description = (filler.repeat(5) + 'y'.repeat(pad) + ' risque élevé. Mise a jour faite').normalize(
      'NFD',
    );
    const text = `News\n${description}`;
    const excerpts = excerptsFor({ title: 'News', description }, 0);
    let at = 0;
    for (const excerpt of excerpts.slice(0, -1)) {
      at += excerpt.text.length;
      assert.doesNotMatch(text[at], /\p{M}/u, `pad ${pad}`);
      checked++;
    }
    const quotes = excerpts.map((excerpt) => excerpt.text).filter((quote) => quote.length >= 20);
    assert.equal(accepts(description, quotes, { products: ['Apache Struts'], versions: ['2.5.32'] }), true);
  }
  assert.ok(checked > 0);
  // A quote that ends inside a Greek word after a capital sigma.
  const greek = 'Η ενημέρωση αφορά το Apache Struts 2.5.32 και το ΣΥΣΤΗΜΑ ελέγχου πρόσβασης σήμερα.';
  const cut = greek.slice(0, greek.indexOf('ΣΥΣ') + 3);
  assert.equal(accepts(greek, [cut], { products: ['Apache Struts'] }), true);
});

test('a worker that dies before its second heartbeat, again and again, still uses up its grace', (t) => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const config = parseConfig({ version: 1 });
  store.setMeta('last_scan', 'null');
  let at = NOW;
  let failedAt;
  // Each life lasts 12 seconds with one heartbeat at its start, and the restart takes a second.
  for (let life = 0; life < 400 && failedAt === undefined; life++) {
    const since = catchingUpFrom(store, iso(at));
    store.setMeta(
      'worker',
      JSON.stringify({
        status: 'running',
        started_at: iso(at),
        catching_up_since: since,
        heartbeat_at: iso(at),
      }),
    );
    if (!checkHealth(store, config, at + 10_000).ok) failedAt = at - NOW;
    at += 13_000;
  }
  assert.ok(failedAt !== undefined && failedAt <= 3_600_000 + 60_000, String(failedAt));
});
