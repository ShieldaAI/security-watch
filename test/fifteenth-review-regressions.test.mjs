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
import { validateAnalysis } from '../dist/models.js';
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

test('an image tag cites its version; a port and a vector do not', () => {
  const sentence = (body) => `The advisory says ${body} is affected in this release cycle.`;
  assert.equal(accepts(sentence('nginx:1.25.3'), [sentence('nginx:1.25.3')], { versions: ['1.25.3'] }), true);
  assert.equal(
    accepts(sentence('library/nginx:1.25.3'), [sentence('library/nginx:1.25.3')], { versions: ['1.25.3'] }),
    true,
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
