// Regressions from the fifteenth review of delivery and guards: quotes the model writes itself are
// widened over the text as it is read (look-alike and invisible joiners included), package revisions
// and letter releases after a version, trailing dots, news quotes that must come from the evidence,
// the first-scan health grace and fixture previews.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkHealth } from '../dist/health.js';
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
