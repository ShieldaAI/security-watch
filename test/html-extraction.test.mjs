import test from 'node:test';
import assert from 'node:assert/strict';
import { collectSources } from '../dist/sources.js';
import { parseConfig } from '../dist/config.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const ARTICLE_URL = 'https://thehackernews.com/2026/10/alpha-extraction-test.html';
const FEED_URL = 'https://vendor.example/security.xml';
const EXCERPT = 'Alpha original feed excerpt.';
const VISIBLE =
  'Alpha is affected by CVE-2026-12345. Install the fixed release after reviewing deployment details.';
const HIDDEN = 'Hidden instructions and CVE-2026-99999.';
const INVENTORY = {
  systems: [{ id: 'alpha', name: 'Alpha', components: [], products: [], keywords: ['Alpha'] }],
};
const response = (body) => ({ status: 200, headers: {}, body });
const rss = (description = EXCERPT) =>
  `<rss version="2.0"><channel><item><title>Alpha security update</title><description><![CDATA[${description}]]></description><link>${ARTICLE_URL}</link><guid>${ARTICLE_URL}</guid><pubDate>2026-10-24T11:59:00Z</pubDate></item></channel></rss>`;
function config(thn) {
  return parseConfig({
    version: 1,
    sources: {
      cve_now: false,
      hacker_news: thn,
      osv: false,
      github: false,
      kev: false,
      feeds: thn ? [] : [FEED_URL],
    },
  });
}
async function collectArticle(html) {
  return collectSources(
    INVENTORY,
    config(true),
    {},
    async (url, options) => {
      assert.equal(options.maxBytes, 2_000_000);
      if (url === 'https://feeds.feedburner.com/TheHackersNews') return response(rss());
      assert.equal(url, ARTICLE_URL);
      return response(html);
    },
    NOW,
  );
}
async function collectFeed(html) {
  return collectSources(
    INVENTORY,
    config(false),
    {},
    async (url) => {
      assert.equal(url, FEED_URL);
      return response(rss(html));
    },
    NOW,
  );
}
function assertFull(result, expected = VISIBLE) {
  assert.deepEqual(result.errors, []);
  assert.equal(result.evidence.length, 1);
  assert.equal(result.evidence[0].content_status, 'full');
  assert.equal(result.evidence[0].description, expected);
  assert.deepEqual(result.evidence[0].aliases, ['CVE-2026-12345']);
}
function assertExcerpt(result) {
  assert.equal(result.evidence.length, 1);
  assert.equal(result.evidence[0].description, EXCERPT);
  assert.equal(result.evidence[0].content_status, 'excerpt');
  assert.deepEqual(result.evidence[0].aliases, []);
  assert(result.errors.some((error) => error.source === 'hacker_news:articles'));
}

// Each malformed attribute is parsed by browsers without turning its quote into
// an attribute-value delimiter. Hidden script text must remain hidden.
test('malformed unquoted attributes cannot expose script text as article evidence', async (t) => {
  for (const [name, opening] of [
    ['apostrophe in value', "<span title=don't>"],
    ['quote in value', '<span title=a">'],
    ['apostrophe in name', "<span bad'name=value>"],
    ['leading equals and double quote', '<span ="x>'],
    ['leading equals and apostrophe', "<span ='x>"],
  ])
    await t.test(name, async () => {
      const hidden = `${opening}<script><div class="articlebody">${HIDDEN}</div></script></span>`;
      assertFull(await collectArticle(`${hidden}<div class="articlebody">${hidden}<p>${VISIBLE}</p></div>`));
    });
});

test('quoted attribute content never becomes visible text or a discovered CVE', async (t) => {
  const html = `<p title="attribute > ${HIDDEN}" data-note='<script>${HIDDEN}</script>'>${VISIBLE}</p>`;
  await t.test('article', async () =>
    assertFull(await collectArticle(`<div class="articlebody">${html}</div>`)),
  );
  await t.test('feed', async () => {
    const result = await collectFeed(html);
    assert.deepEqual(result.errors, []);
    assert.equal(result.evidence[0].description, VISIBLE);
    assert.deepEqual(result.evidence[0].aliases, ['CVE-2026-12345']);
    assert.equal(result.evidence[0].content_status, 'excerpt');
  });
});

test('only parsed article marker attributes select a full article', async (t) => {
  await t.test('marker-like text in an attribute is ignored', async () => {
    const fake = `<div data-note='class="articlebody"'>${HIDDEN}</div>`;
    assertFull(await collectArticle(`${fake}<section itemprop="articleBody">${VISIBLE}</section>`));
  });
  await t.test('an unquoted real marker is recognized', async () => {
    assertFull(await collectArticle(`<article class=articlebody>${VISIBLE}</article>`));
  });
});

test('hidden templates, noscript, comments and style blocks cannot supply article wrappers or claims', async (t) => {
  for (const [name, hidden] of [
    ['template', `<template><div class="articlebody">${HIDDEN}</div></template>`],
    ['noscript', `<noscript><div class="articlebody">${HIDDEN}</div></noscript>`],
    ['comment', `<!--<div class="articlebody">${HIDDEN}</div>-->`],
    ['style', `<style><div class="articlebody">${HIDDEN}</div></style>`],
  ])
    await t.test(name, async () => {
      assertFull(await collectArticle(`${hidden}<div class="articlebody">${hidden}<p>${VISIBLE}</p></div>`));
      const feed = await collectFeed(`${hidden}<p>${VISIBLE}</p>`);
      assert.deepEqual(feed.errors, []);
      assert.equal(feed.evidence[0].description, VISIBLE);
      assert.deepEqual(feed.evidence[0].aliases, ['CVE-2026-12345']);
    });
});

test('a parser-repaired article wrapper is never called complete without its explicit closing tag', async (t) => {
  for (const [name, html] of [
    ['unclosed wrapper', `<article class="articlebody">${VISIBLE}`],
    ['wrapper implicitly closed by parent', `<section><div class="articlebody">${VISIBLE}</section>`],
    ['end tag inside a comment', `<div class="articlebody">${VISIBLE}<!--</div>-->`],
    [
      'end tag inside an unterminated script',
      `<div class="articlebody">${VISIBLE}<script>const text="</div>";`,
    ],
  ])
    await t.test(name, async () => assertExcerpt(await collectArticle(html)));
  await t.test('implicit child closure with an explicit wrapper remains complete', async () => {
    assertFull(
      await collectArticle(`<div class="articlebody"><p>${VISIBLE}<p>Additional context.</div>`),
      `${VISIBLE} Additional context.`,
    );
  });
});

test('HTML input byte limits apply before parsing even when a custom HTTP client ignores maxBytes', async (t) => {
  await t.test('oversized ASCII', async () => {
    assertExcerpt(await collectArticle(`<div class="articlebody">${'x'.repeat(2_000_001)}</div>`));
  });
  await t.test('UTF-8 bytes exceed the limit while character count does not', async () => {
    const html = `<div class="articlebody">${'🔒'.repeat(500_001)}</div>`;
    assert(html.length < 2_000_000);
    assert(Buffer.byteLength(html) > 2_000_000);
    assertExcerpt(await collectArticle(html));
  });
  await t.test('a bounded large comment does not hide the complete article', async () => {
    const html = `<!--${'x'.repeat(1_900_000)}--><div class="articlebody">${VISIBLE}</div>`;
    assert(Buffer.byteLength(html) <= 2_000_000);
    assertFull(await collectArticle(html));
  });
});

test('excessive visible depth or node counts retain the original excerpt', async (t) => {
  await t.test('depth', async () => {
    const html = `<div class="articlebody">${'<span>'.repeat(300)}${VISIBLE}${'</span>'.repeat(300)}</div>`;
    assertExcerpt(await collectArticle(html));
  });
  await t.test('nodes', async () => {
    const html = `<div class="articlebody">${'<span></span>'.repeat(100_001)}${VISIBLE}</div>`;
    assert(Buffer.byteLength(html) < 2_000_000);
    assertExcerpt(await collectArticle(html));
  });
  await t.test('hidden template nodes still count during tree construction', async () => {
    const html = `<template>${'<i></i>'.repeat(100_001)}</template><div class="articlebody">${VISIBLE}</div>`;
    assert(Buffer.byteLength(html) < 2_000_000);
    assertExcerpt(await collectArticle(html));
  });
  await t.test('hidden template nesting still counts during tree construction', async () => {
    const hidden = `<template>${'<span>'.repeat(300)}${HIDDEN}${'</span>'.repeat(300)}</template>`;
    assertExcerpt(await collectArticle(`${hidden}<div class="articlebody">${VISIBLE}</div>`));
  });
  await t.test('ordinary nesting stays readable', async () => {
    assertFull(
      await collectArticle(
        `<div class="articlebody">${'<span>'.repeat(64)}${VISIBLE}${'</span>'.repeat(64)}</div>`,
      ),
    );
  });
});

test('feed parser limits report a source failure without advancing its checkpoint', async () => {
  const result = await collectFeed(`${'<span>'.repeat(300)}${VISIBLE}${'</span>'.repeat(300)}`);
  assert.deepEqual(result.evidence, []);
  assert.equal(result.errors.length, 1);
  assert(result.errors[0].source.startsWith('feed:'));
  assert.deepEqual(result.checkpoints, {});
});
