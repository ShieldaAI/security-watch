import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig } from '../dist/config.js';
import { collectSources } from '../dist/sources.js';
import { VENDOR_FEEDS, vendorArticleTarget } from '../dist/vendor-sources.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const DATE = new Date(NOW).toISOString();
const TITLE = 'Runtime security bulletin';
const BODY = `${TITLE}. Runtime 1.0.0 is affected by CVE-2026-12345. Update to 1.0.1.`;
const inventory = {
  systems: [{ id: 'test', components: [], products: [{ name: 'Runtime', keywords: [] }], keywords: [] }],
};
const urls = {
  nodejs: 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases',
  python: 'https://blog.python.org/2026/10/python-3151-3149-31317/',
  php: 'https://www.php.net/index.php#2026-10-21-5',
};
const response = (body, status = 200) => ({ status, headers: {}, body });
const rss = (url, title = TITLE) =>
  `<rss version="2.0"><channel><item><title>${title}</title><link>${url}</link><guid>${url}</guid><pubDate>${DATE}</pubDate><description>Runtime needs review.</description></item></channel></rss>`;
const wrapper = (vendor, body = BODY) =>
  vendor === 'nodejs'
    ? `<main id="main"><h1>${TITLE}</h1><p>${body}</p></main>`
    : vendor === 'python'
      ? `<article class="prose"><h1>${TITLE}</h1><p>${body}</p></article>`
      : `<article class="newsentry"><header><h2><a id="2026-10-21-5">${TITLE}</a></h2></header><div class="newscontent">${body}</div></article>`;
const config = (vendor, overrides = {}) =>
  parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false, vendor_feeds: [vendor], ...overrides },
  });

for (const vendor of Object.keys(VENDOR_FEEDS)) {
  test(`${vendor} retrieves only its official article and excludes hidden HTML`, async () => {
    const calls = [];
    const result = await collectSources(
      inventory,
      config(vendor),
      {},
      async (url, options) => {
        calls.push(url);
        if (url === VENDOR_FEEDS[vendor].feed) return response(rss(urls[vendor]));
        assert.deepEqual(options.allowedRedirectOrigins, [VENDOR_FEEDS[vendor].origin]);
        assert.equal(options.maxBytes, 2_000_000);
        assert.equal(options.minIntervalMs, 500);
        return response(
          wrapper(vendor, `${BODY}<script>Hidden token</script><template>Hidden template</template>`),
        );
      },
      NOW,
    );
    assert.equal(calls.length, 2);
    assert.equal(new URL(calls[1]).hash, '');
    assert.equal(result.evidence[0].content_status, 'full');
    assert(result.evidence[0].description.includes('CVE-2026-12345'));
    assert(!result.evidence[0].description.includes('Hidden'));
    assert.equal(result.checkpoints[`vendor:${vendor}`], DATE);
    assert.deepEqual(result.errors, []);
  });

  test(`${vendor} keeps excerpts for unrelated, incomplete, oversized or failed articles`, async (t) => {
    for (const failure of [
      'wrong-title',
      'missing-close',
      'too-long',
      'foreign-namespace',
      'http',
      'transport',
    ])
      await t.test(failure, async () => {
        const result = await collectSources(
          inventory,
          config(vendor),
          {},
          async (url) => {
            if (url === VENDOR_FEEDS[vendor].feed) return response(rss(urls[vendor]));
            if (failure === 'http') return response('Unavailable', 503);
            if (failure === 'transport') throw new Error('private transport details');
            const html =
              failure === 'foreign-namespace'
                ? `<svg><main id="main">${BODY}</main><article class="prose newsentry"><a id="2026-10-21-5">${BODY}</a></article></svg>`
                : wrapper(vendor, failure === 'too-long' ? BODY + ' content'.repeat(3000) : BODY);
            return response(
              failure === 'wrong-title'
                ? html.replaceAll(TITLE, 'Unrelated article')
                : failure === 'missing-close'
                  ? html.slice(0, html.lastIndexOf('</'))
                  : html,
            );
          },
          NOW,
        );
        assert.equal(result.evidence[0].content_status, 'excerpt');
        assert(result.errors.some((error) => error.source === `vendor:${vendor}:articles`));
        assert(!JSON.stringify(result.errors).includes('private transport'));
      });
  });
}

test('vendor URL rules reject unrelated hosts, paths, credentials and query strings', () => {
  for (const vendor of Object.keys(VENDOR_FEEDS)) {
    assert(vendorArticleTarget(vendor, urls[vendor]));
    for (const value of [
      'https://attacker.example/post',
      urls[vendor].replace('https://', 'http://'),
      urls[vendor].replace('https://', 'https://secret@'),
      `${urls[vendor].split('#')[0]}?token=secret`,
      `${VENDOR_FEEDS[vendor].origin}/download`,
    ])
      assert.equal(vendorArticleTarget(vendor, value), undefined);
  }
});

test('PHP extracts the exact anchor article without adjacent releases', async () => {
  const result = await collectSources(
    inventory,
    config('php'),
    {},
    async (url) =>
      url === VENDOR_FEEDS.php.feed
        ? response(rss(urls.php))
        : response(
            `<article class="newsentry"><a id="2026-10-21-4">Wrong release</a><p>Adjacent unsafe claim.</p></article>${wrapper('php')}`,
          ),
    NOW,
  );
  assert.equal(result.evidence[0].content_status, 'full');
  assert(!result.evidence[0].description.includes('Adjacent unsafe'));
});

test('a verified updated vendor article replaces its longer stale feed excerpt', async () => {
  const stale = 'Older feed guidance that has since been removed. '.repeat(20);
  const result = await collectSources(
    inventory,
    config('php'),
    {},
    async (url) =>
      url === VENDOR_FEEDS.php.feed
        ? response(rss(urls.php).replace('Runtime needs review.', stale))
        : response(wrapper('php')),
    NOW,
  );
  assert.equal(result.evidence[0].content_status, 'full');
  assert(result.evidence[0].description.includes('CVE-2026-12345'));
  assert(!result.evidence[0].description.includes('Older feed guidance'));
});

test('a title-only vendor wrapper cannot claim a complete article', async () => {
  for (const vendor of Object.keys(VENDOR_FEEDS)) {
    const result = await collectSources(
      inventory,
      config(vendor),
      {},
      async (url) =>
        url === VENDOR_FEEDS[vendor].feed ? response(rss(urls[vendor])) : response(wrapper(vendor, TITLE)),
      NOW,
    );
    assert.equal(result.evidence[0].content_status, 'excerpt');
  }
});

test('generic feeds remain excerpt-only and do not opt into vendor article requests', async () => {
  let calls = 0;
  const result = await collectSources(
    inventory,
    config('nodejs', { vendor_feeds: [], feeds: [VENDOR_FEEDS.nodejs.feed] }),
    {},
    async () => {
      calls++;
      return response(rss(urls.nodejs));
    },
    NOW,
  );
  assert.equal(calls, 1);
  assert.equal(result.evidence[0].content_status, 'excerpt');
});

test('PHP accepts its bounded historical feed while generic feed limits remain unchanged', async () => {
  const old = Array.from(
    { length: 501 },
    (_, index) =>
      `<item><title>Old PHP release</title><guid>old-${index}</guid><link>https://www.php.net/index.php#2010-01-01-${index}</link><pubDate>2010-01-01T00:00:00Z</pubDate><description>Old release.</description></item>`,
  ).join('');
  const recent = `<item><title>${TITLE}</title><link>${urls.php}</link><pubDate>${DATE}</pubDate><description>Runtime needs review.</description></item>`;
  const xml = `<rss><channel>${old}${recent}</channel></rss>`;
  let articles = 0;
  const http = async (url) => {
    if (url === VENDOR_FEEDS.php.feed) return response(xml);
    articles++;
    return response(wrapper('php'));
  };
  const result = await collectSources(inventory, config('php'), {}, http, NOW);
  assert.equal(result.evidence.length, 1);
  assert.equal(result.evidence[0].content_status, 'full');
  assert.equal(articles, 1);
  const generic = await collectSources(
    inventory,
    config('php', { vendor_feeds: [], feeds: [VENDOR_FEEDS.php.feed] }),
    {},
    http,
    NOW,
  );
  assert.equal(generic.evidence.length, 0);
  assert.match(generic.errors[0].message, /entry limit/);
});

test('vendor collection is capped at twenty article requests and cancellation propagates', async () => {
  const entries = Array.from(
    { length: 21 },
    (_, index) =>
      `<item><title>${TITLE}</title><link>https://nodejs.org/en/blog/vulnerability/item-${index}</link><pubDate>${DATE}</pubDate><description>Runtime needs review.</description></item>`,
  ).join('');
  let articles = 0;
  const result = await collectSources(
    inventory,
    config('nodejs'),
    {},
    async (url) => {
      if (url === VENDOR_FEEDS.nodejs.feed) return response(`<rss><channel>${entries}</channel></rss>`);
      articles++;
      return response(wrapper('nodejs'));
    },
    NOW,
  );
  assert.equal(articles, 20);
  assert.equal(result.evidence.filter((entry) => entry.content_status === 'full').length, 20);
  assert.equal(result.evidence.filter((entry) => entry.content_status === 'excerpt').length, 1);
  await assert.rejects(
    collectSources(
      inventory,
      config('nodejs'),
      {},
      async (url) => {
        if (url === VENDOR_FEEDS.nodejs.feed) return response(rss(urls.nodejs));
        throw new DOMException('Aborted', 'AbortError');
      },
      NOW,
    ),
    { name: 'AbortError' },
  );
});
