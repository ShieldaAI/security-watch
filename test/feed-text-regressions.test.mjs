import test from 'node:test';
import assert from 'node:assert/strict';
import { collectSources } from '../dist/sources.js';

// Feed text as real publishers send it: Rapid7 and Dark Reading put an image in <media:content>
// beside the article in <description>; Tenable and seclists escape their HTML with entities
// instead of CDATA.
const NOW = Date.parse('2026-11-19T12:00:00Z');
const DATE = 'Wed, 18 Nov 2026 14:38:55 GMT';
function config(feeds) {
  return {
    news_lookback_minutes: 10080,
    sources: {
      cve_now: false,
      hacker_news: false,
      osv: false,
      github: false,
      github_token_env: 'SECURITY_WATCH_TEST_UNUSED_TOKEN',
      kev: false,
      feeds,
    },
  };
}
const inventory = { systems: [{ id: 'prod', components: [] }] };
const xml = (body) => ({ status: 200, headers: {}, body });
async function read(body) {
  const result = await collectSources(
    inventory,
    config(['https://feeds.example/rss']),
    {},
    async () => xml(body),
    NOW,
  );
  assert.deepEqual(result.errors, []);
  return result.evidence;
}
const rss = (item) =>
  `<rss version="2.0" xmlns:media="http://search.yahoo.com/mrss/" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Feed</title><item><guid>id-1</guid><link>https://feeds.example/post</link><pubDate>${DATE}</pubDate>${item}</item></channel></rss>`;

test('an image in media:content does not hide the article in description', async () => {
  const [item] = await read(
    rss(
      '<title><![CDATA[CVE-2026-1111: critical flaw]]></title><description><![CDATA[<p>The flaw CVE-2026-2222 is exploited.</p>]]></description><media:content url="https://img.example/a.png" medium="image" />',
    ),
  );
  assert.equal(item.title, 'CVE-2026-1111: critical flaw');
  assert.equal(item.description, 'The flaw CVE-2026-2222 is exploited.');
  assert.deepEqual(item.aliases, ['CVE-2026-1111', 'CVE-2026-2222']);
  assert.equal(item.content_status, 'excerpt');
});

test('an empty content:encoded falls through to the description', async () => {
  const [item] = await read(
    rss(
      '<title>Post</title><content:encoded><![CDATA[]]></content:encoded><description>Summary text</description>',
    ),
  );
  assert.equal(item.description, 'Summary text');
});

test('content:encoded still wins over the description when it has text', async () => {
  const [item] = await read(
    rss(
      '<title>Post</title><content:encoded><![CDATA[<p>Full article</p>]]></content:encoded><description>Short</description>',
    ),
  );
  assert.equal(item.description, 'Full article');
});

test('HTML escaped with entities instead of CDATA is read as HTML, not as tag text', async () => {
  const [item] = await read(
    rss(
      '<title>CVE-2026-3333: Apache Kudu</title><description>&lt;p&gt;Posted by A on Nov 18&lt;/p&gt;Severity: moderate &lt;br&gt; Affected: Kudu &amp;lt; 1.17.2 &lt;br&gt; AT&amp;amp;T &amp;#169; &lt;script&gt;evil()&lt;/script&gt;</description>',
    ),
  );
  assert.equal(item.description, 'Posted by A on Nov 18 Severity: moderate Affected: Kudu < 1.17.2 AT&T ©');
});

test('Atom HTML content escaped with entities is read as HTML', async () => {
  const result = await collectSources(
    inventory,
    config(['https://feeds.example/atom']),
    {},
    async () =>
      xml(
        `<feed xmlns="http://www.w3.org/2005/Atom"><title>Feed</title><entry><id>urn:1</id><title>Post</title><link href="https://feeds.example/post"/><updated>2026-11-18T10:00:00Z</updated><content type="html">&lt;p&gt;Body &amp;amp; more&lt;/p&gt;</content></entry></feed>`,
      ),
    NOW,
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.evidence[0].description, 'Body & more');
});

test('CDATA content is decoded once, as before', async () => {
  const [item] = await read(
    rss('<title>Post</title><description><![CDATA[<p>1 &lt; 2 &amp;amp; &lt;b&gt;</p>]]></description>'),
  );
  assert.equal(item.description, '1 < 2 &amp; <b>');
});

test('numeric character references in escaped HTML are decoded', async () => {
  const [item] = await read(
    rss('<title>Post</title><description>&#x41;&#66; &amp;quot;C&amp;quot;</description>'),
  );
  assert.equal(item.description, 'AB "C"');
});

// Review of 2026-11-19: plain-text fields must not be read as HTML after unescaping.
async function atom(entry) {
  const result = await collectSources(
    inventory,
    config(['https://feeds.example/atom']),
    {},
    async () =>
      xml(
        `<feed xmlns="http://www.w3.org/2005/Atom"><title>Feed</title><entry><id>urn:1</id><link href="https://feeds.example/post"/><updated>2026-11-18T10:00:00Z</updated>${entry}</entry></feed>`,
      ),
    NOW,
  );
  assert.deepEqual(result.errors, []);
  return result.evidence[0];
}

test('escaped tags in plain-text fields stay text', async () => {
  const titled = await atom(
    '<title>Stored XSS via &lt;script&gt; tag in Acme Portal (CVE-2026-1234)</title><summary>s</summary>',
  );
  assert.equal(titled.title, 'Stored XSS via <script> tag in Acme Portal (CVE-2026-1234)');
  assert.deepEqual(titled.aliases, ['CVE-2026-1234']);
  const summary = await atom(
    '<title>Post</title><summary type="text">Filter bypass with &lt;!-- in Acme. CVE-2026-1234 is exploited.</summary>',
  );
  assert.equal(summary.description, 'Filter bypass with <!-- in Acme. CVE-2026-1234 is exploited.');
  const content = await atom('<title>Post</title><content type="text">if a &lt;b&gt; c</content>');
  assert.equal(content.description, 'if a <b> c');
  const [titledItem] = await read(
    rss('<title>std::vector&lt;bool&gt; and Foo&lt;T&gt;</title><description>d</description>'),
  );
  assert.equal(titledItem.title, 'std::vector<bool> and Foo<T>');
});

test('Atom summary with type="html" and escaped markup is read as HTML', async () => {
  const item = await atom(
    '<title>Post</title><summary type="html">&lt;p&gt;One&lt;/p&gt;&lt;p&gt;Two&lt;/p&gt;</summary>',
  );
  assert.equal(item.description, 'One Two');
});

test('text mixed with CDATA keeps its order and its id', async () => {
  const body = (guid) =>
    rss(
      `<title>Post</title><guid>${guid}</guid><description>Before <![CDATA[<b>inside</b>]]> after</description>`,
    );
  const [item] = await read(body('abc<![CDATA[-1]]>'));
  assert.equal(item.description, 'Before inside after');
  const [same] = await read(body('abc-1'));
  assert.equal(item.id, same.id);
});
