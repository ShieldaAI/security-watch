// Regressions from the twelfth reviews: a GitHub catch-up and a GitHub record that cannot be read,
// followed scan by scan; merged events through a whole scan; the listing room when the lookups name
// thousands of records; the confirmation and OSV boundaries; and model claims inside longer names.
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import http from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { notificationText } from '../dist/delivery.js';
import { safeHttp } from '../dist/http.js';
import { assess, decide } from '../dist/assessment.js';
import { parseConfig, runScan } from '../dist/index.js';
import { validateAnalysis } from '../dist/models.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value, headers = {}) => ({ status: 200, headers, body: JSON.stringify(value) });
const inventory = (components, at = NOW) => ({
  systems: [
    {
      id: 'prod',
      name: 'prod',
      updated_at: iso(at),
      products: [],
      keywords: [],
      components: components.map(([name, version, ecosystem = 'npm']) => ({
        id: `c:${name}`,
        ecosystem,
        name,
        version,
      })),
    },
  ],
});
const rule = { levels: ['critical'], basis: 'source_severity', channels: ['slack'] };
const config = (sources) => ({
  news_lookback_minutes: 40,
  poll_interval_minutes: 30,
  inventory_stale_days: 30,
  models: { enabled: false },
  policy: {
    library: rule,
    product: rule,
    news: rule,
    health_channels: ['slack'],
    urgent_unknown: true,
    exploited_override: true,
    malware_override: true,
  },
  sources: {
    cve_now: false,
    hacker_news: false,
    osv: false,
    github: false,
    github_token_env: 'TWELFTH_REVIEW_UNUSED',
    kev: false,
    feeds: [],
    ...sources,
  },
});
const ghsa = (id, name, range, modified) => ({
  ghsa_id: id,
  cve_id: null,
  type: 'reviewed',
  summary: `${name} flaw`,
  description: `A flaw in ${name}.`,
  severity: 'critical',
  updated_at: iso(modified),
  published_at: iso(NOW - 10 * DAY),
  withdrawn_at: null,
  vulnerabilities: [
    { package: { ecosystem: 'npm', name }, vulnerable_version_range: range, first_patched_version: null },
  ],
});

/** Serves `updates(from)` page by page, as GitHub answers a window of modifications. */
const githubServer = (updates) => async (raw) => {
  const url = new URL(raw);
  if (url.searchParams.get('type') === 'malware') return json([]);
  const [from] = url.searchParams.get('modified').split('..');
  const pending = updates(Date.parse(from));
  const page = Number(url.searchParams.get('page') ?? 0);
  const headers = {};
  if (pending.length > (page + 1) * 100) {
    const next = new URL(url);
    next.searchParams.set('page', String(page + 1));
    headers.link = `<${next.href}>; rel="next"`;
  }
  return json(pending.slice(page * 100, page * 100 + 100), headers);
};

test('after a GitHub catch-up over more updates than one scan reads, stored records are confirmed again', async () => {
  const store = new Store(':memory:');
  const settings = config({ github: true });
  const back = NOW + 3 * DAY;
  // 6,000 updates to other packages within those three days, more than one scan's 50 pages.
  const backlog = Array.from({ length: 6_000 }, (_, index) =>
    ghsa(
      `GHSA-zzzz-${String(index).padStart(4, '0')}-zzzz`,
      `other-${index}`,
      '< 1.0.0',
      NOW + HOUR + index * 30_000,
    ),
  );
  const rounds = [];
  for (const [poll, now] of [
    NOW,
    back,
    back + 30 * MINUTE,
    back + 60 * MINUTE,
    back + 90 * MINUTE,
  ].entries()) {
    const http =
      poll === 0
        ? githubServer(() => [ghsa('GHSA-aaaa-bbbb-0001', 'alpha', '< 2.0.0', NOW - HOUR)])
        : githubServer((from) => backlog.filter((item) => Date.parse(item.updated_at) >= from));
    const inv = inventory([['alpha', '3.0.0']], now);
    const result = await collectSources(inv, settings, store.checkpoints(), http, now, store.evidence());
    store.saveEvidence(result.evidence, result.checkpoints);
    const finding = assess(inv, store.evidence(), settings, now).find(
      (item) => item.component_id === 'c:alpha',
    );
    rounds.push({ result, finding, since: result.checkpoints['github:reviewed:since'] });
  }
  // The catch-up scan saves where its chain began, the scan before the backlog.
  assert.match(rounds[1].result.errors[0].message, /more updated advisories than one run reads/);
  assert.ok(Date.parse(rounds[1].since) <= NOW, rounds[1].since);
  // Once the backlog is read the stored record is confirmed and the exclusion holds again.
  const last = rounds.at(-1);
  assert.deepEqual(last.result.errors, []);
  assert.equal(last.since, '');
  assert.equal(last.finding.applicability, 'not_affected');
  assert.equal(decide(last.finding, settings).action, 'record');
});

test('a GitHub record that cannot be read is remembered by identifier and given up on only after three failed reads and a day', async () => {
  const store = new Store(':memory:');
  const settings = config({ github: true });
  const id = 'GHSA-bbbb-cccc-0002';
  const good = (modified) => ghsa(id, 'alpha', '< 2.0.0', modified);
  const broken = (modified) => ({
    ghsa_id: id,
    updated_at: iso(modified),
    vulnerabilities: [{ package: null }],
  });
  const other = (modified) => ghsa('GHSA-dddd-eeee-0003', 'zeta', '< 1.0.0', modified);
  // Asked for by identifier, GitHub serves it in the same unreadable form.
  const byId = (now) => broken(now - HOUR);
  const asked = [];
  const run = async (now, items) => {
    const http = async (raw) => {
      const url = new URL(raw);
      if (url.pathname !== '/advisories') {
        asked.push(url.pathname);
        return json(byId(now));
      }
      return url.searchParams.get('type') === 'malware' ? json([]) : json(items(now));
    };
    const result = await collectSources(
      inventory([['alpha', '3.0.0']], now),
      settings,
      store.checkpoints(),
      http,
      now,
      store.evidence(),
    );
    store.saveEvidence(result.evidence, result.checkpoints);
    return result;
  };
  const pending = (result) => JSON.parse(result.checkpoints['github:reviewed:unreadable']);
  await run(NOW, (now) => [good(now - HOUR)]);
  // GitHub updates the record and serves it in a form that cannot be read.
  const first = await run(NOW + 30 * MINUTE, (now) => [broken(now - MINUTE), other(now - MINUTE)]);
  assert.match(first.errors[0].message, /asked for again by identifier/);
  assert.equal(first.checkpoints['github:reviewed'], iso(NOW + 30 * MINUTE), 'the checkpoint moves on');
  assert.deepEqual(
    pending(first).map(([key, , attempts]) => [key, attempts]),
    [[id.toUpperCase(), 1]],
  );
  assert.ok(!first.evidence.some((item) => item.id === `github:${id}`), 'its stored copy is not confirmed');
  // A run in which nothing at all can be read is an outage: no attempt is counted.
  const outage = await run(NOW + 60 * MINUTE, (now) => [broken(now - MINUTE)]);
  assert.deepEqual(
    pending(outage).map(([, , attempts]) => attempts),
    [1],
  );
  // Later runs ask for it by identifier while the window no longer lists it.
  await run(NOW + 2 * HOUR, () => [other(NOW + 2 * HOUR - MINUTE)]);
  assert.ok(asked.length >= 1);
  await run(NOW + 3 * HOUR, () => [other(NOW + 3 * HOUR - MINUTE)]);
  // Three failed reads, but not yet a day: still remembered.
  const early = await run(NOW + 4 * HOUR, () => [other(NOW + 4 * HOUR - MINUTE)]);
  assert.equal(pending(early).length, 1);
  // A day later it is given up on; its stored copy is never confirmed again until it is read.
  const passed = await run(NOW + 25 * HOUR, () => [other(NOW + 25 * HOUR - MINUTE)]);
  assert.match(passed.errors.map((error) => error.message).join(' '), /were given up on/);
  assert.deepEqual(pending(passed), []);
  assert.ok(JSON.parse(passed.checkpoints['github:reviewed:skipped']).includes(id.toUpperCase()));
  const after = await run(NOW + 26 * HOUR, () => []);
  assert.ok(!after.evidence.some((item) => item.id === `github:${id}`));
  // Once GitHub serves it readably again, it is read and confirmed as usual.
  const fixed = await run(NOW + 27 * HOUR, (now) => [good(now - MINUTE)]);
  assert.ok(fixed.evidence.some((item) => item.id === `github:${id}`));
  assert.deepEqual(JSON.parse(fixed.checkpoints['github:reviewed:skipped']), []);
});

test('two events merged by one advisory keep both findings through a whole scan, without a new alert', async () => {
  const scanConfig = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
    policy: { library: { levels: ['high', 'critical'], channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'TWELFTH_REVIEW_SLACK' } },
  });
  const store = new Store(':memory:');
  const inv = inventory([
    ['alpha', '1.0.0'],
    ['beta', '1.0.0'],
  ]);
  const advisory = (id, aliases, names, source, at) => ({
    id: `${source}:${id}`,
    source,
    kind: 'advisory',
    title: id,
    url: 'https://example.com/a',
    description: '',
    aliases,
    severity: 'high',
    modified_at: iso(NOW - DAY),
    fetched_at: iso(at),
    packages: names.map((name) => ({ ecosystem: 'npm', name, range: '<2.0.0' })),
  });
  const separate = (at) => [
    advisory('CVE-2026-0001', ['CVE-2026-0001'], ['alpha'], 'cve_now', at),
    advisory('CVE-2026-0002', ['CVE-2026-0002'], ['beta'], 'cve_now', at),
  ];
  const first = await runScan({
    config: scanConfig,
    inventory: inv,
    store,
    fixture: separate(NOW),
    now: NOW,
  });
  const jobs = store.jobs().length;
  const later = NOW + MINUTE;
  const second = await runScan({
    config: scanConfig,
    inventory: inv,
    store,
    fixture: [
      ...separate(later),
      advisory(
        'GHSA-aaaa-bbbb-cccc',
        ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-0001', 'CVE-2026-0002'],
        ['alpha', 'beta'],
        'osv',
        later,
      ),
    ],
    now: later,
  });
  const ids = (report) =>
    report.findings
      .filter((finding) => finding.category === 'library')
      .map((finding) => [finding.component_id, finding.id, finding.event_id])
      .sort();
  assert.deepEqual(ids(second), ids(first));
  assert.equal(store.findings().filter((finding) => finding.active === false).length, 0);
  assert.equal(store.jobs().length, jobs, 'no new alert');
});

test('lookups that name thousands of records leave the listing its room, and are sent first next time', async () => {
  // One looked-up version names 5,000 records; ten new records are listed.
  const named = Array.from({ length: 5_000 }, (_, index) => `CVE-2025-${200_000 + index}`);
  const fresh = Array.from({ length: 10 }, (_, index) => `CVE-2026-9${String(index).padStart(4, '0')}`);
  const names = [
    ['alpha', '3.0.0'],
    ...Array.from({ length: 1_200 }, (_, index) => [`pkg-${String(index).padStart(5, '0')}`, '1.0.0']),
  ];
  let checkpoints = { cve_now: iso(NOW - HOUR) };
  const rounds = [];
  for (let poll = 0; poll < 2; poll++) {
    const details = [];
    const lookups = [];
    const http = async (url) => {
      const { pathname, searchParams } = new URL(url);
      if (pathname === '/stack') {
        lookups.push(searchParams.get('p'));
        return searchParams.get('p') === 'npm:alpha@3.0.0'
          ? json({
              items: named.map((id) => ({
                id,
                _cve_now: { matched: { ecosystem: 'npm', name: 'alpha', version: '3.0.0' } },
              })),
            })
          : json({ packages: 1, entries: [] });
      }
      if (pathname === '/api/v1/entries')
        return json({ entries: fresh.map((id) => ({ id, publishedAt: iso(NOW - 10 * MINUTE) })) });
      const id = decodeURIComponent(pathname.split('/').at(-1));
      details.push(id);
      return json({
        id,
        status: 'published',
        title: id,
        originalDescription: 'A flaw in alpha.',
        affected: [{ ecosystem: 'npm', package: 'alpha', ranges: [{ introduced: '0', fixed: '2.0.0' }] }],
        publishedAt: iso(NOW - 10 * DAY),
        modifiedAt: iso(NOW - 10 * DAY),
      });
    };
    const result = await collectSources(
      inventory(names),
      config({ cve_now: true }),
      checkpoints,
      http,
      NOW + poll * 30 * MINUTE,
      [],
    );
    checkpoints = result.checkpoints;
    rounds.push({ result, details, lookups });
  }
  const [first, second] = rounds;
  for (const id of fresh) assert.ok(first.details.includes(id), `${id} is read`);
  assert.equal(first.details.length, 4_010);
  assert.equal(first.result.checkpoints.cve_now, iso(NOW));
  assert.match(
    first.result.errors.map((error) => error.message).join(' '),
    /1000 requested record\(s\) were not read/,
  );
  // The lookup whose records did not all fit is sent first on the next poll.
  assert.equal(second.lookups[0], 'npm:alpha@3.0.0');
});

test('a stored GitHub record is confirmed when it was read exactly at the start of the window, not before', async () => {
  const checkpoint = NOW - 30 * MINUTE;
  const stored = (fetched) => ({
    id: 'github:GHSA-cccc-dddd-0003',
    source: 'github:reviewed',
    kind: 'advisory',
    title: 'alpha flaw',
    url: 'https://github.com/advisories/GHSA-cccc-dddd-0003',
    description: '',
    aliases: [],
    severity: 'critical',
    modified_at: iso(NOW - DAY),
    fetched_at: iso(fetched),
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
  });
  const confirmed = async (fetched) =>
    (
      await collectSources(
        inventory([['alpha', '3.0.0']]),
        config({ github: true }),
        { 'github:reviewed': iso(checkpoint), 'github:malware': iso(NOW) },
        githubServer(() => []),
        NOW,
        [stored(fetched)],
      )
    ).evidence.some((item) => item.id === 'github:GHSA-cccc-dddd-0003');
  assert.equal(await confirmed(checkpoint - HOUR), true);
  assert.equal(await confirmed(checkpoint - HOUR - 1), false);
});

test('a stored OSV record is refreshed whatever the letter case of its package name', async () => {
  const read = [];
  await collectSources(
    inventory([['django', '4.2.0', 'PyPI']]),
    config({ osv: true }),
    {},
    async (url) => {
      if (url.endsWith('/querybatch')) return json({ results: [{}] });
      read.push(url.split('/').at(-1));
      return { status: 404, headers: {}, body: '' };
    },
    NOW,
    [
      {
        id: 'osv:PYSEC-2026-1',
        source: 'osv',
        kind: 'advisory',
        title: 'Django flaw',
        url: 'https://osv.dev/x',
        description: '',
        aliases: [],
        severity: 'high',
        modified_at: iso(NOW - DAY),
        fetched_at: iso(NOW - HOUR),
        packages: [{ ecosystem: 'PyPI', name: 'Django', range: '<4.2.1' }],
      },
    ],
  );
  assert.deepEqual(read, ['PYSEC-2026-1']);
});

// ---- Model claims ----------------------------------------------------------------------------------

const claim = (quote, product, version = '8.6') => {
  const story = {
    id: 'feed:x:entry:13',
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
          affected_products: [product],
          affected_versions: [version],
          prerequisites: [],
          rationale: 'Checked.',
          quotes: [{ evidence_id: story.id, quote }],
        },
      },
      [story],
    );
    return true;
  } catch (error) {
    if (!/MODEL_UNSUPPORTED_NEWS_CLAIM/.test(String(error.message ?? error))) throw error;
    return false;
  }
};

test('a claim is refused inside a scoped name, after a plus, inside a word with combining marks, or before a letter', () => {
  for (const [quote, product] of [
    ['The @angular 8.6 release is affected.', 'angular'],
    ['C++Builder 8.6 is affected.', 'Builder'],
    ['C++x 8.6 is affected.', 'C++'],
    ['नमस्ते 8.6 सर्वर प्रभावित है।', 'नमस'],
  ])
    assert.equal(claim(quote, product), false, `${product} in ${quote}`);
  assert.equal(claim('नमस्ते 8.6 सर्वर प्रभावित है।', 'नमस्ते'), true);
  assert.equal(claim('C++Builder 8.6 is affected.', 'C++Builder'), true);
});

test('claims and versions read Unicode hyphens, full-width marks and text without spaces the same way', () => {
  for (const [quote, product] of [
    ['Confluence‑Cloud 8.6 is affected.', 'Confluence'],
    ['express‐forms 8.6 is affected.', 'express'],
    ['Notepad＋＋ 8.6 is affected.', 'Notepad'],
    ['The @angular∕core 8.6 compiler is affected.', 'core'],
    // A token after a hyphen or "@" that starts with a digit is not a version: another name.
    ['vue-3d-model 8.6 is affected.', 'vue'],
    ['node-7z 8.6 is affected.', 'node'],
    ['react-16-polyfill 8.6 is affected.', 'react'],
    ['Confluence-2fa-plugin 8.6 is affected.', 'Confluence'],
    ['express@4evil 8.6 is affected.', 'express'],
    // A path names a repository, not the product; a "/" list is refused rather than guessed.
    ['github.com/apache/struts 8.6 is affected.', 'Apache'],
    ['grafana/loki 8.6 is affected.', 'Grafana'],
    ['Chrome/Chromium 8.6 is affected.', 'Chromium'],
    // A digit joined to the name, and Korean inside a Korean word.
    ['Struts2 8.6 is affected.', 'Struts'],
    ['\uce74\uce74\uc624\ud1a1 8.6 is affected.', '\uce74\uce74\uc624'],
  ])
    assert.equal(claim(quote, product), false, `${product} in ${quote}`);
  for (const [quote, product] of [
    // A name followed by its own version.
    ['Apache/8.6 servers are affected.', 'Apache'],
    ['lodash@8.6 is affected.', 'lodash'],
    ['node-8.6 builds are affected.', 'node'],
    // Versions next to text written without spaces.
    ['Example Databaseのバージョン8.6以前に脆弱性があります。', 'Example Database'],
    ['Example Database 版本8.6之前', 'Example Database'],
  ])
    assert.equal(claim(quote, product), true, `${product} in ${quote}`);
});

test('a one-character product cannot carry a decisive impact', () => {
  assert.equal(
    (() => {
      try {
        claim('Version 8.6 of X is affected by the flaw.', 'X');
        return 'accepted';
      } catch (error) {
        return String(error.message ?? error);
      }
    })(),
    'MODEL_UNSUPPORTED_NEWS_IMPACT',
  );
});

test('a request that times out before it connects failed to connect, and one that times out after did not', async (t) => {
  const fake = (connects) =>
    function () {
      const request = new EventEmitter();
      request.write = () => true;
      request.end = () => {
        const socket = new EventEmitter();
        socket.connecting = true;
        request.emit('socket', socket);
        if (connects) socket.emit('connect');
      };
      request.destroy = (error) => request.emit('error', error);
      return request;
    };
  const original = http.request;
  t.after(() => {
    http.request = original;
    syncBuiltinESMExports();
  });
  for (const [connects, code] of [
    [false, 'CONNECTION_FAILED'],
    [true, 'REQUEST_TIMEOUT'],
  ]) {
    http.request = fake(connects);
    syncBuiltinESMExports();
    await assert.rejects(safeHttp('http://127.0.0.1:9/', { allowPrivate: true, timeoutMs: 50 }), (error) => {
      assert.equal(error.code, code, `connected: ${connects}`);
      return true;
    });
  }
});

test('when the notes give way, the reasons that fit are still shown', () => {
  const text = notificationText({
    id: 'D'.repeat(200),
    payload: JSON.stringify({
      reason: 'R'.repeat(180),
      assessment: {
        id: 'F'.repeat(200),
        event_id: 'CVE-2026-93001',
        system_id: 'S'.repeat(200),
        component_id: 'C'.repeat(200),
        category: 'library',
        title: 'T'.repeat(400),
        priority: 'critical',
        applicability: 'affected',
        source_severity: 'critical',
        summary: 'Y'.repeat(600),
        reasons: ['a short reason'],
        evidence_ids: [],
        urls: [],
        exploited: true,
        updated_at: iso(NOW),
        fix: '1.2.3',
        location: {
          system: 'W'.repeat(120),
          owner: 'O'.repeat(80),
          system_note: 'N'.repeat(300),
          component: 'I'.repeat(160),
          component_note: 'M'.repeat(300),
        },
      },
    }),
  }).text;
  assert.ok(text.length <= 2900, `${text.length}`);
  assert.doesNotMatch(text, /N{300}/, 'the notes gave way');
  assert.match(text, /^• a short reason$/m);
  assert.match(text, /^Summary: Y{600}$/m);
});

test('a version is not read into superscripts, circled digits or digits of another script', () => {
  for (const [quote, version] of [
    ['Example Server 2.4¹ is affected.', '2.41'],
    ['Example Server 2.4.1² is affected.', '2.4.12'],
    ['Example Server ⒈⒉ is affected.', '1.2'],
    ['Example Server 2.4.① is affected.', '2.4.1'],
    ['Example Server 2.4.1๑ is affected.', '2.4.1'],
    ['Example Server 版本2.4〇 is affected.', '2.4'],
    ['Example Server 2.4.1𐒡 is affected.', '2.4.1'],
  ])
    assert.equal(claim(quote, 'Example Server', version), false, `${version} in ${quote}`);
  for (const [quote, version] of [
    ['Example Server 2.4¹ is affected.', '2.4'],
    ['Example Server ２.４.１ is affected.', '2.4.1'],
    ['Example Server 2.4.1버전 is affected.', '2.4.1'],
    ['Example Server Struts의 2.4.1 is affected.', '2.4.1'],
  ])
    assert.equal(claim(quote, 'Example Server', version), true, `${version} in ${quote}`);
});

test('a version followed by a unit written as one symbol is an amount', () => {
  for (const [quote, version] of [
    ['Example Server answered in 8.0.3㎳ under load.', '8.0.3'],
    ['Example Server shows a 2㎝ gap on the screen.', '2'],
  ])
    assert.equal(claim(quote, 'Example Server', version), false, `${version} in ${quote}`);
});

test('claim boundaries: "#" before a name, a deeper scoped path, and Thai text after a name', () => {
  assert.equal(claim('C#Express 8.6 is affected.', 'Express'), false);
  assert.equal(claim('#Express 8.6 is affected.', 'Express'), true);
  assert.equal(claim('@angular/core/testing 8.6 is affected.', '@angular/core'), false);
  assert.equal(claim('@angular/core 8.6 is affected.', '@angular/core'), true);
  assert.equal(claim('Example Serverเวอร์ชัน 8.6', 'Example Server'), true);
});

test('a network that cannot be reached before connecting is a failed connection', async (t) => {
  const original = http.request;
  t.after(() => {
    http.request = original;
    syncBuiltinESMExports();
  });
  for (const code of ['ENETUNREACH', 'EHOSTUNREACH', 'ECONNREFUSED']) {
    http.request = function () {
      const request = new EventEmitter();
      request.write = () => true;
      request.end = () => {
        const socket = new EventEmitter();
        socket.connecting = true;
        request.emit('socket', socket);
        request.emit('error', Object.assign(new Error(code), { code }));
      };
      request.destroy = () => {};
      return request;
    };
    syncBuiltinESMExports();
    await assert.rejects(
      safeHttp('http://127.0.0.1:9/', { allowPrivate: true, timeoutMs: 1000 }),
      (error) => {
        assert.equal(error.code, 'CONNECTION_FAILED', code);
        return true;
      },
    );
  }
});

test('a backlog with many records that cannot be read still makes progress, remembering them by identifier', async () => {
  const store = new Store(':memory:');
  const settings = config({ github: true });
  // 6,000 updates, one in eight in a form that cannot be read.
  const backlog = Array.from({ length: 6_000 }, (_, index) => {
    const item = ghsa(
      `GHSA-yyyy-${String(index).padStart(4, '0')}-yyyy`,
      `other-${index}`,
      '< 1.0.0',
      NOW - 3 * HOUR + index * 1_000,
    );
    return index % 8 === 0 ? { ghsa_id: item.ghsa_id, updated_at: item.updated_at } : item;
  });
  store.saveEvidence([], { 'github:reviewed': iso(NOW - 3 * HOUR), 'github:malware': iso(NOW) });
  const run = async (now) => {
    const result = await collectSources(
      inventory([['alpha', '3.0.0']], now),
      settings,
      store.checkpoints(),
      githubServer((from) => backlog.filter((item) => Date.parse(item.updated_at) >= from)),
      now,
      store.evidence(),
    );
    store.saveEvidence(result.evidence, result.checkpoints);
    return result;
  };
  const first = await run(NOW);
  assert.match(first.errors[0].message, /the next run continues from there/);
  assert.ok(Date.parse(first.checkpoints['github:reviewed']) > NOW - 3 * HOUR, 'the checkpoint moved');
  assert.equal(JSON.parse(first.checkpoints['github:reviewed:unreadable']).length, 625);
  const second = await run(NOW + 30 * MINUTE);
  assert.doesNotMatch(second.errors[0]?.message ?? '', /pagination limit/);
  assert.equal(JSON.parse(second.checkpoints['github:reviewed:unreadable']).length, 750);
});
