// Regressions from the fourteenth review of GitHub collection: records that cannot be read are
// remembered by identifier, asked for in GitHub's own spelling within a request budget, given up on
// only after three failed reads over a day, and a format outage holds the checkpoint so that the
// whole window is listed again.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateDestination } from '../dist/http.js';
import { deliverPending } from '../dist/delivery.js';
import { validateAnalysis } from '../dist/models.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value, headers = {}) => ({ status: 200, headers, body: JSON.stringify(value) });
const config = {
  news_lookback_minutes: 40,
  poll_interval_minutes: 30,
  inventory_stale_days: 30,
  models: { enabled: false },
  policy: {},
  sources: {
    cve_now: false,
    hacker_news: false,
    osv: false,
    github: true,
    github_token_env: 'FOURTEENTH_GITHUB_TOKEN',
    kev: false,
    feeds: [],
  },
};
const inventory = (at) => ({
  systems: [
    {
      id: 'prod',
      name: 'prod',
      updated_at: iso(at),
      products: [],
      keywords: [],
      components: [{ id: 'c:alpha', ecosystem: 'npm', name: 'alpha', version: '3.0.0' }],
    },
  ],
});
const advisory = (id, name, modified, readable = true) =>
  readable
    ? {
        ghsa_id: id,
        cve_id: null,
        type: 'reviewed',
        summary: `${name} flaw`,
        description: `A flaw in ${name}.`,
        severity: 'critical',
        updated_at: iso(modified),
        published_at: iso(modified),
        withdrawn_at: null,
        vulnerabilities: [
          {
            package: { ecosystem: 'npm', name },
            vulnerable_version_range: '< 2.0.0',
            first_patched_version: null,
          },
        ],
      }
    : { ghsa_id: id, updated_at: iso(modified), affected: [] };

/**
 * A GitHub stand-in: `records(now)` lists every record with its current form; the listing serves the
 * window asked for, and a request by identifier is answered only in GitHub's own spelling.
 */
function github(records, { byId = (record) => json(record) } = {}) {
  const log = { listings: 0, byId: [] };
  const http = (now) => async (raw) => {
    const url = new URL(raw);
    if (url.pathname !== '/advisories') {
      const id = decodeURIComponent(url.pathname.split('/').at(-1));
      log.byId.push(id);
      const record = records(now).find((item) => item.ghsa_id === id);
      return record ? byId(record) : { status: 404, headers: {}, body: '' };
    }
    if (url.searchParams.get('type') === 'malware') return json([]);
    log.listings++;
    const [from, to] = url.searchParams.get('modified').split('..').map(Date.parse);
    return json(
      records(now)
        .filter(
          (item) => Date.parse(item.updated_at) >= from && Date.parse(item.updated_at) <= Math.min(to, now),
        )
        .sort((a, b) => Date.parse(a.updated_at) - Date.parse(b.updated_at)),
    );
  };
  return { http, log };
}
async function poll(store, http, now) {
  const result = await collectSources(
    inventory(now),
    config,
    store.checkpoints(),
    http(now),
    now,
    store.evidence(),
  );
  store.saveEvidence(result.evidence, result.checkpoints);
  return result;
}
const remembered = (result) => JSON.parse(result.checkpoints['github:reviewed:unreadable'] ?? '[]');

test('a format outage holds the checkpoint, counts no attempt, and the window is read again when it ends', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], { 'github:reviewed': iso(NOW), 'github:malware': iso(NOW) });
  const until = NOW + 6 * HOUR;
  // 30 records over the outage, one of them for an inventory package; nothing can be read until it ends.
  const records = (now) =>
    Array.from({ length: 30 }, (_, index) =>
      advisory(
        `GHSA-zzzz-${String(index).padStart(4, '0')}-zzzz`,
        index === 7 ? 'alpha' : `other-${index}`,
        NOW + (index + 1) * 10 * MINUTE,
        now >= until,
      ),
    );
  const { http } = github(records);
  let during;
  for (let now = NOW + 30 * MINUTE; now < until; now += 30 * MINUTE) during = await poll(store, http, now);
  assert.equal(during.checkpoints['github:reviewed'], iso(NOW), 'the checkpoint waits');
  assert.ok(
    remembered(during).every(([, , attempts]) => attempts === 0),
    'no attempt is counted',
  );
  const after = await poll(store, http, until + 30 * MINUTE);
  assert.ok(
    after.evidence.some((item) => item.id === 'github:GHSA-zzzz-0007-zzzz'),
    'the alpha record is read',
  );
  assert.deepEqual(remembered(after), []);
  assert.equal(JSON.parse(after.checkpoints['github:reviewed:skipped']).length, 0);
});

test("a remembered record is asked for in GitHub's own spelling, the longest waiting first, within the budget", async () => {
  const store = new Store(':memory:');
  const ids = ['GHSA-aaaa-bbbb-0003', 'GHSA-aaaa-bbbb-0001', 'GHSA-aaaa-bbbb-0002'];
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    // First met at different times; the earliest is asked for first.
    'github:reviewed:unreadable': JSON.stringify([
      [ids[0], NOW - 3 * HOUR, 1],
      [ids[1], NOW - 5 * HOUR, 1],
      [ids[2], NOW - 4 * HOUR, 1],
    ]),
  });
  const { http, log } = github(() => ids.map((id) => advisory(id, 'zeta', NOW - 6 * HOUR, false)));
  const result = await poll(store, http, NOW + 30 * MINUTE);
  // Without a token, two per run.
  assert.deepEqual(log.byId, ['GHSA-aaaa-bbbb-0001', 'GHSA-aaaa-bbbb-0002']);
  assert.deepEqual(
    remembered(result)
      .map(([id, , attempts]) => [id, attempts])
      .sort(),
    [
      ['GHSA-aaaa-bbbb-0001', 2],
      ['GHSA-aaaa-bbbb-0002', 2],
      ['GHSA-aaaa-bbbb-0003', 1],
    ],
  );
  // With a token, up to ten.
  process.env.FOURTEENTH_GITHUB_TOKEN = 'synthetic';
  try {
    log.byId.length = 0;
    await poll(store, http, NOW + 60 * MINUTE);
    assert.equal(log.byId.length, 3);
  } finally {
    delete process.env.FOURTEENTH_GITHUB_TOKEN;
  }
});

test('a record listed in this run is not asked for again by identifier; a 404 is a failed read', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([
      ['GHSA-aaaa-bbbb-0010', NOW - HOUR, 0],
      ['GHSA-aaaa-bbbb-0011', NOW - 2 * HOUR, 0],
    ]),
  });
  // 0010 is listed again (unreadable); 0011 is no longer served at all.
  const { http, log } = github(() => [
    advisory('GHSA-aaaa-bbbb-0010', 'zeta', NOW + 10 * MINUTE, false),
    advisory('GHSA-aaaa-bbbb-0012', 'omega', NOW + 5 * MINUTE),
  ]);
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(log.byId, ['GHSA-aaaa-bbbb-0011']);
  assert.deepEqual(
    remembered(result)
      .map(([id, , attempts]) => [id, attempts])
      .sort(),
    [
      ['GHSA-aaaa-bbbb-0010', 1],
      ['GHSA-aaaa-bbbb-0011', 1],
    ],
  );
});

test('a record is not given up on after one or two failed reads, however long it waited', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([['GHSA-aaaa-bbbb-0020', NOW - 3 * DAY, 1]]),
  });
  const { http } = github(() => [
    advisory('GHSA-aaaa-bbbb-0020', 'zeta', NOW + 10 * MINUTE, false),
    advisory('GHSA-aaaa-bbbb-0021', 'omega', NOW + 5 * MINUTE),
  ]);
  const second = await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(
    remembered(second).map(([, , attempts]) => attempts),
    [2],
  );
  const third = await poll(store, http, NOW + 60 * MINUTE);
  assert.deepEqual(remembered(third), []);
  assert.deepEqual(JSON.parse(third.checkpoints['github:reviewed:skipped']), ['GHSA-aaaa-bbbb-0020']);
});

test('a rate limit on a request by identifier ends those requests and is reported', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([
      ['GHSA-aaaa-bbbb-0030', NOW - 2 * HOUR, 1],
      ['GHSA-aaaa-bbbb-0031', NOW - HOUR, 1],
    ]),
  });
  const { http, log } = github(
    () => [
      advisory('GHSA-aaaa-bbbb-0030', 'zeta', NOW - DAY),
      advisory('GHSA-aaaa-bbbb-0031', 'zeta', NOW - DAY),
    ],
    {
      byId: () => ({ status: 429, headers: {}, body: '' }),
    },
  );
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(log.byId, ['GHSA-aaaa-bbbb-0030']);
  assert.match(result.errors[0].message, /rate limit/);
  assert.deepEqual(
    remembered(result).map(([, , attempts]) => attempts),
    [1, 1],
    'a refusal is not a failed read',
  );
});

test('once a record is read again by identifier, the listing is read again from the oldest still remembered', async () => {
  const store = new Store(':memory:');
  const updated = NOW - 5 * HOUR;
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([
      ['GHSA-aaaa-bbbb-0040', NOW - 4 * HOUR, 1, updated],
      ['GHSA-aaaa-bbbb-0041', NOW - 3 * HOUR, 1, updated + HOUR],
      ['GHSA-aaaa-bbbb-0042', NOW - 2 * HOUR, 1, updated + 2 * HOUR],
    ]),
  });
  // The format is back: every record reads.
  const { http } = github(() => [
    advisory('GHSA-aaaa-bbbb-0040', 'zeta', updated),
    advisory('GHSA-aaaa-bbbb-0041', 'zeta', updated + HOUR),
    advisory('GHSA-aaaa-bbbb-0042', 'zeta', updated + 2 * HOUR),
  ]);
  const first = await poll(store, http, NOW + 30 * MINUTE);
  // Two were read by identifier; the third waits, so the listing goes back to it.
  assert.equal(first.checkpoints['github:reviewed'], iso(updated + 2 * HOUR + HOUR));
  const second = await poll(store, http, NOW + 60 * MINUTE);
  assert.deepEqual(remembered(second), []);
  assert.deepEqual(second.errors, []);
});

test('beyond the cap of 10,000 remembered records, those whose day has passed are given up on first, and the checkpoint moves', async () => {
  const store = new Store(':memory:');
  // 9,999 met an hour ago, and two met two days ago.
  const remember = [
    ...Array.from({ length: 9_999 }, (_, index) => [
      `GHSA-cccc-${String(index).padStart(4, '0')}-cccc`,
      NOW - HOUR + index,
      1,
    ]),
    ['GHSA-old0-0000-old0', NOW - 2 * DAY, 1],
    ['GHSA-old1-0000-old1', NOW - 2 * DAY + 1, 1],
  ];
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify(remember),
  });
  const { http } = github(() => [advisory('GHSA-dddd-0000-dddd', 'omega', NOW + 5 * MINUTE)], {
    byId: () => ({ status: 503, headers: {}, body: '' }),
  });
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.equal(remembered(result).length, 10_000);
  assert.deepEqual(JSON.parse(result.checkpoints['github:reviewed:skipped']), ['GHSA-old1-0000-old1']);
  assert.equal(result.checkpoints['github:reviewed'], iso(NOW + 30 * MINUTE), 'the checkpoint moves');
});

test('a window holding only records that cannot be read for more than a day is not an outage', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([['GHSA-aaaa-bbbb-0060', NOW - 2 * DAY, 1]]),
  });
  const { http } = github(() => [advisory('GHSA-aaaa-bbbb-0060', 'zeta', NOW + 5 * MINUTE, false)]);
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.equal(result.checkpoints['github:reviewed'], iso(NOW + 30 * MINUTE), 'the checkpoint moves');
  assert.deepEqual(
    remembered(result).map(([, , attempts]) => attempts),
    [2],
    'the failed read counts',
  );
});

test('a record given up on keeps its place while its stored copy exists', async () => {
  const store = new Store(':memory:');
  const skipped = Array.from(
    { length: 2_005 },
    (_, index) => `GHSA-eeee-${String(index).padStart(4, '0')}-eeee`,
  );
  const stored = {
    id: `github:${skipped[0]}`,
    source: 'github:reviewed',
    kind: 'advisory',
    title: 'alpha flaw',
    url: 'https://github.com/advisories/x',
    description: '',
    aliases: [],
    severity: 'critical',
    modified_at: iso(NOW - DAY),
    fetched_at: iso(NOW - HOUR),
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
  };
  store.saveEvidence([stored], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:skipped': JSON.stringify(skipped),
  });
  const { http } = github(() => [advisory('GHSA-dddd-0001-dddd', 'omega', NOW + 5 * MINUTE)]);
  const result = await poll(store, http, NOW + 30 * MINUTE);
  const kept = JSON.parse(result.checkpoints['github:reviewed:skipped']);
  assert.ok(kept.includes(skipped[0]), 'the one with a stored copy is kept');
  assert.ok(!result.evidence.some((item) => item.id === stored.id), 'its stored copy is not confirmed');
});

test('a listed row dated in the future does not move the listing past records not yet read', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], { 'github:reviewed': iso(NOW), 'github:malware': iso(NOW) });
  const rows = Array.from({ length: 5_000 }, (_, index) =>
    advisory(`GHSA-ffff-${String(index).padStart(4, '0')}-ffff`, `other-${index}`, NOW + index * 100),
  );
  rows.push({ ...advisory('GHSA-ffff-9999-ffff', 'other', NOW + DAY), updated_at: iso(NOW + DAY) });
  const http = (now) => async (raw) => {
    const url = new URL(raw);
    if (url.searchParams.get('type') === 'malware') return json([]);
    const page = Number(url.searchParams.get('page') ?? 0);
    const headers = {};
    if (rows.length > (page + 1) * 100) {
      const next = new URL(url);
      next.searchParams.set('page', String(page + 1));
      headers.link = `<${next.href}>; rel="next"`;
    }
    return json(rows.slice(page * 100, page * 100 + 100), headers);
  };
  const result = await poll(store, http, NOW + HOUR);
  assert.ok(Date.parse(result.checkpoints['github:reviewed']) <= NOW + HOUR, 'not past the clock');
});

// ---- Delivery and claim checks from the fourteenth delivery review ------------------------------

const claim = (quote, product, version = '8.6', freeQuote = quote) => {
  const story = {
    id: 'feed:x:entry:14',
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
        quotes: [{ evidence_id: story.id, quote: freeQuote }],
        news_analysis: {
          classification: 'new_vulnerability',
          impact: 'affected',
          affected_products: [product],
          affected_versions: [version],
          prerequisites: [],
          rationale: 'Checked.',
          quotes: [{ evidence_id: story.id, quote: freeQuote }],
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

test('a quote the model writes itself is read with the words it cuts from the evidence', () => {
  const text = 'Example Server 12.4.1 lets unauthenticated users of expressive-forms upload files.';
  // The product claim is supported either way; only the version decides.
  assert.equal(claim(text, 'unauthenticated users', '2.4.1', '2.4.1 lets unauthenticated users'), false);
  assert.equal(claim(text, 'unauthenticated users', '12.4.1', '12.4.1 lets unauthenticated users'), true);
  assert.equal(claim(text, 'express', '12.4.1', '12.4.1 lets unauthenticated users of express'), false);
  assert.equal(claim(text, 'Example Server', '12.4.1', 'Example Server 12.4.1 lets'), true);
});

test('a version may carry a package revision, a qualifier or a file extension after the name', () => {
  for (const [quote, product, version] of [
    ['Upgrade openssl-3.0.7-r0 now; 8.6 is affected.', 'openssl'],
    ['The glibc-2.35-0ubuntu3 package, 8.6, is affected.', 'glibc'],
    ['Tomcat-9.0.80-beta and 8.6 are affected.', 'Tomcat'],
    ['spring-core-5.3.20.RELEASE and 8.6 are affected.', 'spring-core'],
    ['log4j-core-2.14.1.jar and 8.6 are affected.', 'log4j-core'],
    ['node-v18 builds and 8.6 are affected.', 'node'],
  ])
    assert.equal(claim(quote, product), true, `${product} in ${quote}`);
  for (const [quote, product] of [
    ['vue-3.model 8.6 is affected.', 'vue'],
    ['vue-3:d 8.6 is affected.', 'vue'],
    ['express:session 8.6 is affected.', 'express'],
    ['express·forms 8.6 is affected.', 'express'],
    ['The @angular⧸core 8.6 compiler is affected.', 'core'],
  ])
    assert.equal(claim(quote, product), false, `${product} in ${quote}`);
});

test('claim and version edges: astral characters, a bare "#" or "-", a CJK name next to Latin, "№"', () => {
  assert.equal(claim('𐐀express 8.6 is affected.', 'express'), false);
  assert.equal(claim('express𐐀 8.6 is affected.', 'express'), false);
  assert.equal(claim('#PHP 8.6 is affected.', 'PHP'), true);
  assert.equal(claim('- Git 8.6 is affected.', 'Git'), true);
  assert.equal(claim('微信app 8.6 is affected.', '微信'), true);
  assert.equal(claim('Example Server №5 is affected.', 'Example Server', '5'), false);
  assert.equal(claim('Example Server 𐐀2.4.1 is affected.', 'Example Server', '2.4.1'), false);
  assert.equal(claim('Example Server 2.4.1 is affected.', 'Example Server', '2.4.'), false);
});

test('"localhost." is refused like "localhost"', () => {
  assert.throws(() => validateDestination('https://localhost./ping'), /./);
});

const rule = { levels: ['critical'], basis: 'source_severity', channels: ['slack', 'email'] };
const deliveryConfig = {
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
  notifications: {
    max_attempts: 3,
    slack: { webhook_url_env: 'FOURTEENTH_SLACK' },
    email: { smtp_url_env: 'FOURTEENTH_SMTP', from: 'watch@example.com', to: ['security@example.com'] },
  },
};
function deliveryStore(t, channels) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  process.env.FOURTEENTH_SLACK = 'https://hooks.slack.com/services/T/B/secret';
  process.env.FOURTEENTH_SMTP = 'smtps://user:password@mail.example.com';
  t.after(() => {
    delete process.env.FOURTEENTH_SLACK;
    delete process.env.FOURTEENTH_SMTP;
  });
  store.saveAssessment(
    {
      id: 'finding-1',
      event_id: 'CVE-2026-94001',
      system_id: 'prod',
      category: 'library',
      applicability: 'affected',
      source_severity: 'critical',
      priority: 'critical',
      title: 'flaw',
      summary: 'A flaw.',
      reasons: [],
      evidence_ids: [],
      urls: [],
      exploited: false,
      updated_at: iso(NOW),
    },
    { action: 'notify', channels, reason: 'critical' },
    1000,
  );
  return store;
}

test('a recipient the mail server rejected leaves the receipt uncertain', async (t) => {
  const store = deliveryStore(t, ['email']);
  await deliverPending(
    store,
    deliveryConfig,
    async () => assert.fail('no Slack'),
    1000,
    async () => ({
      accepted: ['security@example.com'],
      rejected: ['security@example.com'],
    }),
  );
  assert.equal(store.jobs()[0].status, 'unknown');
});

test('a job taken back while Slack answered with an unexpected success is marked uncertain', async (t) => {
  const store = deliveryStore(t, ['slack']);
  await deliverPending(
    store,
    deliveryConfig,
    async () => {
      const [job] = store.jobs();
      store.recoverSending(1000);
      store.retryJob(job.id, 1000);
      return { status: 202, body: 'queued', headers: {} };
    },
    1000,
  );
  assert.equal(store.jobs()[0].status, 'unknown', 'not left pending, where it would be sent again');
});

test('a failed request for a single GitHub record is reported, not swallowed', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([['GHSA-aaaa-bbbb-0050', NOW - HOUR, 1]]),
  });
  const { http } = github(() => [advisory('GHSA-aaaa-bbbb-0050', 'zeta', NOW - DAY)], {
    byId: () => ({ status: 503, headers: {}, body: '' }),
  });
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.match(
    result.errors.map((error) => error.message).join(' '),
    /1 request\(s\) for single records failed/,
  );
  assert.deepEqual(
    remembered(result).map(([, , attempts]) => attempts),
    [1],
    'not a failed read',
  );
});

test('a format outage over more rows than one scan reads holds the checkpoint too', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], { 'github:reviewed': iso(NOW), 'github:malware': iso(NOW) });
  const rows = Array.from({ length: 5_100 }, (_, index) =>
    advisory(`GHSA-gggg-${String(index).padStart(4, '0')}-gggg`, `other-${index}`, NOW + index * 100, false),
  );
  const http = () => async (raw) => {
    const url = new URL(raw);
    if (url.searchParams.get('type') === 'malware') return json([]);
    const page = Number(url.searchParams.get('page') ?? 0);
    const headers = {};
    if (rows.length > (page + 1) * 100) {
      const next = new URL(url);
      next.searchParams.set('page', String(page + 1));
      headers.link = `<${next.href}>; rel="next"`;
    }
    return json(rows.slice(page * 100, page * 100 + 100), headers);
  };
  const result = await poll(store, http, NOW + HOUR);
  assert.equal(result.checkpoints['github:reviewed'], iso(NOW), 'not moved past rows that could not be read');
  // Each remembered row keeps the update time it was listed with, for the listing to come back to.
  const [first] = remembered(result);
  assert.equal(first[3], NOW);
});

test('a record read again by identifier keeps the update time it was listed with', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([
      ['GHSA-aaaa-bbbb-0070', NOW - 2 * HOUR, 1, NOW - 3 * HOUR],
      ['GHSA-aaaa-bbbb-0071', NOW - HOUR, 1, NOW + DAY],
    ]),
  });
  const { http } = github(() => [
    advisory('GHSA-aaaa-bbbb-0070', 'zeta', NOW - 3 * HOUR, false),
    advisory('GHSA-aaaa-bbbb-0071', 'zeta', NOW - 3 * HOUR, false),
  ]);
  const result = await poll(store, http, NOW + 30 * MINUTE);
  const entries = Object.fromEntries(remembered(result).map((entry) => [entry[0], entry]));
  assert.equal(entries['GHSA-aaaa-bbbb-0070'][3], NOW - 3 * HOUR, 'kept through a failed read by identifier');
  // A time ahead of the clock is not kept.
  assert.equal(entries['GHSA-aaaa-bbbb-0071'].length, 3);
});

test('records given up on are asked for again in turn with the room left, and found once GitHub serves them readably', async () => {
  const store = new Store(':memory:');
  const ids = ['GHSA-aaaa-bbbb-0080', 'GHSA-aaaa-bbbb-0081', 'GHSA-aaaa-bbbb-0082'];
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:skipped': JSON.stringify(ids),
  });
  let readable = false;
  const { http, log } = github(() => ids.map((id) => advisory(id, 'alpha', NOW - DAY, readable)));
  const first = await poll(store, http, NOW + 30 * MINUTE);
  // Without a token two requests per run, both spare: two records, in turn.
  assert.deepEqual(log.byId, [ids[0], ids[1]]);
  assert.deepEqual(first.errors, [], 'no new report while they still cannot be read');
  await poll(store, http, NOW + 60 * MINUTE);
  assert.deepEqual(log.byId.slice(2), [ids[2], ids[0]], 'the next in turn');
  readable = true;
  const found = await poll(store, http, NOW + 90 * MINUTE);
  assert.ok(found.evidence.some((item) => item.id === `github:${ids[1]}`));
  assert.ok(found.evidence.some((item) => item.id === `github:${ids[2]}`));
  assert.deepEqual(JSON.parse(found.checkpoints['github:reviewed:skipped']), [ids[0]]);
});

test("GitHub's primary rate limit (403) also ends the requests by identifier", async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([
      ['GHSA-aaaa-bbbb-0090', NOW - 2 * HOUR, 1],
      ['GHSA-aaaa-bbbb-0091', NOW - HOUR, 1],
    ]),
  });
  const { http, log } = github(() => [advisory('GHSA-aaaa-bbbb-0090', 'zeta', NOW - DAY)], {
    byId: () => ({ status: 403, headers: {}, body: '' }),
  });
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(log.byId, ['GHSA-aaaa-bbbb-0090']);
  assert.match(result.errors[0].message, /rate limit/);
});

test('a given-up record with a stored copy gets a turn every run, and cannot keep the others from theirs', async () => {
  const store = new Store(':memory:');
  const copy = {
    id: 'github:GHSA-aaaa-bbbb-0100',
    source: 'github:reviewed',
    kind: 'advisory',
    title: 'alpha flaw',
    url: 'https://github.com/advisories/x',
    description: '',
    aliases: [],
    severity: 'critical',
    modified_at: iso(NOW - 2 * DAY),
    fetched_at: iso(NOW - DAY),
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
  };
  store.saveEvidence([copy], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:skipped': JSON.stringify([
      'GHSA-aaaa-bbbb-0101',
      'GHSA-aaaa-bbbb-0102',
      'GHSA-aaaa-bbbb-0100',
    ]),
  });
  // The one with a stored copy never becomes readable; 0102 does.
  const { http, log } = github(() => [
    advisory('GHSA-aaaa-bbbb-0100', 'alpha', NOW - DAY, false),
    advisory('GHSA-aaaa-bbbb-0101', 'zeta', NOW - DAY, false),
    advisory('GHSA-aaaa-bbbb-0102', 'alpha', NOW - DAY),
  ]);
  const first = await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(log.byId, ['GHSA-aaaa-bbbb-0100', 'GHSA-aaaa-bbbb-0101']);
  const second = await poll(store, http, NOW + 60 * MINUTE);
  assert.deepEqual(log.byId.slice(2), ['GHSA-aaaa-bbbb-0100', 'GHSA-aaaa-bbbb-0102']);
  assert.ok(
    second.evidence.some((item) => item.id === 'github:GHSA-aaaa-bbbb-0102'),
    'the other record is found',
  );
  assert.ok(!first.evidence.some((item) => item.id === copy.id), 'the stored copy is not confirmed');
});

test('a given-up record asked for again that answers 404 is not reported or remembered again', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:skipped': JSON.stringify(['GHSA-aaaa-bbbb-0110']),
  });
  const { http } = github(() => []);
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(remembered(result), []);
  assert.deepEqual(JSON.parse(result.checkpoints['github:reviewed:skipped']), ['GHSA-aaaa-bbbb-0110']);
});

test('the re-ask of a given-up record stays within the budget without a token', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([
      ['GHSA-aaaa-bbbb-0120', NOW - 3 * HOUR, 1],
      ['GHSA-aaaa-bbbb-0121', NOW - 2 * HOUR, 1],
    ]),
    'github:reviewed:skipped': JSON.stringify(['GHSA-aaaa-bbbb-0122']),
  });
  const { http, log } = github(() => [
    advisory('GHSA-aaaa-bbbb-0120', 'zeta', NOW - DAY, false),
    advisory('GHSA-aaaa-bbbb-0121', 'zeta', NOW - DAY, false),
  ]);
  await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(
    log.byId,
    ['GHSA-aaaa-bbbb-0120', 'GHSA-aaaa-bbbb-0121'],
    'two remembered, no room for a re-ask',
  );
});

test('records given up because of the cap are counted in the report', async () => {
  const store = new Store(':memory:');
  const remember = Array.from({ length: 10_002 }, (_, index) => [
    `GHSA-hhhh-${String(index).padStart(4, '0')}-hhhh`,
    NOW - HOUR + index,
    1,
  ]);
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify(remember),
  });
  const { http } = github(() => [advisory('GHSA-dddd-0002-dddd', 'omega', NOW + 5 * MINUTE)], {
    byId: () => ({ status: 503, headers: {}, body: '' }),
  });
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.match(
    result.errors.map((error) => error.message).join(' '),
    /GitHub: 2 record\(s\) could not be read three times/,
  );
});

test('a window of unreadable records first met just under a day ago is an outage; just over is not', async () => {
  for (const [age, held] of [
    [23 * HOUR, true],
    [25 * HOUR, false],
  ]) {
    const store = new Store(':memory:');
    store.saveEvidence([], {
      'github:reviewed': iso(NOW),
      'github:malware': iso(NOW),
      'github:reviewed:unreadable': JSON.stringify([['GHSA-aaaa-bbbb-0130', NOW + 30 * MINUTE - age, 1]]),
    });
    const { http } = github(() => [advisory('GHSA-aaaa-bbbb-0130', 'zeta', NOW + 5 * MINUTE, false)]);
    const result = await poll(store, http, NOW + 30 * MINUTE);
    assert.equal(result.checkpoints['github:reviewed'] === iso(NOW), held, `${age / HOUR} h`);
  }
});

test('beyond 10,000 given-up records the oldest without a stored copy are dropped, in place', async () => {
  const store = new Store(':memory:');
  const withCopy = 'GHSA-kkkk-0000-kkkk';
  const others = Array.from(
    { length: 10_001 },
    (_, index) => `GHSA-jjjj-${String(index).padStart(4, '0')}-jjjj`,
  );
  store.saveEvidence(
    [
      {
        id: `github:${withCopy}`,
        source: 'github:reviewed',
        kind: 'advisory',
        title: 'alpha flaw',
        url: 'https://github.com/advisories/x',
        description: '',
        aliases: [],
        severity: 'critical',
        modified_at: iso(NOW - 2 * DAY),
        fetched_at: iso(NOW - DAY),
        packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
      },
    ],
    {
      'github:reviewed': iso(NOW),
      'github:malware': iso(NOW),
      'github:reviewed:skipped': JSON.stringify([withCopy, ...others]),
    },
  );
  // No request to spare for re-asking: GitHub refuses requests by identifier.
  const { http } = github(() => [], { byId: () => ({ status: 429, headers: {}, body: '' }) });
  const result = await poll(store, http, NOW + 30 * MINUTE);
  const kept = JSON.parse(result.checkpoints['github:reviewed:skipped']);
  assert.ok(kept.includes(withCopy));
  assert.ok(!kept.includes(others[0]) || !kept.includes(others[1]), 'the oldest without a copy go');
  assert.equal(kept.filter((id) => id !== withCopy).length, 10_000);
});

test('a stored copy counts only for its own GitHub type', async () => {
  const store = new Store(':memory:');
  store.saveEvidence(
    [
      {
        id: 'github:GHSA-llll-0000-llll',
        source: 'github:reviewed',
        kind: 'advisory',
        title: 'alpha flaw',
        url: 'https://github.com/advisories/x',
        description: '',
        aliases: [],
        severity: 'critical',
        modified_at: iso(NOW - 2 * DAY),
        fetched_at: iso(NOW - DAY),
        packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
      },
    ],
    {
      'github:reviewed': iso(NOW),
      'github:malware': iso(NOW),
      'github:malware:skipped': JSON.stringify([
        'GHSA-mmmm-0001-mmmm',
        'GHSA-mmmm-0002-mmmm',
        'GHSA-llll-0000-llll',
      ]),
    },
  );
  const asked = [];
  const http = () => async (raw) => {
    const url = new URL(raw);
    if (url.pathname !== '/advisories') {
      asked.push(decodeURIComponent(url.pathname.split('/').at(-1)));
      return { status: 404, headers: {}, body: '' };
    }
    return json([]);
  };
  await poll(store, http, NOW + 30 * MINUTE);
  // For the malware type there is no stored copy: the records simply take their turns.
  assert.deepEqual(asked, ['GHSA-mmmm-0001-mmmm', 'GHSA-mmmm-0002-mmmm']);
});

const storedCopy = (id) => ({
  id: `github:${id}`,
  source: 'github:reviewed',
  kind: 'advisory',
  title: 'alpha flaw',
  url: 'https://github.com/advisories/x',
  description: '',
  aliases: [],
  severity: 'critical',
  modified_at: iso(NOW - 2 * DAY),
  fetched_at: iso(NOW - DAY),
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
});

test('with one request to spare, given-up records simply take turns', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([storedCopy('GHSA-aaaa-bbbb-0131')], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([['GHSA-aaaa-bbbb-0129', NOW - 2 * HOUR, 1]]),
    'github:reviewed:skipped': JSON.stringify(['GHSA-aaaa-bbbb-0130', 'GHSA-aaaa-bbbb-0131']),
  });
  const { http, log } = github(() => [
    advisory('GHSA-aaaa-bbbb-0129', 'zeta', NOW - DAY, false),
    advisory('GHSA-aaaa-bbbb-0130', 'zeta', NOW - DAY, false),
    advisory('GHSA-aaaa-bbbb-0131', 'alpha', NOW - DAY, false),
  ]);
  await poll(store, http, NOW + 30 * MINUTE);
  // One remembered record, then the next given up on in turn, not the one with a stored copy.
  assert.deepEqual(log.byId, ['GHSA-aaaa-bbbb-0129', 'GHSA-aaaa-bbbb-0130']);
});

test('a given-up record with a stored copy that is also next in turn is asked for once', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([storedCopy('GHSA-aaaa-bbbb-0140')], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:skipped': JSON.stringify(['GHSA-aaaa-bbbb-0140', 'GHSA-aaaa-bbbb-0141']),
  });
  const { http, log } = github(() => [
    advisory('GHSA-aaaa-bbbb-0140', 'alpha', NOW - DAY, false),
    advisory('GHSA-aaaa-bbbb-0141', 'zeta', NOW - DAY, false),
  ]);
  await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(log.byId, ['GHSA-aaaa-bbbb-0140', 'GHSA-aaaa-bbbb-0141']);
});

test('a given-up record that this scan could not read in the listing is not asked for again by identifier', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW - HOUR),
    'github:malware': iso(NOW),
    'github:reviewed:skipped': JSON.stringify(['GHSA-aaaa-bbbb-0150', 'GHSA-aaaa-bbbb-0151']),
  });
  const { http, log } = github(() => [
    advisory('GHSA-aaaa-bbbb-0150', 'zeta', NOW - 10 * MINUTE, false),
    advisory('GHSA-aaaa-bbbb-0152', 'zeta', NOW - 10 * MINUTE),
  ]);
  await poll(store, http, NOW + 30 * MINUTE);
  assert.ok(!log.byId.includes('GHSA-aaaa-bbbb-0150'), JSON.stringify(log.byId));
  assert.ok(log.byId.includes('GHSA-aaaa-bbbb-0151'), JSON.stringify(log.byId));
});

test('a given-up record listed again is remembered once more and asked for once per run', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW - HOUR),
    'github:malware': iso(NOW),
    'github:reviewed:skipped': JSON.stringify(['GHSA-aaaa-bbbb-0160', 'GHSA-aaaa-bbbb-0161']),
  });
  // Updated again and still unreadable.
  const { http, log } = github(() => [advisory('GHSA-aaaa-bbbb-0160', 'zeta', NOW - 10 * MINUTE, false)]);
  const first = await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(
    remembered(first).map((entry) => entry[0]),
    ['GHSA-aaaa-bbbb-0160'],
  );
  assert.deepEqual(JSON.parse(first.checkpoints['github:reviewed:skipped']), ['GHSA-aaaa-bbbb-0161']);
  for (let run = 2; run <= 4; run++) {
    log.byId.length = 0;
    const result = await poll(store, http, NOW + run * 3 * HOUR);
    assert.equal(new Set(log.byId).size, log.byId.length, `run ${run}: ${log.byId}`);
    assert.ok(
      remembered(result).some((entry) => entry[0] === 'GHSA-aaaa-bbbb-0160') ||
        JSON.parse(result.checkpoints['github:reviewed:skipped']).includes('GHSA-aaaa-bbbb-0160'),
    );
  }
  // An entry already in both lists (saved by an earlier version) is still asked for once.
  const both = new Store(':memory:');
  both.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify([['GHSA-aaaa-bbbb-0170', NOW - 2 * HOUR, 1]]),
    'github:reviewed:skipped': JSON.stringify(['GHSA-aaaa-bbbb-0170']),
  });
  const again = github(() => [advisory('GHSA-aaaa-bbbb-0170', 'zeta', NOW - DAY, false)]);
  await poll(both, again.http, NOW + 30 * MINUTE);
  assert.deepEqual(again.log.byId, ['GHSA-aaaa-bbbb-0170']);
});

test('with a token, at most two given-up records are asked for again per run', async () => {
  const store = new Store(':memory:');
  const ids = Array.from({ length: 6 }, (_, index) => `GHSA-aaaa-bbbb-018${index}`);
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:skipped': JSON.stringify(ids),
  });
  const { http, log } = github(() => ids.map((id) => advisory(id, 'zeta', NOW - DAY, false)));
  process.env.FOURTEENTH_GITHUB_TOKEN = 'synthetic';
  try {
    await poll(store, http, NOW + 30 * MINUTE);
  } finally {
    delete process.env.FOURTEENTH_GITHUB_TOKEN;
  }
  assert.deepEqual(log.byId, ids.slice(0, 2));
});

test('beyond the cap of given-up records, one with a stored copy is kept although it is the oldest', async () => {
  const store = new Store(':memory:');
  const others = Array.from(
    { length: 10_001 },
    (_, index) => `GHSA-jjjj-${String(index).padStart(4, '0')}-jjjj`,
  );
  store.saveEvidence([storedCopy('GHSA-aaaa-bbbb-0190')], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    // Two remembered records take the whole budget, so no given-up record moves to the back.
    'github:reviewed:unreadable': JSON.stringify([
      ['GHSA-aaaa-bbbb-0191', NOW - 2 * HOUR, 1],
      ['GHSA-aaaa-bbbb-0192', NOW - HOUR, 1],
    ]),
    'github:reviewed:skipped': JSON.stringify(['GHSA-aaaa-bbbb-0190', ...others]),
  });
  const { http, log } = github(() => []);
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.ok(!log.byId.includes('GHSA-aaaa-bbbb-0190'));
  const kept = JSON.parse(result.checkpoints['github:reviewed:skipped']);
  assert.equal(kept[0], 'GHSA-aaaa-bbbb-0190');
  assert.equal(kept.filter((id) => id.startsWith('GHSA-jjjj')).length, 10_000);
  assert.ok(!kept.includes(others[0]), 'the oldest without a copy is dropped');
});

test('a row without a usable identifier holds the checkpoint for a day, then breaks the chain of confirmations', async () => {
  const store = new Store(':memory:');
  const copy = { ...storedCopy('GHSA-aaaa-bbbb-0200'), fetched_at: iso(NOW) };
  store.saveEvidence([copy], { 'github:reviewed': iso(NOW), 'github:malware': iso(NOW) });
  // GitHub widens the range and serves the row without its identifier.
  let served = 'none';
  const row = () => {
    const record = advisory('GHSA-aaaa-bbbb-0200', 'alpha', NOW + 10 * MINUTE);
    if (served === 'none') delete record.ghsa_id;
    if (served === 'null') record.ghsa_id = null;
    return record;
  };
  const { http } = github((now) => (now >= NOW + 10 * MINUTE ? [row()] : []));
  for (let run = 1; run <= 4; run++) {
    const result = await poll(store, http, NOW + run * 30 * MINUTE);
    assert.ok(Date.parse(result.checkpoints['github:reviewed']) <= NOW + 10 * MINUTE + HOUR, `run ${run}`);
    assert.ok(!result.evidence.some((item) => item.id === copy.id), 'the stored copy is not confirmed');
    served = run % 2 ? 'null' : 'none';
  }
  // Served with its identifier again: read, and the checkpoint moves on.
  served = 'id';
  const read = await poll(store, http, NOW + 3 * HOUR);
  assert.ok(read.evidence.some((item) => item.id === copy.id && item.fetched_at === iso(NOW + 3 * HOUR)));
  assert.equal(read.checkpoints['github:reviewed'], iso(NOW + 3 * HOUR));
  assert.equal(read.checkpoints['github:reviewed:unidentified'], '');

  // Without an identifier for more than a day: the checkpoint moves, and no stored copy read before
  // is confirmed again.
  const later = new Store(':memory:');
  later.saveEvidence([copy], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unidentified': String(NOW - DAY - HOUR),
  });
  served = 'none';
  const moved = await poll(later, http, NOW + 30 * MINUTE);
  assert.equal(moved.checkpoints['github:reviewed'], iso(NOW + 30 * MINUTE));
  assert.equal(moved.checkpoints['github:reviewed:unconfirmed_before'], iso(NOW + 30 * MINUTE));
  const next = await poll(later, github(() => []).http, NOW + HOUR);
  assert.ok(!next.evidence.some((item) => item.id === copy.id), 'the old copy is not confirmed again');
});

test('a listing whose rows all lack an identifier is an outage: no failed read is counted', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    // First met two days ago, so only the row without an identifier makes this an outage.
    'github:reviewed:unreadable': JSON.stringify([['GHSA-aaaa-bbbb-0210', NOW - 2 * DAY, 1]]),
  });
  const { http } = github(() => {
    const listed = advisory('GHSA-aaaa-bbbb-0211', 'zeta', NOW + 10 * MINUTE);
    delete listed.ghsa_id;
    return [listed, advisory('GHSA-aaaa-bbbb-0210', 'zeta', NOW - DAY, false)];
  });
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.deepEqual(
    remembered(result).map(([id, , attempts]) => [id, attempts]),
    [['GHSA-aaaa-bbbb-0210', 1]],
  );
});
