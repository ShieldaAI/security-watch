// Regressions from the fourteenth review of GitHub collection: records that cannot be read are
// remembered by identifier, asked for in GitHub's own spelling within a request budget, given up on
// only after three failed reads over a day, and a format outage holds the checkpoint so that the
// whole window is listed again.
import test from 'node:test';
import assert from 'node:assert/strict';
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
  assert.deepEqual(JSON.parse(third.checkpoints['github:reviewed:skipped']), ['GHSA-AAAA-BBBB-0020']);
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

test('remembered records beyond the cap are listed again, not given up on', async () => {
  const store = new Store(':memory:');
  const remember = Array.from({ length: 2_001 }, (_, index) => [
    `GHSA-cccc-${String(index).padStart(4, '0')}-cccc`,
    NOW - DAY + index,
    1,
    NOW - 10 * HOUR + index * 1000,
  ]);
  store.saveEvidence([], {
    'github:reviewed': iso(NOW),
    'github:malware': iso(NOW),
    'github:reviewed:unreadable': JSON.stringify(remember),
  });
  const { http } = github(() => [advisory('GHSA-dddd-0000-dddd', 'omega', NOW + 5 * MINUTE)], {
    byId: () => ({ status: 503, headers: {}, body: '' }),
  });
  const result = await poll(store, http, NOW + 30 * MINUTE);
  assert.equal(remembered(result).length, 2_000);
  assert.equal(JSON.parse(result.checkpoints['github:reviewed:skipped']).length, 0, 'none is given up on');
  // The newest, beyond the cap, is listed again from its update time.
  assert.equal(result.checkpoints['github:reviewed'], iso(NOW - 10 * HOUR + 2_000 * 1000 + HOUR));
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
  assert.ok(kept.includes(skipped[0].toUpperCase()), 'the one with a stored copy is kept');
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
