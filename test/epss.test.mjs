import test from 'node:test';
import assert from 'node:assert/strict';
import { attachEpss, findingCves, readEpssCache, refreshEpss } from '../dist/epss.js';
import { parseConfig } from '../dist/config.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';
import { notificationText, digestText } from '../dist/delivery.js';

const DAY = 86_400_000;
const now = Date.parse('2026-11-19T12:00:00Z');
const iso = (time = now) => new Date(time).toISOString();
const cve = (n) => `CVE-2026-${String(10000 + n)}`;
/** A stand-in for api.first.org: scores every requested CVE except those in `unscored`. */
function first({ unscored = new Set(), probability = 0.0164, fail = () => false, body } = {}) {
  const calls = [];
  const http = async (url) => {
    calls.push(url);
    const parsed = new URL(url);
    assert.equal(parsed.origin + parsed.pathname, 'https://api.first.org/data/v1/epss');
    const ids = parsed.searchParams.get('cve').split(',');
    if (fail(calls.length)) return { status: 503, headers: {}, body: '' };
    if (body) return { status: 200, headers: {}, body };
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        status: 'OK',
        'status-code': 200,
        total: ids.length,
        data: ids
          .filter((id) => !unscored.has(id))
          .map((id) => ({
            cve: id,
            epss: String(probability),
            percentile: '0.768600000',
            date: '2026-11-18',
          })),
      }),
    };
  };
  return { http, calls };
}

test('lookups are batched by 50, send only CVE identifiers and parse the API strings', async () => {
  const ids = Array.from({ length: 120 }, (_, i) => cve(i));
  const { http, calls } = first({ unscored: new Set([cve(7)]) });
  const result = await refreshEpss(
    [...ids, 'GHSA-aaaa-bbbb-cccc', 'not-an-id', cve(1).toLowerCase()],
    {},
    http,
    now,
  );
  assert.equal(calls.length, 3);
  for (const url of calls)
    assert.match(
      decodeURIComponent(new URL(url).searchParams.get('cve')),
      /^CVE-\d{4}-\d+(?:,CVE-\d{4}-\d+)*$/,
    );
  assert.equal(result.failed, 0);
  assert.equal(result.pending, 0);
  assert.deepEqual(result.cache[cve(0)], {
    fetched: now,
    score: { probability: 0.0164, percentile: 0.7686, date: '2026-11-18' },
  });
  assert.deepEqual(result.cache[cve(7)], { fetched: now }, 'no score yet is remembered as looked up');
  assert.equal(Object.keys(result.cache).length, 120);
});

test('a score is refreshed once a day, the oldest first, within the request budget', async () => {
  const ids = Array.from({ length: 600 }, (_, i) => cve(i));
  const { http, calls } = first();
  const first600 = await refreshEpss(ids, {}, http, now);
  assert.equal(calls.length, 10, 'ten requests a scan');
  assert.equal(first600.pending, 100);
  const later = await refreshEpss(ids, first600.cache, http, now + 60_000);
  assert.equal(calls.length, 12, 'the remaining 100 the next scan');
  assert.equal(later.pending, 0);
  const sameDay = await refreshEpss(ids, later.cache, http, now + DAY - 60_000);
  assert.equal(calls.length, 12, 'nothing is due within a day');
  assert.equal(sameDay.pending, 0);
  await refreshEpss(ids, later.cache, http, now + DAY);
  assert.equal(calls.length, 22);
  const first10 = new URL(calls[12]).searchParams.get('cve').split(',');
  assert.equal(first10[0], cve(0), 'the longest unrefreshed come first');
  // A lookup stamped in the future is due again.
  const { http: again, calls: againCalls } = first();
  await refreshEpss([cve(1)], { [cve(1)]: { fetched: now + DAY } }, again, now);
  assert.equal(againCalls.length, 1);
});

test('a failed lookup ends the scan s lookups and keeps the earlier scores', async () => {
  const ids = Array.from({ length: 150 }, (_, i) => cve(i));
  const old = { probability: 0.5, percentile: 0.99, date: '2026-11-17' };
  const stored = Object.fromEntries(ids.map((id) => [id, { fetched: now - 2 * DAY, score: old }]));
  const { http, calls } = first({ fail: (n) => n === 2 });
  const result = await refreshEpss(ids, stored, http, now);
  assert.equal(calls.length, 2);
  assert.equal(result.failed, 1);
  assert.equal(result.pending, 100);
  assert.equal(result.cache[cve(0)].score.probability, 0.0164, 'the first batch was refreshed');
  assert.deepEqual(result.cache[cve(149)].score, old, 'the rest keep their earlier score');
  for (const body of [
    'not json',
    JSON.stringify({ status: 'ERROR' }),
    JSON.stringify({ status: 'OK', data: {} }),
  ]) {
    const broken = await refreshEpss([cve(1)], {}, first({ body }).http, now);
    assert.equal(broken.failed, 1, body);
    assert.equal(broken.cache[cve(1)], undefined);
  }
  const thrown = await refreshEpss(
    [cve(1)],
    {},
    async () => {
      throw new Error('network down');
    },
    now,
  );
  assert.equal(thrown.failed, 1);
});

test('rows that are not valid scores, or not asked for, are ignored', async () => {
  const body = JSON.stringify({
    status: 'OK',
    data: [
      { cve: cve(1), epss: '1.5', percentile: '0.5', date: '2026-11-18' },
      { cve: cve(2), epss: '0.1', percentile: '0.5', date: 'yesterday' },
      { cve: cve(3), epss: 0.1, percentile: '0.5', date: '2026-11-18' },
      { cve: cve(9), epss: '0.1', percentile: '0.5', date: '2026-11-18' },
      null,
      { cve: cve(4), epss: '0.25', percentile: '0.9', date: '2026-11-18' },
    ],
  });
  const result = await refreshEpss([cve(1), cve(2), cve(3), cve(4)], {}, first({ body }).http, now);
  assert.equal(result.cache[cve(1)].score, undefined);
  assert.equal(result.cache[cve(2)].score, undefined);
  assert.equal(result.cache[cve(3)].score, undefined);
  assert.equal(result.cache[cve(9)], undefined);
  assert.equal(result.cache[cve(4)].score.probability, 0.25);
});

test('the stored cache is read defensively and attached by the finding s CVE', () => {
  assert.deepEqual(readEpssCache(undefined), {});
  assert.deepEqual(readEpssCache('{oops'), {});
  assert.deepEqual(readEpssCache('[1,2]'), {});
  const cache = readEpssCache(
    JSON.stringify({
      [cve(1)]: { fetched: now, score: { probability: 0.2, percentile: 0.9, date: '2026-11-18' } },
      [cve(2)]: { fetched: now, score: { probability: 2, percentile: 0.9, date: '2026-11-18' } },
      [cve(3)]: { fetched: 'yesterday' },
      'GHSA-aaaa-bbbb-cccc': { fetched: now },
    }),
  );
  assert.deepEqual(Object.keys(cache), [cve(1), cve(2)]);
  assert.equal(cache[cve(2)].score, undefined);
  const finding = {
    id: 'f',
    event_id: cve(1).toLowerCase(),
    evidence_ids: [],
    epss: { cve: cve(9), probability: 0.9, percentile: 1, date: '2026-01-01' },
  };
  assert.deepEqual(attachEpss(finding, cache, [cve(1).toLowerCase()]).epss, {
    cve: cve(1),
    probability: 0.2,
    percentile: 0.9,
    date: '2026-11-18',
  });
  assert.equal('epss' in attachEpss(finding, cache, [cve(5)]), false, 'an old score is removed');
  assert.equal('epss' in attachEpss(finding, cache, []), false);
  // Several CVEs: the highest score, and which CVE it is for.
  const both = {
    ...cache,
    [cve(6)]: { fetched: now, score: { probability: 0.7, percentile: 0.99, date: '2026-11-18' } },
  };
  assert.equal(attachEpss(finding, both, [cve(1), cve(6)]).epss.cve, cve(6));
});

test('a finding s CVEs: its event, and the aliases of its advisories, not of the news it cites', () => {
  const evidence = new Map([
    ['cve_now:x', { id: 'cve_now:x', kind: 'advisory', aliases: [cve(1), 'GHSA-aaaa-bbbb-cccc'] }],
    ['kev:y', { id: 'kev:y', kind: 'kev', aliases: [cve(2)] }],
    ['news:z', { id: 'news:z', kind: 'news', aliases: [cve(3), cve(4)] }],
  ]);
  const finding = { event_id: 'GHSA-AAAA-BBBB-CCCC', evidence_ids: ['cve_now:x', 'kev:y', 'news:z', 'gone'] };
  assert.deepEqual(findingCves(finding, evidence), [cve(1), cve(2)]);
  assert.deepEqual(findingCves({ event_id: cve(5).toLowerCase(), evidence_ids: [] }, evidence), [cve(5)]);
});

// Scans: a score that changes daily must not re-send, reopen or re-analyse anything.
const advisory = (id, aliases = []) => ({
  id: `cve_now:${id}`,
  source: 'cve_now',
  kind: 'advisory',
  title: `${id} in alpha`,
  url: `https://cve.now/${id}`,
  description: 'Overflow in alpha.',
  aliases: [id, ...aliases],
  severity: 'critical',
  modified_at: iso(),
  fetched_at: iso(),
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
});
const scanConfig = (epss) =>
  parseConfig({
    version: 1,
    poll_interval_minutes: 1440,
    sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false, epss },
    policy: { library: { levels: ['critical'], basis: 'source_severity', channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'EPSS_TEST_UNUSED' } },
  });
const inventory = {
  systems: [
    {
      id: 'prod',
      name: 'Production',
      environment: 'production',
      exposure: 'internet',
      criticality: 'high',
      updated_at: iso(),
      components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
      products: [],
      keywords: [],
    },
  ],
};

test('a scan shows EPSS; a new daily score keeps the revision and sends nothing again', async () => {
  const store = new Store(':memory:');
  const id = cve(42);
  store.saveEvidence([advisory(id)], {});
  let probability = 0.0164;
  const calls = [];
  const http = async (url) => {
    calls.push(url);
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        status: 'OK',
        data: [{ cve: id, epss: String(probability), percentile: '0.7686', date: '2026-11-18' }],
      }),
    };
  };
  const first = await runScan({ config: scanConfig(true), inventory, store, http, now });
  const finding = store.findings().find((item) => item.event_id === id);
  assert.equal(finding.epss.probability, 0.0164);
  assert.equal(calls.length, 1);
  assert.ok(first.findings.find((item) => item.event_id === id).epss, 'the report carries it too');
  const jobs = store.jobs().length;
  assert.ok(jobs > 0);
  const revisions = store.history(finding.id).length;
  const basis = store.getMeta(`assessment-basis:${finding.id}`);
  assert.ok(basis);

  probability = 0.97;
  store.saveEvidence([{ ...advisory(id), fetched_at: iso(now + DAY) }], {});
  await runScan({ config: scanConfig(true), inventory, store, http, now: now + DAY });
  const updated = store.findings().find((item) => item.event_id === id);
  assert.equal(calls.length, 2);
  assert.equal(updated.epss.probability, 0.97);
  assert.equal(store.history(finding.id).length, revisions, 'no new revision');
  assert.equal(store.jobs().length, jobs, 'no new delivery');
  assert.equal(store.getMeta(`assessment-basis:${finding.id}`), basis, 'no new model analysis');
});

test('a failed EPSS lookup is a notice, not degraded monitoring, and the old score stays', async () => {
  const store = new Store(':memory:');
  const id = cve(43);
  store.saveEvidence([advisory(id)], {});
  const ok = async () => ({
    status: 200,
    headers: {},
    body: JSON.stringify({
      status: 'OK',
      data: [{ cve: id, epss: '0.3', percentile: '0.95', date: '2026-11-18' }],
    }),
  });
  await runScan({ config: scanConfig(true), inventory, store, http: ok, now });
  store.saveEvidence([{ ...advisory(id), fetched_at: iso(now + DAY) }], {});
  const report = await runScan({
    config: scanConfig(true),
    inventory,
    store,
    http: async () => ({ status: 503, headers: {}, body: '' }),
    now: now + DAY,
  });
  assert.ok(report.notices.some((notice) => /EPSS scores could not be refreshed/.test(notice)));
  assert.equal(
    report.errors.some((error) => /epss/i.test(`${error.source} ${error.message}`)),
    false,
  );
  assert.equal(store.findings().find((item) => item.event_id === id).epss.probability, 0.3);
});

test('with EPSS off nothing is requested and no score is shown', async () => {
  const store = new Store(':memory:');
  store.saveEvidence([advisory(cve(44))], {});
  const calls = [];
  await runScan({
    config: scanConfig(false),
    inventory,
    store,
    http: async (url) => {
      calls.push(url);
      return { status: 500, headers: {}, body: '' };
    },
    now,
  });
  assert.deepEqual(calls, []);
  assert.equal('epss' in store.findings().find((item) => item.event_id === cve(44)), false);
  assert.equal(parseConfig({ version: 1 }).sources.epss, false);
  assert.throws(() => parseConfig({ version: 1, sources: { epss: 'yes' } }));
});

test('a review is not reopened by a new score', () => {
  const store = new Store(':memory:');
  const base = {
    id: 'review-finding',
    event_id: cve(45),
    system_id: 'prod',
    category: 'news',
    applicability: 'relevant',
    source_severity: 'unknown',
    priority: 'medium',
    title: 't',
    summary: 's',
    reasons: [],
    evidence_ids: [],
    urls: [],
    exploited: false,
    updated_at: iso(),
  };
  const decision = { action: 'digest', channels: ['slack'], review: 'ai_not_affected', reason: 'r' };
  store.saveAssessment(
    { ...base, epss: { cve: cve(45), probability: 0.1, percentile: 0.5, date: '2026-11-18' } },
    decision,
    now,
  );
  store.saveAssessment(
    { ...base, epss: { cve: cve(45), probability: 0.9, percentile: 0.99, date: '2026-11-19' } },
    decision,
    now + DAY,
  );
  assert.equal(store.history(base.id).length, 1);
});

test('alerts and digests show EPSS as numbers', () => {
  const assessment = {
    id: 'f1',
    event_id: cve(46),
    system_id: 'prod',
    category: 'library',
    applicability: 'affected',
    source_severity: 'critical',
    priority: 'critical',
    title: 'alpha overflow',
    summary: 's',
    reasons: [],
    evidence_ids: [],
    urls: [],
    exploited: false,
    updated_at: iso(),
    epss: { cve: cve(46), probability: 0.0164, percentile: 0.7686, date: '2026-11-18' },
  };
  const job = (id, a = assessment) => ({
    id,
    finding_id: a.id,
    revision: 1,
    channel: 'slack',
    payload: JSON.stringify({ assessment: a, reason: 'r' }),
    status: 'pending',
    attempts: 0,
    available_at: now,
  });
  assert.match(
    notificationText(job('d1')).text,
    /EPSS for CVE-2026-10046: 1\.6% chance of exploitation in the next 30 days; higher than 76% of scored CVEs \(FIRST, 2026-11-18\)/,
  );
  const tiny = {
    ...assessment,
    epss: { cve: cve(46), probability: 0.0004, percentile: 0.1, date: '2026-11-18' },
  };
  assert.match(notificationText(job('d2', tiny)).text, /EPSS for CVE-2026-10046: under 0\.1% chance/);
  const high = {
    ...assessment,
    epss: { cve: cve(46), probability: 0.97, percentile: 1, date: '2026-11-18' },
  };
  assert.match(
    notificationText(job('d3', high)).text,
    /EPSS for CVE-2026-10046: 97% chance .* higher than 100%/,
  );
  assert.match(digestText([job('d1'), job('d4')]).text, /EPSS for CVE-2026-10046: 1\.6%/);
  assert.doesNotMatch(notificationText(job('d5', { ...assessment, epss: undefined })).text, /EPSS/);
});

test('a library finding keyed by its GHSA identifier shows the EPSS of its CVE', async () => {
  const store = new Store(':memory:');
  const id = cve(47);
  store.saveEvidence([advisory(id, ['GHSA-qqqq-wwww-eeee'])], {});
  const asked = [];
  const http = async (url) => {
    asked.push(...new URL(url).searchParams.get('cve').split(','));
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        status: 'OK',
        data: [{ cve: id, epss: '0.42', percentile: '0.98', date: '2026-11-18' }],
      }),
    };
  };
  await runScan({ config: scanConfig(true), inventory, store, http, now });
  const finding = store.findings().find((item) => item.category === 'library');
  assert.equal(finding.event_id, 'GHSA-QQQQ-WWWW-EEEE');
  assert.deepEqual(asked, [id]);
  assert.equal(finding.epss.cve, id);
  assert.equal(finding.epss.probability, 0.42);
});

test('a scan without findings keeps recent scores; unused ones go after 30 days', async () => {
  const score = { probability: 0.3, percentile: 0.9, date: '2026-11-18' };
  const stored = {
    [cve(1)]: { fetched: now - 2 * DAY, score },
    [cve(2)]: { fetched: now - 31 * DAY, score },
  };
  const { http, calls } = first();
  const result = await refreshEpss([], stored, http, now);
  assert.equal(calls.length, 0);
  assert.deepEqual(Object.keys(result.cache), [cve(1)]);
});

test('a score a successful answer leaves out is kept while recent', async () => {
  const recent = { probability: 0.3, percentile: 0.9, date: '2026-11-17' };
  const old = { probability: 0.3, percentile: 0.9, date: '2026-11-01' };
  const stored = {
    [cve(1)]: { fetched: now - 2 * DAY, score: recent },
    [cve(2)]: { fetched: now - 2 * DAY, score: old },
  };
  const { http } = first({ unscored: new Set([cve(1), cve(2)]) });
  const result = await refreshEpss([cve(1), cve(2)], stored, http, now);
  assert.deepEqual(result.cache[cve(1)], { fetched: now, score: recent });
  assert.deepEqual(result.cache[cve(2)], { fetched: now });
});

test('a retired finding drops its score', async () => {
  const store = new Store(':memory:');
  const id = cve(48);
  store.saveEvidence([advisory(id)], {});
  const http = async () => ({
    status: 200,
    headers: {},
    body: JSON.stringify({
      status: 'OK',
      data: [{ cve: id, epss: '0.2', percentile: '0.9', date: '2026-11-18' }],
    }),
  });
  await runScan({ config: scanConfig(true), inventory, store, http, now });
  assert.ok(store.findings().find((item) => item.event_id === id).epss);
  const without = { systems: [{ ...inventory.systems[0], components: [] }] };
  await runScan({ config: scanConfig(true), inventory: without, store, http, now: now + 60_000 });
  const retired = store.findings().find((item) => item.event_id === id);
  assert.equal(retired.active, false);
  assert.equal('epss' in retired, false);
});
