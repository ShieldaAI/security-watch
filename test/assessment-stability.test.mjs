// A finding must not change state, or alert, for reasons that say nothing about the finding itself:
// a news article that could not be read, time that passed while the monitor was stopped, or an
// advisory record whose package claims this application cannot use.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig } from '../dist/config.js';
import { assess, decide } from '../dist/assessment.js';
import { runScan } from '../dist/engine.js';
import { Store } from '../dist/store.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
process.env.STABILITY_UNUSED = 'https://hooks.slack.com/services/T/B/x';
const config = (sources) =>
  parseConfig({
    version: 1,
    poll_interval_minutes: 15,
    sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false, ...sources },
    policy: {
      library: { levels: ['critical'], channels: ['slack'] },
      news: { levels: ['high', 'critical'], channels: ['slack'] },
    },
    notifications: { slack: { webhook_url_env: 'STABILITY_UNUSED' } },
  });
const inventory = (time) => ({
  systems: [
    {
      id: 'prod',
      name: 'Production',
      environment: 'production',
      exposure: 'internet',
      criticality: 'critical',
      updated_at: iso(time),
      products: [],
      keywords: [],
      components: [{ id: 'lodash', ecosystem: 'npm', name: 'lodash', version: '4.17.21' }],
    },
  ],
});
const published = iso(NOW - 3_600_000);
const osvRecord = {
  id: 'GHSA-aaaa-bbbb-cccc',
  summary: 'lodash prototype pollution',
  details: 'Prototype pollution in lodash.',
  modified: published,
  database_specific: { severity: 'CRITICAL' },
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.20' }] }],
    },
  ],
};
const storedAdvisory = {
  id: 'osv:GHSA-aaaa-bbbb-cccc',
  source: 'osv',
  kind: 'advisory',
  title: 'lodash prototype pollution',
  url: 'https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc',
  description: 'Prototype pollution in lodash.',
  aliases: ['GHSA-aaaa-bbbb-cccc'],
  severity: 'critical',
  modified_at: published,
  fetched_at: iso(NOW - 900_000),
  packages: [{ ecosystem: 'npm', name: 'lodash', range: '<4.17.20', fixed: '4.17.20' }],
  withdrawn: false,
  malware: false,
};
const reply = (body, status = 200) => ({
  status,
  headers: {},
  body: typeof body === 'string' ? body : JSON.stringify(body),
});
/** OSV answers normally; The Hacker News lists one story about the advisory. */
const sources =
  ({ time, article = 200, observe }) =>
  async (url, request) => {
    observe?.();
    if (url.includes('feedburner'))
      return reply(
        `<?xml version="1.0"?><rss version="2.0"><channel><title>x</title><item><title>lodash npm package flaw GHSA-aaaa-bbbb-cccc patched</title><link>https://thehackernews.com/2026/10/lodash.html</link><guid>g1</guid><pubDate>${new Date(time - 600_000).toUTCString()}</pubDate><description>The lodash npm package fixed GHSA-aaaa-bbbb-cccc in 4.17.20.</description></item></channel></rss>`,
      );
    if (url.includes('thehackernews.com'))
      return article === 200
        ? reply(
            `<html><body><div class="articlebody">The lodash npm package fixed GHSA-aaaa-bbbb-cccc in 4.17.20. Upgrade now. ${'More text. '.repeat(20)}</div></body></html>`,
          )
        : reply('', article);
    if (url.endsWith('/querybatch'))
      return reply({ results: JSON.parse(request.body).queries.map(() => ({})) });
    if (url.endsWith('/vulns/GHSA-aaaa-bbbb-cccc')) return reply(osvRecord);
    throw new Error(`unexpected request ${url}`);
  };
const library = (store) => store.findings().filter((finding) => finding.category !== 'health');

test('a linked news article that cannot be read does not void a version exclusion', async () => {
  const cfg = config({ hacker_news: true });
  const store = new Store(':memory:');
  store.saveEvidence([storedAdvisory], {});
  // The article fails on the first and third scans.
  for (const [scan, article] of [500, 200, 500].entries()) {
    const time = NOW + scan * 15 * 60_000;
    const report = await runScan({
      config: cfg,
      inventory: inventory(time),
      store,
      http: sources({ time, article }),
      now: time,
    });
    const coverage = Object.fromEntries(report.coverage.map((receipt) => [receipt.source, receipt.status]));
    assert.equal(coverage.osv, 'complete');
    assert.equal(coverage.hacker_news, article === 200 ? 'complete' : 'partial', `scan ${scan}`);
    const [finding] = report.findings.filter((item) => item.category !== 'health');
    assert.ok(
      finding.evidence_ids.some((id) => id.startsWith('hacker_news:')),
      'the story is linked',
    );
    assert.equal(finding.applicability, 'not_affected', `scan ${scan}`);
    assert.equal(report.decisions[finding.id].action, 'record', `scan ${scan}`);
  }
  const [finding] = library(store);
  assert.equal(store.history(finding.id).length, 1, 'one revision');
  assert.deepEqual(
    store.jobs().filter((job) => job.finding_id === finding.id),
    [],
    'no alert',
  );
});

test('time that passed while the monitor was stopped does not raise an alert before evidence is refreshed', async () => {
  const cfg = config({});
  const store = new Store(':memory:');
  store.saveEvidence([storedAdvisory], {});
  // Scans at the start, after 30 minutes, then after a three-hour gap (twelve poll intervals).
  for (const offset of [0, 30, 210]) {
    const time = NOW + offset * 60_000;
    const during = [];
    const report = await runScan({
      config: cfg,
      inventory: inventory(time),
      store,
      now: time,
      http: sources({
        time,
        // What a delivery worker running beside the scan would see and could send.
        observe: () => {
          for (const finding of library(store)) during.push(finding.applicability);
          const job = store.claimDue(time);
          if (job) during.push(`claimed revision ${job.revision}`);
        },
      }),
    });
    assert.deepEqual(report.errors, []);
    assert.deepEqual(
      [...new Set(during)].filter((state) => state !== 'not_affected'),
      [],
      `+${offset} min`,
    );
    const [finding] = report.findings.filter((item) => item.category !== 'health');
    assert.equal(finding.applicability, 'not_affected');
  }
  const [finding] = library(store);
  assert.equal(store.history(finding.id).length, 1, 'one revision across the gap');
  assert.deepEqual(store.jobs(), []);
});

test('evidence that was already stale at the last collection stays unknown before the refresh', async () => {
  const cfg = config({});
  const store = new Store(':memory:');
  const failing = async (url, request) => {
    if (url.endsWith('/querybatch'))
      return reply({ results: JSON.parse(request.body).queries.map(() => ({})) });
    return reply('unavailable', 500);
  };
  store.saveEvidence([storedAdvisory], {});
  // OSV cannot refresh the record for an hour: it ages past two poll intervals and becomes unknown.
  for (const offset of [0, 60]) {
    const time = NOW + offset * 60_000;
    await runScan({ config: cfg, inventory: inventory(time), store, http: failing, now: time });
  }
  assert.equal(library(store)[0].applicability, 'unknown');
  // The next scan's first pass must not quietly restore the exclusion from that old evidence.
  const time = NOW + 75 * 60_000;
  const during = new Set();
  await runScan({
    config: cfg,
    inventory: inventory(time),
    store,
    now: time,
    http: async (url, request) => {
      for (const finding of library(store)) during.add(finding.applicability);
      return failing(url, request);
    },
  });
  assert.deepEqual([...during], ['unknown']);
});

test('an advisory whose package claims cannot be used keeps the news finding it is linked to', () => {
  const cfg = config({});
  const story = {
    id: 'hacker_news:entry:1',
    source: 'hacker_news',
    kind: 'news',
    title: 'tj-actions/changed-files compromised (CVE-2026-30066)',
    url: 'https://thehackernews.com/x',
    description: 'The tj-actions/changed-files action leaked secrets; tracked as CVE-2026-30066.',
    aliases: ['CVE-2026-30066'],
    severity: 'critical',
    modified_at: iso(NOW),
    fetched_at: iso(NOW),
    packages: [],
    content_status: 'full',
  };
  const kev = {
    id: 'kev:CVE-2026-30066',
    source: 'kev',
    kind: 'kev',
    title: 'tj-actions/changed-files',
    url: 'https://www.cisa.gov/kev',
    description: 'Known exploited.',
    aliases: ['CVE-2026-30066'],
    severity: 'unknown',
    modified_at: iso(NOW),
    fetched_at: iso(NOW),
    packages: [],
  };
  const advisory = (packages) => ({
    id: 'github:GHSA-mrrh-fwg8-r2c3',
    source: 'github',
    kind: 'advisory',
    title: 'tj-actions/changed-files through 45.0.7 allows remote attackers to discover secrets',
    url: 'https://github.com/advisories/GHSA-mrrh-fwg8-r2c3',
    description: 'Secrets are exposed in workflow logs.',
    aliases: ['CVE-2026-30066', 'GHSA-mrrh-fwg8-r2c3'],
    severity: 'critical',
    modified_at: iso(NOW),
    fetched_at: iso(NOW),
    packages,
  });
  const shapes = {
    keyword: { keywords: ['tj-actions/changed-files'], components: [] },
    package: {
      keywords: [],
      components: [{ id: 'c', ecosystem: 'npm', name: 'tj-actions-changed-files', version: '1.0.0' }],
    },
  };
  const packageStory = {
    ...story,
    description: `${story.description} The npm package tj-actions-changed-files is also affected.`,
  };
  const run = (shape, evidence) => {
    const inv = {
      systems: [{ id: 'prod', name: 'prod', updated_at: iso(NOW), products: [], ...shapes[shape] }],
    };
    return assess(inv, evidence, cfg, NOW).map((finding) => [
      finding.category,
      finding.exploited,
      decide(finding, cfg).action,
    ]);
  };
  for (const shape of ['keyword', 'package']) {
    const news = shape === 'package' ? packageStory : story;
    const expected = run(shape, [news, kev, advisory([])]);
    assert.equal(expected.length, 1, shape);
    assert.equal(expected[0][2], 'notify', shape);
    for (const claims of [
      [{ ecosystem: 'actions', name: 'tj-actions/changed-files', range: '<= 45.0.7', fixed: '46.0.1' }],
      [{ ecosystem: 'npm', name: 'Bad Name!' }],
      [{ ecosystem: 'Debian:12', name: 'changed-files' }],
      [{ ecosystem: 'other', name: 'changed-files' }],
    ])
      assert.deepEqual(run(shape, [news, kev, advisory(claims)]), expected, JSON.stringify([shape, claims]));
  }
  // A usable claim for a package that is not installed still settles the question.
  assert.deepEqual(run('keyword', [story, kev, advisory([{ ecosystem: 'npm', name: 'other-package' }])]), []);
});
