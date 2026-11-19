import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig } from '../dist/config.js';
import { assess, decide } from '../dist/assessment.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';

const now = Date.parse('2026-10-24T12:00:00Z');
const iso = (time = now) => new Date(time).toISOString();
const routed = { channels: ['slack'] };
const config = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
  policy: {
    library: { levels: ['critical'], basis: 'source_severity', ...routed },
    product: { levels: ['high', 'critical'], ...routed },
    news: { levels: ['high', 'critical'], ...routed },
  },
  notifications: { slack: { webhook_url_env: 'ROUTING_REGRESSION_UNUSED' } },
});
const system = (extra = {}, updated = now) => ({
  id: 'prod',
  name: 'Production',
  environment: 'production',
  exposure: 'internet',
  criticality: 'critical',
  updated_at: iso(updated),
  components: [],
  products: [],
  keywords: [],
  ...extra,
});
const leftPad = { id: 'lp', ecosystem: 'npm', name: 'qrlib-pad', version: '1.3.0' };
const story = {
  id: 'hacker_news:entry:abc',
  source: 'hacker_news',
  kind: 'news',
  title: 'Ivanti Connect Secure zero-day CVE-2026-20001 exploited in the wild',
  url: 'https://example.com/a',
  description:
    'Attackers exploit CVE-2026-20001 in Ivanti Connect Secure appliances; qrlib-pad is also abused.',
  aliases: ['CVE-2026-20001'],
  severity: 'unknown',
  modified_at: iso(),
  fetched_at: iso(),
  packages: [],
  content_status: 'full',
};
const advisory = {
  id: 'cve_now:CVE-2026-20001',
  source: 'cve_now',
  kind: 'advisory',
  title: 'CVE-2026-20001',
  url: 'https://cve.now/CVE-2026-20001',
  description: 'Stack-based buffer overflow allows remote code execution.',
  aliases: ['CVE-2026-20001'],
  severity: 'critical',
  modified_at: iso(),
  fetched_at: iso(),
  packages: [],
  exploited: true,
};
const kev = {
  id: 'kev:CVE-2026-20001',
  source: 'kev',
  kind: 'kev',
  title: 'Ivanti Connect Secure buffer overflow',
  url: 'https://www.cisa.gov/',
  description: 'Ivanti Connect Secure\nBuffer overflow\nRequired action: patch',
  aliases: ['CVE-2026-20001'],
  severity: 'unknown',
  modified_at: iso(),
  fetched_at: iso(),
  packages: [],
  exploited: true,
};
const loudness = { record: 0, digest: 1, notify: 2 };
// The story reports exploitation in its title, which news signals read (1.2.0). The tests below
// are about other rules, so they read it without signals; the last test covers signals.
const noSignals = { ...config, policy: { ...config.policy, news_signals: false } };

test('a validated AI impact claim is never quieter than an uncertain or unclassified news finding', () => {
  const targets = [
    system({ components: [leftPad] }),
    system({ products: [{ name: 'qrlib-pad', version: '1.3.0', keywords: [] }] }),
    system({ keywords: ['qrlib-pad'] }),
  ];
  const modelsOn = { ...noSignals, models: { ...noSignals.models, enabled: true } };
  for (const target of targets) {
    const [candidate] = assess({ systems: [target] }, [story], noSignals, now);
    assert.equal(candidate.source_severity, 'unknown');
    const unclassified = loudness[decide(candidate, noSignals).action];
    for (const classification of ['new_vulnerability', 'known_vulnerability_update'])
      for (const priority of ['low', 'medium', 'high', 'critical']) {
        const reviewed = (impact) =>
          decide(
            {
              ...candidate,
              priority,
              ai: { provider: 'openai-compatible', model: 'm', prompt_version: 't', status: 'complete' },
              news_analysis: {
                classification,
                impact,
                affected_products: [],
                affected_versions: [],
                prerequisites: [],
                rationale: 'r',
                quotes: [],
              },
            },
            modelsOn,
          );
        const affected = reviewed('affected');
        const label = `${candidate.category}/${classification}/${priority}`;
        assert.ok(loudness[affected.action] >= loudness[reviewed('unknown').action], label);
        assert.ok(loudness[affected.action] >= unclassified, label);
        assert.deepEqual(affected.channels, ['slack'], label);
        if (priority === 'critical') assert.equal(affected.action, 'notify', label);
      }
  }
});

test('an advisory record without package claims strengthens a news candidate instead of retiring it', async () => {
  for (const target of [system({ keywords: ['Ivanti'] }), system({ components: [leftPad] })]) {
    const inventory = { systems: [target] };
    const [before] = assess(inventory, [story], noSignals, now);
    const after = assess(inventory, [story, advisory], noSignals, now);
    assert.equal(after.length, 1);
    assert.equal(after[0].id, before.id);
    assert.equal(decide(before, noSignals).action, 'digest');
    assert.equal(after[0].source_severity, 'critical');
    assert.equal(after[0].exploited, true);
    assert.deepEqual(after[0].evidence_ids, [advisory.id, story.id]);
    assert.equal(decide(after[0], noSignals).action, 'notify');
  }

  // An advisory that names other packages settles which packages the event concerns.
  const named = { ...advisory, packages: [{ ecosystem: 'npm', name: 'other-package', range: '<2.0.0' }] };
  assert.deepEqual(assess({ systems: [system({ components: [leftPad] })] }, [story, named], config, now), []);
  // An advisory alone still creates no candidate from its own description.
  assert.deepEqual(assess({ systems: [system({ keywords: ['overflow'] })] }, [advisory], config, now), []);

  const store = new Store(':memory:');
  const inventory = { systems: [system({ keywords: ['Ivanti'] })] };
  const http = async () => {
    throw new Error('no network');
  };
  store.saveEvidence([story], {});
  const first = await runScan({ config: noSignals, inventory, store, http, now });
  const [finding] = first.findings.filter((item) => item.category !== 'health');
  assert.equal(first.decisions[finding.id].action, 'digest');
  store.saveEvidence([advisory], {});
  const second = await runScan({ config: noSignals, inventory, store, http, now: now + 60_000 });
  const stored = store.findings().find((item) => item.id === finding.id);
  assert.notEqual(stored.active, false);
  assert.equal(second.decisions[finding.id].action, 'notify');
  assert.ok(
    store.jobs().some((job) => job.finding_id === finding.id && job.status === 'pending'),
    'the escalated finding keeps a deliverable job',
  );
});

test('known exploitation applies to a cited CVE before any advisory record exists', () => {
  const inventory = {
    systems: [system({ products: [{ name: 'Ivanti Connect Secure', version: '22.7', keywords: [] }] })],
  };
  const [plain] = assess(inventory, [story], noSignals, now);
  assert.equal(plain.exploited, false);
  assert.equal(decide(plain, noSignals).action, 'digest');

  const [listed] = assess(inventory, [story, kev], noSignals, now);
  assert.equal(listed.id, plain.id);
  assert.equal(listed.exploited, true);
  assert.deepEqual(listed.evidence_ids, [story.id, kev.id]);
  assert.equal(listed.category, 'news');
  assert.equal(listed.news_only, true, 'a KEV entry does not turn a report into an advisory');
  assert.equal(listed.title, story.title);
  assert.equal(decide(listed, config).action, 'notify');
  const quiet = { ...noSignals, policy: { ...noSignals.policy, exploited_override: false } };
  assert.equal(decide(listed, quiet).action, 'digest');

  // A KEV entry for another CVE, or one with no report, creates nothing.
  const other = { ...kev, id: 'kev:CVE-2026-29999', aliases: ['CVE-2026-29999'] };
  assert.equal(assess(inventory, [story, other], noSignals, now)[0].exploited, false);
  assert.deepEqual(assess(inventory, [kev], config, now), []);
});

test('npm ranges outside the comparator subset cannot exclude an installed version', async (t) => {
  const status = (ranges, version) => {
    const record = {
      ...advisory,
      id: 'github:GHSA-aaaa-bbbb-cccc',
      source: 'github',
      aliases: ['GHSA-aaaa-bbbb-cccc'],
      exploited: false,
      packages: ranges.map((range) => ({ ecosystem: 'npm', name: 'alpha', range })),
    };
    const inventory = {
      systems: [system({ components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version }] })],
    };
    return assess(inventory, [record], config, now)[0].applicability;
  };
  const cases = [
    [['>= 1.0.0, < 1.2.4'], '1.2.3', 'affected'],
    [['>= 1.0.0, < 1.2.4'], '1.2.4', 'not_affected'],
    [['>=1.0.0 <1.2.4'], '1.2.4', 'not_affected'],
    [['= 1.2.3'], '1.2.4', 'not_affected'],
    [['1.2.3'], '1.2.3', 'affected'],
    [['>= 0'], '5.0.0', 'affected'],
    [['*'], '5.0.0', 'affected'],
    [['>= 1.2, < 3.0.0'], '1.2.0', 'affected'],
    [['< 1.2'], '1.2.0', 'not_affected'],
    [['<1.0.0 || >=2.0.0 <=2.3.0'], '1.5.0', 'not_affected'],
    [['<1.0.0 || >=2.0.0 <=2.3.0'], '2.1.0', 'affected'],
    // Partial versions under these operators mean different bounds to npm and to the source.
    [['> 1.2, < 3.0.0'], '1.2.5', 'unknown'],
    [['> 1, < 3.0.0'], '1.5.0', 'unknown'],
    [['<= 1.2'], '1.2.5', 'unknown'],
    [['= 1.2'], '1.3.0', 'unknown'],
    // npm-only grammar is not advisory syntax.
    [['^1.0.0'], '2.0.0', 'unknown'],
    [['~1.2.0'], '1.3.0', 'unknown'],
    [['1.0.0 - 1.5.0'], '1.6.0', 'unknown'],
    [['1.x'], '2.0.0', 'unknown'],
    [['< v2.0.0'], '2.0.0', 'unknown'],
    [['< 2.0.0 ||'], '2.0.0', 'unknown'],
    [[''], '2.0.0', 'unknown'],
    // An unsupported form beside a supported one still blocks the exclusion, never the match.
    [['>= 1.0.0, < 1.2.4', '^3.0.0'], '1.5.0', 'unknown'],
    [['>= 1.0.0, < 1.2.4', '^3.0.0'], '1.2.0', 'affected'],
    [['< 2.0.0'], '2.0.0-beta.2', 'unknown'],
  ];
  for (const [ranges, version, expected] of cases)
    await t.test(`${JSON.stringify(ranges)} at ${version}`, () =>
      assert.equal(status(ranges, version), expected),
    );
});

test('an exclusion whose own record is read holds while another record of the source keeps failing', async () => {
  const osvConfig = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false },
    policy: { library: { levels: ['critical'], ...routed } },
    notifications: { slack: { webhook_url_env: 'ROUTING_REGRESSION_UNUSED' } },
  });
  const inventory = (time) => ({
    systems: [
      system({ components: [{ id: 'lodash', ecosystem: 'npm', name: 'lodash', version: '4.17.21' }] }, time),
    ],
  });
  const published = iso(now - 86_400_000);
  const store = new Store(':memory:');
  store.saveEvidence(
    [
      {
        id: 'osv:GHSA-aaaa-bbbb-cccc',
        source: 'osv',
        kind: 'advisory',
        title: 'lodash prototype pollution',
        url: 'https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc',
        description: 'Prototype pollution in lodash.',
        aliases: ['GHSA-aaaa-bbbb-cccc'],
        severity: 'critical',
        modified_at: published,
        fetched_at: iso(now - 900_000),
        packages: [{ ecosystem: 'npm', name: 'lodash', range: '<4.17.20', fixed: '4.17.20' }],
        withdrawn: false,
        malware: false,
      },
    ],
    {},
  );
  const seenDuringCollection = new Set();
  const http = async (url, request) => {
    for (const finding of store.findings())
      if (finding.category !== 'health') seenDuringCollection.add(finding.applicability);
    if (url.endsWith('/querybatch'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          results: JSON.parse(request.body).queries.map(() => ({
            vulns: [{ id: 'GHSA-dddd-eeee-ffff', modified: published }],
          })),
        }),
      };
    if (url.endsWith('/vulns/GHSA-aaaa-bbbb-cccc'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
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
        }),
      };
    // Another advisory's detail request keeps failing, so the OSV receipt stays partial.
    return { status: 500, headers: {}, body: 'unavailable' };
  };
  let id;
  for (let scan = 0; scan < 4; scan++) {
    const time = now + scan * 15 * 60_000;
    const result = await runScan({ config: osvConfig, inventory: inventory(time), store, http, now: time });
    assert.ok(result.coverage.some((receipt) => receipt.status !== 'complete'));
    const [finding] = result.findings.filter((item) => item.category !== 'health');
    id = finding.id;
    // The advisory record behind the exclusion is read on every scan: its range is current, and
    // what the source missed concerns other findings.
    assert.equal(finding.applicability, 'not_affected');
    assert.equal(result.decisions[id].action, 'record');
  }
  assert.ok(!seenDuringCollection.has('unknown'), 'the result never flips to unknown');
  assert.equal(store.history(id).length, 1);
  assert.deepEqual(
    store.jobs().filter((job) => job.finding_id === id),
    [],
    'no alert is sent',
  );
});

test('running without an AI model is reported as a notice, not as degraded monitoring', async (t) => {
  const before = process.env.ROUTING_REGRESSION_UNUSED;
  process.env.ROUTING_REGRESSION_UNUSED = 'https://hooks.slack.com/services/T/B/x';
  t.after(() => {
    if (before === undefined) delete process.env.ROUTING_REGRESSION_UNUSED;
    else process.env.ROUTING_REGRESSION_UNUSED = before;
  });
  const starter = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: true, osv: false, github: false, kev: false },
    policy: { library: { levels: ['critical'], ...routed }, health_channels: ['slack'] },
    notifications: { slack: { webhook_url_env: 'ROUTING_REGRESSION_UNUSED' } },
  });
  const emptyFeed = async () => ({
    status: 200,
    headers: {},
    body: '<?xml version="1.0"?><rss version="2.0"><channel><title>x</title></channel></rss>',
  });
  const store = new Store(':memory:');
  const inventory = { systems: [system({ components: [leftPad] })] };
  const report = await runScan({ config: starter, inventory, store, http: emptyFeed, now });
  assert.deepEqual(report.errors, []);
  assert.equal(report.degraded, false);
  assert.equal(report.notices.length, 1);
  assert.match(report.notices[0], /^AI is disabled\./);
  assert.deepEqual(
    report.findings.filter((finding) => finding.category === 'health'),
    [],
  );
  assert.deepEqual(store.jobs(), [], 'no health alert is queued for a supported setup');

  // A real fault still degrades the scan.
  const failing = await runScan({
    config: starter,
    inventory,
    store,
    http: async () => ({ status: 503, headers: {}, body: '' }),
    now: now + 60_000,
  });
  assert.equal(failing.degraded, true);
  assert.ok(failing.errors.some((error) => error.source === 'hacker_news'));
});
