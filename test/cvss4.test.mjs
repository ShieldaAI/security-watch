import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { cvssV4BaseScore } from '../dist/cvss4.js';
import { collectSources, assess, decide, parseConfig, Store } from '../dist/index.js';

const BASE = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
const LOW = 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N';
const ZERO = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N';
const V3 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const NOW = Date.parse('2026-11-05T00:00:00Z');
const AT = new Date(NOW).toISOString();
const config = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false, osv: true },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'NEVER_READ' } },
});
const inventory = (version = '1.0.0', updated_at = AT) => ({
  version: 1,
  systems: [
    {
      id: 'synthetic',
      name: 'synthetic',
      environment: 'test',
      exposure: 'unknown',
      criticality: 'low',
      updated_at,
      components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', ...(version ? { version } : {}) }],
      products: [],
      keywords: [],
    },
  ],
});
const advisory = (extra = {}) => ({
  id: 'OSV-synthetic-v4',
  modified: AT,
  published: AT,
  summary: 'Synthetic v4 advisory',
  details: 'Synthetic only.',
  aliases: ['CVE-2099-99901'],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'alpha' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
    },
  ],
  severity: [{ type: 'CVSS_V4', score: BASE }],
  ...extra,
});
const response = (body) => ({ status: 200, headers: {}, body: JSON.stringify(body) });
async function collect(raw = advisory(), inv = inventory()) {
  return collectSources(
    inv,
    config,
    {},
    async (url) => response(url.endsWith('/querybatch') ? { results: [{ vulns: [{ id: raw.id }] }] } : raw),
    NOW,
  );
}
function route(evidence, inv = inventory()) {
  const finding = assess(inv, evidence, config, NOW)[0];
  const decision = decide(finding, config);
  const store = new Store(':memory:');
  try {
    store.saveEvidence(evidence, {});
    store.saveAssessment(finding, decision, NOW);
    return { finding, decision, jobs: store.jobs(), stored: store.getEvidence(finding.evidence_ids) };
  } finally {
    store.close();
  }
}

test('CVSS-B scores agree with independently published FIRST v4 examples', () => {
  // Published numeric facts, not generated expected scores: https://www.first.org/cvss/v4.0/examples
  const examples = [
    [7.3, 'AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
    [7.7, 'AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
    [4.6, 'AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N'],
    [5.1, 'AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N'],
    [6.9, 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N'],
    [5.9, 'AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N'],
    [9.4, 'AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'],
    [7.1, 'AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'],
    [8.2, 'AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'],
    [8.7, 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L'],
    [8.3, 'AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'],
    [8.5, 'AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
    [9.3, BASE.slice(9)],
    [10, 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'],
  ];
  for (const [score, vector] of examples)
    assert.equal(cvssV4BaseScore('CVSS:4.0/' + vector)?.score, score, vector);
});

test('adapted scorer matches 512 pinned unmodified-reference samples without global mutation', () => {
  const fixture = JSON.parse(
    readFileSync(new URL('./fixtures/cvss-v4-reference.json', import.meta.url), 'utf8'),
  );
  assert.equal(fixture.cases.length, 512);
  const before = Reflect.ownKeys(globalThis);
  for (const item of fixture.cases)
    assert.equal(cvssV4BaseScore(item.vector)?.score, item.score, item.vector);
  assert.deepEqual(Reflect.ownKeys(globalThis), before);
});

test('valid context is explicitly projected to base without borrowing exploitation or inventory facts', () => {
  for (const suffix of [
    '/E:U',
    '/E:A/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Red',
    '/E:X/U:Clear',
  ]) {
    const score = cvssV4BaseScore(BASE + suffix);
    assert.equal(score.score, 9.3);
    assert.equal(score.base_vector, BASE);
    assert.equal(score.vector, BASE + suffix);
    assert.equal(score.context_removed, true);
  }
  assert.equal(cvssV4BaseScore(BASE).context_removed, false);
  assert.equal(cvssV4BaseScore(LOW).score, 1);
  assert.equal(cvssV4BaseScore(ZERO).score, 0);
});

test('invalid order, duplicates, omitted base metrics, unknown or case-mismatched values stay unsupported', () => {
  const invalid = [
    undefined,
    null,
    9.3,
    BASE + '/',
    BASE + '/E:U/E:A',
    BASE + '/U:Red/E:U',
    BASE.replace('/AV:N/AC:L', '/AC:L/AV:N'),
    BASE.replace('/AT:N', ''),
    BASE.replace('CVSS:4.0', 'CVSS:4.1'),
    BASE.replace('/SI:N', '/SI:S'),
    BASE + '/E:INVALID',
    BASE + '/UNKNOWN:X',
    BASE + '/U:red',
    BASE + '/E:a',
    BASE.replace('/AV:N', '/AV:X'),
    BASE + '\n',
    BASE + ' ',
    BASE + '/E:U:extra',
    BASE + '/x'.repeat(600),
    BASE.replace('/AV:N', '/__proto__:N'),
    BASE.replace('CVSS', 'cvss'),
  ];
  for (const vector of invalid) assert.equal(cvssV4BaseScore(vector), undefined, String(vector));
});

test('v4-only critical OSV evidence reaches immediate outbox and retains vectors with source timestamps', async () => {
  const result = await collect();
  assert.deepEqual(result.errors, []);
  const item = result.evidence[0];
  assert.equal(item.severity, 'critical');
  assert.equal(item.cvss_v4.base_scores[0].score, 9.3);
  const out = route(result.evidence);
  assert.equal(out.finding.applicability, 'affected');
  assert.equal(out.decision.action, 'notify');
  assert.equal(out.jobs.length, 1);
  assert.equal(out.jobs[0].status, 'pending');
  assert.deepEqual(out.stored[0].cvss_v4, item.cvss_v4);
  assert.equal(out.stored[0].fetched_at, AT);
  assert.equal(out.finding.exploited, false);
});

test('CVSS v4 severity boundaries and affected-package ratings retain the highest independent floor', async () => {
  const fixture = JSON.parse(
    readFileSync(new URL('./fixtures/cvss-v4-reference.json', import.meta.url), 'utf8'),
  );
  for (const [score, severity] of [
    [2.4, 'low'],
    [4, 'medium'],
    [6.9, 'medium'],
    [7, 'high'],
    [8.9, 'high'],
    [9, 'critical'],
  ]) {
    // These boundaries lie outside the 512-case sample; verified with the pinned original.
    const vector =
      score === 4
        ? 'CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:H'
        : score === 8.9
          ? 'CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
          : fixture.cases.find((item) => item.score === score)?.vector;
    assert(vector, `Reference fixture includes score ${score}`);
    const result = await collect(advisory({ severity: [{ type: 'CVSS_V4', score: vector }] }));
    assert.equal(result.evidence[0].severity, severity, String(score));
  }
  const raw = advisory({ severity: [{ type: 'CVSS_V4', score: LOW }] });
  raw.affected[0].severity = [{ type: 'CVSS_V4', score: BASE }];
  const nested = await collect(raw);
  assert.equal(nested.evidence[0].severity, 'critical');
  assert.equal(nested.evidence[0].cvss_v4.base_scores.length, 2);
});

test('offline explain publishes v4 diagnostics beside evidence age without making network requests', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-v4-explain-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const result = await collect(
    advisory({
      severity: [
        { type: 'CVSS_V4', score: BASE },
        { type: 'CVSS_V4', score: BASE + '/BAD:X' },
      ],
    }),
  );
  const finding = assess(inventory(), result.evidence, config, NOW)[0];
  const database = join(dir, 'watch.db');
  const store = new Store(database);
  try {
    store.saveEvidence(result.evidence, {});
    store.saveAssessment(finding, decide(finding, config), NOW);
  } finally {
    store.close();
  }
  const path = join(dir, 'config.json');
  writeFileSync(path, JSON.stringify({ ...config, database }));
  const noNetwork =
    'data:text/javascript,' +
    encodeURIComponent(
      "import http from 'node:http';import https from 'node:https';import {syncBuiltinESMExports} from 'node:module';const fail=()=>{throw new Error('TEST_NETWORK_FORBIDDEN')};http.request=fail;https.request=fail;globalThis.fetch=fail;syncBuiltinESMExports();",
    );
  const child = spawnSync(
    process.execPath,
    [
      '--import',
      noNetwork,
      fileURLToPath(new URL('../dist/cli.js', import.meta.url)),
      'explain',
      finding.id,
      '--config',
      path,
    ],
    {
      cwd: dir,
      encoding: 'utf8',
      timeout: 8000,
    },
  );
  assert.equal(child.status, 0, child.stderr);
  const explanation = JSON.parse(child.stdout);
  assert.deepEqual(explanation.evidence[0].cvss_v4, result.evidence[0].cvss_v4);
  assert.equal(explanation.evidence[0].fetched_at, AT);
  assert.equal(explanation.evidence[0].modified_at, AT);
});

test('v4 labels do not lower severity floors or manufacture impact, exploitation or freshness', async () => {
  for (const [vector, expected] of [
    [LOW, 'low'],
    [ZERO, 'unknown'],
    [BASE + '/E:U/MVC:N/MVI:N/MVA:N', 'critical'],
  ]) {
    const result = await collect(advisory({ severity: [{ type: 'CVSS_V4', score: vector }] }));
    assert.equal(result.evidence[0].severity, expected);
    assert.equal(result.evidence[0].exploited, undefined);
    const out = route(result.evidence);
    assert.equal(out.finding.applicability, 'affected');
    assert.equal(out.finding.exploited, false);
  }
  const mixed = await collect(
    advisory({
      database_specific: { severity: 'CRITICAL' },
      severity: [
        { type: 'CVSS_V4', score: LOW },
        { type: 'CVSS_V4', score: BASE + '/BAD:X' },
      ],
    }),
  );
  assert.equal(mixed.evidence[0].severity, 'critical');
  assert.equal(mixed.evidence[0].cvss_v4.unsupported_vectors, 1);
  const affected = await collect();
  const noVersion = inventory();
  delete noVersion.systems[0].components[0].version;
  assert.equal(route(affected.evidence, noVersion).finding.applicability, 'unknown');
  assert.equal(
    route(affected.evidence, inventory('1.0.0', '2025-01-01T00:00:00Z')).finding.applicability,
    'unknown',
  );
  const stale = affected.evidence.map((item) => ({ ...item, fetched_at: '2025-01-01T00:00:00Z' }));
  assert.equal(route(stale).finding.applicability, 'affected');
  assert(route(stale).finding.reasons.some((reason) => reason.includes('historical')));
  const excluded = affected.evidence.map((item) => ({
    ...item,
    packages: item.packages.map((p) => {
      const { matched_versions, ...rest } = p;
      return rest;
    }),
  }));
  assert.equal(route(excluded, inventory('2.0.0')).finding.applicability, 'not_affected');
  assert.equal(route(excluded, inventory('2.0.0')).decision.action, 'record');
  assert.equal(
    route(
      excluded.map((item) => ({ ...item, fetched_at: '2025-01-01T00:00:00Z' })),
      inventory('2.0.0'),
    ).finding.applicability,
    'unknown',
  );
  const conflicting = excluded.map((item) => ({
    ...item,
    id: 'independent-v4-exclusion',
    source: 'github',
    aliases: affected.evidence[0].aliases,
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '>=2.0.0' }],
  }));
  const disputed = route([...affected.evidence, ...conflicting]);
  assert.equal(disputed.finding.applicability, 'conflicting');
  assert.equal(disputed.decision.action, 'notify');
  const withdrawn = affected.evidence.map((item) => ({ ...item, withdrawn: true }));
  assert.equal(route(withdrawn).decision.action, 'record');
  assert.equal(route(withdrawn).jobs.length, 0);
});

test('OSV type/version mismatch and malformed v4 diagnostics cannot silently score, overflow rejects whole advisory', async () => {
  for (const severity of [
    [{ type: 'CVSS_V3', score: BASE }],
    [{ type: 'CVSS_V4', score: V3 }],
    [{ type: 'CVSS_V4', score: BASE + '/NOPE:X' }],
  ]) {
    const result = await collect(advisory({ severity }));
    assert.equal(result.evidence[0].severity, 'unknown');
    assert.equal(result.evidence[0].cvss_v4.unsupported_vectors, 1);
    assert.deepEqual(result.evidence[0].cvss_v4.base_scores, []);
  }
  const result = await collect(
    advisory({ severity: Array.from({ length: 33 }, () => ({ type: 'CVSS_V4', score: BASE })) }),
  );
  assert.equal(result.evidence.length, 0);
  assert(result.errors.length > 0);
  assert.equal(result.checkpoints.osv, undefined);
});

test('GitHub versioned v4 vectors use the same base projection and preserve explicit source severity', async () => {
  const cfg = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false, osv: false, github: true },
    policy: { library: { levels: ['critical'], channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'NEVER_READ' } },
  });
  const raw = {
    ghsa_id: 'GHSA-abcd-2345-efgh',
    type: 'reviewed',
    summary: 'Synthetic GHSA',
    description: 'Synthetic.',
    severity: 'low',
    updated_at: AT,
    published_at: AT,
    vulnerabilities: [{ package: { ecosystem: 'npm', name: 'alpha' }, vulnerable_version_range: '<2.0.0' }],
    cvss_severities: { cvss_v4: { vector_string: BASE + '/E:U', score: 2.7 } },
  };
  const result = await collectSources(
    inventory(),
    cfg,
    {},
    async (url) => response(new URL(url).searchParams.get('type') === 'reviewed' ? [raw] : []),
    NOW,
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.evidence[0].severity, 'critical');
  assert.equal(result.evidence[0].cvss_v4.base_scores[0].score, 9.3);
  assert.equal(result.evidence[0].cvss_v4.base_scores[0].context_removed, true);
  assert.equal(route(result.evidence).decision.action, 'notify');
});
