import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  codeChangeUrl,
  cveNowExploitSources,
  evidenceContent,
  githubReferences,
  githubWeaknesses,
  osvFixCommits,
  osvReferences,
  osvWeaknesses,
  safeHttpsUrl,
} from '../dist/shield-inputs.js';
import { shieldCandidates } from '../dist/shield-candidates.js';
import { parseConfig, loadConfig } from '../dist/config.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';
import { notificationText, digestText } from '../dist/delivery.js';

const now = Date.parse('2026-11-24T12:00:00Z');
const iso = (time = now) => new Date(time).toISOString();
const temp = () => mkdtempSync(join(tmpdir(), 'sw-shields-'));

// Advisory links, fix commits, weaknesses and exploit code.

test('only https links without credentials are kept', () => {
  assert.equal(
    safeHttpsUrl('https://github.com/a/b/commit/abcdef1'),
    'https://github.com/a/b/commit/abcdef1',
  );
  for (const bad of [
    'http://github.com/a/b',
    'https://user:pass@github.com/a',
    'javascript:alert(1)',
    'https://localhost/x',
    'not a url',
    `https://example.com/${'a'.repeat(2100)}`,
    42,
    null,
  ])
    assert.equal(safeHttpsUrl(bad), undefined, String(bad).slice(0, 40));
});

test('commit, pull request, merge request, compare and patch links are code changes', () => {
  for (const url of [
    'https://github.com/apache/logging-log4j2/commit/7e745b42bda9bd6b3a9fbf2e1d6d4a8f8a2c1d3e',
    'https://github.com/a/b/pull/123',
    'https://github.com/a/b/pull/123/commits/abcdef12',
    'https://gitlab.com/a/b/-/commit/abcdef12',
    'https://gitlab.com/a/b/-/merge_requests/9',
    'https://github.com/a/b/compare/v1.0.0...v1.0.1',
    'https://example.com/fix.patch',
    'https://git.kernel.org/stable/c/abcdef1234',
    'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abcdef1234',
    'https://git.kernel.org/linus/c/abcdef1234',
    'https://example.org/gitweb/?p=project.git;a=commitdiff;h=abcdef1234',
  ])
    assert.ok(codeChangeUrl(url), url);
  for (const url of [
    'https://github.com/a/b',
    'https://github.com/a/b/issues/4',
    'https://nvd.nist.gov/vuln/detail/CVE-2026-1',
    'https://github.com/a/b/releases/tag/v1.2.3',
    'https://github.com/github/advisory-database/pull/5501',
    'https://github.com/pypa/advisory-database/commit/abcdef1234',
    'https://example.com/stable/c/abcdef1234',
    'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=nothex',
  ])
    assert.ok(!codeChangeUrl(url), url);
});

test('OSV references keep their type; a commit typed WEB is a fix; the most specific type wins', () => {
  const references = osvReferences([
    { type: 'WEB', url: 'https://example.com/blog' },
    { type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1' },
    { type: 'WEB', url: 'https://github.com/a/b/commit/abcdef1234' },
    { type: 'FIX', url: 'https://github.com/a/b/pull/7' },
    { type: 'EVIDENCE', url: 'https://example.com/poc' },
    { type: 'WEB', url: 'https://example.com/poc' },
    { type: 'INTRODUCED', url: 'https://github.com/a/b/commit/1111111' },
    { type: 'FIX', url: 'http://insecure.example.com/fix' },
    { type: 'SOMETHING_NEW', url: 'https://example.com/new' },
    'not an object',
    { url: 42 },
  ]);
  assert.deepEqual(references, [
    { type: 'fix', url: 'https://github.com/a/b/commit/abcdef1234' },
    { type: 'fix', url: 'https://github.com/a/b/pull/7' },
    { type: 'evidence', url: 'https://example.com/poc' },
    { type: 'advisory', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1' },
    { type: 'introduced', url: 'https://github.com/a/b/commit/1111111' },
    { type: 'web', url: 'https://example.com/blog' },
    { type: 'web', url: 'https://example.com/new' },
  ]);
  assert.deepEqual(osvReferences(undefined), []);
  assert.deepEqual(osvReferences('x'), []);
  const many = Array.from({ length: 100 }, (_, i) => ({ type: 'WEB', url: `https://example.com/${i}` }));
  assert.equal(osvReferences(many).length, 40);
});

test('OSV fix commits come from GIT ranges with an https repository', () => {
  assert.deepEqual(
    osvFixCommits([
      {
        ranges: [
          {
            type: 'GIT',
            repo: 'https://github.com/a/b',
            events: [{ introduced: '0' }, { fixed: 'ABCDEF1234' }, { fixed: 'not-a-sha' }],
          },
          { type: 'SEMVER', events: [{ fixed: '1.2.3' }] },
          { type: 'GIT', repo: 'git://github.com/a/b', events: [{ fixed: 'abcdef1' }] },
        ],
      },
      { ranges: [{ type: 'GIT', repo: 'https://github.com/a/b', events: [{ fixed: 'abcdef1234' }] }] },
      null,
      { ranges: 'x' },
    ]),
    [{ repo: 'https://github.com/a/b', commit: 'abcdef1234' }],
  );
});

test('weaknesses are normalised CWE identifiers from OSV and GitHub', () => {
  assert.deepEqual(
    osvWeaknesses({
      database_specific: { cwe_ids: ['CWE-502', 'cwe-0079', 'NVD-CWE-noinfo', 7] },
      affected: [{ database_specific: { cwe_ids: ['CWE-502', 'CWE-20'] } }],
    }),
    ['CWE-502', 'CWE-79', 'CWE-20'],
  );
  assert.deepEqual(
    githubWeaknesses([{ cwe_id: 'CWE-917', name: 'Expression Language Injection' }, { cwe_id: 'bad' }]),
    ['CWE-917'],
  );
  assert.deepEqual(githubWeaknesses(undefined), []);
});

test('GitHub references: code changes are fixes, advisory databases are advisories', () => {
  assert.deepEqual(
    githubReferences([
      'https://github.com/a/b/commit/abcdef1234',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-2',
      'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
      'https://github.com/a/b/security/advisories/GHSA-aaaa-bbbb-cccc',
      'https://example.com/writeup',
      { url: 'https://github.com/a/b/pull/3' },
      'http://example.com/insecure',
    ]),
    [
      { type: 'fix', url: 'https://github.com/a/b/commit/abcdef1234' },
      { type: 'fix', url: 'https://github.com/a/b/pull/3' },
      { type: 'advisory', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-2' },
      { type: 'advisory', url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc' },
      { type: 'advisory', url: 'https://github.com/a/b/security/advisories/GHSA-aaaa-bbbb-cccc' },
      { type: 'web', url: 'https://example.com/writeup' },
    ],
  );
});

test('cve.now exploit entries count only when present', () => {
  assert.deepEqual(
    cveNowExploitSources({ kev: null, exploitDb: null, metasploit: null, nuclei: null, githubPoc: null }),
    [],
  );
  assert.deepEqual(cveNowExploitSources({ exploitDb: [], metasploit: {}, nuclei: false, githubPoc: 0 }), []);
  // The shapes cve.now uses, with nothing in them.
  assert.deepEqual(
    cveNowExploitSources({
      exploitDb: { ids: [] },
      metasploit: { modules: [] },
      nuclei: { templates: [] },
      githubPoc: { repos: [null, ''] },
    }),
    [],
  );
  assert.deepEqual(
    cveNowExploitSources({
      exploitDb: { ids: ['50592'], publishedAt: '2021-12-14' },
      metasploit: { modules: ['modules/exploits/multi/http/log4shell_header_injection.rb'] },
      nuclei: { templates: ['http/cves/2021/CVE-2021-44228.yaml'] },
      githubPoc: { repos: ['example/poc'] },
    }),
    ['exploit-db', 'metasploit', 'nuclei', 'github-poc'],
  );
  assert.deepEqual(cveNowExploitSources(undefined), []);
});

const advisory = (id, extra = {}) => ({
  id: `osv:${id}`,
  source: 'osv',
  kind: 'advisory',
  title: `${id} in alpha`,
  url: `https://osv.dev/vulnerability/${id}`,
  description: 'Deserialization in alpha.',
  aliases: [id, 'CVE-2026-20001'],
  severity: 'critical',
  modified_at: iso(),
  fetched_at: iso(),
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0', fixed: '2.0.0' }],
  ...extra,
});

test('shield inputs are not a new evidence revision and never ask for a new analysis', () => {
  const plain = advisory('GHSA-aaaa-bbbb-cccc');
  const enriched = {
    ...plain,
    fetched_at: iso(now + 60_000),
    references: [{ type: 'fix', url: 'https://github.com/a/b/commit/abcdef1234' }],
    fix_commits: [{ repo: 'https://github.com/a/b', commit: 'abcdef1234' }],
    weaknesses: ['CWE-502'],
    exploit_sources: ['github-poc'],
  };
  assert.deepEqual(evidenceContent(enriched), evidenceContent(plain));
  const store = new Store(':memory:');
  store.saveEvidence([plain], {});
  store.saveEvidence([enriched], {});
  assert.equal(store.evidenceHistory('osv', plain.id).length, 1, 'one revision');
  assert.deepEqual(store.getEvidence([plain.id])[0].references, enriched.references, 'stored all the same');
});

// A scan reading OSV keeps the links and hands them to shield-candidates.

const inventory = {
  systems: [
    {
      id: 'fleet-os',
      name: 'Fleet OS image',
      environment: 'production',
      owner: 'Dana, platform team',
      note: 'runs on 4 nodes in eu-1',
      exposure: 'internet',
      criticality: 'high',
      updated_at: iso(),
      components: [
        { id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0', note: 'api, package.json' },
        { id: 'beta', ecosystem: 'npm', name: 'beta' },
      ],
      products: [{ name: 'Gamma Server', version: '3.1', keywords: [] }],
      keywords: [],
    },
  ],
};
const osvConfig = (extra = {}) =>
  parseConfig({
    version: 1,
    poll_interval_minutes: 1440,
    sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false },
    policy: { library: { levels: ['critical'], basis: 'source_severity', channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'SHIELD_TEST_UNUSED' } },
    ...extra,
  });
function osvApi() {
  return async (url, request) => {
    if (url.endsWith('/querybatch'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          results: JSON.parse(request.body).queries.map((query) => ({
            vulns: query.package.name === 'alpha' ? [{ id: 'GHSA-aaaa-bbbb-cccc', modified: iso() }] : [],
          })),
        }),
      };
    if (url.endsWith('/vulns/GHSA-aaaa-bbbb-cccc'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          id: 'GHSA-aaaa-bbbb-cccc',
          aliases: ['CVE-2026-20001'],
          summary: 'Unsafe deserialization in alpha',
          details: 'alpha deserializes untrusted input.',
          modified: iso(),
          published: iso(),
          database_specific: { severity: 'CRITICAL', cwe_ids: ['CWE-502'] },
          references: [
            { type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-20001' },
            { type: 'FIX', url: 'https://github.com/alpha/alpha/commit/abcdef1234' },
            { type: 'PACKAGE', url: 'https://www.npmjs.com/package/alpha' },
          ],
          affected: [
            {
              package: { ecosystem: 'npm', name: 'alpha' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
            },
            {
              ranges: [
                {
                  type: 'GIT',
                  repo: 'https://github.com/alpha/alpha',
                  events: [{ introduced: '0' }, { fixed: 'abcdef1234' }],
                },
              ],
            },
          ],
        }),
      };
    return { status: 404, headers: {}, body: '' };
  };
}

test('an OSV scan keeps fix links, commits and CWEs, and the finding is fix_known', async () => {
  const store = new Store(':memory:');
  await runScan({ config: osvConfig(), inventory, store, http: osvApi(), now });
  const [evidence] = store.getEvidence(['osv:GHSA-aaaa-bbbb-cccc']);
  assert.deepEqual(evidence.fix_commits, [{ repo: 'https://github.com/alpha/alpha', commit: 'abcdef1234' }]);
  assert.deepEqual(evidence.weaknesses, ['CWE-502']);
  assert.equal(evidence.references[0].type, 'fix');
  const report = shieldCandidates({
    findings: store.findings(),
    evidence: (ids) => store.getEvidence(ids),
    inventory,
    controls: (id) => store.controls(id, now),
    now,
  });
  assert.equal(report.candidates.length, 1);
  const [candidate] = report.candidates;
  assert.equal(candidate.readiness, 'fix_known');
  assert.deepEqual(candidate.fix_links, ['https://github.com/alpha/alpha/commit/abcdef1234']);
  assert.deepEqual(candidate.package, {
    ecosystem: 'npm',
    name: 'alpha',
    installed: '1.0.0',
    fixed: '2.0.0',
  });
  assert.deepEqual(candidate.weaknesses, ['CWE-502']);
  assert.ok(candidate.identifiers.includes('CVE-2026-20001'));
  assert.equal(candidate.revision, 1);
  assert.equal(candidate.location.owner, 'Dana, platform team');
  assert.ok(
    candidate.missing.some((line) => /No public exploit code/.test(line)),
    'no exploit code is reported, so testing against an attack is listed as missing',
  );
  assert.equal(report.counts.fix_known, 1);

  const omitted = shieldCandidates({
    findings: store.findings(),
    evidence: (ids) => store.getEvidence(ids),
    inventory,
    omitLocation: true,
    now,
  });
  assert.equal(omitted.candidates[0].location, undefined);
  assert.equal(omitted.location, 'omitted');
  assert.ok(!JSON.stringify(omitted).includes('Dana'), 'no owner, name or note anywhere');
  assert.ok(!JSON.stringify(omitted).includes('package.json'));
});

// Readiness without a scan: findings and evidence as stored.

const finding = (over = {}) => ({
  id: over.id ?? 'f1',
  event_id: 'CVE-2026-20001',
  system_id: 'fleet-os',
  component_id: 'alpha',
  category: 'library',
  applicability: 'affected',
  source_severity: 'critical',
  priority: 'critical',
  title: 'alpha deserialization',
  summary: 'alpha',
  reasons: [],
  evidence_ids: ['osv:GHSA-aaaa-bbbb-cccc'],
  urls: [],
  exploited: false,
  fix: '2.0.0',
  updated_at: iso(),
  ...over,
});
const report = (findings, evidence, extra = {}) =>
  shieldCandidates({
    findings,
    evidence: (ids) => evidence.filter((item) => ids.includes(item.id)),
    inventory,
    now,
    ...extra,
  });

test('readiness: fixed_version_known, advisory_only and news_only say what is missing', () => {
  const plain = advisory('GHSA-aaaa-bbbb-cccc');
  const news = {
    id: 'news:1',
    source: 'hacker_news',
    kind: 'news',
    title: 'Gamma Server exploited',
    url: 'https://thehackernews.com/x',
    description: 'Attackers exploit Gamma Server.',
    aliases: ['CVE-2026-30000'],
    severity: 'unknown',
    modified_at: iso(),
    fetched_at: iso(),
    packages: [],
  };
  const { candidates } = report(
    [
      finding({ id: 'version' }),
      finding({ id: 'unknown-version', component_id: 'beta', applicability: 'unknown', fix: undefined }),
      finding({
        id: 'product',
        category: 'product',
        component_id: 'product:gamma server',
        applicability: 'unknown',
        fix: undefined,
      }),
      finding({
        id: 'news',
        category: 'news',
        component_id: 'product:gamma server',
        event_id: 'news:1',
        evidence_ids: ['news:1'],
        applicability: 'relevant',
        priority: 'high',
        source_severity: 'unknown',
        news_signals: {
          exploitation: { subject: 'Gamma Server', excerpt: 'Attackers exploit Gamma Server.' },
        },
        fix: undefined,
      }),
    ],
    [plain, news],
  );
  const by = Object.fromEntries(candidates.map((item) => [item.finding_id, item]));
  assert.equal(by.version.readiness, 'fixed_version_known');
  assert.ok(by.version.missing.some((line) => /No fix commit or patch link/.test(line)));
  assert.equal(by['unknown-version'].readiness, 'advisory_only');
  assert.ok(by['unknown-version'].missing.some((line) => /installed version is unknown/.test(line)));
  assert.equal(by.product.readiness, 'advisory_only');
  assert.ok(by.product.missing.some((line) => /Matched by product or keyword/.test(line)));
  assert.equal(by.news.readiness, 'news_only');
  assert.ok(by.news.missing[0].startsWith('No advisory yet.'));
  assert.equal(by.news.exploitation_reported, true);
  assert.deepEqual(
    candidates.map((item) => item.readiness),
    ['fixed_version_known', 'advisory_only', 'advisory_only', 'news_only'],
    'most ready first',
  );
});

test('the default list is urgent findings only; --all adds the rest and suppressed ones', () => {
  const evidence = [advisory('GHSA-aaaa-bbbb-cccc')];
  const findings = [
    finding({ id: 'critical' }),
    finding({ id: 'kev', priority: 'medium', source_severity: 'medium', exploited: true }),
    finding({ id: 'medium', priority: 'medium', source_severity: 'medium' }),
    finding({ id: 'suppressed' }),
    finding({ id: 'malware', category: 'malware' }),
    finding({ id: 'health', category: 'health' }),
    finding({ id: 'gone', active: false }),
    finding({ id: 'withdrawn', withdrawn: true }),
    finding({ id: 'not-affected', applicability: 'not_affected' }),
  ];
  const controls = (id) => ({
    revision: 2,
    acknowledged: id === 'kev',
    suppressed: id === 'suppressed',
    suppressed_until: id === 'suppressed' ? now + 3_600_000 : null,
  });
  const urgent = report(findings, evidence, { controls });
  assert.deepEqual(urgent.candidates.map((item) => item.finding_id).sort(), ['critical', 'kev']);
  assert.equal(urgent.candidates.find((item) => item.finding_id === 'kev').acknowledged, true);
  assert.equal(urgent.candidates[0].finding_id, 'kev', 'exploited first among equally ready');
  const all = report(findings, evidence, { controls, all: true });
  assert.deepEqual(all.candidates.map((item) => item.finding_id).sort(), [
    'critical',
    'kev',
    'medium',
    'suppressed',
  ]);
  assert.equal(
    all.candidates.find((item) => item.finding_id === 'suppressed').suppressed_until,
    iso(now + 3_600_000),
  );
});

test('public exploit code from cve.now or news counts; withdrawn advisories do not', () => {
  const { candidates } = report(
    [
      finding({
        evidence_ids: ['osv:GHSA-aaaa-bbbb-cccc', 'cve_now:CVE-2026-20001', 'osv:GHSA-zzzz-zzzz-zzzz'],
        news_signals: { public_exploit: { subject: 'alpha', excerpt: 'A PoC is public.' } },
      }),
    ],
    [
      advisory('GHSA-aaaa-bbbb-cccc'),
      {
        ...advisory('CVE-2026-20001'),
        id: 'cve_now:CVE-2026-20001',
        source: 'cve_now',
        exploit_sources: ['github-poc'],
      },
      {
        ...advisory('GHSA-zzzz-zzzz-zzzz'),
        withdrawn: true,
        references: [{ type: 'fix', url: 'https://github.com/x/y/commit/abcdef1' }],
      },
    ],
  );
  assert.deepEqual(candidates[0].public_exploit, ['github-poc', 'news']);
  assert.ok(!candidates[0].missing.some((line) => /No public exploit/.test(line)));
  assert.deepEqual(candidates[0].fix_links, [], 'a withdrawn advisory gives no fix link');
  assert.equal(candidates[0].readiness, 'fixed_version_known');
});

test('the shield-candidates command: read-only JSON, --omit-location, --output never overwrites', async (t) => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const { readFileSync, statSync, mkdirSync } = await import('node:fs');
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const dir = temp();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const run = (args) =>
    spawnSync(process.execPath, [cli, ...args], { cwd: dir, encoding: 'utf8', timeout: 15000 });
  writeFileSync(
    join(dir, 'security-watch.yaml'),
    'version: 1\ninventory: ./systems.yaml\ndatabase: ./data/watch.db\nsources:\n  cve_now: false\n  hacker_news: false\n  osv: true\n',
  );
  writeFileSync(join(dir, 'systems.yaml'), JSON.stringify(inventory));
  assert.match(run(['shield-candidates', '--config', 'security-watch.yaml']).stdout, /not_started/);
  mkdirSync(join(dir, 'data'), { mode: 0o700 });
  const store = new Store(join(dir, 'data', 'watch.db'));
  await runScan({ config: osvConfig(), inventory, store, http: osvApi(), now });
  store.close();

  const listed = run(['shield-candidates', '--config', 'security-watch.yaml']);
  assert.equal(listed.status, 0, listed.stderr);
  const report = JSON.parse(listed.stdout);
  assert.equal(report.selection, 'urgent');
  assert.equal(report.candidates[0].readiness, 'fix_known');
  assert.equal(report.candidates[0].location.system, 'Fleet OS image');

  const omitted = run(['shield-candidates', '--config', 'security-watch.yaml', '--omit-location', '--all']);
  assert.equal(omitted.status, 0, omitted.stderr);
  assert.ok(!omitted.stdout.includes('Dana'));
  assert.equal(JSON.parse(omitted.stdout).selection, 'all');

  const saved = run(['shield-candidates', '--config', 'security-watch.yaml', '--output', 'candidates.json']);
  assert.equal(saved.status, 0, saved.stderr);
  assert.match(saved.stdout, /1 shield candidate\(s\) saved/);
  assert.equal(JSON.parse(readFileSync(join(dir, 'candidates.json'), 'utf8')).candidates.length, 1);
  if (process.platform !== 'win32') assert.equal(statSync(join(dir, 'candidates.json')).mode & 0o777, 0o600);
  const again = run(['shield-candidates', '--config', 'security-watch.yaml', '--output', 'candidates.json']);
  assert.notEqual(again.status, 0, 'an existing file is never replaced');

  const wrongFlag = run(['findings', '--config', 'security-watch.yaml', '--omit-location']);
  assert.notEqual(wrongFlag.status, 0);
  assert.match(wrongFlag.stderr, /--omit-location is not supported by findings/);
});

// Review findings, 2026-11-24.

test('review: gitweb a=commit, googlesource, Bitbucket and GitLab diffs are code changes; cvelist is not', () => {
  for (const url of [
    'https://sourceware.org/git/?p=glibc.git;a=commit;h=abcdef1',
    'https://android.googlesource.com/platform/frameworks/base/+/abcdef1234',
    'https://bitbucket.org/team/repo/pull-requests/12/diff',
    'https://gitlab.com/a/b/-/merge_requests/9/diffs',
  ])
    assert.ok(codeChangeUrl(url), url);
  for (const url of [
    'https://github.com/CVEProject/cvelist/commit/abcdef1234',
    'https://sourceware.org/git/?p=glibc.git;a=commitdif;h=abcdef1',
  ])
    assert.ok(!codeChangeUrl(url), url);
});

test('review: a commit the advisory types as evidence keeps that type', () => {
  assert.deepEqual(
    osvReferences([
      { type: 'EVIDENCE', url: 'https://github.com/attacker/poc/commit/abcdef1' },
      { type: 'REPORT', url: 'https://github.com/a/b/pull/4' },
      { type: 'ARTICLE', url: 'https://github.com/a/b/commit/1234567' },
    ]),
    [
      { type: 'fix', url: 'https://github.com/a/b/commit/1234567' },
      { type: 'evidence', url: 'https://github.com/attacker/poc/commit/abcdef1' },
      { type: 'report', url: 'https://github.com/a/b/pull/4' },
    ],
  );
});

test('review: hostile nesting and huge lists cost nothing but the extra fields', () => {
  let deep = 1;
  for (let i = 0; i < 20_000; i++) deep = [deep];
  assert.doesNotThrow(() => cveNowExploitSources({ exploitDb: deep }));
  assert.deepEqual(cveNowExploitSources({ exploitDb: deep }), [], 'nothing is looked for beyond two levels');
  const many = Array.from({ length: 300_000 }, () => 'CWE-79');
  assert.deepEqual(osvWeaknesses({ database_specific: { cwe_ids: many } }), ['CWE-79']);
  assert.deepEqual(githubWeaknesses(many), ['CWE-79']);
  const tricky = {
    get references() {
      throw new Error('boom');
    },
  };
  assert.deepEqual(
    osvReferences([
      tricky,
      {
        get url() {
          throw new Error('boom');
        },
      },
    ]),
    [],
  );
});

test('review: --omit-location leaves out system IDs, purl qualifiers and news links', () => {
  const withPurl = {
    systems: [
      {
        ...inventory.systems[0],
        id: 'acme-payments-prod',
        components: [
          {
            id: 'alpha',
            ecosystem: 'npm',
            name: 'alpha',
            version: '1.0.0',
            purl: 'pkg:npm/alpha@1.0.0?repository_url=https://npm.acme.internal/',
          },
        ],
      },
    ],
  };
  const news = {
    id: 'news:internal',
    source: 'feed',
    kind: 'news',
    title: 'alpha',
    url: 'https://intranet.acme.internal/sec/123',
    description: '',
    aliases: [],
    severity: 'unknown',
    modified_at: iso(),
    fetched_at: iso(),
    packages: [],
  };
  const base = {
    findings: [
      finding({
        system_id: 'acme-payments-prod',
        evidence_ids: ['osv:GHSA-aaaa-bbbb-cccc', 'news:internal'],
      }),
    ],
    evidence: (ids) => [advisory('GHSA-aaaa-bbbb-cccc'), news].filter((item) => ids.includes(item.id)),
    inventory: withPurl,
    now,
  };
  const text = JSON.stringify(shieldCandidates({ ...base, omitLocation: true }));
  for (const leak of ['acme-payments-prod', 'npm.acme.internal', 'intranet.acme.internal', 'Dana'])
    assert.ok(!text.includes(leak), leak);
  assert.match(text, /pkg:npm\/alpha@1\.0\.0"/);
  const full = shieldCandidates(base).candidates[0];
  assert.equal(full.system_id, 'acme-payments-prod');
  assert.equal(full.package.purl, 'pkg:npm/alpha@1.0.0?repository_url=https://npm.acme.internal/');
  assert.equal(full.advisories.length, 2);
});

test('review: without the inventory, the package an advisory matched exactly is used', () => {
  const matched = advisory('GHSA-aaaa-bbbb-cccc', {
    packages: [{ ecosystem: 'npm', name: 'alpha', fixed: '2.0.0', matched_versions: ['1.2.3'] }],
    fix_commits: [{ repo: 'https://github.com/alpha/alpha', commit: 'abcdef1234' }],
  });
  const [candidate] = shieldCandidates({
    findings: [finding()],
    evidence: () => [matched],
    now,
  }).candidates;
  assert.equal(candidate.readiness, 'fix_known');
  assert.deepEqual(candidate.package, {
    ecosystem: 'npm',
    name: 'alpha',
    installed: '1.2.3',
    fixed: '2.0.0',
  });
  const two = advisory('GHSA-aaaa-bbbb-cccc', {
    packages: [
      { ecosystem: 'npm', name: 'alpha', matched_versions: ['1.2.3'] },
      { ecosystem: 'npm', name: 'beta', matched_versions: ['1.0.0'] },
    ],
  });
  const [unsure] = shieldCandidates({ findings: [finding()], evidence: () => [two], now }).candidates;
  assert.equal(unsure.package, undefined, 'two matched packages: no guess');
  assert.equal(unsure.readiness, 'advisory_only');
});

test('review: fixtures accept the new evidence fields within bounds; rehearsal ignores the export', async () => {
  const { evidenceSchema } = await import('../dist/engine.js');
  const enriched = {
    ...advisory('GHSA-aaaa-bbbb-cccc'),
    references: [{ type: 'fix', url: 'https://github.com/a/b/commit/abcdef1234' }],
    fix_commits: [{ repo: 'https://github.com/a/b', commit: 'abcdef1234' }],
    weaknesses: ['CWE-502'],
    exploit_sources: ['github-poc'],
  };
  assert.ok(evidenceSchema.safeParse(enriched).success);
  assert.ok(
    !evidenceSchema.safeParse({ ...enriched, references: [{ type: 'fix', url: 'http://x.example/' }] })
      .success,
  );
  assert.ok(!evidenceSchema.safeParse({ ...enriched, exploit_sources: ['rumour'] }).success);
  // The packaged rehearsal example with a configured export that does not exist: nothing is read.
  const { spawnSync } = await import('node:child_process');
  const { readFileSync, appendFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const example = fileURLToPath(new URL('../examples/rehearsal.json', import.meta.url));
  const dir = temp();
  try {
    const init = spawnSync(
      process.execPath,
      [cli, 'init', '--directory', dir, '--yes', '--notifications', 'slack'],
      {
        encoding: 'utf8',
      },
    );
    assert.equal(init.status, 0, init.stderr);
    appendFileSync(
      join(dir, 'security-watch.yaml'),
      'mitigations:\n  - format: shirudo\n    file: ./missing.jsonl\n',
    );
    const output = join(dir, 'rehearsal.json');
    const rehearsal = spawnSync(
      process.execPath,
      [
        cli,
        'rehearse',
        '--config',
        join(dir, 'security-watch.yaml'),
        '--input',
        example,
        '--sink',
        'accepted',
        '--output',
        output,
      ],
      { encoding: 'utf8', timeout: 60_000 },
    );
    assert.equal(rehearsal.status, 0, rehearsal.stderr);
    const text = readFileSync(output, 'utf8');
    assert.ok(!/shirudo|mitigation/i.test(text));
    assert.ok(!text.includes('"degraded":true'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
