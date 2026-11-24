// Cases from the 1.3.0 edge-case catalogue (guardian/SECURITY_WATCH_1.3_EDGE_CASES.md), by ID.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { codeChangeUrl, cveNowExploitSources, osvReferences, safeHttpsUrl } from '../dist/shield-inputs.js';
import { shieldCandidates } from '../dist/shield-candidates.js';
import {
  attachMitigations,
  exportProblems,
  MitigationIndex,
  parseGenericRow,
  parseShirudoRow,
  readMitigationExport,
} from '../dist/mitigations.js';
import { importCycloneDxValue } from '../dist/sbom.js';
import { buildPurl, openVex, publishablePurl } from '../dist/vex.js';
import { parseConfig } from '../dist/config.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';
import { syncShirudoSboms } from '../dist/shirudo-sboms.js';

const now = Date.parse('2026-11-24T12:00:00Z');
const iso = (time = now) => new Date(time).toISOString();
const temp = () => mkdtempSync(join(tmpdir(), 'sw-edge-'));

const advisory = (id, extra = {}) => ({
  id: `osv:${id}`,
  source: 'osv',
  kind: 'advisory',
  title: id,
  url: `https://osv.dev/vulnerability/${id}`,
  description: 'x',
  aliases: [id, 'CVE-2026-20001'],
  severity: 'critical',
  modified_at: iso(),
  fetched_at: iso(),
  packages: [{ ecosystem: 'npm', name: 'alpha', fixed: '2.0.0' }],
  ...extra,
});
const system = (components, id = 'web') => ({
  id,
  name: id,
  environment: 'production',
  exposure: 'internet',
  criticality: 'high',
  updated_at: iso(),
  components,
  products: [],
  keywords: [],
});
const alpha = { id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' };
const inventory = { systems: [system([alpha])] };
const finding = (over = {}) => ({
  id: 'f1',
  event_id: 'GHSA-aaaa-bbbb-cccc',
  system_id: 'web',
  component_id: 'alpha',
  category: 'library',
  applicability: 'affected',
  source_severity: 'critical',
  priority: 'critical',
  title: 't',
  summary: 's',
  reasons: [],
  evidence_ids: ['osv:GHSA-aaaa-bbbb-cccc'],
  urls: [],
  exploited: false,
  fix: '2.0.0',
  updated_at: iso(),
  ...over,
});

// Advisory links.

test('ADV-01 ADV-03 ADV-04 ADV-18: links inside a network, odd characters and fragments', () => {
  for (const bad of [
    'https://example.com/a\nb',
    'https://example.com/a\tb',
    'https://example.com/a b',
    'https://10.0.0.5/commit/abcdef1',
    'https://127.0.0.1/',
    'https://[::1]/',
    'https://2130706433/',
    'https://0x7f.1/',
    'https://169.254.169.254/latest',
    'https://localhost./x',
    'https://intranet./x',
    'https://x.internal/',
    'https://host.local/',
    'https://a.test/',
    'https://svc.corp/x',
  ])
    assert.equal(safeHttpsUrl(bad), undefined, JSON.stringify(bad));
  assert.equal(safeHttpsUrl('https://example.com./c'), 'https://example.com/c', 'a trailing dot is dropped');
  assert.equal(
    safeHttpsUrl('https://github.com/a/b/commit/abcdef1#diff-1'),
    'https://github.com/a/b/commit/abcdef1',
  );
  assert.equal(
    osvReferences([
      { type: 'FIX', url: 'https://github.com/a/b/commit/abcdef1#diff-1' },
      { type: 'FIX', url: 'https://github.com/a/b/commit/abcdef1' },
    ]).length,
    1,
  );
});

test('ADV-11 ADV-13: a page typed FIX that is not a code change is an advisory', () => {
  assert.deepEqual(
    osvReferences([
      { type: 'FIX', url: 'https://vendor.example.com/bulletins/2026-11' },
      { type: 'FIX', url: 'https://github.com/github/advisory-database/pull/123' },
      { type: 'FIX', url: 'https://github.com/a/b/commit/abcdef1' },
    ]),
    [
      { type: 'fix', url: 'https://github.com/a/b/commit/abcdef1' },
      { type: 'advisory', url: 'https://vendor.example.com/bulletins/2026-11' },
      { type: 'advisory', url: 'https://github.com/github/advisory-database/pull/123' },
    ],
  );
});

test('ADV-12: compares of branches and gitweb pages without a commit are not code changes', () => {
  assert.ok(!codeChangeUrl('https://github.com/a/b/compare/main...feature'));
  assert.ok(codeChangeUrl('https://github.com/a/b/compare/v1.2.3...v1.2.4'));
  assert.ok(!codeChangeUrl('https://example.com/x?a=commit'));
  assert.ok(codeChangeUrl('https://sourceware.org/git/?p=glibc.git;a=commit;h=abcdef1'));
});

test('ADV-16: a multi-package advisory’s fix links count only when they name the package', () => {
  const shared = advisory('GHSA-aaaa-bbbb-cccc', {
    packages: [
      { ecosystem: 'npm', name: 'alpha', fixed: '2.0.0' },
      { ecosystem: 'Maven', name: 'org.example:beta', fixed: '3.0.0' },
    ],
    references: [{ type: 'fix', url: 'https://github.com/example/beta/commit/abcdef1' }],
  });
  const [candidate] = shieldCandidates({
    findings: [finding()],
    evidence: () => [shared],
    inventory,
    now,
  }).candidates;
  assert.equal(candidate.readiness, 'fixed_version_known');
  assert.ok(
    candidate.missing.some((line) =>
      /covers several packages and its fix links do not name alpha/.test(line),
    ),
  );
  assert.deepEqual(candidate.fix_links, ['https://github.com/example/beta/commit/abcdef1'], 'still listed');
  const named = {
    ...shared,
    references: [{ type: 'fix', url: 'https://github.com/example/alpha/commit/abcdef1' }],
  };
  assert.equal(
    shieldCandidates({ findings: [finding()], evidence: () => [named], inventory, now }).candidates[0]
      .readiness,
    'fix_known',
  );
});

test('ADV-21 ADV-22: cve.now entries that name nothing are not exploit code', () => {
  for (const entry of [
    { ids: [], checked: true },
    { ids: [], lastChecked: '2026-11-20' },
    'false',
    'none',
    'N/A',
    { a: { b: { c: {} } } },
    { count: 0 },
  ])
    assert.deepEqual(cveNowExploitSources({ exploitDb: entry }), [], JSON.stringify(entry));
  for (const entry of [
    { ids: ['50592'] },
    { count: 2 },
    ['https://github.com/x/poc'],
    true,
    'https://github.com/x/poc',
  ])
    assert.deepEqual(cveNowExploitSources({ githubPoc: entry }), ['github-poc'], JSON.stringify(entry));
});

// Shield candidates.

test('SHC-05: the installed version comes from a claim of the same ecosystem', () => {
  const claims = advisory('GHSA-aaaa-bbbb-cccc', {
    packages: [
      { ecosystem: 'PyPI', name: 'alpha', matched_versions: ['9.9.9'] },
      { ecosystem: 'npm', name: 'alpha', matched_versions: ['1.2.3'] },
    ],
  });
  const [candidate] = shieldCandidates({
    findings: [finding()],
    evidence: () => [claims],
    inventory: { systems: [system([{ ...alpha, version: undefined }])] },
    now,
  }).candidates;
  assert.equal(candidate.package.installed, '1.2.3');
});

const status = (over = {}) => ({
  source: 'Shirudo',
  format: 'shirudo',
  exported_at: iso(now - 60_000),
  stale: false,
  hosts: 3,
  states: { mitigated: 3 },
  mitigations: ['guard-1'],
  summary: 'Shirudo: mitigated on 3 of 3 hosts.',
  ...over,
});
const candidatesWith = (mitigations, extra = {}) =>
  shieldCandidates({
    findings: [finding({ mitigations })],
    evidence: () => [advisory('GHSA-aaaa-bbbb-cccc')],
    inventory,
    now,
    ...extra,
  }).candidates;

test('SHC-08: --omit-location keeps only whether every host is proven mitigated', () => {
  const [candidate] = candidatesWith([status()], { omitLocation: true });
  assert.equal(candidate.mitigations, undefined);
  assert.equal(candidate.mitigated_everywhere, true);
  assert.ok(!JSON.stringify(candidate).includes('guard-1'));
  assert.ok(!JSON.stringify(candidate).includes('Shirudo'));
});

test('SHC-11 SHC-12: --unmitigated hides a finding only when every source proves every host now', () => {
  const hidden = (mitigations) => candidatesWith(mitigations, { unmitigatedOnly: true }).length === 0;
  assert.equal(hidden([status()]), true);
  assert.equal(
    hidden([status(), status({ source: 'WAF', hosts: 7, states: { unmitigated: 7 } })]),
    false,
    'another source shows exposed hosts',
  );
  assert.equal(hidden([status({ not_listed: true, states: {} })]), false);
  assert.equal(hidden([status({ expires_at: iso(now - 1) })]), false, 'expired since the scan');
  assert.equal(hidden([status({ expires_at: iso(now + 60_000) })]), true);
});

// Mitigation files.

const shirudoLine = (over = {}) =>
  JSON.stringify({
    node_id: 'n1',
    image_id: 'web',
    vuln_id: 'CVE-2026-20001',
    package: 'alpha',
    exposure: 'shielded',
    upatch_id: 'g',
    ...over,
  });
const genericLine = (over = {}) =>
  JSON.stringify({
    system_id: 'web',
    host: 'h1',
    identifier: 'CVE-2026-20001',
    package: 'alpha',
    status: 'mitigated',
    ...over,
  });
const source = (file, over = {}) => ({
  name: 'S',
  format: 'generic',
  file,
  max_age_minutes: 120,
  systems: {},
  ...over,
});
const evidence = new Map([['osv:GHSA-aaaa-bbbb-cccc', advisory('GHSA-aaaa-bbbb-cccc')]]);
function indexOf(lines, over = {}) {
  const dir = temp();
  try {
    const path = join(dir, 'x.jsonl');
    writeFileSync(path, lines.join('\n') + '\n');
    utimesSync(path, (now - 60_000) / 1000, (now - 60_000) / 1000);
    const s = source(path, over);
    const exported = readMitigationExport(s, now);
    return { index: new MitigationIndex(exported, s), exported, s };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('SHC-13 MIT-17: a row without a package says nothing about a library; names compare per ecosystem', () => {
  const { index } = indexOf([genericLine({ package: undefined })]);
  assert.equal(index.status(finding(), evidence, inventory).not_listed, true);
  const product = finding({ category: 'product', component_id: 'product:gamma', applicability: 'unknown' });
  assert.equal(
    index.status(product, evidence, inventory).states.mitigated,
    1,
    'a product finding has no package',
  );
  const npmUnderscore = indexOf([genericLine({ package: 'a_b' })]).index;
  const npmInventory = {
    systems: [system([{ id: 'alpha', ecosystem: 'npm', name: 'a-b', version: '1.0.0' }])],
  };
  assert.equal(
    npmUnderscore.status(finding(), evidence, npmInventory).not_listed,
    true,
    'npm a_b is not a-b',
  );
  const pypiInventory = {
    systems: [system([{ id: 'alpha', ecosystem: 'PyPI', name: 'a-b', version: '1.0.0' }])],
  };
  assert.equal(
    npmUnderscore.status(finding(), evidence, pypiInventory).states.mitigated,
    1,
    'PyPI a_b is a-b',
  );
});

test('MIT-05 MIT-09: values this release does not know are counted and reported', () => {
  const { exported, s } = indexOf([
    genericLine({ status: 'ok' }),
    genericLine({ status: 'Mitigated', host: 'h2' }),
    genericLine({ host: 'h3' }),
  ]);
  assert.equal(exported.unknown_values, 2);
  assert.match(
    exportProblems(exported, s, now).join(' '),
    /S: 2 row\(s\) have a status this release does not know/,
  );
});

test('MIT-06 MIT-07 MIT-08: unbound nodes, nodes that stopped reporting, machine IDs beyond 2^53', () => {
  assert.deepEqual(parseShirudoRow(shirudoLine({ image_id: '' })), { unbound: true });
  assert.deepEqual(parseShirudoRow(shirudoLine({ image_id: null })), { unbound: true });
  const { exported, s } = indexOf([shirudoLine({ image_id: '' }), shirudoLine()], { format: 'shirudo' });
  assert.equal(exported.unbound, 1);
  assert.equal(exported.skipped, 0);
  assert.deepEqual(exportProblems(exported, s, now), [], 'unbound nodes are not damage');
  assert.equal(parseShirudoRow(shirudoLine({ status: 'stale' })).row.state, 'unknown');
  assert.equal(parseShirudoRow(shirudoLine({ status: 'healthy' })).row.state, 'mitigated');
  assert.throws(
    () =>
      parseShirudoRow(
        '{"node_id":9007199254740993,"image_id":"web","vuln_id":"CVE-1","exposure":"shielded"}',
      ),
    /not text/,
  );
  assert.equal(parseShirudoRow(shirudoLine({ node_id: 42 })).row.host, '42');
});

test('MIT-10: expires_at is an ISO time with a zone, or a date read as UTC', () => {
  const state = (expires_at) => parseGenericRow(genericLine({ expires_at }), now).row.state;
  assert.equal(state('2026-11-24T11:59:59Z'), 'expired');
  assert.equal(state('2026-11-24T13:30:00+02:00'), 'expired', '11:30 UTC');
  assert.equal(state('2026-11-24T14:30:00+02:00'), 'mitigated');
  assert.equal(state('2026-11-24'), 'expired', 'midnight UTC');
  assert.equal(state('2026-11-25'), 'mitigated');
  for (const bad of [
    '2026-12-01T10:00:00',
    '1700000000',
    '1',
    'never',
    'Dec 1 2026',
    '',
    '0000-00-00T00:00:00Z',
  ])
    assert.throws(() => parseGenericRow(genericLine({ expires_at: bad }), now), /invalid expires_at/, bad);
  assert.throws(() => parseGenericRow(genericLine({ expires_at: 1700000000 }), now), /invalid expires_at/);
});

test('MIT-19: an export whose rows all miss the inventory is reported by the scan', async () => {
  const dir = temp();
  try {
    const path = join(dir, 'x.jsonl');
    writeFileSync(path, genericLine({ system_id: 'web-typo' }) + '\n');
    const config = parseConfig({
      version: 1,
      sources: { cve_now: false, hacker_news: false },
      mitigations: [{ format: 'generic', name: 'WAF', file: path }],
    });
    const report = await runScan({
      config,
      inventory,
      store: new Store(':memory:'),
      now: Date.now(),
      fixture: [],
    });
    assert.ok(
      report.errors.some(
        (e) =>
          e.source === 'mitigations:WAF' &&
          /no system key in the export is a system in the inventory \(web-typo\)/.test(e.message),
      ),
      JSON.stringify(report.errors),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('MIT-23: 100,000 rows and 1,000 findings are matched in well under a second each', () => {
  const lines = [];
  for (let i = 0; i < 100_000; i++)
    lines.push(
      genericLine({
        host: `h${i % 2000}`,
        identifier: `CVE-2026-${10000 + (i % 100)}`,
        package: `p${i % 50}`,
      }),
    );
  const { index } = indexOf(lines);
  const findings = Array.from({ length: 1000 }, (_, i) =>
    finding({ id: `f${i}`, event_id: `CVE-2026-${10000 + (i % 100)}`, evidence_ids: [] }),
  );
  const started = performance.now();
  for (const item of findings) attachMitigations(item, [index], new Map(), inventory);
  // Indexed by identifier: about 1,000 rows per finding are looked at, not 100,000.
  assert.ok(performance.now() - started < 3000, `${Math.round(performance.now() - started)} ms`);
});

test('MIT-28: a UTF-16 file is named as such', () => {
  const dir = temp();
  try {
    const path = join(dir, 'x.jsonl');
    writeFileSync(path, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(genericLine(), 'utf16le')]));
    assert.throws(() => readMitigationExport(source(path), now), /UTF-16 text; write it as UTF-8/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('MIT-02: source names reject line separators and bidirectional marks', () => {
  for (const name of ['a\u2028b', 'a\u0085b', 'a\u202eb', 'a\u200bb'])
    assert.throws(
      () => parseConfig({ version: 1, mitigations: [{ format: 'generic', file: 'x', name }] }),
      JSON.stringify(name),
    );
  assert.equal(
    parseConfig({ version: 1, mitigations: [{ format: 'generic', file: 'x', name: 'Edge WAF 🔒' }] })
      .mitigations[0].name,
    'Edge WAF 🔒',
  );
});

test('UPG-05: a status saved by a development build under its old name is dropped', () => {
  const old = { ...finding(), runtime_shield: { summary: 'old' } };
  assert.equal('runtime_shield' in attachMitigations(old, [], new Map(), inventory), false);
});

// CycloneDX.

test('CDX-07 CDX-12: no leading zeros; a BOM without components is an empty list', () => {
  assert.throws(() =>
    importCycloneDxValue({ bomFormat: 'CycloneDX', specVersion: '1.07', components: [] }, 'sha256:x'),
  );
  const empty = importCycloneDxValue({ bomFormat: 'CycloneDX', specVersion: '1.6' }, 'sha256:x');
  assert.equal(empty.components.length, 0);
  assert.throws(() =>
    importCycloneDxValue({ bomFormat: 'CycloneDX', specVersion: '1.6', components: {} }, 'sha256:x'),
  );
});

// The SBOM-store sync.

test('SYN-14: a running image whose list does not change is still confirmed every day', () => {
  const dir = temp();
  try {
    const store = join(dir, 'store');
    const out = join(dir, 'sboms');
    mkdirSync(join(store, 'web', '1.0', '-'), { recursive: true });
    mkdirSync(out);
    writeFileSync(
      join(store, 'web', '1.0', '-', 'sbom.cdx.json'),
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        components: [{ name: 'alpha', version: '1.0.0', purl: 'pkg:npm/alpha@1.0.0' }],
      }),
    );
    const running = join(dir, 'running.jsonl');
    writeFileSync(running, JSON.stringify({ node_id: 'n1', image_id: 'web', image_version: '1.0' }) + '\n');
    const sync = (at) => syncShirudoSboms({ store, output: out, exposure: running, apply: true, now: at });
    assert.equal(sync(now).images[0].action, 'write');
    assert.equal(sync(now + 3_600_000).images[0].action, 'unchanged', 'an hour later: kept');
    assert.equal(sync(now + 2 * 86_400_000).images[0].action, 'write', 'two days later: confirmed again');
    const written = JSON.parse(readFileSync(join(out, 'web.cdx.json'), 'utf8'));
    assert.equal(written.metadata.timestamp, iso(now + 2 * 86_400_000));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// VEX.

test('VEX-01 VEX-02 VEX-03: purl names per specification; bad names skipped, not fatal', () => {
  assert.equal(
    buildPurl({ ecosystem: 'Packagist', name: 'Vendor/Pkg', version: '1.0.0' }),
    'pkg:composer/vendor/pkg@1.0.0',
  );
  assert.equal(
    buildPurl({ ecosystem: 'Go', name: 'github.com/Foo/Bar', version: 'v1.0.0' }),
    'pkg:golang/github.com/Foo/Bar@v1.0.0',
  );
  assert.equal(buildPurl({ ecosystem: 'Maven', name: 'artifact', version: '1' }), undefined);
  assert.equal(buildPurl({ ecosystem: 'Maven', name: 'g:a:classifier', version: '1' }), undefined);
  assert.equal(buildPurl({ ecosystem: 'npm', name: 'a\ud800b', version: '1' }), undefined);
  const { document, skipped } = openVex({
    findings: [finding()],
    evidence: () => [],
    inventory: { systems: [system([{ ...alpha, name: 'a\ud800b' }])] },
    now,
  });
  assert.equal(document.statements.length, 0);
  assert.equal(skipped.no_purl_type, 1);
});

test('VEX-05 VEX-06: inventory purls lose private qualifiers, gain the version, and must agree with it', () => {
  assert.deepEqual(
    publishablePurl(
      'pkg:NPM/alpha@1.0.0?repository_url=https://npm.acme.internal/&arch=x64&registry=corp#sub',
      '1.0.0',
    ),
    { purl: 'pkg:npm/alpha@1.0.0?arch=x64' },
  );
  assert.deepEqual(publishablePurl('pkg:npm/alpha', '1.0.0'), { purl: 'pkg:npm/alpha@1.0.0' });
  assert.deepEqual(publishablePurl('pkg:npm/alpha@2.0.0', '1.0.0'), { mismatch: true });
  assert.deepEqual(publishablePurl('not a purl', '1.0.0'), {});
  // D8: a scoped npm purl written with a literal @ is read, and the @ is encoded.
  assert.deepEqual(publishablePurl('pkg:npm/@angular/core@1.0.0', '1.0.0'), {
    purl: 'pkg:npm/%40angular/core@1.0.0',
  });
  assert.deepEqual(publishablePurl('pkg:npm/@angular/core', '1.0.0'), {
    purl: 'pkg:npm/%40angular/core@1.0.0',
  });
  const vex = (purl) =>
    openVex({
      findings: [finding()],
      evidence: () => [],
      inventory: { systems: [system([{ ...alpha, purl }])] },
      now,
    });
  assert.equal(vex('pkg:npm/alpha@2.0.0').skipped.purl_version_mismatch, 1);
  assert.deepEqual(
    vex('unreadable').document.statements[0].products,
    [{ '@id': 'pkg:npm/alpha@1.0.0' }],
    'an unreadable inventory purl falls back to one built from the component',
  );
});

test('VEX-07: systems that disagree give one statement, the most severe', () => {
  const twoSystems = { systems: [system([alpha], 'web'), system([alpha], 'api')] };
  const { document } = openVex({
    findings: [
      finding({ id: 'a', applicability: 'not_affected' }),
      finding({ id: 'b', system_id: 'api', applicability: 'affected' }),
    ],
    evidence: () => [],
    inventory: twoSystems,
    includeNotAffected: true,
    now,
  });
  assert.equal(document.statements.length, 1);
  assert.equal(document.statements[0].status, 'affected');
});
