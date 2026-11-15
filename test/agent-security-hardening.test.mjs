import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import {
  importCycloneDx,
  loadInventory,
  compareInventories,
  attachRemediation,
  collectSources,
  parseConfig,
  runScan,
  Store,
  assess,
  readFixture,
  refreshCoverage,
} from '../dist/index.js';

const now = Date.parse('2026-10-28T12:00:00Z');
const at = new Date(now).toISOString();
const digest = `sha256:${'a'.repeat(64)}`;
const config = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
});
const inventory = () => ({
  systems: [
    {
      id: 'agent',
      name: 'Agent',
      environment: 'production',
      exposure: 'internet',
      criticality: 'high',
      updated_at: at,
      components: [{ id: 'dep', ecosystem: 'npm', name: 'dep', version: '2.0.0' }],
      products: [],
      keywords: [],
    },
  ],
});
const advisory = (extra = {}) => ({
  id: 'CVE-2026-12345',
  source: 'osv',
  kind: 'advisory',
  title: 'Synthetic regression advisory',
  url: 'https://example.com/advisory',
  description: '',
  aliases: [],
  severity: 'high',
  fetched_at: at,
  modified_at: at,
  packages: [{ ecosystem: 'npm', name: 'dep', range: '<2.0.0', fixed: '2.0.0' }],
  ...extra,
});
function directory(t) {
  const dir = mkdtempSync(join(tmpdir(), 'security-watch-hardening-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function storeFor(t) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  return store;
}

test('bounded CycloneDX import retains hashes and nested package identities without executing references', (t) => {
  const dir = directory(t),
    path = join(dir, 'bom.json');
  writeFileSync(
    path,
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [
        {
          type: 'library',
          'bom-ref': 'npm',
          purl: 'pkg:npm/%40org/pkg@1.2.3',
          version: '1.2.3',
          hashes: [{ alg: 'SHA-256', content: 'a'.repeat(64) }],
          externalReferences: [{ type: 'distribution', url: 'file:///etc/passwd' }],
          properties: [{ name: 'script', value: 'touch SHOULD_NOT_EXIST' }],
          components: [{ 'bom-ref': 'python', purl: 'pkg:pypi/LangFlow@1.9.0' }],
        },
        { purl: 'pkg:deb/unknown@1.0' },
      ],
    }),
  );
  const imported = importCycloneDx(path);
  assert.equal(imported.components.length, 2);
  assert.equal(imported.components.find((item) => item.ecosystem === 'npm').name, '@org/pkg');
  assert.equal(imported.components.find((item) => item.ecosystem === 'npm').digest, digest);
  assert.equal(imported.warnings.length, 1);
  assert.equal(existsSync(join(dir, 'SHOULD_NOT_EXIST')), false);
  assert.match(imported.source.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(
    imported.components.some((item) => item.origin),
    false,
  );
  const file = join(dir, 'inventory.json');
  writeFileSync(
    file,
    JSON.stringify({ systems: [{ id: 'agent', name: 'Agent', updated_at: at, sbom: 'bom.json' }] }),
  );
  assert.equal(loadInventory(file).import_warnings.length, 1);
});

test('CycloneDX rejects conflicting versions, duplicate refs, malformed hashes, unsupported format and excessive nesting', (t) => {
  const dir = directory(t),
    file = join(dir, 'bom.json');
  const samples = [
    { components: [{ purl: 'pkg:npm/dep@1.0.0', version: '2.0.0' }] },
    {
      components: [
        { 'bom-ref': 'x', purl: 'pkg:npm/a@1.0.0' },
        { 'bom-ref': 'x', purl: 'pkg:npm/b@1.0.0' },
      ],
    },
    { components: [{ purl: 'pkg:npm/a@1.0.0', hashes: [{ alg: 'SHA-256', content: 'abc' }] }] },
    { bomFormat: 'SPDX', components: [] },
  ];
  let nested = { purl: 'pkg:npm/a@1.0.0' };
  for (let i = 0; i < 34; i++) nested = { components: [nested] };
  samples.push({ components: [nested] });
  for (const sample of samples) {
    writeFileSync(file, JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', ...sample }));
    assert.throws(() => importCycloneDx(file));
  }
});

test('optional provenance and deployment evidence preserve legacy inventory parsing and do not imply attestation', (t) => {
  const file = join(directory(t), 'inventory.json');
  const inv = inventory();
  Object.assign(inv.systems[0], {
    digest,
    origin: 'registry.example/agent',
    provenance: { source: 'CI', recorded_at: at, reference: 'build-123' },
    observation: { observed_at: at, method: 'operator inspection' },
    configuration: { LANGFLOW_WEBHOOK_AUTH_ENABLE: false },
  });
  writeFileSync(file, JSON.stringify(inv));
  assert.equal(loadInventory(file).systems[0].digest, digest);
  inv.systems[0].digest = 'latest';
  writeFileSync(file, JSON.stringify(inv));
  assert.throws(() => loadInventory(file));
});

test('drift identifies unchanged-version artifact/configuration replacement and removal without exposing values', () => {
  const before = inventory(),
    after = inventory();
  before.systems[0].components[0].digest = digest;
  after.systems[0].components[0].digest = `sha256:${'b'.repeat(64)}`;
  after.systems[0].configuration = { internal_setting: 'private-value' };
  const drift = compareInventories(before, after);
  assert.equal(drift.length, 2);
  assert.deepEqual(drift.find((change) => change.component_id).fields, ['digest']);
  assert.equal(JSON.stringify(drift).includes('private-value'), false);
  assert.deepEqual(compareInventories(undefined, after), []);
  assert.equal(
    compareInventories(after, { systems: [] }).filter((item) => item.change === 'removed').length,
    2,
  );
});

test('source receipts distinguish empty complete queries from failed stale coverage without claiming safety', async () => {
  const inv = inventory(),
    cfg = { ...config, sources: { ...config.sources, osv: true } };
  const empty = await collectSources(
    inv,
    cfg,
    {},
    async () => ({ status: 200, headers: {}, body: JSON.stringify({ results: [{}] }) }),
    now,
  );
  assert.equal(empty.coverage[0].status, 'complete');
  assert.equal(empty.coverage[0].evidence_count, 0);
  assert.match(empty.coverage[0].scope, /no absence/);
  const old = new Date(now - 86400000).toISOString();
  const failed = await collectSources(
    inv,
    cfg,
    { osv: old },
    async () => {
      throw new Error('SECRET_TOKEN');
    },
    now,
  );
  assert.equal(failed.coverage[0].status, 'failed');
  assert.equal(failed.coverage[0].freshness, 'stale');
  assert.equal(failed.checkpoints.osv, old);
  assert.equal(JSON.stringify(failed).includes('SECRET_TOKEN'), false);
});

test('stale negative evidence cannot clear an advisory, while a historical positive remains visible', () => {
  const old = new Date(now - 86400000).toISOString();
  assert.equal(assess(inventory(), [advisory({ fetched_at: old })], config, now)[0].applicability, 'unknown');
  const vulnerable = inventory();
  vulnerable.systems[0].components[0].version = '1.0.0';
  assert.equal(assess(vulnerable, [advisory({ fetched_at: old })], config, now)[0].applicability, 'affected');
});

test('scan retains inventory drift and source receipts and separates observed exclusion from verified remediation', async (t) => {
  const store = storeFor(t),
    inv = inventory();
  inv.systems[0].components[0].observation = { observed_at: at, method: 'runtime inventory' };
  inv.systems[0].components[0].digest = digest;
  const first = await runScan({ config, inventory: inv, store, fixture: [advisory()], now });
  assert.equal(first.findings[0].remediation.status, 'observed_version_excluded');
  assert.match(first.findings[0].remediation.note, /not verified attestations/);
  inv.systems[0].components[0].digest = `sha256:${'b'.repeat(64)}`;
  const second = await runScan({ config, inventory: inv, store, fixture: [advisory()], now: now + 1000 });
  assert.deepEqual(second.inventory_drift[0].fields, ['digest']);
  assert.equal(JSON.parse(store.getMeta('inventory:last_drift')).length, 1);
  assert.deepEqual(JSON.parse(store.getMeta('source:coverage')), []);
});

test('recent source-derived agent advisories retain configuration-dependent remediation even after declared version changes', () => {
  const fixtures = readFixture(new URL('../examples/agent-advisories-2026.json', import.meta.url).pathname);
  for (const evidence of fixtures) {
    const inv = inventory();
    const assessedAt = Math.max(now, Date.parse(evidence.fetched_at));
    inv.systems[0].components = evidence.packages.length
      ? [
          {
            id: 'agent-dep',
            ecosystem: 'PyPI',
            name: evidence.packages[0].name,
            version: evidence.packages[0].versions[0],
          },
        ]
      : [];
    if (!evidence.packages.length)
      inv.systems[0].products = [{ name: 'OpenHands Software Agent SDK', version: '1.51.0', keywords: [] }];
    inv.systems[0].configuration = {
      LANGFLOW_WEBHOOK_AUTH_ENABLE: false,
      namespace_used_as_tenant_boundary: true,
      secret: 'NEVER_INCLUDE',
    };
    const finding = assess(inv, [evidence], config, assessedAt)[0];
    const result = attachRemediation(finding, inv, [evidence], config, assessedAt);
    assert.equal(result.remediation.status, 'review_required');
    assert.ok(result.remediation.requirements.length >= 2);
    assert.equal(JSON.stringify(result.remediation).includes('NEVER_INCLUDE'), false);
    const fakeExclusion = attachRemediation(
      { ...finding, applicability: 'not_affected' },
      inv,
      [evidence],
      config,
      assessedAt,
    );
    assert.equal(fakeExclusion.remediation.status, 'review_required');
  }
});

test('saved coverage ages while the monitor is stopped and partial receipts do not inherit discovery success', async () => {
  const cfg = { ...config, sources: { ...config.sources, osv: true } };
  const first = await collectSources(
    inventory(),
    cfg,
    {},
    async () => {
      throw new Error('offline');
    },
    now,
  );
  const failedAgain = await collectSources(
    inventory(),
    cfg,
    { osv: at },
    async () => {
      throw new Error('offline');
    },
    now,
    [],
    first.coverage,
  );
  assert.equal(failedAgain.coverage[0].freshness, 'never');
  const complete = await collectSources(
    inventory(),
    cfg,
    {},
    async () => ({ status: 200, headers: {}, body: JSON.stringify({ results: [{}] }) }),
    now,
  );
  assert.equal(refreshCoverage(complete.coverage, now + 86400000)[0].freshness, 'stale');
});

test('unchanged deployment evidence does not generate repeated finding revisions and digest changes remain auditable', async (t) => {
  const store = storeFor(t),
    inv = inventory();
  inv.systems[0].components[0].digest = digest;
  inv.systems[0].components[0].observation = { observed_at: at, method: 'runtime inventory' };
  const first = await runScan({ config, inventory: inv, store, fixture: [advisory()], now });
  const id = first.findings[0].id;
  const count = store.history(id).length;
  await runScan({ config, inventory: inv, store, fixture: [advisory()], now: now + 1000 });
  assert.equal(store.history(id).length, count);
  inv.systems[0].components[0].digest = `sha256:${'b'.repeat(64)}`;
  await runScan({ config, inventory: inv, store, fixture: [advisory()], now: now + 2000 });
  assert.equal(store.history(id).length, count + 1);
});

test('CLI SBOM import needs no config and refuses overwrite; read-only coverage ages without network', (t) => {
  const dir = directory(t),
    input = join(dir, 'bom.json'),
    output = join(dir, 'report.json');
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { cwd: dir, encoding: 'utf8' });
  writeFileSync(
    input,
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [{ purl: 'pkg:npm/dep@1.0.0' }],
    }),
  );
  assert.equal(run('import-sbom', '--input', input, '--output', output).status, 0);
  assert.notEqual(run('import-sbom', '--input', input, '--output', output).status, 0);
  const database = join(dir, 'watch.db'),
    configuration = join(dir, 'config.json');
  const store = new Store(database);
  store.setMeta(
    'source:coverage',
    JSON.stringify([
      {
        source: 'osv',
        attempted_at: '2020-01-01T00:00:00Z',
        last_success_at: '2020-01-01T00:00:00Z',
        fresh_until: '2020-01-01T01:00:00Z',
        status: 'complete',
        freshness: 'fresh',
        evidence_count: 0,
        errors: [],
        scope: 'test',
      },
    ]),
  );
  store.setMeta(
    'inventory:last_drift',
    JSON.stringify([{ system_id: 'agent', change: 'removed', fields: ['digest'] }]),
  );
  store.close();
  writeFileSync(configuration, JSON.stringify({ version: 1, database }));
  const coverage = run('coverage', '--config', configuration);
  assert.equal(coverage.status, 0, coverage.stderr);
  assert.equal(JSON.parse(coverage.stdout)[0].freshness, 'stale');
  const drift = run('inventory-drift', '--config', configuration);
  assert.equal(drift.status, 0, drift.stderr);
  assert.equal(JSON.parse(drift.stdout)[0].change, 'removed');
});
