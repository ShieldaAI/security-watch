import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadInventory,
  importCycloneDx,
  compareInventories,
  attachRemediation,
  assess,
  parseConfig,
} from '../dist/index.js';

const at = '2026-10-28T12:00:00Z';
const component = { id: 'sdk', ecosystem: 'npm', name: 'sdk', version: '1.0.0' };
const system = { id: 'agent', name: 'Agent', updated_at: at, components: [component] };
const verification = {
  status: 'verified',
  reference: 'ci:signature-check-123',
  recorded_at: at,
  recorded_by: 'release-operator',
};
const remediation = {
  event_id: 'CVE-2026-12345',
  stage: 'deployed',
  verification: 'supported',
  reference: 'ci:negative-test-124',
  recorded_at: at,
};
function files(t) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-evidence-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return { inventory: join(dir, 'inventory.json'), sbom: join(dir, 'bom.json') };
}
const write = (file, value) => writeFileSync(file, JSON.stringify(value));

test('inventory retains bounded artifact identity and declared verification/lifecycle evidence', (t) => {
  const file = files(t).inventory;
  const evidence = {
    artifact_kind: 'mcp_server',
    purl: 'pkg:npm/sdk@1.0.0',
    source_url: 'https://github.com/example/sdk',
    source_revision: 'revision-123',
    dependencies: [{ ref: 'dependency', component_id: 'dep' }],
    signature_verification: verification,
    attestation_verification: { ...verification, status: 'unknown' },
    remediation_evidence: [remediation],
  };
  write(file, {
    systems: [{ ...system, artifact_kind: 'model', components: [{ ...component, ...evidence }] }],
  });
  const loaded = loadInventory(file);
  assert.equal(loaded.systems[0].artifact_kind, 'model');
  for (const [key, value] of Object.entries(evidence))
    assert.deepEqual(loaded.systems[0].components[0][key], value);
  for (const kind of ['plugin', 'skill', 'mcp_client']) {
    write(file, { systems: [{ ...system, artifact_kind: kind, components: [] }] });
    assert.equal(loadInventory(file).systems[0].artifact_kind, kind);
  }
});

test('verification and lifecycle evidence require bounded typed references and dated declarations', (t) => {
  const file = files(t).inventory;
  const invalid = [
    { artifact_kind: 'mcp_magic' },
    { purl: 'https://example.com/package' },
    { source_url: 'https://user:password@example.com/repo' },
    { source_url: 'file:///etc/passwd' },
    { source_revision: 'x'.repeat(501) },
    { source_revision: 'revision\ncommand' },
    { signature_verification: { ...verification, status: 'safe' } },
    { signature_verification: { status: 'verified', recorded_at: at } },
    { attestation_verification: { ...verification, recorded_at: 'yesterday' } },
    { remediation_evidence: [{ ...remediation, verification: 'verified' }] },
    { remediation_evidence: [{ ...remediation, stage: 'closed' }] },
    { remediation_evidence: Array.from({ length: 101 }, () => remediation) },
    { dependencies: [{ ref: 'dep' }, { ref: 'dep' }] },
    { dependencies: Array.from({ length: 1001 }, (_, index) => ({ ref: `dep-${index}` })) },
  ];
  for (const evidence of invalid) {
    write(file, { systems: [{ ...system, ...evidence }] });
    assert.throws(() => loadInventory(file));
  }
});

test('declared verified signatures and deployed/supported remediation cannot suppress applicability', (t) => {
  const file = files(t).inventory,
    config = parseConfig({ version: 1 });
  const evidence = {
    id: 'CVE-2026-12345',
    source: 'fixture',
    kind: 'advisory',
    title: 'SDK flaw',
    url: 'https://example.com/advisory',
    description: '',
    aliases: ['GHSA-aaaa-bbbb-cccc'],
    severity: 'high',
    modified_at: at,
    fetched_at: at,
    packages: [{ ecosystem: 'npm', name: 'sdk', range: '<2.0.0' }],
  };
  write(file, { systems: [system] });
  const before = loadInventory(file);
  write(file, {
    systems: [
      {
        ...system,
        components: [
          {
            ...component,
            signature_verification: verification,
            attestation_verification: verification,
            remediation_evidence: [
              remediation,
              { ...remediation, event_id: 'CVE-2026-99999', reference: 'unrelated' },
            ],
          },
        ],
      },
    ],
  });
  const after = loadInventory(file);
  const finding = assess(after, [evidence], config, Date.parse(at))[0];
  assert.equal(finding.applicability, assess(before, [evidence], config, Date.parse(at))[0].applicability);
  assert.equal(finding.applicability, 'affected');
  const enriched = attachRemediation(finding, after, [evidence], config, Date.parse(at));
  assert.equal(enriched.applicability, 'affected');
  assert.equal(enriched.remediation.status, 'review_required');
  assert.deepEqual(enriched.remediation.operator_records, [remediation]);
  assert.equal(enriched.remediation.signature_verification.status, 'verified');
  assert.match(enriched.remediation.note, /no cryptographic verification/);
  assert.deepEqual(compareInventories(before, after)[0].fields, [
    'signature_verification',
    'attestation_verification',
    'remediation_evidence',
  ]);
});

test('SBOM package URLs and dependency graphs survive import without invented verification', (t) => {
  const file = files(t);
  write(file.sbom, {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    components: [
      {
        type: 'library',
        'bom-ref': 'sdk-ref',
        purl: 'pkg:npm/sdk@1.0.0',
        signature: { value: 'unverified-by-importer' },
      },
      { type: 'machine-learning-model', 'bom-ref': 'model-ref', purl: 'pkg:npm/model@1.0.0' },
    ],
    dependencies: [
      { ref: 'sdk-ref', dependsOn: ['model-ref', 'unknown-ref'] },
      { ref: 'root-app', dependsOn: ['sdk-ref'] },
    ],
  });
  const imported = importCycloneDx(file.sbom);
  assert.equal(imported.components[0].purl, 'pkg:npm/sdk@1.0.0');
  assert.equal(imported.components[0].sbom_ref, 'sdk-ref');
  assert.deepEqual(imported.components[0].dependencies, [
    { ref: 'model-ref', component_id: imported.components[1].id },
    { ref: 'unknown-ref' },
  ]);
  assert.equal(imported.components[1].artifact_kind, 'model');
  assert.equal(imported.components[0].signature_verification, undefined);
  assert.equal(imported.dependencies.length, 2);
  assert.match(imported.warnings.join(' '), /not an imported package/);
  write(file.inventory, { systems: [{ ...system, components: [], sbom: './bom.json' }] });
  const loaded = loadInventory(file.inventory);
  assert.deepEqual(loaded.systems[0].sbom_dependencies, imported.dependencies);
  assert.deepEqual(loaded.systems[0].components, imported.components);
  assert.equal(loaded.import_warnings.length, 2);
});

test('malformed duplicate and excessive SBOM dependency edges fail visibly', (t) => {
  const file = files(t).sbom;
  for (const dependencies of [
    'invalid',
    [{ ref: 'sdk', dependsOn: [null] }],
    [{ ref: 'sdk', dependsOn: ['x', 'x'] }],
    [
      { ref: 'sdk', dependsOn: [] },
      { ref: 'sdk', dependsOn: [] },
    ],
    [{ ref: 'sdk', dependsOn: Array.from({ length: 1001 }, (_, index) => `dep-${index}`) }],
  ]) {
    write(file, {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [{ 'bom-ref': 'sdk', purl: 'pkg:npm/sdk@1.0.0' }],
      dependencies,
    });
    assert.throws(() => importCycloneDx(file), /SBOM dependenc/);
  }
});

test('a declared CycloneDX metadata root retains its edges without an incomplete-package warning', (t) => {
  const file = files(t).sbom;
  write(file, {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    metadata: { component: { 'bom-ref': 'application', type: 'application' } },
    components: [{ 'bom-ref': 'sdk', purl: 'pkg:npm/sdk@1.0.0' }],
    dependencies: [{ ref: 'application', dependsOn: ['sdk'] }],
  });
  const imported = importCycloneDx(file);
  assert.deepEqual(imported.dependencies, [{ ref: 'application', depends_on: ['sdk'] }]);
  assert.deepEqual(imported.warnings, []);
});
