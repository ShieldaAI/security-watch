import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cycloneDxMinor, importSbom } from '../dist/sbom.js';
import { loadInventory } from '../dist/inventory.js';

const REFUSED = /Expected CycloneDX JSON 1\.2 or later 1\.x/;
const temp = (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sw-cdx-versions-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
const document = (specVersion) => ({
  bomFormat: 'CycloneDX',
  ...(specVersion === undefined ? {} : { specVersion }),
  version: 1,
  components: [
    { type: 'library', 'bom-ref': 'a', name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0' },
  ],
});
function imported(t, specVersion) {
  const path = join(temp(t), 'sbom.json');
  writeFileSync(path, JSON.stringify(document(specVersion)));
  return importSbom(path);
}

test('cycloneDxMinor reads 1.2 and later 1.x only', () => {
  assert.equal(cycloneDxMinor('1.2'), 2);
  assert.equal(cycloneDxMinor('1.7'), 7);
  assert.equal(cycloneDxMinor('1.10'), 10);
  assert.equal(cycloneDxMinor('1.999'), 999);
  assert.equal(cycloneDxMinor(1.6), 6);
  for (const bad of [
    '1.1',
    '1.0',
    '2.0',
    '1.x',
    '',
    undefined,
    null,
    '01.6',
    ' 1.6',
    '1.6 ',
    '1.',
    '1',
    '1.1000',
    '1.6.1',
    1,
    2.1,
    {},
    [],
  ])
    assert.equal(cycloneDxMinor(bad), undefined, `${JSON.stringify(bad)}`);
});

test('CycloneDX 1.2 to 1.7 are accepted without a notice', (t) => {
  for (const version of ['1.2', '1.3', '1.4', '1.5', '1.6', '1.7']) {
    const result = imported(t, version);
    assert.equal(result.components.length, 1, version);
    assert.equal(result.source.spec_version, version);
    assert.equal(result.notices, undefined, version);
  }
});

test('a numeric 1.6 is accepted', (t) => {
  const result = imported(t, 1.6);
  assert.equal(result.components.length, 1);
  assert.equal(result.source.spec_version, '1.6');
  assert.equal(result.notices, undefined);
});

test('later 1.x versions are accepted with a notice that names the version', (t) => {
  for (const version of ['1.8', '1.10']) {
    const result = imported(t, version);
    assert.equal(result.components.length, 1);
    assert.equal(result.source.spec_version, version);
    assert.equal(result.notices?.length, 1);
    assert.match(result.notices[0], new RegExp(`CycloneDX ${version.replace('.', '\\.')} is newer`));
  }
});

test('versions before 1.2, 2.x and malformed values are refused', (t) => {
  for (const version of ['1.1', '1.0', '2.0', '1.x', '', undefined, '01.6', ' 1.6', null, ['1.6'], { v: 1 }])
    assert.throws(() => imported(t, version), REFUSED, JSON.stringify(version));
});

test('through an SBOM folder a newer version is a name notice, not an import warning', (t) => {
  const dir = temp(t);
  mkdirSync(join(dir, 'sboms'));
  writeFileSync(join(dir, 'systems.yaml'), 'sbom_directory: ./sboms\n');
  writeFileSync(join(dir, 'sboms', 'new.cdx.json'), JSON.stringify(document('1.8')));
  writeFileSync(join(dir, 'sboms', 'old.cdx.json'), JSON.stringify(document('1.6')));
  const inventory = loadInventory(join(dir, 'systems.yaml'));
  assert.deepEqual(inventory.systems.map((system) => system.id).sort(), ['new', 'old']);
  assert.equal(inventory.import_warnings, undefined);
  assert.equal(inventory.name_notices?.length, 1);
  assert.match(inventory.name_notices[0], /new: CycloneDX 1\.8 is newer/);
});

test('through an SBOM folder a refused version is an import warning and the system is not watched', (t) => {
  const dir = temp(t);
  mkdirSync(join(dir, 'sboms'));
  writeFileSync(join(dir, 'systems.yaml'), 'sbom_directory: ./sboms\n');
  writeFileSync(join(dir, 'sboms', 'v2.cdx.json'), JSON.stringify(document('2.0')));
  writeFileSync(join(dir, 'sboms', 'ok.cdx.json'), JSON.stringify(document('1.4')));
  const inventory = loadInventory(join(dir, 'systems.yaml'));
  assert.deepEqual(
    inventory.systems.map((system) => system.id),
    ['ok'],
  );
  assert.match(inventory.import_warnings.join('\n'), /v2\.cdx\.json.*Expected CycloneDX JSON 1\.2/);
});
