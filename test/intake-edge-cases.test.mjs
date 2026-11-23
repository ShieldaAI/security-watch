import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSbom, loadInventory } from '../dist/index.js';
import { inventoryMatcher, packageMentioned } from '../dist/matching.js';

function project(t, files) {
  const directory = mkdtempSync(join(tmpdir(), 'sw-intake-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(directory, name), text);
  return directory;
}
const purls = (directory) => generateSbom({ project: directory }).bom.components.map((item) => item.purl);

test('a requirements file does not hide the pyproject.toml beside it', (t) => {
  const directory = project(t, {
    'pyproject.toml': '[project]\nname = "svc"\ndependencies = ["Django==4.2.0", "requests>=2"]\n',
    'requirements-dev.txt': 'pytest==7.0.0\nrequests==2.31.0\n',
  });
  const sbom = generateSbom({ project: directory });
  assert.deepEqual(
    sbom.bom.components.map((item) => item.purl),
    ['pkg:pypi/django@4.2.0', 'pkg:pypi/pytest@7.0.0', 'pkg:pypi/requests@2.31.0'],
  );
  // Read like a workspace member: no warning about ranges the requirements file already pins.
  assert.deepEqual(sbom.warnings, []);
  // A real lockfile still resolves the manifest beside it.
  writeFileSync(join(directory, 'poetry.lock'), '[[package]]\nname = "django"\nversion = "4.2.1"\n');
  assert.deepEqual(purls(directory), [
    'pkg:pypi/django@4.2.1',
    'pkg:pypi/pytest@7.0.0',
    'pkg:pypi/requests@2.31.0',
  ]);
});

test('a go.mod replace that names a version applies to that version only', (t) => {
  const directory = project(t, {
    'go.mod': [
      'module example.com/app',
      'require (',
      '\tgolang.org/x/net v0.17.0',
      '\texample.com/lib v1.2.0',
      '\texample.com/old v1.0.0',
      ')',
      'replace golang.org/x/net v0.1.0 => golang.org/x/net v0.18.0',
      'replace example.com/lib v1.0.0 => ../lib',
      'replace example.com/old v1.0.0 => example.com/fork v1.1.0',
      '',
    ].join('\n'),
  });
  assert.deepEqual(purls(directory), [
    'pkg:golang/example.com/fork@v1.1.0',
    'pkg:golang/example.com/lib@v1.2.0',
    'pkg:golang/golang.org/x/net@v0.17.0',
  ]);
});

test('Git and URL entries of an npm v1 lockfile are not taken for registry packages', (t) => {
  const directory = project(t, {
    'package-lock.json': JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        gh: { version: 'github:user/gh#0123456789abcdef' },
        short: { version: 'user/short#0123456789abcdef' },
        lodash: { version: '4.17.21' },
      },
    }),
  });
  const sbom = generateSbom({ project: directory });
  assert.deepEqual(
    sbom.bom.components.map((item) => item.purl),
    ['pkg:npm/lodash@4.17.21'],
  );
  assert.match(sbom.warnings.join('\n'), /2 entries come from Git/);
});

test('pdm.lock Git, path and URL packages are not taken for PyPI releases', (t) => {
  const directory = project(t, {
    'pdm.lock': [
      '[[package]]',
      'name = "requests"',
      'version = "2.31.0"',
      'groups = ["default"]',
      '',
      '[[package]]',
      'name = "mylib"',
      'version = "0.1.0"',
      'git = "https://example.com/mylib.git"',
      'revision = "0123456789abcdef"',
      '',
      '[[package]]',
      'name = "local"',
      'version = "0.2.0"',
      'path = "./local"',
      '',
    ].join('\n'),
  });
  assert.deepEqual(purls(directory), ['pkg:pypi/requests@2.31.0']);
});

test('a Yarn resolution with archive parameters keeps its version', (t) => {
  const directory = project(t, {
    'yarn.lock': [
      '__metadata:',
      '  version: 8',
      '',
      '"lodash@npm:^4.17.0":',
      '  version: 4.17.20',
      '  resolution: "lodash@npm:4.17.20::__archiveUrl=https%3A%2F%2Fregistry.example.com%2Flodash.tgz"',
      '',
    ].join('\n'),
  });
  assert.deepEqual(purls(directory), ['pkg:npm/lodash@4.17.20']);
});

test('an inventory lockfile that starts with a byte order mark is read', (t) => {
  const directory = project(t, {
    'package-lock.json': `\uFEFF${JSON.stringify({
      lockfileVersion: 3,
      packages: { 'node_modules/lodash': { version: '4.17.20' } },
    })}`,
    'inventory.yaml':
      'systems:\n  - id: app\n    name: app\n    updated_at: "2026-11-01T00:00:00Z"\n    lockfile: package-lock.json\n',
  });
  const inventory = loadInventory(join(directory, 'inventory.yaml'));
  assert.deepEqual(
    inventory.systems[0].components.map((item) => [item.name, item.version]),
    [['lodash', '4.17.20']],
  );
});

test('news names a PyPI package by its published spelling, not only the normalised one', () => {
  for (const [text, name] of [
    ['Attackers exploit a flaw in typing_extensions 4.5.0 to run code.', 'typing-extensions'],
    ['A vulnerability in ruamel.yaml allows code execution.', 'ruamel-yaml'],
    ['Malicious versions of zope.interface were uploaded to PyPI.', 'zope-interface'],
  ]) {
    const component = { ecosystem: 'PyPI', name };
    assert.equal(packageMentioned(text, component), true, text);
    const inventory = { systems: [{ id: 's', components: [component], products: [], keywords: [] }] };
    assert.equal(inventoryMatcher(inventory).packageNamed(text), true, text);
  }
  // The other ecosystems keep their own spelling.
  assert.equal(
    packageMentioned('A vulnerability in ruamel.yaml allows code execution.', {
      ecosystem: 'npm',
      name: 'ruamel-yaml',
    }),
    false,
  );
});
