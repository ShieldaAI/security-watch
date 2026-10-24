import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadInventory } from '../dist/inventory.js';

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'security-watch-inventory-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return { dir, file: join(dir, 'inventory.yaml') };
}
const system = { id: 'api', name: 'API', updated_at: '2026-10-24T12:00:00Z' };

test('strict YAML and JSON inventory defaults preserve explicit uncertainty', (t) => {
  const { file } = fixture(t);
  writeFileSync(file, 'systems:\n  - id: api\n    name: API\n    updated_at: "2026-10-24T12:00:00Z"\n');
  const result = loadInventory(file);
  assert.equal(result.systems[0].exposure, 'unknown');
  assert.deepEqual(result.systems[0].components, []);
  writeFileSync(
    file,
    JSON.stringify({
      systems: [
        { ...system, components: [{ id: 'dep', ecosystem: 'npm', name: '@org/pkg', version: '1.0.0' }] },
      ],
    }),
  );
  assert.equal(loadInventory(file).systems[0].components[0].name, '@org/pkg');
});

test('imports transitive and scoped npm packages from a relative v2/v3 lockfile without running scripts', (t) => {
  const { dir, file } = fixture(t);
  mkdirSync(join(dir, 'app'));
  for (const lockfileVersion of [2, 3]) {
    writeFileSync(
      join(dir, 'app', 'package-lock.json'),
      JSON.stringify({
        lockfileVersion,
        packages: {
          '': { name: 'app', version: '1.0.0', scripts: { install: 'touch SHOULD_NOT_EXIST' } },
          'node_modules/dep': { version: '1.2.3' },
          'node_modules/dep/node_modules/@org/nested': { version: '2.3.4' },
          'node_modules/local-workspace': { link: true, resolved: '../packages/local' },
          'node_modules/alias': { name: 'real-package', version: '3.4.5' },
        },
      }),
    );
    writeFileSync(file, JSON.stringify({ systems: [{ ...system, lockfile: './app/package-lock.json' }] }));
    const components = loadInventory(file).systems[0].components;
    assert.deepEqual(
      components.map((item) => [item.name, item.version]),
      [
        ['dep', '1.2.3'],
        ['@org/nested', '2.3.4'],
        ['real-package', '3.4.5'],
      ],
    );
    assert.equal(components[1].id, 'lock:node_modules/dep/node_modules/@org/nested');
    assert.equal('lockfile' in loadInventory(file).systems[0], false);
  }
});

test('rejects unknown keys, duplicate identifiers, unsupported lockfiles and invalid timestamps', (t) => {
  const { dir, file } = fixture(t);
  const invalid = [
    { systems: [{ ...system, enviroment: 'production' }] },
    { systems: [system, system] },
    { systems: [{ ...system, updated_at: 'yesterday' }] },
    {
      systems: [
        {
          ...system,
          components: [
            { id: 'x', ecosystem: 'npm', name: 'dep' },
            { id: 'x', ecosystem: 'npm', name: 'other' },
          ],
        },
      ],
    },
    { systems: [{ ...system, products: [{ name: 'Postgres' }, { name: 'postgres' }] }] },
  ];
  for (const value of invalid) {
    writeFileSync(file, JSON.stringify(value));
    assert.throws(() => loadInventory(file));
  }
  writeFileSync(join(dir, 'old-lock.json'), JSON.stringify({ lockfileVersion: 1, dependencies: {} }));
  writeFileSync(file, JSON.stringify({ systems: [{ ...system, lockfile: 'old-lock.json' }] }));
  assert.throws(() => loadInventory(file), /v2 or v3/);
});

test('rejects YAML aliases, duplicate keys, oversized inputs and non-files', (t) => {
  const { dir, file } = fixture(t);
  writeFileSync(file, 'systems: &systems []\nother: *systems\n');
  assert.throws(() => loadInventory(file));
  writeFileSync(file, 'systems: []\nsystems: []\n');
  assert.throws(() => loadInventory(file), /Invalid inventory YAML/);
  writeFileSync(file, ' '.repeat(2 * 1024 * 1024 + 1));
  assert.throws(() => loadInventory(file), /regular file/);
  assert.throws(() => loadInventory(dir), /regular file/);
});
