// One package at one exact version listed twice in one system is one component and one finding.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkPackages, checkProject } from '../dist/check.js';
import { parseConfig } from '../dist/config.js';
import { runScan } from '../dist/engine.js';
import { foldDuplicateComponents, loadInventory } from '../dist/inventory.js';
import { Store } from '../dist/store.js';
import { hash } from '../dist/util.js';

const now = Date.parse('2026-11-24T12:00:00Z');
const iso = (time = now) => new Date(time).toISOString();
const sbomId = (ref) => `sbom:${hash(ref).slice(0, 32)}`;

/** OSV with one advisory for minimist below 1.2.6. */
function osv() {
  const record = {
    id: 'GHSA-xvch-5gv4-984h',
    aliases: ['CVE-2021-44906'],
    summary: 'Prototype pollution in minimist',
    details: 'minimist before 1.2.6 is vulnerable to prototype pollution.',
    modified: iso(now - 86_400_000),
    published: iso(now - 86_400_000),
    database_specific: { severity: 'CRITICAL' },
    affected: [
      {
        package: { ecosystem: 'npm', name: 'minimist' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.6' }] }],
      },
    ],
  };
  return async (url, options = {}) => {
    if (url === 'https://api.osv.dev/v1/querybatch')
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          results: JSON.parse(options.body).queries.map((query) => ({
            vulns: query.package.name === 'minimist' ? [{ id: record.id, modified: record.modified }] : [],
          })),
        }),
      };
    if (url === `https://api.osv.dev/v1/vulns/${record.id}`)
      return { status: 200, headers: {}, body: JSON.stringify(record) };
    return { status: 404, headers: {}, body: '' };
  };
}

const minimist = (ref, location, version = '1.2.5') => ({
  ...(ref ? { 'bom-ref': ref } : {}),
  type: 'library',
  name: 'minimist',
  version,
  purl: `pkg:npm/minimist@${version}`,
  ...(location ? { evidence: { occurrences: [{ location }] } } : {}),
});
const bom = (components, dependencies) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  metadata: { component: { 'bom-ref': 'root', name: 'web' } },
  components,
  ...(dependencies ? { dependencies } : {}),
});

function folder(t) {
  const dir = mkdtempSync(join(tmpdir(), 'sw-duplicates-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

async function scan(inventory) {
  const store = new Store(':memory:');
  try {
    const config = parseConfig({
      version: 1,
      sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false },
    });
    const report = await runScan({ config, inventory, store, http: osv(), now });
    return report.findings.filter((finding) => finding.category !== 'health');
  } finally {
    store.close();
  }
}

test('case 1: one SBOM listing a package twice with its own bom-refs gives one finding with both places', async (t) => {
  const dir = folder(t);
  mkdirSync(join(dir, 'sboms'));
  writeFileSync(
    join(dir, 'sboms', 'web.cdx.json'),
    JSON.stringify(
      bom(
        [
          minimist('b', 'tools/node_modules/minimist'),
          minimist('a', 'app/node_modules/minimist'),
          { 'bom-ref': 'cli', type: 'library', name: 'cli', version: '1.0.0', purl: 'pkg:npm/cli@1.0.0' },
          { 'bom-ref': 'opts', type: 'library', name: 'opts', version: '1.0.0', purl: 'pkg:npm/opts@1.0.0' },
        ],
        [
          { ref: 'root', dependsOn: ['a', 'cli'] },
          { ref: 'cli', dependsOn: ['b'] },
          { ref: 'b', dependsOn: ['opts'] },
        ],
      ),
    ),
  );
  writeFileSync(join(dir, 'systems.yaml'), 'sbom_directory: sboms\n');
  const inventory = loadInventory(join(dir, 'systems.yaml'));
  const [system] = inventory.systems;
  const kept = [sbomId('a'), sbomId('b')].sort()[0];
  const folded = [sbomId('a'), sbomId('b')].sort()[1];
  const listed = system.components.filter((component) => component.name === 'minimist');
  assert.equal(listed.length, 1);
  assert.equal(listed[0].id, kept, 'the smallest identifier is kept, whatever the document order');
  const places = listed[0].note.slice('found in '.length).split(', ').sort();
  assert.deepEqual(places, ['app/node_modules/minimist', 'tools/node_modules/minimist']);
  // The folded listing's own edges move to the one kept, and edges to it now lead there.
  assert.deepEqual(
    listed[0].dependencies.map((link) => link.ref),
    ['opts'],
  );
  const cli = system.components.find((component) => component.name === 'cli');
  assert.deepEqual(cli.dependencies, [{ ref: 'b', component_id: kept }]);
  assert.ok(!system.components.some((component) => component.id === folded));

  const findings = await scan(inventory);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].component_id, kept);
});

test('case 1, check: --sbom reports the package once with every file it was found in', async (t) => {
  const dir = folder(t);
  const path = join(dir, 'dup.cdx.json');
  writeFileSync(
    path,
    JSON.stringify(
      bom([minimist('a', 'app/node_modules/minimist'), minimist('b', 'tools/node_modules/minimist')]),
    ),
  );
  const report = await checkProject({ sbom: path, http: osv(), now });
  assert.equal(report.findings.length, 1);
  assert.deepEqual(report.findings[0].files.sort(), [
    'app/node_modules/minimist',
    'tools/node_modules/minimist',
  ]);
  const named = await checkPackages(
    [
      { ecosystem: 'npm', name: 'minimist', version: '1.2.5' },
      { ecosystem: 'npm', name: 'minimist', version: '1.2.5' },
    ],
    { http: osv(), now },
  );
  assert.equal(named.findings.length, 1);
});

test('case 2: libraries, an SBOM and a lockfile naming one package version are one component', async (t) => {
  const dir = folder(t);
  writeFileSync(join(dir, 'web.cdx.json'), JSON.stringify(bom([minimist('m', 'app/node_modules/minimist')])));
  writeFileSync(
    join(dir, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'web' },
        'node_modules/minimist': { version: '1.2.5' },
        'node_modules/cli/node_modules/minimist': { version: '1.2.5' },
        'node_modules/old/node_modules/minimist': { version: '1.2.0' },
      },
    }),
  );
  const system = (id, extra) =>
    [
      `  - id: ${id}`,
      `    name: ${id}`,
      `    updated_at: ${iso()}`,
      ...extra.map((line) => `    ${line}`),
    ].join('\n');
  writeFileSync(
    join(dir, 'systems.yaml'),
    [
      'systems:',
      system('all', [
        'libraries:',
        '  - "npm:minimist@1.2.5  # checkout service"',
        'sbom: web.cdx.json',
        'lockfile: package-lock.json',
      ]),
      system('libraries-sbom', ['libraries: [npm:minimist@1.2.5]', 'sbom: web.cdx.json']),
      system('libraries-lockfile', ['libraries: [npm:minimist@1.2.5]', 'lockfile: package-lock.json']),
      system('sbom-lockfile', ['sbom: web.cdx.json', 'lockfile: package-lock.json']),
      '',
    ].join('\n'),
  );
  const inventory = loadInventory(join(dir, 'systems.yaml'));
  for (const system of inventory.systems) {
    const exact = system.components.filter((component) => component.version === '1.2.5');
    assert.equal(exact.length, 1, system.id);
    // Another version of the package is its own component.
    assert.equal(
      system.components.filter((component) => component.version === '1.2.0').length,
      system.id.includes('lockfile') || system.id === 'all' ? 1 : 0,
    );
  }
  const all = inventory.systems.find((system) => system.id === 'all');
  const [kept] = all.components.filter((component) => component.version === '1.2.5');
  assert.match(kept.id, /^library:/);
  assert.equal(
    kept.note,
    'checkout service | found in node_modules/cli/node_modules/minimist, node_modules/minimist, app/node_modules/minimist',
  );
  const findings = await scan(inventory);
  const bySystem = Object.groupBy(findings, (finding) => finding.system_id);
  assert.equal(bySystem.all.length, 2, 'one for 1.2.5 and one for 1.2.0');
  assert.equal(bySystem['libraries-sbom'].length, 1);
  assert.equal(bySystem['libraries-lockfile'].length, 2);
  assert.equal(bySystem['sbom-lockfile'].length, 2);
});

test('fold: only one exact version; nothing changes for a system without duplicates', () => {
  const components = [
    { id: 'b', ecosystem: 'npm', name: 'minimist', version: '1.2.5' },
    { id: 'c', ecosystem: 'npm', name: 'minimist', version: '1.2.6' },
    { id: 'a', ecosystem: 'npm', name: 'minimist', version: '1.2.5', note: 'api' },
    { id: 'x', ecosystem: 'npm', name: 'other' },
    { id: 'w', ecosystem: 'npm', name: 'other' },
  ];
  const folded = foldDuplicateComponents(components);
  assert.deepEqual(
    folded.map((component) => component.id),
    ['a', 'c', 'w'],
  );
  assert.equal(folded[0].note, 'api');
  const unique = [components[1], components[3]];
  assert.equal(foldDuplicateComponents(unique), unique, 'the same list, untouched');
});
