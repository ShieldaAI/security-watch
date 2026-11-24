// One package at one exact version listed twice in one system is one component and one finding.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { checkPackages, checkProject } from '../dist/check.js';
import { parseConfig } from '../dist/config.js';
import { runScan } from '../dist/engine.js';
import {
  foldDuplicateComponents,
  inventorySnapshotSchema,
  keepComponentIds,
  loadInventory,
} from '../dist/inventory.js';
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
  // The SBOM entry is kept: it carries the package URL.
  assert.match(kept.id, /^sbom:/);
  assert.equal(kept.purl, 'pkg:npm/minimist@1.2.5');
  assert.equal(
    kept.note,
    'found in app/node_modules/minimist, node_modules/cli/node_modules/minimist, node_modules/minimist | checkout service',
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

// Edge cases from the review of the first version of the fold.

/** A monitor database in a folder with an SBOM folder, scanned with Slack routing. */
function monitor(t) {
  const dir = folder(t);
  const db = join(dir, 'watch.db');
  const config = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false },
    policy: { library: { levels: ['critical', 'high'], basis: 'source_severity', channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'DUPLICATES_SLACK' } },
  });
  const sboms = join(dir, 'sboms');
  mkdirSync(sboms);
  writeFileSync(join(dir, 'systems.yaml'), 'sbom_directory: sboms\n');
  let time = now;
  return {
    write: (components) => writeFileSync(join(sboms, 'web.cdx.json'), JSON.stringify(bom(components))),
    async scan() {
      time += 3_600_000;
      const store = new Store(db);
      try {
        const inventory = loadInventory(join(dir, 'systems.yaml'));
        await runScan({ config, inventory, store, http: osv(), now: time });
      } finally {
        store.close();
      }
    },
    read() {
      const d = new DatabaseSync(db, { readOnly: true });
      const out = {
        findings: d.prepare('select id,revision,fingerprint,payload from findings order by id').all(),
        notifications: d
          .prepare('select finding_id,revision,channel from notifications order by 1,2,3')
          .all(),
      };
      d.close();
      return out;
    },
  };
}
const active = (state) =>
  state.findings.filter((row) => JSON.parse(row.payload).active !== false && !row.id.startsWith('health'));

test('removing the listing that was kept, while another copy stays, sends nothing again', async (t) => {
  const watch = monitor(t);
  const [low, high] = ['a', 'b'].sort((x, y) => (sbomId(x) < sbomId(y) ? -1 : 1));
  watch.write([minimist(low, 'app/node_modules/minimist'), minimist(high, 'tools/node_modules/minimist')]);
  await watch.scan();
  const first = watch.read();
  assert.equal(active(first).length, 1);
  assert.equal(JSON.parse(active(first)[0].payload).component_id, sbomId(low));
  // The kept copy goes and the other stays; then a generator renames the remaining reference.
  for (const listing of [
    minimist(high, 'tools/node_modules/minimist'),
    minimist('c', 'tools/node_modules/minimist'),
  ]) {
    watch.write([listing]);
    await watch.scan();
    const later = watch.read();
    assert.deepEqual(later.notifications, first.notifications, 'no alert is queued');
    assert.deepEqual(
      active(later).map((row) => [row.id, row.revision, row.fingerprint]),
      active(first).map((row) => [row.id, row.revision, row.fingerprint]),
      'the finding already reported goes on',
    );
    assert.equal(
      JSON.parse(active(later)[0].payload).location.component_note,
      'found in tools/node_modules/minimist',
      'the note says where the package is now',
    );
  }
  // A new release of the package is a new finding, as before.
  watch.write([minimist('c', 'tools/node_modules/minimist', '1.2.0')]);
  await watch.scan();
  assert.equal(watch.read().notifications.length, first.notifications.length + 1);
});

test('notes: an operator note and a long list of places both survive, within 500 characters', () => {
  const places = Array.from({ length: 30 }, (_, index) => `services/service-${index}/node_modules/minimist`);
  const listing = (id, note) => ({
    id,
    ecosystem: 'npm',
    name: 'minimist',
    version: '1.2.5',
    ...(note ? { note } : {}),
  });
  const cases = [
    // A short operator note and a list longer than a note can hold.
    [
      listing('library:1', 'checkout service, owned by payments'),
      listing('sbom:1', `found in ${places.join(', ')}`),
    ],
    // A note already at the limit, and one more place.
    [listing('sbom:1', `found in ${'p'.repeat(491)}`), listing('sbom:2', 'found in other/place')],
    // An operator note of 500 characters, and a lockfile path.
    [listing('library:1', 'x'.repeat(500)), listing('lock:node_modules/minimist')],
  ];
  for (const components of cases) {
    const [kept] = foldDuplicateComponents(components);
    assert.ok(kept.note.length <= 500, `${kept.note.length} characters`);
    assert.match(kept.note, /found in /);
    inventorySnapshotSchema.parse({
      systems: [{ id: 's', name: 's', updated_at: iso(), components: [kept] }],
    });
  }
  assert.match(
    foldDuplicateComponents(cases[0])[0].note,
    /^found in services\/service-0\/node_modules\/minimist, .* and others \| checkout service, owned by payments$/,
  );
  assert.match(foldDuplicateComponents(cases[2])[0].note, /^x+… \| found in node_modules\/minimist$/);
});

test('notes: folding thousands of listings with many places each stays fast', () => {
  const components = Array.from({ length: 2000 }, (_, index) => ({
    id: `sbom:${index}`,
    ecosystem: 'npm',
    name: 'minimist',
    version: '1.2.5',
    note: `found in ${Array.from({ length: 100 }, (_, place) => `p${index}-${place}`).join(', ')}`,
  }));
  const started = performance.now();
  const folded = foldDuplicateComponents(components);
  const elapsed = performance.now() - started;
  assert.equal(folded.length, 1);
  assert.ok(elapsed < 1000, `${Math.round(elapsed)} ms`);
  assert.match(folded[0].note, / and others$/);
});

test('evidence: the operator-declared listing is kept, with what the others add and nothing that re-sends', () => {
  const record = {
    event_id: 'GHSA-xvch-5gv4-984h',
    stage: 'deployed',
    verification: 'supported',
    reference: 'CHG-1',
    recorded_at: iso(),
  };
  const declared = {
    id: 'web-minimist',
    ecosystem: 'npm',
    name: 'minimist',
    version: '1.2.5',
    remediation_evidence: [record],
    signature_verification: { status: 'verified', reference: 'sig', recorded_at: iso() },
  };
  const imported = {
    id: 'sbom:1',
    ecosystem: 'npm',
    name: 'minimist',
    version: '1.2.5',
    purl: 'pkg:npm/minimist@1.2.5',
    sbom_ref: 'a',
    artifact_kind: 'library',
    digest: `sha256:${'a'.repeat(64)}`,
    remediation_evidence: [{ ...record, reference: 'CHG-2' }],
  };
  const [kept] = foldDuplicateComponents([imported, declared]);
  assert.equal(kept.id, 'web-minimist');
  assert.deepEqual(
    kept.remediation_evidence.map((item) => item.reference),
    ['CHG-1', 'CHG-2'],
  );
  assert.equal(kept.signature_verification.status, 'verified');
  assert.equal(kept.purl, 'pkg:npm/minimist@1.2.5');
  assert.equal(kept.sbom_ref, 'a');
  assert.equal(kept.artifact_kind, 'library');
  // A digest decides a finding's remediation status: taking it would re-send the finding reported.
  assert.equal(kept.digest, undefined);
});

test('versions: the same release written two ways is one component; other releases stay apart', () => {
  const folded = foldDuplicateComponents([
    { id: 'library:1', ecosystem: 'PyPI', name: 'requests', version: '2.0' },
    { id: 'sbom:1', ecosystem: 'PyPI', name: 'requests', version: '2.0.0' },
    { id: 'sbom:2', ecosystem: 'PyPI', name: 'requests', version: '2.0.1' },
    { id: 'library:2', ecosystem: 'Go', name: 'github.com/gin-gonic/gin', version: 'v1.9.1' },
    { id: 'sbom:3', ecosystem: 'Go', name: 'github.com/gin-gonic/gin', version: '1.9.1' },
    { id: 'lock:a', ecosystem: 'npm', name: 'left-pad', version: '1.0.0' },
    { id: 'lock:b', ecosystem: 'npm', name: 'left-pad', version: 'v1.0.0' },
  ]);
  assert.deepEqual(
    folded.map((component) => `${component.id} ${component.version}`),
    ['sbom:1 2.0.0', 'sbom:2 2.0.1', 'sbom:3 1.9.1', 'lock:a 1.0.0', 'lock:b v1.0.0'],
  );
});

test('dependency links between two listings of one package do not become a link to itself', () => {
  const listing = (id, dependencies) => ({
    id,
    ecosystem: 'npm',
    name: 'minimist',
    version: '1.2.5',
    dependencies,
  });
  const [kept] = foldDuplicateComponents([
    listing('sbom:1', [{ ref: 'b', component_id: 'sbom:2' }]),
    listing('sbom:2', [{ ref: 'x' }]),
  ]);
  assert.deepEqual(kept.dependencies, [{ ref: 'x' }]);
});

test('keepComponentIds: vex and shield-candidates see the identifiers the scan gave the findings', () => {
  const minimistAt = (id, version, extra = {}) => ({
    id,
    ecosystem: 'npm',
    name: 'minimist',
    version,
    ...extra,
  });
  const previous = { systems: [{ id: 's', components: [minimistAt('sbom:old', '1.2.5')] }] };
  const current = {
    systems: [
      {
        id: 's',
        components: [
          minimistAt('sbom:new', '1.2.5', { note: 'found in x' }),
          {
            id: 'sbom:dep',
            ecosystem: 'npm',
            name: 'cli',
            dependencies: [{ ref: 'n', component_id: 'sbom:new' }],
          },
        ],
      },
    ],
  };
  const kept = keepComponentIds(current, previous);
  assert.deepEqual(
    kept.systems[0].components.map((component) => component.id),
    ['sbom:old', 'sbom:dep'],
  );
  assert.deepEqual(kept.systems[0].components[1].dependencies, [{ ref: 'n', component_id: 'sbom:old' }]);
  assert.equal(kept.systems[0].components[0].note, 'found in x');
  assert.equal(keepComponentIds(current, undefined), current);
  // An identifier another current component uses is not taken, and another release is not renamed.
  const busy = {
    systems: [{ id: 's', components: [minimistAt('sbom:new', '1.2.5'), minimistAt('sbom:old', '1.2.6')] }],
  };
  assert.equal(keepComponentIds(busy, previous), busy);
});

// Second review of the fold.

test('a package URL is taken only from a listing that writes the version the same way', () => {
  const [python] = foldDuplicateComponents([
    { id: 'web-requests', ecosystem: 'PyPI', name: 'requests', version: '2.0' },
    { id: 'sbom:1', ecosystem: 'PyPI', name: 'requests', version: '2.0.0', purl: 'pkg:pypi/requests@2.0.0' },
  ]);
  assert.equal(python.id, 'web-requests');
  assert.equal(python.purl, undefined, 'a package URL for 2.0.0 does not describe 2.0');
  const [same] = foldDuplicateComponents([
    { id: 'web-requests', ecosystem: 'PyPI', name: 'requests', version: '2.0.0' },
    { id: 'sbom:1', ecosystem: 'PyPI', name: 'requests', version: '2.0.0', purl: 'pkg:pypi/requests@2.0.0' },
  ]);
  assert.equal(same.purl, 'pkg:pypi/requests@2.0.0');
});

test('versions: thousands of PyPI releases of one package are grouped quickly', () => {
  const components = Array.from({ length: 4000 }, (_, index) => ({
    id: `sbom:${index}`,
    ecosystem: 'PyPI',
    name: 'requests',
    version: `${Math.floor(index / 2)}.${index % 2 ? '0' : '0.0'}`,
  }));
  let started = performance.now();
  const folded = foldDuplicateComponents(components);
  assert.equal(folded.length, 2000, 'x.0 and x.0.0 are one release');
  assert.ok(performance.now() - started < 1000, `fold ${Math.round(performance.now() - started)} ms`);
  started = performance.now();
  const renamed = folded.map((component) => ({ ...component, id: `${component.id}-new` }));
  const kept = keepComponentIds(
    { systems: [{ id: 's', components: renamed }] },
    { systems: [{ id: 's', components: folded }] },
  );
  assert.deepEqual(
    kept.systems[0].components.map((component) => component.id),
    folded.map((component) => component.id),
  );
  assert.ok(
    performance.now() - started < 1000,
    `keepComponentIds ${Math.round(performance.now() - started)} ms`,
  );
});

test('keepComponentIds: identifiers move along a chain, never two components with one identifier', () => {
  const pkg = (id, name) => ({ id, ecosystem: 'npm', name, version: '1.0.0' });
  // Before: a had X, b had Y. Now: a is listed as Y and b as Z.
  const previous = { systems: [{ id: 's', components: [pkg('X', 'a'), pkg('Y', 'b')] }] };
  const chain = keepComponentIds(
    { systems: [{ id: 's', components: [pkg('Y', 'a'), pkg('Z', 'b')] }] },
    previous,
  );
  assert.deepEqual(
    chain.systems[0].components.map((component) => `${component.name}=${component.id}`),
    ['a=X', 'b=Y'],
  );
  // Two that swapped: each keeps the identifier it has now rather than risk a clash.
  const swapped = keepComponentIds(
    { systems: [{ id: 's', components: [pkg('Y', 'a'), pkg('X', 'b')] }] },
    previous,
  );
  const ids = swapped.systems[0].components.map((component) => component.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('a scan folds an inventory handed to it directly, such as a rehearsal snapshot', async () => {
  const findings = await scan({
    systems: [
      {
        id: 'web',
        name: 'Web',
        environment: 'production',
        exposure: 'internet',
        criticality: 'high',
        updated_at: iso(),
        components: [
          { id: 'one', ecosystem: 'npm', name: 'minimist', version: '1.2.5' },
          { id: 'two', ecosystem: 'npm', name: 'minimist', version: '1.2.5' },
        ],
        products: [],
        keywords: [],
      },
    ],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].component_id, 'one');
});

test('keepComponentIds: a chain of 20,000 moves takes one pass', () => {
  // Generated references shift by one when the first package is removed: each component's earlier
  // identifier is now held by the next one, which is moving too.
  const size = 20_000;
  const pkg = (index, id) => ({ id, ecosystem: 'npm', name: `p${index}`, version: '1.0.0' });
  const previous = {
    systems: [
      { id: 's', components: Array.from({ length: size }, (_, index) => pkg(index, `ref-${index}`)) },
    ],
  };
  const current = {
    systems: [
      {
        id: 's',
        components: Array.from({ length: size - 1 }, (_, index) => pkg(index + 1, `ref-${index}`)),
      },
    ],
  };
  const started = performance.now();
  const kept = keepComponentIds(current, previous);
  const elapsed = performance.now() - started;
  assert.ok(
    kept.systems[0].components.every((component) => component.id === `ref-${component.name.slice(1)}`),
    'every package has its earlier identifier back',
  );
  assert.ok(elapsed < 1000, `${Math.round(elapsed)} ms`);
});
