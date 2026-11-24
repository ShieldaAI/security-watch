import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareVersions, mergeCycloneDx, syncShirudoSboms } from '../dist/shirudo-sboms.js';
import { importSbom } from '../dist/sbom.js';
import { loadInventory } from '../dist/inventory.js';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const now = Date.parse('2026-11-24T12:00:00Z');
const ROOT = 'a'.repeat(64);

function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'sw-shirudo-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const store = join(dir, 'store');
  const output = join(dir, 'sboms');
  mkdirSync(store);
  mkdirSync(output);
  return { dir, store, output };
}

const component = (name, version, ref = name, extra = {}) => ({
  type: 'library',
  'bom-ref': ref,
  name,
  version,
  purl: `pkg:npm/${name}@${version}`,
  ...extra,
});
const bom = (components, dependencies, extra = {}) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  version: 1,
  metadata: { timestamp: '2026-01-01T00:00:00Z' },
  components,
  ...(dependencies ? { dependencies } : {}),
  ...extra,
});
/** Puts an SBOM into the store at <image>/<version>/<root>/sbom.cdx.json. */
function put(store, image, version, document, root = '-') {
  const dir = join(store, image, version, root);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, 'sbom.cdx.json');
  writeFileSync(file, typeof document === 'string' ? document : JSON.stringify(document));
  writeFileSync(join(dir, 'image.json'), '{}');
  return file;
}
function exportFile(dir, rows, name = 'running.jsonl') {
  const path = join(dir, name);
  writeFileSync(
    path,
    rows.map((row) => (typeof row === 'string' ? row : JSON.stringify(row))).join('\n') + '\n',
  );
  return path;
}
const row = (image_id, image_version, node_id) => ({ image_id, image_version, node_id });
const sync = (ctx, options = {}) =>
  syncShirudoSboms({ store: ctx.store, output: ctx.output, now, ...options });
const read = (ctx, file) => JSON.parse(readFileSync(join(ctx.output, file), 'utf8'));
const property = (doc, name) => doc.metadata.properties.find((item) => item.name === name)?.value;
const names = (doc) => doc.components.map((item) => item.name).sort();

// Natural version order.

test('versions compare in natural order', () => {
  assert.ok(compareVersions('2026.11.10', '2026.11.9') > 0);
  assert.ok(compareVersions('2026.11.9', '2026.11.10') < 0);
  assert.ok(compareVersions('1.10', '1.9') > 0);
  assert.ok(compareVersions('1.2', '1.2') === 0);
  assert.ok(compareVersions('1.2', '1.2.1') < 0);
  assert.ok(compareVersions('1.2.1', '1.2') > 0);
  assert.ok(compareVersions('v2', 'v10') < 0);
  assert.ok(compareVersions('1.0-alpha', '1.0-beta') < 0);
  assert.ok(compareVersions('1.0-rc1', '1.0-rc2') < 0);
  assert.ok(compareVersions('1.0-rc9', '1.0-rc10') < 0);
  // Numbers beyond 2^53 still compare by value, and leading zeros do not matter.
  assert.ok(compareVersions('1.99999999999999999999', '1.99999999999999999998') > 0);
  assert.ok(compareVersions('1.123456789012345678901234567890', '1.9') > 0);
  assert.equal(compareVersions('1.007', '1.7'), 0);
  assert.deepEqual(['2026.11.10', '2026.9', '2026.11.9'].sort(compareVersions), [
    '2026.9',
    '2026.11.9',
    '2026.11.10',
  ]);
});

// Selection.

test('without an export the newest version of each image is taken', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'fleet-os', '2026.11.9', bom([component('old', '1.0.0')]));
  put(ctx.store, 'fleet-os', '2026.11.10', bom([component('new', '1.0.0')]));
  put(ctx.store, 'fleet-os', '2026.9', bom([component('older', '1.0.0')]));
  put(ctx.store, 'edge', '1.9', bom([component('a', '1.0.0')]));
  put(ctx.store, 'edge', '1.10', bom([component('b', '1.0.0')]));
  mkdirSync(join(ctx.store, 'empty-image'));
  const plan = sync(ctx);
  assert.equal(plan.selection, 'newest');
  assert.deepEqual(
    plan.images.map((item) => [item.image_id, item.versions, item.action]),
    [
      ['edge', [{ version: '1.10' }], 'write'],
      ['fleet-os', [{ version: '2026.11.10' }], 'write'],
    ],
  );
  assert.deepEqual(plan.problems, ['empty-image: no version in the store; left as it was.']);
  assert.deepEqual(readdirSync(ctx.output), [], 'a dry run writes nothing');
  sync(ctx, { apply: true });
  assert.deepEqual(names(read(ctx, 'fleet-os.cdx.json')), ['new']);
  assert.deepEqual(names(read(ctx, 'edge.cdx.json')), ['b']);
  // The store confirms the list is current: its time is the sync's, so the image does not turn stale
  // seven days after it was built.
  assert.equal(read(ctx, 'edge.cdx.json').metadata.timestamp, new Date(now).toISOString());
  assert.match(
    property(read(ctx, 'edge.cdx.json'), 'security-watch:note'),
    /^Shirudo image edge: version 1\.10 \(newest in the store\)$/,
  );
});

test('with an export only running images are taken, with host counts in the note', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'fleet-os', '1.0', bom([component('a', '1.0.0')]));
  put(ctx.store, 'idle', '1.0', bom([component('b', '1.0.0')]));
  const running = exportFile(ctx.dir, [
    row('fleet-os', '1.0', 'n1'),
    row('fleet-os', '1.0', 'n2'),
    row('fleet-os', '1.0', 'n1'),
    row('solo', '1', 'x'),
  ]);
  const plan = sync(ctx, { exposure: running, apply: true });
  assert.equal(plan.selection, 'running');
  assert.deepEqual(
    plan.images.map((item) => [item.image_id, item.versions]),
    [['fleet-os', [{ version: '1.0', hosts: 2 }]]],
  );
  assert.deepEqual(plan.problems, ['solo: runs on machines but is not in the store.']);
  assert.deepEqual(readdirSync(ctx.output), ['fleet-os.cdx.json']);
  const doc = read(ctx, 'fleet-os.cdx.json');
  assert.equal(property(doc, 'security-watch:note'), 'Shirudo image fleet-os: version 1.0 on 2 hosts');
  assert.equal(doc.metadata.timestamp, new Date(now).toISOString());
});

test('a single host is worded in the singular', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'img', '1', bom([component('a', '1.0.0')]));
  sync(ctx, { exposure: exportFile(ctx.dir, [row('img', '1', 'n1')]), apply: true });
  assert.match(property(read(ctx, 'img.cdx.json'), 'security-watch:note'), /version 1 on 1 host$/);
});

test('running versions are merged: same package once, references unique, edges kept, nested components', (t) => {
  const ctx = setup(t);
  put(
    ctx.store,
    'app',
    '1.1',
    bom(
      [
        component('web', '1.0.0', 'web', { components: [component('nested-new', '2.0.0', 'nested')] }),
        component('shared', '1.0.0', 'shared'),
        component('only-new', '1.0.0', 'only-new'),
      ],
      [
        { ref: 'web', dependsOn: ['shared', 'only-new', 'nested'] },
        { ref: 'shared', dependsOn: [] },
      ],
    ),
  );
  put(
    ctx.store,
    'app',
    '1.0',
    bom(
      [
        component('shared', '1.0.0', 'shared'),
        component('only-old', '1.0.0', 'only-old'),
        component('web', '0.9.0', 'web'),
      ],
      [
        { ref: 'web', dependsOn: ['shared', 'only-old'] },
        { ref: 'shared', dependsOn: ['only-old'] },
        { ref: 'ghost', dependsOn: ['shared'] },
        { ref: 'only-old', dependsOn: ['missing'] },
      ],
      { specVersion: '1.4' },
    ),
  );
  const running = exportFile(ctx.dir, [
    row('app', '1.0', 'n1'),
    row('app', '1.1', 'n2'),
    row('app', '1.1', 'n3'),
  ]);
  const plan = sync(ctx, { exposure: running, apply: true });
  assert.deepEqual(plan.problems, []);
  assert.deepEqual(plan.images[0].versions, [
    { version: '1.1', hosts: 2 },
    { version: '1.0', hosts: 1 },
  ]);
  const doc = read(ctx, 'app.cdx.json');
  assert.equal(
    property(doc, 'security-watch:note'),
    'Shirudo image app: version 1.1 on 2 hosts, version 1.0 on 1 host',
  );
  assert.equal(doc.specVersion, '1.6', 'the newest spec version of the parts');
  const purls = [];
  const refs = [];
  const walk = (list) =>
    list.forEach((item) => {
      purls.push(item.purl);
      refs.push(item['bom-ref']);
      walk(item.components ?? []);
    });
  walk(doc.components);
  assert.equal(new Set(refs).size, refs.length, 'references are unique');
  assert.ok(refs.every((ref) => /^v\d+:/.test(ref)));
  assert.equal(
    purls.filter((purl) => purl === 'pkg:npm/shared@1.0.0').length,
    1,
    'the same purl is kept once',
  );
  assert.deepEqual(purls.sort(), [
    'pkg:npm/nested-new@2.0.0',
    'pkg:npm/only-new@1.0.0',
    'pkg:npm/only-old@1.0.0',
    'pkg:npm/shared@1.0.0',
    'pkg:npm/web@0.9.0',
    'pkg:npm/web@1.0.0',
  ]);
  // Edges: kept where both ends survive; one to a dropped duplicate points at the kept one.
  const all = new Map();
  const index = (list) =>
    list.forEach(
      (item) => (all.set(item['bom-ref'], item.name + '@' + item.version), index(item.components ?? [])),
    );
  index(doc.components);
  const edges = Object.fromEntries(
    doc.dependencies.map((entry) => [all.get(entry.ref), entry.dependsOn.map((ref) => all.get(ref)).sort()]),
  );
  assert.deepEqual(edges['web@1.0.0'], ['nested-new@2.0.0', 'only-new@1.0.0', 'shared@1.0.0']);
  assert.deepEqual(edges['web@0.9.0'], ['only-old@1.0.0', 'shared@1.0.0']);
  assert.deepEqual(
    edges['shared@1.0.0'],
    ['only-old@1.0.0'],
    "the dropped duplicate's edges move to the one kept",
  );
  for (const entry of doc.dependencies) {
    assert.ok(all.has(entry.ref));
    for (const target of entry.dependsOn) assert.ok(all.has(target), `${target} exists`);
  }
  assert.ok(!('ghost' in edges));
  // The merged file imports cleanly.
  const imported = importSbom(join(ctx.output, 'app.cdx.json'));
  assert.deepEqual(imported.warnings, []);
  assert.equal(imported.components.length, 6);
});

test('the merged document carries the SBOM edges of the older version through a kept duplicate', () => {
  const merged = mergeCycloneDx([
    bom([component('a', '1.0.0', 'a'), component('b', '1.0.0', 'b')], [{ ref: 'a', dependsOn: ['b'] }]),
    bom([component('a', '1.0.0', 'a'), component('c', '1.0.0', 'c')], [{ ref: 'a', dependsOn: ['c'] }]),
  ]);
  const byRef = new Map(merged.components.map((item) => [item['bom-ref'], item.name]));
  assert.equal(merged.components.length, 3);
  assert.equal(merged.dependencies.length, 1);
  assert.deepEqual(
    merged.dependencies[0].dependsOn.map((ref) => byRef.get(ref)),
    ['b', 'c'],
  );
});

test('a package that is nested in one version and top-level in another is listed once', (t) => {
  const ctx = setup(t);
  put(
    ctx.store,
    'app',
    '2',
    bom([component('host', '1.0.0', 'host', { components: [component('lib', '1.0.0', 'lib')] })]),
  );
  put(ctx.store, 'app', '1', bom([component('host', '1.0.0', 'host'), component('lib', '1.0.0', 'lib')]));
  const running = exportFile(ctx.dir, [row('app', '1', 'n1'), row('app', '2', 'n2')]);
  const plan = sync(ctx, { exposure: running, apply: true });
  assert.deepEqual(plan.problems, []);
  const imported = importSbom(join(ctx.output, 'app.cdx.json'));
  assert.equal(imported.components.length, 2, JSON.stringify(imported.components.map((item) => item.name)));
});

// Properties and timestamps.

test('the system ID is the image ID and Security Watch properties come first, replacing the source ones', (t) => {
  const ctx = setup(t);
  put(
    ctx.store,
    'fleet-os',
    '1',
    bom([component('a', '1.0.0')], undefined, {
      metadata: {
        timestamp: '2026-01-01T00:00:00Z',
        properties: [
          { name: 'security-watch:system-id', value: 'someone-else' },
          { name: 'security-watch:written-by', value: 'forged' },
          { name: 'security-watch:owner', value: 'old-owner' },
          { name: 'vendor:keep', value: 'yes' },
        ],
      },
    }),
  );
  sync(ctx, { apply: true });
  const doc = read(ctx, 'fleet-os.cdx.json');
  assert.deepEqual(
    doc.metadata.properties.map((item) => item.name),
    ['security-watch:system-id', 'security-watch:note', 'security-watch:written-by', 'vendor:keep'],
  );
  assert.equal(property(doc, 'security-watch:system-id'), 'fleet-os');
  assert.equal(property(doc, 'security-watch:written-by'), 'shirudo-sboms');
});

// Problems.

test('problems: running version missing in the store, running image not in the store', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '1', bom([component('a', '1.0.0')]));
  put(ctx.store, 'other', '1', bom([component('b', '1.0.0')]));
  const running = exportFile(ctx.dir, [
    row('app', '1', 'n1'),
    row('app', '2', 'n2'),
    row('other', '9', 'n1'),
    row('nowhere', '1', 'n1'),
  ]);
  const plan = sync(ctx, { exposure: running });
  assert.deepEqual(
    plan.images.map((item) => item.image_id),
    ['app'],
  );
  assert.ok(plan.problems.includes('app 2: runs on 1 host but has no SBOM in the store.'));
  assert.ok(plan.problems.includes('other 9: runs on 1 host but has no SBOM in the store.'));
  assert.ok(plan.problems.includes('nowhere: runs on machines but is not in the store.'));
  assert.equal(plan.problems.length, 3);
});

test('several roots: the most recently stored one is used, and it is said', (t) => {
  const ctx = setup(t);
  const older = put(ctx.store, 'app', '1', bom([component('older', '1.0.0')]), 'b'.repeat(64));
  const newer = put(ctx.store, 'app', '1', bom([component('newer', '1.0.0')]), ROOT);
  utimesSync(older, new Date(now), new Date(now));
  utimesSync(newer, new Date(now - 86400_000), new Date(now - 86400_000));
  // The root that sorts first is the older one here; mtime decides, not the name.
  let plan = sync(ctx, { apply: true });
  assert.equal(plan.problems.length, 1);
  assert.match(plan.problems[0], /app 1: 2 builds in the store; the most recently stored one is used/);
  assert.deepEqual(names(read(ctx, 'app.cdx.json')), ['older']);
  utimesSync(older, new Date(now - 2 * 86400_000), new Date(now - 2 * 86400_000));
  plan = sync(ctx, { apply: true });
  assert.deepEqual(names(read(ctx, 'app.cdx.json')), ['newer']);
  assert.equal(plan.images[0].action, 'write');
});

test('roots that are not 64 hex characters or "-" are ignored', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '1', bom([component('bad', '1.0.0')]), 'ABCDEF');
  put(ctx.store, 'app', '1', bom([component('bad', '1.0.0')]), 'a'.repeat(63));
  const plan = sync(ctx);
  assert.deepEqual(plan.images, []);
  assert.match(plan.problems.join('\n'), /no readable sbom\.cdx\.json/);
});

test('a missing, oversized, non-CycloneDX or CycloneDX 2.0 SBOM leaves its image out', (t) => {
  const ctx = setup(t);
  mkdirSync(join(ctx.store, 'missing', '1', '-'), { recursive: true });
  const big = put(ctx.store, 'big', '1', '');
  writeFileSync(big, Buffer.alloc(20 * 1024 * 1024 + 1, 0x20));
  put(ctx.store, 'spdx', '1', { spdxVersion: 'SPDX-2.3', packages: [] });
  put(ctx.store, 'v2', '1', bom([component('a', '1.0.0')], undefined, { specVersion: '2.0' }));
  put(ctx.store, 'old', '1', bom([component('a', '1.0.0')], undefined, { specVersion: '1.1' }));
  put(ctx.store, 'broken', '1', '{ not json');
  put(ctx.store, 'ok', '1', bom([component('a', '1.0.0')]));
  const plan = sync(ctx, { apply: true });
  assert.deepEqual(
    plan.images.map((item) => item.image_id),
    ['ok'],
  );
  const text = plan.problems.join('\n');
  assert.match(text, /missing 1: no readable sbom\.cdx\.json of at most 20 MiB/);
  assert.match(text, /big 1: no readable sbom\.cdx\.json of at most 20 MiB/);
  assert.match(text, /spdx 1: the SBOM cannot be read/);
  assert.match(text, /v2 1: the SBOM cannot be read/);
  assert.match(text, /old 1: the SBOM cannot be read/);
  assert.match(text, /broken 1: the SBOM cannot be read/);
  assert.deepEqual(readdirSync(ctx.output), ['ok.cdx.json']);
});

test('a version whose SBOM cannot be read is left out of the merge and said', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '2', bom([component('a', '1.0.0')]));
  put(ctx.store, 'app', '1', '{ nope');
  const plan = sync(ctx, {
    exposure: exportFile(ctx.dir, [row('app', '1', 'n'), row('app', '2', 'n')]),
    apply: true,
  });
  assert.deepEqual(plan.images[0].versions, [{ version: '2', hosts: 1 }]);
  assert.equal(plan.problems.length, 1);
  assert.match(plan.problems[0], /^app 1: the SBOM cannot be read/);
  assert.match(
    property(read(ctx, 'app.cdx.json'), 'security-watch:note'),
    /^Shirudo image app: version 2 on 1 host$/,
  );
});

test('export rows without image_version or node_id, bad names and an empty export are reported', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '1', bom([component('a', '1.0.0')]));
  const running = exportFile(ctx.dir, [
    row('app', '1', 'n1'),
    { image_id: 'app', node_id: 'n2' },
    { image_id: 'app', image_version: '1' },
    { image_id: '..', image_version: '1', node_id: 'n' },
    { image_id: '.hidden', image_version: '1', node_id: 'n' },
    { image_id: 'a/b', image_version: '1', node_id: 'n' },
    { image_id: 'app', image_version: '../1', node_id: 'n' },
    'not json',
    '[1,2]',
    'null',
  ]);
  const plan = sync(ctx, { exposure: running });
  assert.deepEqual(
    plan.images.map((item) => [item.image_id, item.versions]),
    [['app', [{ version: '1', hosts: 1 }]]],
  );
  assert.deepEqual(plan.problems, [
    '9 export row(s) without a usable image_id, image_version and node_id were left out; nothing is removed while the export is incomplete.',
  ]);
  const empty = join(ctx.dir, 'empty.jsonl');
  writeFileSync(empty, '\n \n');
  const none = sync(ctx, { exposure: empty });
  assert.deepEqual(none.images, []);
  assert.match(none.problems[0], /The export is empty/);
});

test('an unreadable export or an export that is not a file stops the command', (t) => {
  const ctx = setup(t);
  assert.throws(() => sync(ctx, { exposure: join(ctx.dir, 'nope.jsonl') }), /ENOENT/);
  assert.throws(() => sync(ctx, { exposure: ctx.dir }), /not a regular file/);
  assert.throws(() => sync({ ...ctx, store: join(ctx.dir, 'nope') }), /ENOENT/);
  assert.throws(() => sync({ ...ctx, output: exportFile(ctx.dir, []) }), /not a directory/);
});

// Links and odd names.

test('links are not followed: image directory, version directory and SBOM file', (t) => {
  const ctx = setup(t);
  const outside = join(ctx.dir, 'outside');
  put(outside, 'x', '1', bom([component('secret', '1.0.0')]));
  symlinkSync(join(outside, 'x'), join(ctx.store, 'linked-image'));
  put(ctx.store, 'linked-version', '0', bom([component('a', '1.0.0')]));
  symlinkSync(join(outside, 'x', '1'), join(ctx.store, 'linked-version', '1'));
  const real = put(ctx.store, 'linked-file', '1', bom([component('a', '1.0.0')]));
  const target = join(outside, 'sbom.cdx.json');
  writeFileSync(target, JSON.stringify(bom([component('secret', '1.0.0')])));
  rmSync(real);
  symlinkSync(target, real);
  put(ctx.store, 'ok', '1', bom([component('a', '1.0.0')]));
  const plan = sync(ctx, {
    exposure: exportFile(ctx.dir, [
      row('linked-image', '1', 'n'),
      row('linked-version', '1', 'n'),
      row('linked-file', '1', 'n'),
      row('ok', '1', 'n'),
    ]),
    apply: true,
  });
  assert.deepEqual(
    plan.images.map((item) => item.image_id),
    ['ok'],
  );
  assert.deepEqual(readdirSync(ctx.output), ['ok.cdx.json']);
  const text = plan.problems.join('\n');
  assert.match(text, /linked-image: not a directory \(or a link\) in the store/);
  assert.match(text, /linked-version 1: runs on 1 host but has no SBOM in the store/);
  assert.match(text, /linked-file 1: no readable sbom\.cdx\.json/);
});

test('a link in the newest-version selection is not taken either', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '1', bom([component('good', '1.0.0')]));
  put(ctx.store, 'elsewhere', '9', bom([component('secret', '1.0.0')]));
  symlinkSync(join(ctx.store, 'elsewhere', '9'), join(ctx.store, 'app', '9'));
  sync(ctx, { apply: true });
  assert.deepEqual(names(read(ctx, 'app.cdx.json')), ['good']);
});

test('names that are dots, hidden or contain a slash are never followed', (t) => {
  const ctx = setup(t);
  put(ctx.store, '.hidden', '1', bom([component('a', '1.0.0')]));
  put(ctx.store, 'app', '.hidden', bom([component('hidden', '1.0.0')]));
  put(ctx.store, 'app', '1', bom([component('a', '1.0.0')]));
  const plan = sync(ctx, { apply: true });
  assert.deepEqual(
    plan.images.map((item) => [item.image_id, item.versions]),
    [['app', [{ version: '1' }]]],
  );
  assert.deepEqual(plan.problems, []);
  const running = exportFile(ctx.dir, [
    row('..', '1', 'n'),
    row('app', '..', 'n'),
    row('a/b', '1', 'n'),
    row('app', '.hidden', 'n'),
  ]);
  const again = sync(ctx, { exposure: running });
  assert.deepEqual(again.images, []);
  assert.deepEqual(again.remove, [], 'an export of nothing but unusable rows removes nothing');
  assert.ok(!again.problems.join('\n').includes('hidden'));
});

// The output folder.

test('a file not written by the command is never replaced or removed', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '1', bom([component('a', '1.0.0')]));
  const mine = join(ctx.output, 'app.cdx.json');
  writeFileSync(mine, JSON.stringify(bom([component('handmade', '1.0.0')])));
  writeFileSync(join(ctx.output, 'other.json'), '{"x":1}');
  writeFileSync(
    join(ctx.output, 'forged.json'),
    JSON.stringify(
      bom([], undefined, {
        metadata: { properties: [{ name: 'security-watch:written-by', value: 'someone' }] },
      }),
    ),
  );
  const before = readFileSync(mine, 'utf8');
  const plan = sync(ctx, { apply: true });
  assert.deepEqual(plan.images, []);
  assert.deepEqual(plan.remove, []);
  assert.deepEqual(plan.problems, [
    'app: the system ID is already used by app.cdx.json; this image is not written. Rename that system, or watch the image under another ID.',
  ]);
  assert.equal(readFileSync(mine, 'utf8'), before);
  assert.deepEqual(readdirSync(ctx.output).sort(), ['app.cdx.json', 'forged.json', 'other.json']);
});

test('a file written earlier for an image that is no longer selected is removed only with apply', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'a', '1', bom([component('x', '1.0.0')]));
  put(ctx.store, 'b', '1', bom([component('y', '1.0.0')]));
  sync(ctx, { apply: true });
  writeFileSync(join(ctx.output, 'pipeline.cdx.json'), JSON.stringify(bom([component('z', '1.0.0')])));
  const running = exportFile(ctx.dir, [row('a', '1', 'n')]);
  const dry = sync(ctx, { exposure: running });
  assert.deepEqual(dry.remove, ['b.cdx.json']);
  assert.ok(existsSync(join(ctx.output, 'b.cdx.json')));
  const applied = sync(ctx, { exposure: running, apply: true });
  assert.deepEqual(applied.remove, ['b.cdx.json']);
  assert.deepEqual(readdirSync(ctx.output).sort(), ['a.cdx.json', 'pipeline.cdx.json']);
});

test('an image whose newest SBOM cannot be read keeps its earlier file', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'a', '1', bom([component('x', '1.0.0')]));
  sync(ctx, { apply: true });
  const before = read(ctx, 'a.cdx.json');
  put(ctx.store, 'a', '2', '{ broken');
  const plan = sync(ctx, { apply: true });
  // A failed read is not "no longer selected": the system must not drop out of the inventory.
  assert.deepEqual(plan.remove, []);
  assert.deepEqual(plan.images, []);
  assert.match(plan.problems.join('\n'), /a 2: the SBOM cannot be read/);
  assert.deepEqual(read(ctx, 'a.cdx.json'), before);
});

test('unchanged content is reported unchanged and not rewritten, even if only the observed time differs', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '1', bom([component('a', '1.0.0')]));
  const running = exportFile(ctx.dir, [row('app', '1', 'n1')]);
  sync(ctx, { exposure: running, apply: true, now });
  const target = join(ctx.output, 'app.cdx.json');
  const old = new Date(now - 5 * 86400_000);
  utimesSync(target, old, old);
  const before = statSync(target).mtimeMs;
  const later = sync(ctx, { exposure: running, apply: true, now: now + 3600_000 });
  assert.equal(later.images[0].action, 'unchanged');
  assert.equal(statSync(target).mtimeMs, before);
  assert.equal(read(ctx, 'app.cdx.json').metadata.timestamp, new Date(now).toISOString());
  // A real change is written.
  const hosts = exportFile(ctx.dir, [row('app', '1', 'n1'), row('app', '1', 'n2')]);
  const changed = sync(ctx, { exposure: hosts, apply: true, now: now + 7200_000 });
  assert.equal(changed.images[0].action, 'write');
  assert.equal(read(ctx, 'app.cdx.json').metadata.timestamp, new Date(now + 7200_000).toISOString());
  assert.notEqual(statSync(target).mtimeMs, before);
});

test('apply writes files with mode 0600 and leaves no temporary files', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'a', '1', bom([component('x', '1.0.0')]));
  put(ctx.store, 'b', '1', bom([component('y', '1.0.0')]));
  sync(ctx, { apply: true });
  assert.deepEqual(readdirSync(ctx.output).sort(), ['a.cdx.json', 'b.cdx.json']);
  for (const file of readdirSync(ctx.output))
    assert.equal(statSync(join(ctx.output, file)).mode & 0o777, 0o600);
  assert.ok(!readdirSync(ctx.output).some((name) => name.endsWith('.tmp')));
});

test('two image IDs that differ only in letter case do not share a file name', (t) => {
  const ctx = setup(t);
  mkdirSync(join(ctx.store, 'Fleet-OS'));
  mkdirSync(join(ctx.store, 'fleet-os'), { recursive: true });
  if (readdirSync(ctx.store).length < 2) {
    // A case-insensitive file system holds one of them; the store cannot hold both there.
    assert.equal(sync(ctx).images.length, 0);
    return;
  }
  put(ctx.store, 'Fleet-OS', '1', bom([component('x', '1.0.0')]));
  put(ctx.store, 'fleet-os', '1', bom([component('y', '1.0.0')]));
  const plan = sync(ctx, { apply: true });
  assert.equal(plan.images.length, 1);
  assert.match(
    plan.problems.join('\n'),
    /fleet-os: its file name differs from Fleet-OS's only in letter case; left out/,
  );
  assert.equal(readdirSync(ctx.output).length, 1);
});

test('on a case-insensitive output a file differing only in case is not overwritten when not ours', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'App', '1', bom([component('x', '1.0.0')]));
  writeFileSync(join(ctx.output, 'app.cdx.json'), '{}');
  const plan = sync(ctx, { apply: true });
  // Either the file systems tells them apart (a new file is written) or it does not (the foreign file is protected).
  const folded = readdirSync(ctx.output);
  if (folded.length === 1) {
    assert.equal(readFileSync(join(ctx.output, folded[0]), 'utf8'), '{}');
    assert.equal(plan.images.length, 0);
  } else assert.equal(plan.images.length, 1);
});

test('the SBOM folder limit of 1,000 files refuses the whole sync and writes nothing', (t) => {
  const ctx = setup(t);
  for (let index = 0; index < 999; index++) writeFileSync(join(ctx.output, `dummy-${index}.json`), '{}');
  put(ctx.store, 'a', '1', bom([component('x', '1.0.0')]));
  put(ctx.store, 'b', '1', bom([component('y', '1.0.0')]));
  assert.throws(() => sync(ctx, { apply: true }), /more than 1,000 SBOM files/);
  assert.equal(readdirSync(ctx.output).length, 999);
  rmSync(join(ctx.store, 'b'), { recursive: true });
  sync(ctx, { apply: true });
  assert.equal(readdirSync(ctx.output).length, 1000);
});

test('the limit counts removals: replacing one of ours at the limit is allowed', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'a', '1', bom([component('x', '1.0.0')]));
  sync(ctx, { apply: true });
  for (let index = 0; index < 999; index++) writeFileSync(join(ctx.output, `dummy-${index}.json`), '{}');
  rmSync(join(ctx.store, 'a'), { recursive: true });
  put(ctx.store, 'c', '1', bom([component('x', '1.0.0')]));
  const plan = sync(ctx, { apply: true });
  assert.deepEqual(plan.remove, ['a.cdx.json']);
  assert.equal(readdirSync(ctx.output).length, 1000);
});

// The inventory reads what was written.

test('the written folder loads as an inventory: system IDs are the image IDs and packages are there', (t) => {
  const ctx = setup(t);
  put(
    ctx.store,
    'fleet-os',
    '2',
    bom([component('web', '1.0.0'), component('shared', '1.0.0')], [{ ref: 'web', dependsOn: ['shared'] }]),
  );
  put(ctx.store, 'fleet-os', '1', bom([component('shared', '1.0.0'), component('legacy', '3.0.0')]));
  put(ctx.store, 'edge', '5', bom([component('agent', '2.0.0')], undefined, { specVersion: '1.9' }));
  const running = exportFile(ctx.dir, [
    row('fleet-os', '1', 'n1'),
    row('fleet-os', '2', 'n2'),
    row('edge', '5', 'n3'),
  ]);
  const plan = sync(ctx, { exposure: running, apply: true });
  assert.deepEqual(plan.problems, []);
  writeFileSync(join(ctx.dir, 'systems.yaml'), 'sbom_directory: ./sboms\n');
  const inventory = loadInventory(join(ctx.dir, 'systems.yaml'));
  assert.deepEqual(inventory.systems.map((system) => system.id).sort(), ['edge', 'fleet-os']);
  assert.equal(inventory.import_warnings, undefined);
  const fleet = inventory.systems.find((system) => system.id === 'fleet-os');
  assert.deepEqual(fleet.components.map((item) => item.name).sort(), ['legacy', 'shared', 'web']);
  assert.match(fleet.note, /Shirudo image fleet-os: version 2 on 1 host, version 1 on 1 host/);
  assert.equal(fleet.updated_at, new Date(now).toISOString());
  assert.deepEqual(
    inventory.systems.find((system) => system.id === 'edge').components.map((item) => item.name),
    ['agent'],
  );
  // The newer spec version of a source is carried as a notice, not a warning.
  assert.match(inventory.name_notices?.join('\n') ?? '', /edge: CycloneDX 1\.9 is newer/);
});

// The command line.

test('the command prints the plan as JSON; exit code 2 with problems, 0 without; hint without apply', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '1', bom([component('a', '1.0.0')]));
  const run = (...args) =>
    spawnSync(
      process.execPath,
      [cli, 'shirudo-sboms', '--store', ctx.store, '--directory', ctx.output, ...args],
      { cwd: ctx.dir, encoding: 'utf8', timeout: 30_000 },
    );
  const dry = run();
  assert.equal(dry.status, 0, dry.stderr);
  const plan = JSON.parse(dry.stdout);
  assert.equal(plan.applied, false);
  assert.equal(plan.selection, 'newest');
  assert.deepEqual(
    plan.images.map((item) => [item.image_id, item.action]),
    [['app', 'write']],
  );
  assert.match(dry.stderr, /Nothing was written\. Run again with --apply to write this plan\./);
  assert.deepEqual(readdirSync(ctx.output), []);
  const applied = run('--apply');
  assert.equal(applied.status, 0, applied.stderr);
  assert.equal(JSON.parse(applied.stdout).applied, true);
  assert.ok(!applied.stderr.includes('Run again with --apply'));
  assert.deepEqual(readdirSync(ctx.output), ['app.cdx.json']);
  const again = run();
  assert.equal(again.status, 0);
  assert.ok(!again.stderr.includes('Run again with --apply'), 'nothing to write, no hint');
  // With problems: exit code 2, and the plan is still printed.
  const running = exportFile(ctx.dir, [row('app', '1', 'n1'), row('ghost', '1', 'n1')]);
  const problem = run('--running', running);
  assert.equal(problem.status, 2, problem.stderr);
  const withProblems = JSON.parse(problem.stdout);
  assert.equal(withProblems.selection, 'running');
  assert.deepEqual(withProblems.problems, ['ghost: runs on machines but is not in the store.']);
  const missing = spawnSync(process.execPath, [cli, 'shirudo-sboms', '--store', ctx.store], {
    cwd: ctx.dir,
    encoding: 'utf8',
  });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /--store DIR and --directory SBOM_DIR required/);
});

test('a duplicate that has components of its own passes them on to the merged document', () => {
  const merged = mergeCycloneDx([
    bom([component('host', '1.0.0', 'host')]),
    bom([component('host', '1.0.0', 'host', { components: [component('inner', '1.0.0', 'inner')] })]),
  ]);
  const flat = [];
  const walk = (list) => list.forEach((item) => (flat.push(item.name), walk(item.components ?? [])));
  walk(merged.components);
  assert.deepEqual(flat.sort(), ['host', 'inner']);
});
