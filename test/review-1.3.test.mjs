// Defects from the independent 1.3.0 review (D1–D12), and the upgrade from a real 1.2.1 database.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { syncShirudoSboms } from '../dist/shirudo-sboms.js';
import { currentStatus } from '../dist/mitigations.js';
import { safeHttpsUrl } from '../dist/shield-inputs.js';
import { shieldCandidates } from '../dist/shield-candidates.js';
import { deliverPending, notificationText } from '../dist/delivery.js';
import { parseConfig } from '../dist/config.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';
import { loadInventory } from '../dist/inventory.js';
import * as duplicates from './fixtures/duplicates-1.4.0.mjs';
import { hash } from '../dist/util.js';

const hashOf = (ref) => hash(ref).slice(0, 32);

const now = Date.parse('2026-11-24T12:00:00Z');
const iso = (time = now) => new Date(time).toISOString();
const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'sw-review-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const store = join(dir, 'store');
  const output = join(dir, 'sboms');
  mkdirSync(store);
  mkdirSync(output);
  return { dir, store, output };
}
const bom = (packages, extra = {}) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  components: packages.map((name) => ({
    type: 'library',
    name,
    version: '1.0.0',
    purl: `pkg:npm/${name}@1.0.0`,
    'bom-ref': name,
  })),
  ...extra,
});
function put(store, image, version, document) {
  const dir = join(store, image, version, '-');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'sbom.cdx.json'),
    typeof document === 'string' ? document : JSON.stringify(document),
  );
}
const exportOf = (ctx, rows) => {
  const path = join(ctx.dir, `running-${Math.random().toString(16).slice(2)}.jsonl`);
  writeFileSync(
    path,
    rows.map((row) => (typeof row === 'string' ? row : JSON.stringify(row))).join('\n') + '\n',
  );
  return path;
};
const row = (image, version, node) => ({ image_id: image, image_version: version, node_id: node });
const sync = (ctx, options = {}) =>
  syncShirudoSboms({ store: ctx.store, output: ctx.output, now, ...options });

// D1: a failed read never removes a watched system.

test('D1: an empty export, a version without an SBOM and an incomplete export remove nothing', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'fleet-os', '1.0', bom(['a']));
  put(ctx.store, 'api', '1.0', bom(['b']));
  sync(ctx, {
    exposure: exportOf(ctx, [row('fleet-os', '1.0', 'n1'), row('api', '1.0', 'n2')]),
    apply: true,
  });
  const files = () => readdirSync(ctx.output).sort();
  assert.deepEqual(files(), ['api.cdx.json', 'fleet-os.cdx.json']);

  const empty = sync(ctx, { exposure: exportOf(ctx, []), apply: true });
  assert.deepEqual(empty.remove, []);
  assert.match(
    empty.problems.join(' '),
    /The export is empty: no image is known to run\. Nothing is written or removed\./,
  );
  assert.deepEqual(files(), ['api.cdx.json', 'fleet-os.cdx.json']);

  // Every machine moved to 1.1 before its SBOM reached the store: the 1.0 list stays.
  const moved = sync(ctx, {
    exposure: exportOf(ctx, [row('fleet-os', '1.1', 'n1'), row('api', '1.0', 'n2')]),
    apply: true,
  });
  assert.deepEqual(moved.remove, []);
  assert.match(moved.problems.join(' '), /fleet-os 1\.1: runs on 1 host but has no SBOM in the store/);
  assert.deepEqual(files(), ['api.cdx.json', 'fleet-os.cdx.json']);

  // api is not in this export, but one row is unusable: the export may be cut short, so api stays.
  const partial = sync(ctx, {
    exposure: exportOf(ctx, [row('fleet-os', '1.0', 'n1'), 'not json']),
    apply: true,
  });
  assert.deepEqual(partial.remove, []);
  assert.match(
    partial.problems.join(' '),
    /1 file\(s\) for images no longer seen were kept, because the export is incomplete/,
  );
  assert.deepEqual(files(), ['api.cdx.json', 'fleet-os.cdx.json']);

  // A complete export without api: now it is gone.
  const complete = sync(ctx, { exposure: exportOf(ctx, [row('fleet-os', '1.0', 'n1')]), apply: true });
  assert.deepEqual(complete.remove, ['api.cdx.json']);
  assert.deepEqual(files(), ['fleet-os.cdx.json']);
});

test('D1: without an export a file is removed only when its image left the store', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'a', '1', bom(['x']));
  put(ctx.store, 'b', '1', bom(['y']));
  sync(ctx, { apply: true });
  rmSync(join(ctx.store, 'b'), { recursive: true });
  writeFileSync(join(ctx.store, 'a', '1', '-', 'sbom.cdx.json'), '{ broken');
  const plan = sync(ctx, { apply: true });
  assert.deepEqual(plan.remove, ['b.cdx.json']);
  assert.deepEqual(readdirSync(ctx.output), ['a.cdx.json'], 'the unreadable image keeps its list');
});

// D2: the written file is one the scan reads, and stays this command's.

test('D2: compact output within 20 MiB; a larger list is not written and the old one is kept', (t) => {
  const ctx = setup(t);
  const many = Array.from({ length: 19_000 }, (_, i) => `package-${i}`);
  put(ctx.store, 'big', '1', bom(many));
  sync(ctx, { apply: true });
  const written = join(ctx.output, 'big.cdx.json');
  assert.ok(statSync(written).size < 20 * 1024 * 1024);
  assert.ok(!readFileSync(written, 'utf8').includes('\n  '), 'not indented');
  const inventoryFile = join(ctx.dir, 'systems.yaml');
  writeFileSync(inventoryFile, 'sbom_directory: ./sboms\nsystems: []\n');
  const inventory = loadInventory(inventoryFile);
  assert.deepEqual(inventory.import_warnings ?? [], []);
  assert.equal(inventory.systems[0].components.length, 19_000);
  // The next run still knows the file as its own.
  assert.equal(sync(ctx, { apply: true }).images[0].action, 'unchanged');

  // Two versions that run side by side, each within the limit, merge into more than 20 MiB.
  const half = (tag) => Array.from({ length: 11_000 }, (_, i) => `${tag}${'p'.repeat(350)}-${i}`);
  put(ctx.store, 'big', '2', bom(half('a')));
  put(ctx.store, 'big', '3', bom(half('b')));
  const plan = sync(ctx, {
    exposure: exportOf(ctx, [row('big', '2', 'n1'), row('big', '3', 'n2')]),
    apply: true,
  });
  assert.match(
    plan.problems.join(' '),
    /big: the SBOM would be larger than 20 MiB, which a scan refuses; left as it was/,
  );
  assert.deepEqual(plan.remove, []);
  assert.equal(JSON.parse(readFileSync(written, 'utf8')).components.length, 19_000);
});

// D3: a saved status is judged when it is read.

test('D3: an old export, a removed source and an expired mitigation are out of date when read', () => {
  const status = {
    source: 'Shirudo',
    format: 'shirudo',
    exported_at: iso(now - 30 * 86_400_000),
    stale: false,
    hosts: 1,
    states: { mitigated: 1 },
    mitigations: ['g'],
    summary: 'Shirudo: mitigated on 1 of 1 host.',
  };
  assert.deepEqual(currentStatus(status, { Shirudo: 120 }, now), {
    ...status,
    stale: true,
    stale_reason: 'old_export',
  });
  assert.equal(currentStatus(status, {}, now).stale_reason, 'source_removed');
  const fresh = { ...status, exported_at: iso(now - 60_000) };
  assert.equal(currentStatus(fresh, { Shirudo: 120 }, now), fresh, 'a current status is returned as it is');
  assert.equal(
    currentStatus({ ...fresh, expires_at: iso(now - 1) }, { Shirudo: 120 }, now).stale_reason,
    'expired',
  );
  assert.equal(currentStatus(status, undefined, now).stale, false, 'without limits only expiry is judged');
});

test('D3: findings, explain and vex show a saved status as out of date once scans stopped', async (t) => {
  const ctx = setup(t);
  const inventory = {
    systems: [
      {
        id: 'web',
        name: 'Web',
        environment: 'production',
        exposure: 'internet',
        criticality: 'high',
        updated_at: iso(now - 30 * 86_400_000),
        components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
        products: [],
        keywords: [],
      },
    ],
  };
  writeFileSync(join(ctx.dir, 'systems.yaml'), JSON.stringify(inventory));
  const exportFile = join(ctx.dir, 'node-vulns.jsonl');
  writeFileSync(
    exportFile,
    JSON.stringify({
      node_id: 'n1',
      image_id: 'web',
      vuln_id: 'CVE-2026-20001',
      package: 'alpha',
      exposure: 'shielded',
      upatch_id: 'g',
    }) + '\n',
  );
  writeFileSync(
    join(ctx.dir, 'security-watch.yaml'),
    'version: 1\ninventory: ./systems.yaml\ndatabase: ./data/watch.db\nsources:\n  cve_now: false\n  hacker_news: false\nmitigations:\n  - format: shirudo\n    file: ./node-vulns.jsonl\n',
  );
  mkdirSync(join(ctx.dir, 'data'), { mode: 0o700 });
  // A scan 30 days ago, with a fresh export at the time.
  const then = now - 30 * 86_400_000;
  const { utimesSync } = await import('node:fs');
  utimesSync(exportFile, (then - 60_000) / 1000, (then - 60_000) / 1000);
  const store = new Store(join(ctx.dir, 'data', 'watch.db'));
  const config = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false },
    mitigations: [{ format: 'shirudo', file: exportFile }],
  });
  const advisory = {
    id: 'osv:GHSA-aaaa-bbbb-cccc',
    source: 'osv',
    kind: 'advisory',
    title: 'alpha',
    url: 'https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc',
    description: 'x',
    aliases: ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-20001'],
    severity: 'critical',
    modified_at: iso(then - 3_600_000),
    fetched_at: iso(then - 3_600_000),
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0', fixed: '2.0.0' }],
  };
  await runScan({ config, inventory, store, now: then, fixture: [advisory] });
  const saved = store.findings().find((item) => item.component_id === 'alpha');
  assert.equal(saved.mitigations[0].stale, false, 'current when the scan saved it');
  store.close();
  const run = (...args) =>
    spawnSync(process.execPath, [cli, ...args, '--config', join(ctx.dir, 'security-watch.yaml')], {
      encoding: 'utf8',
    });
  const findings = JSON.parse(run('findings').stdout).find((item) => item.id === saved.id);
  assert.equal(findings.mitigations[0].stale, true);
  assert.equal(findings.mitigations[0].stale_reason, 'old_export');
  const explained = JSON.parse(run('explain', saved.id).stdout);
  assert.equal(explained.finding.mitigations[0].stale, true);
  const vex = JSON.parse(run('vex').stdout);
  assert.equal(vex.statements[0].status, 'affected');
  assert.doesNotMatch(
    vex.statements[0].action_statement,
    /mitigation/i,
    'an out-of-date mitigation is not told outside',
  );
});

// D4, D6, D9, D10: the folder and the store.

test('D4: an image whose ID another SBOM or the inventory already uses is not written', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'fleet-os', '1', bom(['a']));
  writeFileSync(
    join(ctx.output, 'prod.json'),
    JSON.stringify(
      bom(['z'], { metadata: { properties: [{ name: 'security-watch:system-id', value: 'fleet-os' }] } }),
    ),
  );
  const plan = sync(ctx, { apply: true });
  assert.deepEqual(plan.images, []);
  assert.match(
    plan.problems[0],
    /^fleet-os: the system ID is already used by prod\.json; this image is not written/,
  );
  assert.deepEqual(readdirSync(ctx.output), ['prod.json']);
  rmSync(join(ctx.output, 'prod.json'));
  const reserved = sync(ctx, { reserved: ['fleet-os'] });
  assert.match(reserved.problems[0], /^fleet-os: the system ID is already used by the inventory/);
  // Through the command, with the configuration naming a hand-written system.
  writeFileSync(
    join(ctx.dir, 'systems.yaml'),
    'sbom_directory: ./sboms\nsystems:\n  - id: fleet-os\n    name: Fleet\n',
  );
  writeFileSync(join(ctx.dir, 'security-watch.yaml'), 'version: 1\ninventory: ./systems.yaml\n');
  const result = spawnSync(
    process.execPath,
    [
      cli,
      'shirudo-sboms',
      '--store',
      ctx.store,
      '--directory',
      ctx.output,
      '--config',
      join(ctx.dir, 'security-watch.yaml'),
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 2);
  assert.match(JSON.parse(result.stdout).problems[0], /already used by the inventory/);
});

test('D6: rows of machines bound to no image are not problems', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '1', bom(['a']));
  const plan = sync(ctx, {
    exposure: exportOf(ctx, [
      row('app', '1', 'n1'),
      { image_id: '', image_version: '', node_id: 'n2' },
      { image_id: null, node_id: 'n3' },
    ]),
  });
  assert.deepEqual(plan.problems, []);
  assert.equal(plan.images.length, 1);
});

test('D9 D10: an over-long image ID is reported; the folder and the store must be apart', (t) => {
  const ctx = setup(t);
  const long = 'x'.repeat(250);
  put(ctx.store, long, '1', bom(['a']));
  put(ctx.store, 'app', '1', bom(['b']));
  const plan = sync(ctx, { apply: true });
  assert.match(plan.problems.join(' '), /the image ID is too long for a file name/);
  assert.deepEqual(readdirSync(ctx.output), ['app.cdx.json']);
  assert.ok(!readdirSync(ctx.output).some((name) => name.endsWith('.tmp')));
  assert.throws(
    () => syncShirudoSboms({ store: ctx.store, output: ctx.store, now }),
    /must be separate folders/,
  );
  mkdirSync(join(ctx.store, 'out'));
  assert.throws(
    () => syncShirudoSboms({ store: ctx.store, output: join(ctx.store, 'out'), now }),
    /must be separate folders/,
  );
  assert.throws(
    () => syncShirudoSboms({ store: ctx.store, output: ctx.dir, now }),
    /must be separate folders/,
  );
});

// D11, D12.

test('D11: a fix link names a package by a whole path segment; a single claim must be this package', () => {
  const advisory = (packages, url) => ({
    id: 'osv:GHSA-aaaa-bbbb-cccc',
    source: 'osv',
    kind: 'advisory',
    title: 't',
    url: 'https://osv.dev/x',
    description: 'x',
    aliases: ['GHSA-aaaa-bbbb-cccc'],
    severity: 'critical',
    modified_at: iso(),
    fetched_at: iso(),
    packages,
    references: [{ type: 'fix', url }],
  });
  const inventory = {
    systems: [
      {
        id: 'web',
        name: 'web',
        environment: 'production',
        exposure: 'internet',
        criticality: 'high',
        updated_at: iso(),
        components: [{ id: 'core', ecosystem: 'npm', name: 'core', version: '1.0.0' }],
        products: [],
        keywords: [],
      },
    ],
  };
  const readiness = (evidence) =>
    shieldCandidates({
      findings: [
        {
          id: 'f',
          event_id: 'GHSA-aaaa-bbbb-cccc',
          system_id: 'web',
          component_id: 'core',
          category: 'library',
          applicability: 'affected',
          source_severity: 'critical',
          priority: 'critical',
          title: 't',
          summary: 's',
          reasons: [],
          evidence_ids: ['x'],
          urls: [],
          exploited: false,
          fix: '2.0.0',
          updated_at: iso(),
        },
      ],
      evidence: () => [evidence],
      inventory,
      now,
    }).candidates[0].readiness;
  const two = [
    { ecosystem: 'npm', name: 'core', fixed: '2.0.0' },
    { ecosystem: 'npm', name: 'other', fixed: '2.0.0' },
  ];
  assert.equal(
    readiness(advisory(two, 'https://github.com/x/other-core-utils/commit/abcdef1')),
    'fixed_version_known',
  );
  assert.equal(readiness(advisory(two, 'https://github.com/x/core/commit/abcdef1')), 'fix_known');
  assert.equal(readiness(advisory(two, 'https://github.com/x/core.git/commit/abcdef1')), 'fix_known');
  assert.equal(
    readiness(advisory([{ ecosystem: 'npm', name: 'other' }], 'https://github.com/x/other/commit/abcdef1')),
    'fixed_version_known',
    'a single claim of another package is not this package’s fix',
  );
});

test('D12: names that resolve to an address; an alert line says when a mitigation expires', () => {
  for (const host of ['localhost.localdomain', '10.0.0.1.nip.io', 'app.10-0-0-1.sslip.io', 'x.lvh.me'])
    assert.equal(safeHttpsUrl(`https://${host}/a`), undefined, host);
  assert.equal(safeHttpsUrl('https://cve-2026-1234.example.org/a'), 'https://cve-2026-1234.example.org/a');
  const job = {
    id: 'j',
    finding_id: 'f',
    channel: 'slack',
    status: 'pending',
    attempts: 0,
    available_at: now,
    payload: JSON.stringify({
      reason: 'r',
      assessment: {
        id: 'f',
        event_id: 'CVE-1',
        system_id: 'web',
        category: 'library',
        applicability: 'affected',
        source_severity: 'critical',
        priority: 'critical',
        title: 't',
        summary: 's',
        reasons: [],
        evidence_ids: [],
        urls: [],
        exploited: false,
        updated_at: iso(),
        mitigations: [
          {
            source: 'WAF',
            format: 'generic',
            exported_at: iso(),
            stale: false,
            hosts: 1,
            states: { mitigated: 1 },
            mitigations: ['rule'],
            expires_at: '2026-12-01T00:00:00.000Z',
            summary: 'WAF: mitigated on 1 of 1 host.',
          },
        ],
      },
    }),
  };
  assert.match(
    notificationText(job).text,
    /WAF: mitigated on 1 of 1 host\. \(export .* UTC; expires 2026-12-01 00:00 UTC; a mitigation is temporary/,
  );
});

// UPG-01: a database written by the released 1.2.1 build.

test('UPG-01: upgrading a real 1.2.1 database changes no revision, fingerprint, delivery or analysis basis', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sw-upgrade-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const db = join(dir, 'watch.db');
  copyFileSync(fileURLToPath(new URL('./fixtures/watch-1.2.1.db', import.meta.url)), db);
  const { chmodSync } = await import('node:fs');
  chmodSync(db, 0o600);
  const snapshot = () => {
    const d = new DatabaseSync(db, { readOnly: true });
    const q = (sql) => d.prepare(sql).all();
    const out = {
      finding_revisions: q('select finding_id,revision from finding_revisions order by 1,2'),
      findings: q('select id,fingerprint,revision from findings order by 1'),
      evidence_revisions: q('select source,id,content_hash from evidence_revisions order by 1,2,3'),
      notifications: q('select finding_id,revision,channel,status from notifications order by 1,2,3'),
      basis: q("select key,value from metadata where key like 'assessment-basis:%' order by 1"),
    };
    d.close();
    return out;
  };
  const before = snapshot();
  assert.ok(before.findings.length >= 2, 'the fixture holds findings');
  const t0 = Date.parse('2026-11-20T12:00:00Z');
  const http = async (url, request) => {
    if (url.endsWith('/querybatch'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          results: JSON.parse(request.body).queries.map((q) => ({
            vulns:
              q.package.name === 'alpha'
                ? [{ id: 'GHSA-aaaa-bbbb-cccc', modified: iso(t0) }]
                : q.package.name === 'beta'
                  ? [{ id: 'PYSEC-2026-9', modified: iso(t0) }]
                  : [],
          })),
        }),
      };
    // The same records 1.2.1 saw, now read with their links, fix commits and weaknesses kept.
    const record = (id, ecosystem, name, severity) => ({
      id,
      aliases: ['CVE-2026-20001'],
      summary: `Problem in ${name}`,
      details: `${name} deserializes untrusted input.`,
      modified: iso(t0),
      database_specific: { severity, cwe_ids: ['CWE-502'] },
      references: [{ type: 'WEB', url: `https://github.com/example/${name}/commit/abcdef1234` }],
      affected: [
        {
          package: { ecosystem, name },
          ranges: [
            {
              type: ecosystem === 'npm' ? 'SEMVER' : 'ECOSYSTEM',
              events: [{ introduced: '0' }, { fixed: '2.0.0' }],
            },
            {
              type: 'GIT',
              repo: `https://github.com/example/${name}`,
              events: [{ introduced: '0' }, { fixed: 'abcdef1234abcdef1234abcdef1234abcdef1234' }],
            },
          ],
        },
      ],
    });
    if (url.endsWith('/vulns/GHSA-aaaa-bbbb-cccc'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify(record('GHSA-aaaa-bbbb-cccc', 'npm', 'alpha', 'CRITICAL')),
      };
    if (url.endsWith('/vulns/PYSEC-2026-9'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify(record('PYSEC-2026-9', 'PyPI', 'beta', 'HIGH')),
      };
    return { status: 404, headers: {}, body: '' };
  };
  const inventory = (time) => ({
    systems: [
      {
        id: 'web',
        name: 'Web',
        environment: 'production',
        exposure: 'internet',
        criticality: 'high',
        updated_at: iso(time),
        components: [
          { id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' },
          { id: 'beta', ecosystem: 'PyPI', name: 'beta', version: '1.0.0' },
        ],
        products: [],
        keywords: [],
      },
    ],
  });
  const config = parseConfig({
    version: 1,
    poll_interval_minutes: 1440,
    sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false },
    policy: { library: { levels: ['critical', 'high'], basis: 'source_severity', channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'X_UNUSED' } },
  });
  for (const time of [t0 + 7_200_000, t0 + 10_800_000]) {
    const store = new Store(db);
    await runScan({ config, inventory: inventory(time), store, http, now: time });
    const saved = store.evidence().filter((item) => item.source === 'osv');
    assert.ok(
      saved.every((item) => item.fix_commits?.length && item.weaknesses?.includes('CWE-502')),
      'the new fields are read',
    );
    store.close();
    assert.deepEqual(snapshot(), before);
  }
  assert.ok(existsSync(db));
});

// UPG-02: a database written by the released 1.4.0 build, which made one finding and one alert for
// each listing of a package (see test/fixtures/duplicates-1.4.0.mjs).

test('UPG-02: folding a package listed three times re-sends nothing and keeps the finding already sent', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sw-upgrade-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const db = join(dir, 'watch.db');
  copyFileSync(fileURLToPath(new URL('./fixtures/watch-1.4.0-duplicates.db', import.meta.url)), db);
  const { chmodSync } = await import('node:fs');
  chmodSync(db, 0o600);
  const read = () => {
    const d = new DatabaseSync(db, { readOnly: true });
    const q = (sql) => d.prepare(sql).all();
    const out = {
      findings: Object.fromEntries(
        q('select id,payload,fingerprint,revision from findings order by 1').map((row) => [
          row.id,
          { ...row, payload: JSON.parse(row.payload) },
        ]),
      ),
      finding_revisions: q('select finding_id,revision from finding_revisions order by 1,2'),
      notifications: q('select finding_id,revision,channel,status from notifications order by 1,2,3'),
    };
    d.close();
    return out;
  };
  const before = read();
  const alpha = Object.values(before.findings).filter(
    (finding) => finding.payload.component_id && finding.payload.component_id !== 'beta',
  );
  // 1.4.0: the declared alpha, two SBOM listings of alpha 1.0.0 and alpha 1.5.0, each alerted.
  assert.equal(alpha.length, 4);
  assert.ok(before.notifications.every((row) => row.status === 'accepted'));
  assert.equal(before.notifications.length, 5);

  const config = parseConfig(duplicates.configInput);
  const sent = [];
  const http = duplicates.http(sent);
  let inventory;
  for (const time of [duplicates.t0 + 14_400_000, duplicates.t0 + 18_000_000]) {
    inventory = loadInventory(duplicates.writeInventory(dir, time));
    const store = new Store(db);
    await runScan({ config, inventory, store, http, now: time });
    await deliverPending(store, config, http, { now: time, credentials: duplicates.credentials });
    store.close();
  }
  assert.deepEqual(sent, [], 'no message is sent');
  const after = read();
  assert.deepEqual(after.notifications, before.notifications, 'no alert is queued or re-sent');

  const web = inventory.systems.find((system) => system.id === 'web');
  const kept = new Set(web.components.map((component) => component.id));
  assert.deepEqual([...kept].sort(), ['alpha', 'beta', `sbom:${hashOf('alpha-legacy')}`].sort());
  const folded = Object.keys(before.findings).filter(
    (id) => before.findings[id].payload.component_id && !kept.has(before.findings[id].payload.component_id),
  );
  assert.equal(folded.length, 2);
  for (const [id, finding] of Object.entries(after.findings)) {
    const earlier = before.findings[id];
    assert.ok(earlier, 'no new finding');
    if (folded.includes(id)) {
      assert.equal(finding.payload.active, false);
      assert.equal(finding.revision, earlier.revision + 1);
      assert.match(
        finding.payload.reasons.at(-1),
        /listed more than once in this system; it is watched as alpha/,
      );
    } else {
      // The finding already sent, the other version and beta keep their identity and revision.
      assert.notEqual(finding.payload.active, false);
      assert.equal(finding.revision, earlier.revision, id);
      assert.equal(finding.fingerprint, earlier.fingerprint, id);
    }
  }
  const revisions = (rows, id) => rows.filter((row) => row.finding_id === id).length;
  for (const id of Object.keys(after.findings))
    assert.equal(
      revisions(after.finding_revisions, id),
      revisions(before.finding_revisions, id) + (folded.includes(id) ? 1 : 0),
    );
  // The finding kept says every place the package was found at.
  const location = Object.values(after.findings).find((finding) => finding.payload.component_id === 'alpha')
    .payload.location;
  assert.equal(location.component_note, 'found in app/node_modules/alpha, tools/node_modules/alpha');

  // Later the operator removes the declared alpha: the SBOM still lists it, and its finding goes on.
  const time = duplicates.t0 + 21_600_000;
  const path = duplicates.writeInventory(dir, time);
  writeFileSync(
    path,
    readFileSync(path, 'utf8').replace(
      '      - { id: alpha, ecosystem: npm, name: alpha, version: 1.0.0 }\n',
      '',
    ),
  );
  const store = new Store(db);
  await runScan({ config, inventory: loadInventory(path), store, http, now: time });
  await deliverPending(store, config, http, { now: time, credentials: duplicates.credentials });
  store.close();
  assert.deepEqual(sent, []);
  const last = read();
  assert.deepEqual(last.notifications, before.notifications);
  for (const [id, finding] of Object.entries(after.findings)) {
    assert.equal(last.findings[id].revision, finding.revision, id);
    assert.equal(last.findings[id].payload.active, finding.payload.active, id);
  }
  assert.equal(
    Object.values(last.findings).find((finding) => finding.payload.component_id === 'alpha').payload.location
      .component_note,
    'found in app/node_modules/alpha, tools/node_modules/alpha',
  );
});

// Second review: N1, N3, N4 and the mass-removal guard.

test('N1: an empty or unmounted store removes nothing', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'x', '1', bom(['a']));
  put(ctx.store, 'y', '1', bom(['b']));
  sync(ctx, { apply: true });
  rmSync(ctx.store, { recursive: true });
  mkdirSync(ctx.store);
  const plan = sync(ctx, { apply: true });
  assert.deepEqual(plan.remove, []);
  assert.match(
    plan.problems[0],
    /The store holds no image: it may not be mounted or copied\. Nothing is written or removed\./,
  );
  assert.deepEqual(readdirSync(ctx.output).sort(), ['x.cdx.json', 'y.cdx.json']);
});

test('N3: an image directory replaced by a link keeps its file', async (t) => {
  const ctx = setup(t);
  put(ctx.store, 'x', '1', bom(['a']));
  put(ctx.store, 'y', '1', bom(['b']));
  sync(ctx, { apply: true });
  const { renameSync, symlinkSync } = await import('node:fs');
  renameSync(join(ctx.store, 'x'), join(ctx.dir, 'x-elsewhere'));
  symlinkSync(join(ctx.dir, 'x-elsewhere'), join(ctx.store, 'x'));
  const plan = sync(ctx, { apply: true });
  assert.deepEqual(plan.remove, []);
  assert.match(plan.problems.join(' '), /x: not a directory \(or a link\) in the store; left as it was/);
  assert.ok(existsSync(join(ctx.output, 'x.cdx.json')));
});

test('N4: a running version whose SBOM fails keeps the earlier list; a first sync writes what it can', (t) => {
  const ctx = setup(t);
  put(ctx.store, 'app', '1', bom(['old-only', 'shared']));
  const running = exportOf(ctx, [row('app', '1', 'n1')]);
  sync(ctx, { exposure: running, apply: true });
  put(ctx.store, 'app', '2', '{ broken');
  const both = exportOf(ctx, [row('app', '1', 'n1'), row('app', '2', 'n2')]);
  const plan = sync(ctx, { exposure: both, apply: true });
  assert.deepEqual(plan.images, []);
  assert.match(
    plan.problems.join(' '),
    /app: kept as it was, because not every running version's SBOM could be read/,
  );
  const kept = JSON.parse(readFileSync(join(ctx.output, 'app.cdx.json'), 'utf8'));
  assert.deepEqual(kept.components.map((item) => item.name).sort(), ['old-only', 'shared']);
  // Without an earlier list, the readable versions are watched.
  rmSync(join(ctx.output, 'app.cdx.json'));
  const first = sync(ctx, { exposure: both, apply: true });
  assert.deepEqual(first.images[0].versions, [{ version: '1', hosts: 1 }]);
});

test('removing more than half of the watched images needs --allow-removals', (t) => {
  const ctx = setup(t);
  for (const image of ['a', 'b', 'c', 'd']) put(ctx.store, image, '1', bom([image]));
  sync(ctx, { apply: true });
  const onlyA = exportOf(ctx, [row('a', '1', 'n1')]);
  const refused = sync(ctx, { exposure: onlyA, apply: true });
  assert.deepEqual(refused.remove, []);
  assert.match(refused.problems.join(' '), /3 of 4 watched images would be removed; nothing is removed/);
  assert.equal(readdirSync(ctx.output).length, 4);
  const allowed = sync(ctx, { exposure: onlyA, apply: true, allowRemovals: true });
  assert.deepEqual(allowed.remove, ['b.cdx.json', 'c.cdx.json', 'd.cdx.json']);
  assert.deepEqual(readdirSync(ctx.output), ['a.cdx.json']);
});
