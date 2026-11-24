import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  attachMitigations,
  exportProblems,
  mitigatedEverywhere,
  MitigationIndex,
  parseGenericRow,
  parseShirudoRow,
  readMitigationExport,
} from '../dist/mitigations.js';
import { parseConfig, loadConfig } from '../dist/config.js';
import { Store } from '../dist/store.js';
import { runScan } from '../dist/engine.js';
import { notificationText, digestText } from '../dist/delivery.js';
import { shieldCandidates } from '../dist/shield-candidates.js';

const now = Date.parse('2026-11-24T12:00:00Z');
const iso = (time = now) => new Date(time).toISOString();
const temp = () => mkdtempSync(join(tmpdir(), 'sw-mitigations-'));
const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

const shirudo = (over = {}) => ({
  node_id: 'n1',
  host_name: 'eu1-a',
  image_id: 'fleet-os',
  image_version: '2026.11.1',
  source: 'sbom',
  vuln_id: 'CVE-2026-20001',
  package: 'alpha',
  installed: '1.0.0',
  fixed: '2.0.0',
  exposure: 'shielded',
  upatch_id: 'alpha-guard',
  ...over,
});
const generic = (over = {}) => ({
  system_id: 'fleet-os',
  host: 'h1',
  identifier: 'CVE-2026-20001',
  package: 'alpha',
  status: 'mitigated',
  mitigation: 'waf-rule-42',
  ...over,
});
const source = (file, over = {}) => ({
  name: 'Shirudo',
  format: 'shirudo',
  file,
  max_age_minutes: 120,
  systems: {},
  ...over,
});
const lines = (rows) =>
  rows.map((item) => (typeof item === 'string' ? item : JSON.stringify(item))).join('\n') + '\n';
function writeFile(dir, name, rows, mtime = now - 5 * 60_000) {
  const path = join(dir, name);
  writeFileSync(path, typeof rows === 'string' ? rows : lines(rows));
  utimesSync(path, mtime / 1000, mtime / 1000);
  return path;
}

const advisory = (id, extra = {}) => ({
  id: `osv:${id}`,
  source: 'osv',
  kind: 'advisory',
  title: `${id} in alpha`,
  url: `https://osv.dev/vulnerability/${id}`,
  description: 'Deserialization in alpha.',
  aliases: [id, 'CVE-2026-20001'],
  severity: 'critical',
  modified_at: iso(),
  fetched_at: iso(),
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0', fixed: '2.0.0' }],
  ...extra,
});
const inventory = {
  systems: [
    {
      id: 'fleet-os',
      name: 'Fleet OS image',
      environment: 'production',
      exposure: 'internet',
      criticality: 'high',
      updated_at: iso(),
      components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
      products: [],
      keywords: [],
    },
  ],
};
const finding = (over = {}) => ({
  id: 'f1',
  event_id: 'GHSA-aaaa-bbbb-cccc',
  system_id: 'fleet-os',
  component_id: 'alpha',
  category: 'library',
  applicability: 'affected',
  source_severity: 'critical',
  priority: 'critical',
  title: 'alpha deserialization',
  summary: 'alpha',
  reasons: [],
  evidence_ids: ['osv:GHSA-aaaa-bbbb-cccc'],
  urls: [],
  exploited: false,
  fix: '2.0.0',
  updated_at: iso(),
  ...over,
});
const evidence = new Map([
  ['osv:GHSA-aaaa-bbbb-cccc', advisory('GHSA-aaaa-bbbb-cccc')],
  [
    'osv:GHSA-gone-gone-gone',
    advisory('GHSA-gone-gone-gone', { withdrawn: true, aliases: ['CVE-2026-77777'] }),
  ],
  ['news:1', { id: 'news:1', kind: 'news', aliases: ['CVE-2026-99999'] }],
]);
function index(rows, over = {}) {
  const dir = temp();
  try {
    const s = source(writeFile(dir, 'export.jsonl', rows), over);
    return new MitigationIndex(readMitigationExport(s, now), s);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Rows.

test('Shirudo rows: states map to the shared words; matching fields must be valid, display fields need not', () => {
  const state = (exposure) => parseShirudoRow(JSON.stringify(shirudo({ exposure }))).row.state;
  assert.equal(state('shielded'), 'mitigated');
  assert.equal(state('shield_pending'), 'pending');
  assert.equal(state('shield_module_absent'), 'failed');
  assert.equal(state('shield_excludes_node'), 'excluded');
  assert.equal(state('shield_withdrawn'), 'withdrawn');
  assert.equal(state('exposed_no_shield'), 'unmitigated');
  assert.equal(state('a_future_value'), 'unknown');
  assert.equal(state('constructor'), 'unknown', 'no inherited name is a state');
  const none = parseShirudoRow(JSON.stringify(shirudo({ exposure: 'none', vuln_id: '' }))).row;
  assert.equal(none.state, 'none');
  assert.equal(none.identifier, '');
  assert.equal(parseShirudoRow(JSON.stringify(shirudo({ source: 'kernel' }))).row.kernel, true);
  const odd = parseShirudoRow(
    JSON.stringify(shirudo({ host_name: { x: 1 }, upatch_id: 'a\u0001b', installed: 'x'.repeat(600) })),
  ).row;
  assert.equal(odd.mitigation, undefined);
  assert.equal(odd.host, 'n1');
  for (const [over, reason] of [
    [{ vuln_id: '' }, /missing field/],
    [{ node_id: null }, /missing field/],
    [{ image_id: true }, /not text/],
    [{ package: 'a\u2028b' }, /invalid text/],
    [{ package: 'a\u0085b' }, /invalid text/],
    [{ vuln_id: ['CVE-2026-1'] }, /not text/],
  ])
    assert.throws(() => parseShirudoRow(JSON.stringify(shirudo(over))), reason, JSON.stringify(over));
  assert.throws(() => parseShirudoRow('[]'), /not an object/);
  assert.throws(() => parseShirudoRow('null'), /not an object/);
  assert.throws(() => parseShirudoRow('{"a":'), /not JSON/);
});

test('generic rows: states, none, expiry, kernel flag', () => {
  const parse = (over) => parseGenericRow(JSON.stringify(generic(over)), now).row;
  for (const status of [
    'mitigated',
    'pending',
    'failed',
    'excluded',
    'withdrawn',
    'expired',
    'unmitigated',
    'unknown',
  ])
    assert.equal(parse({ status }).state, status);
  assert.equal(parse({ status: 'shielded' }).state, 'unknown', 'Shirudo words are not generic words');
  assert.equal(parse({ status: 'none', identifier: undefined }).state, 'none');
  assert.equal(parse({ expires_at: iso(now - 1) }).state, 'expired');
  assert.equal(
    parse({ status: 'pending', expires_at: iso(now) }).state,
    'expired',
    'expiring now is expired',
  );
  assert.equal(parse({ expires_at: iso(now + 60_000) }).state, 'mitigated');
  assert.equal(
    parse({ status: 'unmitigated', expires_at: iso(now - 1) }).state,
    'unmitigated',
    'only a mitigation expires',
  );
  assert.equal(parse({ expires_at: null }).state, 'mitigated');
  assert.throws(() => parse({ expires_at: 'next week' }), /invalid expires_at/);
  assert.throws(
    () => parse({ expires_at: 1800000000 }),
    /invalid expires_at/,
    'a number is not a time stamp',
  );
  assert.equal(parse({ kernel: true }).kernel, true);
  assert.throws(() => parse({ kernel: 'yes' }), /kernel/);
  assert.throws(() => parse({ host: undefined }), /missing field/);
  assert.throws(() => parse({ system_id: '' }), /missing field/);
  assert.equal(parse({ mitigation: 'x'.repeat(513) }).mitigation, undefined, 'an odd name is left out');
});

// Files.

test('reading an export: CRLF, BOM, stale, future time, skipped lines, empty, missing, a directory', () => {
  const dir = temp();
  try {
    const crlf = writeFile(
      dir,
      'crlf.jsonl',
      '\ufeff' + [shirudo(), shirudo({ node_id: 'n2' })].map((r) => JSON.stringify(r)).join('\r\n') + '\r\n',
    );
    const read = readMitigationExport(source(crlf), now);
    assert.equal(read.rows.length, 2);
    assert.equal(read.skipped, 0);
    assert.equal(read.stale, false);

    const mixed = writeFile(dir, 'mixed.jsonl', [shirudo(), '{broken', shirudo({ node_id: 'n2' })]);
    const partial = readMitigationExport(source(mixed), now);
    assert.equal(partial.skipped, 1);
    assert.match(
      exportProblems(partial, source(mixed), now).join(' '),
      /Shirudo: 1 line\(s\).*line 2: not JSON/,
    );

    const old = writeFile(dir, 'old.jsonl', [shirudo()], now - 3 * 3_600_000);
    const stale = readMitigationExport(source(old), now);
    assert.equal(stale.stale, true);
    assert.match(
      exportProblems(stale, source(old), now)[0],
      /written 180 minutes ago, more than max_age_minutes \(120\)/,
    );

    const ahead = writeFile(dir, 'ahead.jsonl', [shirudo()], now + 3_600_000);
    const future = readMitigationExport(source(ahead), now);
    assert.equal(future.stale, true, 'a time ahead of the clock is not trusted as fresh');
    assert.match(exportProblems(future, source(ahead), now)[0], /60 minutes in the future/);

    const empty = writeFile(dir, 'empty.jsonl', '\n\n');
    assert.match(
      exportProblems(readMitigationExport(source(empty), now), source(empty), now)[0],
      /export has no row for any system/,
    );
    const garbage = writeFile(dir, 'garbage.jsonl', 'nope\n{}\n');
    assert.throws(() => readMitigationExport(source(garbage), now), /no readable row/);
    assert.throws(() => readMitigationExport(source(join(dir, 'missing')), now), { code: 'ENOENT' });
    mkdirSync(join(dir, 'folder.jsonl'));
    assert.throws(() => readMitigationExport(source(join(dir, 'folder.jsonl')), now), /not a regular file/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Matching.

test('status: worst row per host, named mitigations only when in place, hosts from every row of the system', () => {
  const status = index([
    shirudo(),
    shirudo({ node_id: 'n2' }),
    shirudo({ node_id: 'n2' }), // a duplicate row counts once
    shirudo({ node_id: 'n3', exposure: 'exposed_no_shield', upatch_id: '' }),
    shirudo({ node_id: 'n3', exposure: 'shielded', upatch_id: 'late-guard' }),
    shirudo({ node_id: 'n4', exposure: 'shield_withdrawn', upatch_id: 'old-guard' }),
    shirudo({ node_id: 'n5', exposure: 'none', vuln_id: '' }),
    shirudo({ node_id: 'n6', vuln_id: 'CVE-2026-11111', exposure: 'exposed_no_shield' }),
    shirudo({ node_id: 'x1', image_id: 'other' }),
  ]).status(finding(), evidence, inventory);
  assert.equal(status.hosts, 6);
  assert.deepEqual(status.states, { mitigated: 2, unmitigated: 1, withdrawn: 1 });
  assert.deepEqual(status.mitigations, ['alpha-guard', 'late-guard']);
  assert.equal(
    status.summary,
    'Shirudo: mitigated on 2 of 6 hosts; 1 not mitigated; 1 mitigation withdrawn; 2 not listed for it.',
  );
  assert.equal(mitigatedEverywhere(status), false);
});

test('matching: aliases of current advisories only, packages, kernel rows, mapped and odd system keys', () => {
  assert.equal(
    index([shirudo()]).status(finding(), evidence, inventory).states.mitigated,
    1,
    'CVE alias of the GHSA event',
  );
  assert.equal(
    index([shirudo({ vuln_id: 'CVE-2026-77777' })]).status(
      finding({ evidence_ids: ['osv:GHSA-aaaa-bbbb-cccc', 'osv:GHSA-gone-gone-gone'] }),
      evidence,
      inventory,
    ).not_listed,
    true,
    'a withdrawn advisory’s alias is not the finding',
  );
  assert.equal(
    index([shirudo({ vuln_id: 'CVE-2026-99999' })]).status(
      finding({ event_id: 'news:1', category: 'news', component_id: undefined, evidence_ids: ['news:1'] }),
      evidence,
      inventory,
    ).not_listed,
    true,
    'a CVE an article cites is not the finding’s identifier',
  );
  assert.equal(index([shirudo({ package: 'beta' })]).status(finding(), evidence, inventory).not_listed, true);
  assert.equal(
    index([shirudo({ package: 'Alpha' })]).status(finding(), evidence, inventory).states.mitigated,
    1,
  );
  assert.equal(
    index([shirudo({ package: 'linux', source: 'kernel' })]).status(finding(), evidence, inventory).states
      .mitigated,
    1,
    'a kernel row matches by identifier alone',
  );
  assert.equal(index([shirudo({ image_id: 'elsewhere' })]).status(finding(), evidence, inventory), undefined);
  assert.equal(
    index([shirudo({ image_id: 'fleet-os-v2' })], { systems: { 'fleet-os-v2': 'fleet-os' } }).status(
      finding(),
      evidence,
      inventory,
    ).hosts,
    1,
  );
  assert.equal(
    index([shirudo({ image_id: 'constructor' })]).status(
      finding({ system_id: 'constructor' }),
      evidence,
      inventory,
    ).hosts,
    1,
    'an image named like an object method is its own system',
  );
  assert.equal(
    index([shirudo({ image_id: '__proto__' })], { systems: JSON.parse('{"__proto__":"fleet-os"}') }).status(
      finding(),
      evidence,
      inventory,
    ).hosts,
    1,
    'a mapping key named __proto__ is a key',
  );
  assert.equal(
    index([shirudo()]).status(finding({ category: 'malware' }), evidence, inventory),
    undefined,
    'a malicious package is removed, not mitigated',
  );
  assert.equal(index([shirudo()]).status(finding({ category: 'health' }), evidence, inventory), undefined);
});

test('the same host name in two systems is two hosts', () => {
  const s = index(
    [generic({ host: 'web-1' }), generic({ system_id: 'billing', host: 'web-1', status: 'unmitigated' })],
    { format: 'generic', name: 'Edge WAF' },
  );
  const status = s.status(finding(), evidence, inventory);
  assert.equal(status.hosts, 1);
  assert.equal(status.summary, 'Edge WAF: mitigated on 1 of 1 host.');
});

test('several sources: one status each, removed when gone; stale proves nothing', () => {
  const a = index([shirudo()]);
  const b = index([generic({ status: 'unmitigated', mitigation: undefined })], {
    format: 'generic',
    name: 'Edge WAF',
  });
  const attached = attachMitigations(finding(), [a, b], evidence, inventory);
  assert.deepEqual(
    attached.mitigations.map((item) => item.source),
    ['Shirudo', 'Edge WAF'],
  );
  assert.equal(mitigatedEverywhere(attached.mitigations[0]), true);
  assert.equal(mitigatedEverywhere({ ...attached.mitigations[0], stale: true }), false);
  assert.equal(attachMitigations(attached, [], evidence, inventory).mitigations, undefined);
});

// Configuration.

test('the mitigations section: names, formats, limits, strict fields, paths relative to the configuration', () => {
  const config = parseConfig({
    version: 1,
    mitigations: [
      { format: 'shirudo', file: './a.jsonl' },
      { format: 'generic', file: './b.jsonl' },
    ],
  });
  assert.deepEqual(
    config.mitigations.map(({ name, format, max_age_minutes, systems }) => ({
      name,
      format,
      max_age_minutes,
      systems,
    })),
    [
      { name: 'Shirudo', format: 'shirudo', max_age_minutes: 120, systems: {} },
      { name: 'Mitigations', format: 'generic', max_age_minutes: 120, systems: {} },
    ],
  );
  const bad = [
    [{ format: 'tetragon', file: 'x' }],
    [{ format: 'generic', file: 'x', token: 'y' }],
    [{ format: 'generic', file: 'x', max_age_minutes: 1 }],
    [{ format: 'generic', file: 'x', name: 'a\nb' }],
    [
      { format: 'generic', file: 'x', name: 'WAF' },
      { format: 'generic', file: 'y', name: 'waf' },
    ],
    [
      { format: 'generic', file: 'x' },
      { format: 'generic', file: 'y' },
    ],
    Array.from({ length: 11 }, (_, i) => ({ format: 'generic', file: `${i}`, name: `s${i}` })),
  ];
  for (const mitigations of bad)
    assert.throws(() => parseConfig({ version: 1, mitigations }), JSON.stringify(mitigations).slice(0, 80));
  assert.throws(
    () => parseConfig({ version: 1, shirudo: { exposure_file: 'x' } }),
    'the pre-release section name is not accepted',
  );
  const dir = temp();
  try {
    writeFileSync(
      join(dir, 'security-watch.yaml'),
      'version: 1\nmitigations:\n  - format: shirudo\n    file: ./shirudo/node-vulns.jsonl\n',
    );
    assert.equal(
      loadConfig(join(dir, 'security-watch.yaml')).mitigations[0].file,
      join(dir, 'shirudo/node-vulns.jsonl'),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Scans and alerts.

const osvConfig = (extra = {}) =>
  parseConfig({
    version: 1,
    poll_interval_minutes: 1440,
    sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false },
    policy: { library: { levels: ['critical'], basis: 'source_severity', channels: ['slack'] } },
    notifications: { slack: { webhook_url_env: 'MITIGATION_TEST_UNUSED' } },
    ...extra,
  });
function osvApi() {
  return async (url, request) => {
    if (url.endsWith('/querybatch'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          results: JSON.parse(request.body).queries.map(() => ({
            vulns: [{ id: 'GHSA-aaaa-bbbb-cccc', modified: iso() }],
          })),
        }),
      };
    if (url.endsWith('/vulns/GHSA-aaaa-bbbb-cccc'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          id: 'GHSA-aaaa-bbbb-cccc',
          aliases: ['CVE-2026-20001'],
          summary: 'Unsafe deserialization in alpha',
          details: 'alpha deserializes untrusted input.',
          modified: iso(),
          database_specific: { severity: 'CRITICAL' },
          affected: [
            {
              package: { ecosystem: 'npm', name: 'alpha' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
            },
          ],
        }),
      };
    return { status: 404, headers: {}, body: '' };
  };
}

test('a scan shows each source; a changed export keeps the revision and sends nothing again', async () => {
  const dir = temp();
  try {
    const store = new Store(':memory:');
    const shirudoFile = writeFile(dir, 'shirudo.jsonl', [
      shirudo({ exposure: 'exposed_no_shield', upatch_id: '' }),
    ]);
    const wafFile = writeFile(dir, 'waf.jsonl', [generic({ expires_at: iso(now + 86_400_000) })]);
    const config = osvConfig({
      mitigations: [
        { format: 'shirudo', file: shirudoFile },
        { format: 'generic', name: 'Edge WAF', file: wafFile },
      ],
    });
    const first = await runScan({ config, inventory, store, http: osvApi(), now });
    assert.deepEqual(
      first.errors.filter((e) => e.source.startsWith('mitigations')),
      [],
    );
    const saved = store.findings().find((item) => item.component_id === 'alpha');
    assert.deepEqual(
      saved.mitigations.map((item) => [item.source, item.states]),
      [
        ['Shirudo', { unmitigated: 1 }],
        ['Edge WAF', { mitigated: 1 }],
      ],
    );
    const jobs = store.jobs().length;
    assert.ok(jobs > 0);
    const text = notificationText(store.jobs()[0]).text;
    assert.match(
      text,
      /^Shirudo: mitigated on 0 of 1 host; 1 not mitigated\. \(export .* UTC; a mitigation is temporary and does not close the finding\)$/m,
    );
    assert.match(text, /^Edge WAF: mitigated on 1 of 1 host\. \(export .*\) In place: waf-rule-42$/m);
    assert.match(digestText(store.jobs()).text, /Edge WAF: mitigated on 1 of 1 host/);
    const revisions = store.history(saved.id).length;
    const basis = store.getMeta(`assessment-basis:${saved.id}`);

    // Later the WAF rule expires and Shirudo loads a shield.
    const later = now + 2 * 86_400_000;
    writeFile(dir, 'shirudo.jsonl', [shirudo()], later - 60_000);
    writeFile(dir, 'waf.jsonl', [generic({ expires_at: iso(now + 86_400_000) })], later - 60_000);
    await runScan({ config, inventory, store, http: osvApi(), now: later });
    const updated = store.findings().find((item) => item.id === saved.id);
    assert.deepEqual(
      updated.mitigations.map((item) => item.states),
      [{ mitigated: 1 }, { expired: 1 }],
    );
    assert.equal(updated.priority, saved.priority);
    assert.equal(updated.applicability, 'affected');
    assert.equal(store.history(saved.id).length, revisions, 'no new revision');
    assert.equal(store.jobs().length, jobs, 'no new delivery');
    assert.equal(store.getMeta(`assessment-basis:${saved.id}`), basis, 'no new analysis');

    rmSync(wafFile);
    const missing = await runScan({ config, inventory, store, http: osvApi(), now: later + 60_000 });
    assert.ok(
      missing.errors.some(
        (e) => e.source === 'mitigations:Edge WAF' && /the file does not exist/.test(e.message),
      ),
    );
    assert.deepEqual(
      store
        .findings()
        .find((item) => item.id === saved.id)
        .mitigations.map((item) => item.source),
      ['Shirudo'],
      'the unreadable source shows nothing rather than an old status',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('alerts: at most three sources, and long names never push out the reminder', () => {
  const status = (n) => ({
    source: `S${n}`,
    format: 'generic',
    exported_at: iso(),
    stale: n === 0,
    hosts: 9,
    states: {},
    mitigations: ['x'.repeat(500), 'y'.repeat(500), 'z'.repeat(500)],
    summary: `S${n}: mitigated on 1 of 9 hosts; 1 not mitigated; 1 mitigation withdrawn; 1 mitigation excludes the host; 1 mitigation failed to load; 1 status unknown; 1 mitigation waiting to load; 1 mitigation expired; 2 not listed for it.`,
  });
  const job = {
    id: 'job',
    finding_id: 'f1',
    channel: 'slack',
    payload: JSON.stringify({
      assessment: { ...finding(), mitigations: [0, 1, 2, 3, 4].map(status) },
      reason: 'test',
    }),
    status: 'pending',
    attempts: 0,
    available_at: now,
  };
  const text = notificationText(job).text;
  const shown = text.split('\n').filter((line) => /^S\d: /.test(line));
  assert.equal(shown.length, 3);
  for (const line of shown)
    assert.match(
      line,
      /2 not listed for it\. \(export .*a mitigation is temporary and does not close the finding\)/,
    );
  assert.match(shown[0], /out of date/);
  assert.match(text, /^2 more mitigation source\(s\): see explain\.$/m);
  const odd = {
    ...job,
    payload: JSON.stringify({
      assessment: { ...finding(), mitigations: [null, { summary: 7 }] },
      reason: 'x',
    }),
  };
  assert.doesNotThrow(() => notificationText(odd));
});

test('shield-candidates: --unmitigated leaves out findings a fresh status covers everywhere; staleness is now', () => {
  const covered = {
    source: 'Shirudo',
    format: 'shirudo',
    exported_at: iso(now - 30 * 60_000),
    stale: false,
    hosts: 2,
    states: { mitigated: 2 },
    mitigations: ['g'],
    summary: 'Shirudo: mitigated on 2 of 2 hosts.',
  };
  const run = (mitigations, extra = {}) =>
    shieldCandidates({
      findings: [finding({ mitigations })],
      evidence: () => [advisory('GHSA-aaaa-bbbb-cccc')],
      inventory,
      now,
      unmitigatedOnly: true,
      ...extra,
    }).candidates;
  assert.equal(run([covered]).length, 0);
  assert.equal(run([{ ...covered, states: { mitigated: 1, unmitigated: 1 } }]).length, 1);
  assert.equal(run([{ ...covered, stale: true }]).length, 1, 'a stale status proves nothing');
  assert.equal(run([covered], { mitigationMaxAge: { Shirudo: 10 } }).length, 1, 'too old by now');
  assert.equal(run([covered], { mitigationMaxAge: { Shirudo: 10 } })[0].mitigations[0].stale, true);
  assert.equal(run([covered], { unmitigatedOnly: false }).length, 1);
});

test('doctor reads each export, names unmapped system keys and missing files', (t) => {
  const dir = temp();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'systems.yaml'), JSON.stringify(inventory));
  writeFile(
    dir,
    'shirudo.jsonl',
    [shirudo(), shirudo({ image_id: 'unknown-image', node_id: 'n9' })],
    Date.now() - 60_000,
  );
  writeFileSync(
    join(dir, 'security-watch.yaml'),
    'version: 1\ninventory: ./systems.yaml\nsources:\n  cve_now: false\n  hacker_news: false\nmitigations:\n  - format: shirudo\n    file: ./shirudo.jsonl\n  - format: generic\n    name: Edge WAF\n    file: ./missing.jsonl\n',
  );
  const result = spawnSync(process.execPath, [cli, 'doctor', '--config', join(dir, 'security-watch.yaml')], {
    encoding: 'utf8',
  });
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, false);
  assert.ok(
    report.problems.some((p) =>
      /Shirudo: 1 system key\(s\) in the export match no system in the inventory \(unknown-image\)/.test(p),
    ),
  );
  assert.ok(
    report.problems.some((p) => /Edge WAF: the export cannot be read: the file does not exist/.test(p)),
  );
  assert.deepEqual(
    report.mitigations.map(({ name, rows, hosts, systems_matched, readable }) => ({
      name,
      rows,
      hosts,
      systems_matched,
      readable,
    })),
    [
      { name: 'Shirudo', rows: 2, hosts: 2, systems_matched: 1, readable: undefined },
      { name: 'Edge WAF', rows: undefined, hosts: undefined, systems_matched: undefined, readable: false },
    ],
  );
});

test('the vex command: mitigation note only when fresh, private new file, system and author checks', async (t) => {
  const dir = temp();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'systems.yaml'), JSON.stringify(inventory));
  writeFileSync(
    join(dir, 'security-watch.yaml'),
    'version: 1\ninventory: ./systems.yaml\ndatabase: ./data/watch.db\nsources:\n  cve_now: false\n  hacker_news: false\n  osv: true\nmitigations:\n  - format: shirudo\n    file: ./shirudo.jsonl\n',
  );
  mkdirSync(join(dir, 'data'), { mode: 0o700 });
  // The command judges freshness by the real clock, so the scan and the export use it too; the
  // advisories are dated at the fixed test time, which must not be in the scan's future.
  const real = Math.max(Date.now(), now + 3_600_000);
  const exportFile = writeFile(dir, 'shirudo.jsonl', [shirudo()], real - 60_000);
  const store = new Store(join(dir, 'data', 'watch.db'));
  await runScan({
    config: osvConfig({ mitigations: [{ format: 'shirudo', file: exportFile }] }),
    inventory,
    store,
    http: osvApi(),
    now: real,
  });
  store.close();
  const run = (...args) =>
    spawnSync(process.execPath, [cli, 'vex', '--config', join(dir, 'security-watch.yaml'), ...args], {
      encoding: 'utf8',
    });
  const printed = run();
  assert.equal(printed.status, 0, printed.stderr);
  const document = JSON.parse(printed.stdout);
  assert.equal(document.statements.length, 1);
  assert.equal(document.statements[0].status, 'affected');
  assert.deepEqual(document.statements[0].products, [{ '@id': 'pkg:npm/alpha@1.0.0' }]);
  assert.match(
    document.statements[0].action_statement,
    /^Update alpha to 2\.0\.0\. Temporary runtime mitigation on 1 of 1 host\(s\) \(Shirudo, \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\)\.$/,
  );
  const saved = run('--output', join(dir, 'vex.json'), '--author', 'Platform team');
  assert.equal(saved.status, 0, saved.stderr);
  assert.match(saved.stdout, /^1 VEX statement\(s\) saved\./);
  assert.equal(JSON.parse(readFileSync(join(dir, 'vex.json'), 'utf8')).author, 'Platform team');
  if (process.platform !== 'win32') assert.equal(statSync(join(dir, 'vex.json')).mode & 0o777, 0o600);
  assert.notEqual(run('--output', join(dir, 'vex.json')).status, 0, 'never replaces a file');
  assert.match(run('--system', 'nope').stderr, /No system nope in the inventory/);
  assert.match(run('--author', 'a\nb').stderr, /--author must be one line/);
  assert.match(run('--system', 'fleet-os').stdout, /pkg:npm\/alpha@1\.0\.0/);
});
