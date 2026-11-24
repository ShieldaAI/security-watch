import test from 'node:test';
import assert from 'node:assert/strict';
import { buildPurl, openVex } from '../dist/vex.js';

const now = Date.parse('2026-11-24T12:00:00Z');
const iso = new Date(now).toISOString();

const component = (id, ecosystem, name, version = '1.0.0', extra = {}) => ({
  id,
  ecosystem,
  name,
  version,
  ...extra,
});
const inventory = (...components) => ({
  systems: [
    {
      id: 'web',
      name: 'Web',
      environment: 'prod',
      exposure: 'internet',
      criticality: 'high',
      updated_at: iso,
      components,
      products: [],
      keywords: [],
    },
    {
      id: 'api',
      name: 'Api',
      environment: 'prod',
      exposure: 'internal',
      criticality: 'low',
      updated_at: iso,
      components: [],
      products: [],
      keywords: [],
    },
  ],
});
const finding = (over = {}) => ({
  id: 'f1',
  event_id: 'CVE-2026-0001',
  system_id: 'web',
  component_id: 'c1',
  category: 'library',
  applicability: 'affected',
  source_severity: 'high',
  priority: 'high',
  title: 't',
  summary: 's',
  reasons: [],
  evidence_ids: ['e1'],
  urls: [],
  exploited: false,
  updated_at: iso,
  ...over,
});
const advisory = (over = {}) => ({
  id: 'e1',
  source: 'osv',
  kind: 'advisory',
  title: 't',
  url: 'https://example.com',
  description: '',
  aliases: [],
  severity: 'high',
  modified_at: iso,
  fetched_at: iso,
  packages: [],
  ...over,
});
const run = (findings, over = {}) =>
  openVex({
    findings,
    evidence: () => [],
    inventory: inventory(component('c1', 'npm', 'left-pad', '1.3.0')),
    now,
    ...over,
  });

test('purls per ecosystem', () => {
  const p = (ecosystem, name, version = '1.2.3') => buildPurl({ ecosystem, name, version });
  assert.equal(p('npm', 'left-pad'), 'pkg:npm/left-pad@1.2.3');
  assert.equal(p('npm', '@scope/name'), 'pkg:npm/%40scope/name@1.2.3');
  assert.equal(
    p('Maven', 'org.apache.logging.log4j:log4j-core'),
    'pkg:maven/org.apache.logging.log4j/log4j-core@1.2.3',
  );
  assert.equal(p('PyPI', 'Django_Rest.Framework'), 'pkg:pypi/django-rest.framework@1.2.3');
  assert.equal(p('Go', 'github.com/foo/bar', 'v1.2.3'), 'pkg:golang/github.com/foo/bar@v1.2.3');
  assert.equal(p('crates.io', 'serde'), 'pkg:cargo/serde@1.2.3');
  assert.equal(p('Packagist', 'monolog/monolog'), 'pkg:composer/monolog/monolog@1.2.3');
  assert.equal(p('RubyGems', 'rails'), 'pkg:gem/rails@1.2.3');
  assert.equal(p('NuGet', 'Newtonsoft.Json'), 'pkg:nuget/Newtonsoft.Json@1.2.3');
  assert.equal(p('Pub', 'http'), 'pkg:pub/http@1.2.3');
  assert.equal(p('Hex', 'plug'), 'pkg:hex/plug@1.2.3');
  assert.equal(p('Hackage', 'aeson'), 'pkg:hackage/aeson@1.2.3');
  assert.equal(p('SwiftURL', 'github.com/apple/swift-nio'), 'pkg:swift/github.com/apple/swift-nio@1.2.3');
});

test('purls percent-encode special characters', () => {
  assert.equal(
    buildPurl({ ecosystem: 'npm', name: 'a+b', version: '1.0.0+build 5' }),
    'pkg:npm/a%2Bb@1.0.0%2Bbuild%205',
  );
  assert.equal(buildPurl({ ecosystem: 'Maven', name: 'g:a(b)', version: '1' }), 'pkg:maven/g/a%28b%29@1');
  assert.equal(buildPurl({ ecosystem: 'npm', name: 'x', version: undefined }), undefined);
});

test('the inventory purl is kept, with only descriptive qualifiers', () => {
  const inv = inventory(
    component('c1', 'npm', 'left-pad', '1.3.0', {
      purl: 'pkg:npm/left-pad@1.3.0?registry=npm.corp.internal&arch=x64',
    }),
  );
  const { document } = run([finding()], { inventory: inv });
  assert.equal(document.statements[0].products[0]['@id'], 'pkg:npm/left-pad@1.3.0?arch=x64');
});

test('affected with and without a fix, and malware', () => {
  const { document } = run([
    finding({ fix: '1.3.1' }),
    finding({ id: 'f2', event_id: 'CVE-2026-0002' }),
    finding({ id: 'f3', event_id: 'MAL-1', category: 'malware', fix: '9.9.9' }),
  ]);
  const by = Object.fromEntries(document.statements.map((s) => [s.vulnerability.name, s]));
  assert.equal(by['CVE-2026-0001'].status, 'affected');
  assert.equal(by['CVE-2026-0001'].action_statement, 'Update left-pad to 1.3.1.');
  assert.equal(by['CVE-2026-0002'].action_statement, 'No fixed version is published; follow the advisory.');
  assert.equal(by['MAL-1'].action_statement, 'Remove left-pad: it is reported as a malicious package.');
  assert.equal(by['CVE-2026-0001'].timestamp, undefined, 'statements inherit the document time');
});

test('unknown and conflicting are under investigation', () => {
  const { document } = run([
    finding({ applicability: 'unknown' }),
    finding({ id: 'f2', event_id: 'CVE-2026-0002', applicability: 'conflicting' }),
    finding({ id: 'f3', event_id: 'CVE-2026-0003', applicability: 'relevant' }),
  ]);
  assert.deepEqual(
    document.statements.map((s) => s.status),
    ['under_investigation', 'under_investigation'],
  );
  assert.equal(
    openVex({
      findings: [finding({ applicability: 'relevant' })],
      evidence: () => [],
      inventory: inventory(component('c1', 'npm', 'x')),
      now,
    }).skipped.applicability_not_reportable,
    1,
  );
});

test('not_affected is omitted by default and included on request', () => {
  const f = finding({ applicability: 'not_affected' });
  const omitted = run([f]);
  assert.equal(omitted.document.statements.length, 0);
  assert.equal(omitted.skipped.not_affected_omitted, 1);
  const { document } = run([f], { includeNotAffected: true });
  assert.equal(document.statements[0].status, 'not_affected');
  assert.equal(document.statements[0].justification, 'vulnerable_code_not_present');
  assert.match(document.statements[0].impact_statement, /outside the affected versions/);
});

test('findings without a usable package are skipped and counted', () => {
  const inv = inventory(component('c1', 'npm', 'left-pad', '1.3.0'), {
    id: 'c2',
    ecosystem: 'npm',
    name: 'noversion',
  });
  const { document, skipped } = run(
    [
      finding({ active: false }),
      finding({ id: 'w', withdrawn: true }),
      finding({ id: 'n', category: 'news' }),
      finding({ id: 'p', category: 'product' }),
      finding({ id: 'h', category: 'health' }),
      finding({ id: 'nc', component_id: undefined }),
      finding({ id: 'gone', component_id: 'zzz' }),
      finding({ id: 'nv', component_id: 'c2' }),
    ],
    { inventory: inv },
  );
  assert.equal(document.statements.length, 0);
  assert.deepEqual(skipped, { inactive: 2, not_library: 3, no_component: 2, no_version: 1 });
});

test('an ecosystem without a purl type is skipped', () => {
  const inv = inventory(component('c1', 'Bogus', 'x', '1'));
  const { skipped } = run([finding()], { inventory: inv });
  assert.equal(skipped.no_purl_type, 1);
});

test('aliases come from advisory and KEV evidence, not withdrawn or news', () => {
  const evidence = [
    advisory({ id: 'e1', aliases: ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-0001'] }),
    advisory({ id: 'e2', kind: 'kev', aliases: ['CVE-2026-0009'] }),
    advisory({ id: 'e3', withdrawn: true, aliases: ['CVE-2026-0100'] }),
    advisory({ id: 'e4', kind: 'news', aliases: ['CVE-2026-0200'] }),
  ];
  const { document } = run([finding({ evidence_ids: ['e1', 'e2', 'e3', 'e4'] })], {
    evidence: () => evidence,
  });
  assert.deepEqual(document.statements[0].vulnerability, {
    name: 'CVE-2026-0001',
    aliases: ['CVE-2026-0009', 'GHSA-aaaa-bbbb-cccc'],
  });
});

test('systemId limits the findings', () => {
  const { document, skipped } = run(
    [finding(), finding({ id: 'g', system_id: 'api', event_id: 'CVE-2026-0005' })],
    {
      systemId: 'web',
    },
  );
  assert.equal(document.statements.length, 1);
  assert.deepEqual(skipped, {});
});

test('mitigationNote is appended to action statements only', () => {
  const { document } = run(
    [finding({ fix: '2.0.0' }), finding({ id: 'u', event_id: 'CVE-2026-0002', applicability: 'unknown' })],
    {
      mitigationNote: () => 'A runtime shield blocks the exploit path.',
    },
  );
  assert.equal(
    document.statements[0].action_statement,
    'Update left-pad to 2.0.0. A runtime shield blocks the exploit path.',
  );
  assert.equal(document.statements[1].action_statement, undefined);
});

test('output is deterministic and ordered', () => {
  const findings = [finding({ id: 'b', event_id: 'CVE-2026-0002' }), finding({ id: 'a' })];
  const first = run(findings);
  const second = run([...findings].reverse(), { now: now + 5000 });
  assert.equal(first.document['@id'], second.document['@id']);
  assert.match(
    first.document['@id'],
    /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  assert.deepEqual(first.document.statements, second.document.statements);
  assert.deepEqual(
    first.document.statements.map((s) => s.vulnerability.name),
    ['CVE-2026-0001', 'CVE-2026-0002'],
  );
  assert.notEqual(first.document.timestamp, second.document.timestamp);
});

test('empty input is a valid document, and statements meet OpenVEX requirements', () => {
  const empty = run([]);
  assert.deepEqual(empty.document.statements, []);
  assert.equal(empty.document['@context'], 'https://openvex.dev/ns/v0.2.0');
  assert.equal(empty.document.version, 1);
  assert.equal(empty.document.author, 'Security Watch');
  assert.equal(empty.document.tooling, 'Security Watch');
  const { document } = run(
    [
      finding(),
      finding({ id: 'u', event_id: 'CVE-2026-0002', applicability: 'unknown' }),
      finding({ id: 'n', event_id: 'CVE-2026-0003', applicability: 'not_affected' }),
    ],
    { includeNotAffected: true, author: 'Me' },
  );
  assert.equal(document.author, 'Me');
  for (const s of document.statements) {
    assert.ok(s.vulnerability.name && s.products.length === 1 && s.products[0]['@id']);
    if (s.status === 'affected') assert.ok(s.action_statement);
    if (s.status === 'not_affected') assert.ok(s.justification || s.impact_statement);
  }
});

test('a later scan of an unchanged state gives the same document identifier', () => {
  const first = run([finding()]);
  const later = run([finding({ updated_at: new Date(now + 86_400_000).toISOString() })], {
    now: now + 86_400_000,
  });
  assert.equal(first.document['@id'], later.document['@id']);
  assert.notEqual(first.document.timestamp, later.document.timestamp);
});

test('the same package version in two systems is one statement', () => {
  const shared = component('c1', 'npm', 'left-pad', '1.3.0');
  const twoSystems = {
    systems: inventory(shared).systems.map((system) => ({ ...system, components: [shared] })),
  };
  const { document } = run([finding({ id: 'a' }), finding({ id: 'b', system_id: 'api' })], {
    inventory: twoSystems,
  });
  assert.equal(document.statements.length, 1);
  assert.deepEqual(document.statements[0].products, [{ '@id': 'pkg:npm/left-pad@1.3.0' }]);
});
