import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseLibraryList, normalizeEcosystem, samePackage } from '../dist/ecosystems.js';
import { loadInventory } from '../dist/inventory.js';
import { assess } from '../dist/assessment.js';
import { collectSources } from '../dist/sources.js';

const now = Date.parse('2026-10-24T12:00:00Z');
const timestamp = new Date(now).toISOString();
const system = {
  id: 'app',
  name: 'App',
  updated_at: timestamp,
  environment: 'production',
  exposure: 'internal',
  criticality: 'high',
  components: [],
  products: [],
  keywords: [],
};
const config = {
  inventory_stale_days: 7,
  news_lookback_minutes: 60,
  sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false, feeds: [] },
};
const response = (body) => ({ status: 200, headers: {}, body: JSON.stringify(body) });
const evidence = (packages) => ({
  id: 'osv:TEST-1',
  source: 'osv',
  kind: 'advisory',
  title: 'Library advisory',
  description: '',
  url: 'https://osv.dev/vulnerability/TEST-1',
  aliases: [],
  severity: 'high',
  modified_at: timestamp,
  fetched_at: timestamp,
  packages,
});
function result(component, claims) {
  return assess({ systems: [{ ...system, components: [component] }] }, [evidence(claims)], config, now);
}

test('library lists support explicit ecosystems, scoped packages, Maven coordinates and exact versions', () => {
  const components = parseLibraryList(`
    # Declared inventory, without inferred versions
    python:Requests
    python:Django==5.1.2
    php:symfony/http-foundation@7.1.0
    nodejs:@org/pkg@1.2.3
    java:org.example:component 2.0.0
    golang:golang.org/x/net@v0.33.0
    rust:Serde_JSON@1.0.0
    ruby:rails@7.1.0
    dotnet:Newtonsoft.Json@13.0.3
    elixir:phoenix@1.7.0
    dart:http@1.0.0
    haskell:aeson@2.0.0
    swift:https://github.com/apple/swift-nio.git@2.0.0
  `);
  assert.deepEqual(
    components.map(({ ecosystem, name, version }) => [ecosystem, name, version]),
    [
      ['PyPI', 'requests', undefined],
      ['PyPI', 'django', '5.1.2'],
      ['Packagist', 'symfony/http-foundation', '7.1.0'],
      ['npm', '@org/pkg', '1.2.3'],
      ['Maven', 'org.example:component', '2.0.0'],
      ['Go', 'golang.org/x/net', 'v0.33.0'],
      ['crates.io', 'serde_json', '1.0.0'],
      ['RubyGems', 'rails', '7.1.0'],
      ['NuGet', 'Newtonsoft.Json', '13.0.3'],
      ['Hex', 'phoenix', '1.7.0'],
      ['Pub', 'http', '1.0.0'],
      ['Hackage', 'aeson', '2.0.0'],
      ['SwiftURL', 'https://github.com/apple/swift-nio.git', '2.0.0'],
    ],
  );
  assert.equal(components[0].id, parseLibraryList('Requests', 'python')[0].id);
  assert.deepEqual(
    parseLibraryList('Requests\nrequests\nrequests@2.0', 'python').map((c) => c.version),
    [undefined, '2.0'],
  );
  assert.equal(normalizeEcosystem('NuGet'), 'NuGet');
});

test('library parsing rejects guessed ecosystems, ranges, commands and malformed identities', () => {
  for (const entry of [
    'requests',
    'unknown:requests',
    'python:requests>=2',
    'python:requests@>=2',
    'npm:dep@^1.2',
    'npm:dep@*',
    'python:requests 2.0 extra',
    'php:requests',
    'maven:log4j',
    'npm:dep;touch',
    'swift:https://user:pass@example.com/repo.git',
    'python:requests@',
  ])
    assert.throws(() => parseLibraryList(entry), entry);
  assert.throws(() => parseLibraryList('python:requests\n'.repeat(20_001)), /20000/);
  assert.throws(() => parseLibraryList(' '.repeat(2 * 1024 * 1024 + 1)), /2 MiB/);
});

test('grouped libraries and explicit components normalize to one bounded inventory with stable IDs', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-ecosystems-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'inventory.json');
  writeFileSync(
    path,
    JSON.stringify({
      systems: [
        {
          ...system,
          components: [{ id: 'existing', ecosystem: 'python', name: 'Requests' }],
          libraries: {
            python: ['requests', 'Friendly_Bard==1.0rc1', { name: 'Django', version: '5.1' }],
            php: ['symfony/http-foundation'],
          },
        },
      ],
    }),
  );
  const loaded = loadInventory(path).systems[0];
  assert.equal('libraries' in loaded, false);
  assert.equal(loaded.components.length, 4);
  assert.equal(loaded.components[0].ecosystem, 'PyPI');
  assert.equal(loaded.components[1].name, 'friendly-bard');
  assert.equal(loaded.components[1].id, parseLibraryList('friendly-bard==1.0rc1', 'python')[0].id);
  writeFileSync(
    path,
    JSON.stringify({
      systems: [{ ...system, libraries: ['python:requests', 'php:symfony/http-foundation@7.1.0'] }],
    }),
  );
  assert.equal(loadInventory(path).systems[0].components[1].ecosystem, 'Packagist');
  writeFileSync(
    path,
    JSON.stringify({
      systems: [{ ...system, libraries: { python: [{ name: 'requests', ecosystem: 'npm' }] } }],
    }),
  );
  assert.throws(() => loadInventory(path), /does not match/);
});

test('registry identity rules preserve ecosystem separation and case-sensitive Maven/Go names', () => {
  assert(
    samePackage({ ecosystem: 'pip', name: 'Friendly._Bard' }, { ecosystem: 'PyPI', name: 'friendly-bard' }),
  );
  assert(
    samePackage({ ecosystem: 'cargo', name: 'Some_Crate' }, { ecosystem: 'crates.io', name: 'some-crate' }),
  );
  assert(
    samePackage({ ecosystem: 'NuGet', name: 'Library.Core' }, { ecosystem: 'dotnet', name: 'library.core' }),
  );
  assert(
    samePackage(
      { ecosystem: 'SwiftURL', name: 'https://github.com/apple/swift-nio-http2.git' },
      { ecosystem: 'SwiftURL', name: 'github.com/apple/swift-nio-http2' },
    ),
  );
  assert(!samePackage({ ecosystem: 'npm', name: 'requests' }, { ecosystem: 'PyPI', name: 'requests' }));
  assert(
    !samePackage({ ecosystem: 'Go', name: 'example.com/Lib' }, { ecosystem: 'Go', name: 'example.com/lib' }),
  );
  assert(
    !samePackage(
      { ecosystem: 'Maven', name: 'org.example:Lib' },
      { ecosystem: 'Maven', name: 'org.example:lib' },
    ),
  );
});

test('OSV preserves published Rust and NuGet spelling and accepts Swift host/path advisory names', async () => {
  const components = parseLibraryList(
    'rust:azure_core@0.21.0\nrust:crossbeam_utils@0.8.6\ndotnet:Newtonsoft.Json@12.0.1\n' +
      'swift:https://github.com/apple/swift-nio-http2.git@1.0.0\ngo:golang.org/x/net@v0.1.0',
  );
  const packages = [
    ['crates.io', 'azure_core', 'AZURE'],
    ['crates.io', 'crossbeam-utils', 'CROSSBEAM'],
    ['NuGet', 'Newtonsoft.Json', 'NUGET'],
    ['SwiftURL', 'github.com/apple/swift-nio-http2', 'HTTP2'],
    ['Go', 'golang.org/x/net', 'HTTP2'],
  ];
  const queries = [];
  const details = [];
  const collected = await collectSources(
    { systems: [{ ...system, components }] },
    config,
    {},
    async (url, options) => {
      if (url.endsWith('/querybatch')) {
        const batch = JSON.parse(options.body).queries;
        queries.push(...batch);
        return response({
          results: batch.map(({ package: pkg }) => ({
            vulns: packages
              .filter(([ecosystem, name]) => pkg.ecosystem === ecosystem && pkg.name === name)
              .map(([, , id]) => ({ id })),
          })),
        });
      }
      const id = url.split('/').at(-1);
      details.push(id);
      return response({
        id,
        modified: timestamp,
        affected: packages
          .filter(([, , advisory]) => id === advisory)
          .map(([ecosystem, name]) => ({ package: { ecosystem, name } })),
      });
    },
    now,
  );
  assert.deepEqual(collected.errors, []);
  assert.deepEqual(details.sort(), ['AZURE', 'CROSSBEAM', 'HTTP2', 'NUGET']);
  assert.equal(queries.length, 11);
  assert.equal(new Set(queries.map((query) => JSON.stringify(query))).size, queries.length);
  for (const [ecosystem, name] of packages)
    assert(queries.some(({ package: pkg }) => pkg.ecosystem === ecosystem && pkg.name === name));
  const findings = assess({ systems: [{ ...system, components }] }, collected.evidence, config, now);
  for (const component of components)
    assert.equal(
      findings.find((finding) => finding.component_id === component.id)?.applicability,
      'affected',
    );
});

test('Swift repository identities reject credentials, schemes and ambiguous paths', () => {
  assert.equal(
    parseLibraryList('swift:github.com/apple/swift-nio-http2')[0].name,
    'github.com/apple/swift-nio-http2',
  );
  for (const name of [
    'http://github.com/apple/swift-nio-http2',
    'https://user:pass@github.com/apple/swift-nio-http2',
    'github.com/apple/../swift-nio-http2',
    'github.com/apple/%2e%2e/swift-nio-http2',
    'github.com//swift-nio-http2',
    'github.com/apple/swift-nio-http2?token=value',
    'github.com/apple/swift-nio-http2#fragment',
    'github.com/apple\\swift-nio-http2',
  ])
    assert.throws(() => parseLibraryList(`swift:${name}`), name);
});

test('OSV spelling alternatives count toward the existing unique-query limit', async () => {
  const components = parseLibraryList(
    Array.from({ length: 5_001 }, (_, index) => `rust:package_${index}`).join('\n'),
  );
  let requests = 0;
  const collected = await collectSources(
    { systems: [{ ...system, components }] },
    config,
    {},
    async () => {
      requests++;
      throw new Error('Must reject before any request');
    },
    now,
  );
  assert.equal(requests, 0);
  assert.match(collected.errors[0].message, /10,000 unique package queries/);
  assert.deepEqual(collected.evidence, []);
});

test('explicit component inputs cannot bypass the exact-version constraint', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-component-versions-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'inventory.json');
  for (const [ecosystem, name, version] of [
    ['PyPI', 'requests', '>=2.0'],
    ['npm', 'dep', '^1.2.3'],
    ['Go', 'example.com/lib', 'v1.x'],
  ]) {
    const component = { id: 'dep', ecosystem, name, version };
    writeFileSync(path, JSON.stringify({ systems: [{ ...system, components: [component] }] }));
    assert.throws(() => loadInventory(path), /exact installed/);
    assert.equal(
      result(component, [{ ecosystem, name, matched_versions: [version], versions: [version] }])[0]
        .applicability,
      'unknown',
    );
  }
});

test('unresolved imported package versions query only by name and never become exact matches', async () => {
  const component = {
    id: 'unresolved',
    ecosystem: 'npm',
    name: 'alpha',
    version: 'git+https://example.com/repo.git',
  };
  const collected = await collectSources(
    { systems: [{ ...system, components: [component] }] },
    config,
    {},
    async (url, options) => {
      if (url.endsWith('/querybatch')) {
        assert.equal('version' in JSON.parse(options.body).queries[0], false);
        return response({ results: [{ vulns: [{ id: 'TEST-1' }] }] });
      }
      return response({ id: 'TEST-1', modified: timestamp, affected: [] });
    },
    now,
  );
  assert.deepEqual(collected.errors, []);
  assert.equal(collected.evidence[0].packages[0].matched_versions, undefined);
  assert.equal(
    assess({ systems: [{ ...system, components: [component] }] }, collected.evidence, config, now)[0]
      .applicability,
    'unknown',
  );
});

for (const [ecosystem, name, version] of [
  ['PyPI', 'django', '1!2.0rc1+local'],
  ['Packagist', 'vendor/package', '7.0.0'],
  ['Go', 'example.com/module', 'v0.1.0'],
  ['Maven', 'org.example:library', '2.0.Final'],
  ['NuGet', 'library', '1.0.0.1'],
]) {
  test(`${ecosystem} uses exact positive evidence without npm range comparisons`, () => {
    const component = { id: 'library', ecosystem, name, version };
    assert.equal(
      result(component, [{ ecosystem, name, matched_versions: [version] }])[0].applicability,
      'affected',
    );
    assert.equal(result(component, [{ ecosystem, name, versions: [version] }])[0].applicability, 'affected');
    assert.equal(
      result(component, [{ ecosystem, name, versions: ['0.0.1'], range: '<1.0.0' }])[0].applicability,
      'unknown',
    );
    assert.equal(
      result({ ...component, version: undefined }, [{ ecosystem, name, range: '*' }])[0].applicability,
      'unknown',
    );
  });
}

test('OSV sends name-only and versioned queries with canonical identities and binds positives to their ecosystem', async () => {
  const components = parseLibraryList(
    'python:Friendly_Bard==1!2.0rc1\npython:requests\nphp:vendor/library@7.0.0\nnpm:requests@1.0.0',
  );
  const seen = [];
  const collected = await collectSources(
    { systems: [{ ...system, components }] },
    config,
    {},
    async (url, options) => {
      if (url.endsWith('/querybatch')) {
        const queries = JSON.parse(options.body).queries;
        seen.push(...queries);
        return response({ results: queries.map(() => ({ vulns: [{ id: 'TEST-1' }] })) });
      }
      return response({
        id: 'TEST-1',
        modified: timestamp,
        summary: 'Shared advisory',
        affected: [
          {
            package: { ecosystem: 'PyPI', name: 'friendly.bard' },
            ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '3.0' }] }],
          },
          { package: { ecosystem: 'PyPI', name: 'Requests' }, versions: ['2.0'] },
          {
            ranges: [
              { type: 'GIT', repo: 'https://example.org/repository.git', events: [{ introduced: 'abc123' }] },
            ],
          },
        ],
      });
    },
    now,
  );
  assert.deepEqual(collected.errors, []);
  assert.deepEqual(
    seen.map(({ package: pkg, version }) => [pkg.ecosystem, pkg.name, version]),
    [
      ['PyPI', 'friendly-bard', '1!2.0rc1'],
      ['PyPI', 'requests', undefined],
      ['Packagist', 'vendor/library', '7.0.0'],
      ['npm', 'requests', '1.0.0'],
    ],
  );
  assert.equal('version' in seen[1], false);
  const findings = assess({ systems: [{ ...system, components }] }, collected.evidence, config, now);
  assert.equal(findings.find((f) => f.component_id === components[1].id).applicability, 'unknown');
  for (const component of [components[0], components[2], components[3]])
    assert.equal(findings.find((f) => f.component_id === component.id).applicability, 'affected');
  assert.equal(
    collected.evidence[0].packages.find((claim) => claim.ecosystem === 'PyPI' && claim.name === 'requests')
      .matched_versions,
    undefined,
  );
});

test('a later empty OSV version query cannot turn a prior non-npm match into an exclusion', async () => {
  const component = parseLibraryList('python:django@5.1')[0];
  const previous = evidence([{ ecosystem: 'PyPI', name: 'django', matched_versions: ['5.1'] }]);
  const collected = await collectSources(
    { systems: [{ ...system, components: [component] }] },
    config,
    {},
    async (url) =>
      response(
        url.endsWith('/querybatch')
          ? { results: [{}] }
          : {
              id: 'TEST-1',
              modified: timestamp,
              affected: [
                {
                  package: { ecosystem: 'PyPI', name: 'django' },
                  ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '5.0' }] }],
                },
              ],
            },
      ),
    now,
    [previous],
  );
  assert.deepEqual(collected.errors, []);
  assert.equal(
    assess({ systems: [{ ...system, components: [component] }] }, collected.evidence, config, now)[0]
      .applicability,
    'unknown',
  );
});

test('GitHub package aliases normalize but non-npm ranges remain uncertain', async () => {
  const component = parseLibraryList('python:Friendly_Bard@3.0')[0];
  const collected = await collectSources(
    { systems: [{ ...system, components: [component] }] },
    {
      ...config,
      sources: {
        ...config.sources,
        osv: false,
        github: true,
        github_token_env: 'UNUSED_ECOSYSTEM_TEST_TOKEN',
      },
    },
    {},
    async (url) =>
      response(
        new URL(url).searchParams.get('type') === 'malware'
          ? []
          : [
              {
                ghsa_id: 'GHSA-abcd-2345-efgh',
                type: 'reviewed',
                summary: 'Python advisory',
                severity: 'high',
                updated_at: timestamp,
                published_at: timestamp,
                vulnerabilities: [
                  {
                    package: { ecosystem: 'pip', name: 'friendly.bard' },
                    vulnerable_version_range: '<2.0',
                    first_patched_version: '2.0',
                  },
                ],
              },
            ],
      ),
    now,
  );
  assert.deepEqual(collected.errors, []);
  assert.deepEqual(collected.evidence[0].packages[0], {
    ecosystem: 'PyPI',
    name: 'friendly-bard',
    range: '<2.0',
    fixed: '2.0',
  });
  assert.equal(
    assess({ systems: [{ ...system, components: [component] }] }, collected.evidence, config, now)[0]
      .applicability,
    'unknown',
  );
});

test('cve.now normalizes multi-ecosystem records without sending non-npm stack queries', async () => {
  const components = parseLibraryList('python:Friendly_Bard@1.0');
  const calls = [];
  const collected = await collectSources(
    { systems: [{ ...system, components }] },
    { ...config, sources: { ...config.sources, osv: false, cve_now: true } },
    {},
    async (url) => {
      calls.push(url);
      const path = new URL(url).pathname;
      if (path === '/api/v1/entries')
        return response({ entries: [{ id: 'CVE-2026-12345', publishedAt: timestamp }], nextCursor: null });
      assert.equal(path, '/api/v1/entries/CVE-2026-12345');
      return response({
        id: 'CVE-2026-12345',
        status: 'published',
        title: 'Library advisory',
        originalDescription: 'A library vulnerability.',
        affected: [
          {
            ecosystem: 'PyPI',
            package: 'friendly.bard',
            versions: ['1.0'],
            ranges: [{ introduced: '0', fixed: '2.0' }],
          },
        ],
        modifiedAt: timestamp,
        publishedAt: timestamp,
      });
    },
    now,
  );
  assert.deepEqual(collected.errors, []);
  assert.equal(calls.length, 2);
  assert.deepEqual(collected.evidence[0].packages[0], {
    ecosystem: 'PyPI',
    name: 'friendly-bard',
    versions: ['1.0'],
  });
  assert.equal(
    assess({ systems: [{ ...system, components }] }, collected.evidence, config, now)[0].applicability,
    'affected',
  );
});
