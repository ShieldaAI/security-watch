import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  truncateSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import {
  DEPENDENCY_FILES,
  ECOSYSTEMS,
  generateSbom,
  importSbom,
  loadConfig,
  loadInventory,
  notificationText,
  runScan,
  Store,
} from '../dist/index.js';
import { packageUrl } from '../dist/manifests.js';
import { POLYGLOT, writeProject } from './helpers/polyglot.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const cli = join(root, 'dist/cli.js');
const NOW = new Date('2026-11-16T08:00:00.000Z');
const noNetwork =
  'data:text/javascript,' +
  encodeURIComponent(
    "import http from 'node:http'; import https from 'node:https'; import {syncBuiltinESMExports} from 'node:module'; const fail=()=>{throw new Error('TEST_NETWORK_FORBIDDEN')}; http.request=fail; https.request=fail; globalThis.fetch=fail; syncBuiltinESMExports();",
  );

function temp(t, prefix = 'sw-sbom-') {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}
/** The CLI, with every CI variable cleared unless the test sets it. */
function run(args, cwd, env = {}) {
  const clean = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) => !/^(?:GITHUB_|GITLAB_CI|CI_PROJECT_URL|CI_COMMIT_SHA)/.test(key),
    ),
  );
  const result = spawnSync(process.execPath, ['--import', noNetwork, cli, ...args], {
    cwd,
    env: { ...clean, ...env },
    encoding: 'utf8',
    timeout: 20_000,
  });
  if (result.error) throw result.error;
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}
const purls = (result) => result.bom.components.map((component) => component.purl);
const locations = (result, purl) =>
  result.bom.components
    .find((component) => component.purl === purl)
    ?.evidence.occurrences.map((occurrence) => occurrence.location);

const EXPECTED = [
  'pkg:cargo/serde@1.0.193',
  'pkg:cargo/tokio@1.35.0',
  'pkg:composer/acme/branch',
  'pkg:composer/guzzlehttp/guzzle@7.8.0',
  'pkg:composer/monolog/monolog',
  'pkg:composer/phpstan/phpstan@1.10.0',
  'pkg:composer/phpunit/phpunit@10.5.0',
  'pkg:composer/symfony/http-foundation@6.4.0',
  'pkg:gem/nokogiri@1.16.5',
  'pkg:gem/puma',
  'pkg:gem/rails@7.1.3',
  'pkg:gem/sinatra@4.0.0',
  'pkg:golang/github.com/fork/mod@v1.0.1',
  'pkg:golang/github.com/gin-gonic/gin@v1.9.1',
  'pkg:golang/github.com/single/dep@v1.0.0',
  'pkg:golang/golang.org/x/net@v0.17.0',
  'pkg:hackage/aeson@2.1.2.1',
  'pkg:hackage/text@2.0.2',
  'pkg:hex/phoenix@1.7.10',
  'pkg:hex/plug_crypto@2.0.0',
  'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.16.0',
  'pkg:maven/com.google.guava/guava@32.1.3-jre',
  'pkg:maven/junit/junit@4.13.2',
  'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1',
  'pkg:maven/org.example/missing',
  'pkg:maven/org.example/ranged',
  'pkg:maven/org.junit.jupiter/junit-jupiter@5.10.0',
  'pkg:npm/%40babel/code-frame@7.12.13',
  'pkg:npm/%40babel/core@7.24.0',
  'pkg:npm/%40scope/thing@1.0.0',
  'pkg:npm/%40types/node@20.0.0',
  'pkg:npm/%40types/react@18.0.0',
  'pkg:npm/axios@1.6.0',
  'pkg:npm/chalk@5.3.0',
  'pkg:npm/child@2.0.0',
  'pkg:npm/debug@2.6.9',
  'pkg:npm/express@4.21.2',
  'pkg:npm/left-pad@1.3.0',
  'pkg:npm/lodash@4.17.20',
  'pkg:npm/lodash@4.17.21',
  'pkg:npm/minimist@1.2.5',
  'pkg:npm/parent@1.0.0',
  'pkg:npm/react',
  'pkg:npm/semver@7.5.0',
  'pkg:npm/string-width@4.2.3',
  'pkg:npm/vitest@1.0.0',
  'pkg:npm/ws@8.0.0',
  'pkg:nuget/Floating',
  'pkg:nuget/Newtonsoft.Json@13.0.3',
  'pkg:nuget/Polly@8.2.0',
  'pkg:nuget/Serilog@3.1.1',
  'pkg:pub/http@1.1.0',
  'pkg:pub/lints@3.0.0',
  'pkg:pypi/black@24.1.0',
  'pkg:pypi/django@4.2.0',
  'pkg:pypi/flask',
  'pkg:pypi/httpx@0.27.0',
  'pkg:pypi/jinja2@3.1.2',
  'pkg:pypi/mypy@1.8.0',
  'pkg:pypi/numpy',
  'pkg:pypi/pydantic@2.5.0',
  'pkg:pypi/pytest-cov@4.1.0',
  'pkg:pypi/pytest@8.0.0',
  'pkg:pypi/pyyaml',
  'pkg:pypi/requests@2.31.0',
  'pkg:pypi/ruff@0.3.0',
  'pkg:pypi/sphinx@7.2.6',
  'pkg:pypi/urllib3@2.0.7',
  'pkg:swift/github.com/Alamofire/Alamofire@5.8.1',
  'pkg:swift/github.com/acme/branchy',
  'pkg:swift/github.com/apple/swift-nio@2.62.0',
];

test('every supported dependency file is read into one CycloneDX document', (t) => {
  const project = writeProject(temp(t));
  const result = generateSbom({ project, now: NOW, toolVersion: '9.9.9' });
  assert.deepEqual(purls(result), EXPECTED);
  assert.deepEqual(result.ecosystems, [...ECOSYSTEMS].sort());
  assert.equal(result.packages, EXPECTED.length);
  assert.equal(result.unversioned, EXPECTED.filter((purl) => !purl.includes('@', 8)).length);
  // Installed copies, hidden folders and virtual environments are never read.
  assert.ok(!purls(result).some((purl) => purl.includes('never')));
  assert.ok(!result.files.some((file) => /node_modules|\.hidden|\.venv/.test(file.path)));
  // A manifest beside its lockfile adds nothing; one without a lockfile is read.
  assert.ok(!result.files.some((file) => file.path === 'web/package.json'));
  assert.ok(!result.files.some((file) => file.path === 'poetry/pyproject.toml'));
  assert.ok(!result.files.some((file) => file.path === 'dotnet/App.csproj'));
  assert.ok(result.files.some((file) => file.path === 'nolock/package.json' && file.kind === 'manifest'));
  // The same package and version found twice is one component with both places.
  assert.deepEqual(locations(result, 'pkg:npm/left-pad@1.3.0'), [
    'legacy/package-lock.json',
    'nolock/package.json',
  ]);
  // Development-only dependencies are kept and marked.
  const scoped = result.bom.components.filter((component) => component.scope === 'optional');
  assert.deepEqual(scoped.map((component) => component.purl).sort(), [
    'pkg:composer/phpstan/phpstan@1.10.0',
    'pkg:composer/phpunit/phpunit@10.5.0',
    'pkg:maven/junit/junit@4.13.2',
    'pkg:maven/org.junit.jupiter/junit-jupiter@5.10.0',
    'pkg:npm/%40babel/core@7.24.0',
    'pkg:npm/%40types/react@18.0.0',
    'pkg:npm/parent@1.0.0',
    'pkg:npm/vitest@1.0.0',
    'pkg:pub/lints@3.0.0',
    'pkg:pypi/black@24.1.0',
    'pkg:pypi/mypy@1.8.0',
    'pkg:pypi/pytest-cov@4.1.0',
    'pkg:pypi/ruff@0.3.0',
  ]);
  const { metadata } = result.bom;
  assert.equal(result.bom.bomFormat, 'CycloneDX');
  assert.equal(result.bom.specVersion, '1.6');
  assert.equal(metadata.timestamp, NOW.toISOString());
  assert.deepEqual(metadata.tools.components[0], {
    type: 'application',
    group: '@shieldaai',
    name: 'security-watch',
    version: '9.9.9',
  });
  // Warnings say what was left out and why, one line per file and reason.
  const warnings = result.warnings.join('\n');
  assert.match(warnings, /web\/package-lock\.json: 2 entries come from Git, a local path/);
  assert.match(warnings, /nolock\/package\.json: 3 entries come from Git/);
  assert.match(
    warnings,
    /nolock\/package\.json: 1 of 3 dependencies have a version range.*Commit a lockfile/,
  );
  assert.match(warnings, /java\/pom\.xml: 2 of 6 dependencies have no exact version.*parent POM/);
  assert.match(warnings, /py\/requirements\.txt: 2 entries come from Git/);
  // The output is stable: the same project gives the same document.
  assert.deepEqual(generateSbom({ project, now: NOW, toolVersion: '9.9.9' }).bom, result.bom);
});

test('a generated SBOM imports without warnings and its file locations become notes', (t) => {
  const directory = temp(t);
  const project = writeProject(join(directory, 'project'));
  const result = generateSbom({
    project,
    now: NOW,
    name: 'Checkout API',
    owner: 'Dana',
    note: 'cluster eu-1',
    environment: 'production',
    exposure: 'internet',
    criticality: 'high',
    sourceUrl: 'https://github.com/acme/checkout',
    sourceRevision: 'abc123',
  });
  const file = join(directory, 'checkout.cdx.json');
  writeFileSync(file, JSON.stringify(result.bom));
  const imported = importSbom(file);
  assert.deepEqual(imported.warnings, []);
  assert.equal(imported.components.length, EXPECTED.length);
  const express = imported.components.find((component) => component.name === 'express');
  assert.equal(express.version, '4.21.2');
  assert.equal(express.note, 'found in web/package-lock.json');
  const leftPad = imported.components.find((component) => component.name === 'left-pad');
  assert.equal(leftPad.note, 'found in legacy/package-lock.json, nolock/package.json');
  const gin = imported.components.find((component) => component.name === 'github.com/gin-gonic/gin');
  assert.deepEqual([gin.ecosystem, gin.version], ['Go', 'v1.9.1']);
  assert.equal(
    imported.components.find((component) => component.ecosystem === 'Maven' && component.version === '2.17.1')
      .name,
    'org.apache.logging.log4j:log4j-core',
  );
  assert.deepEqual(imported.subject, {
    name: 'Checkout API',
    created: NOW.toISOString(),
    properties: {
      'security-watch:system-id': 'checkout-api',
      'security-watch:owner': 'Dana',
      'security-watch:environment': 'production',
      'security-watch:note': 'cluster eu-1',
      'security-watch:exposure': 'internet',
      'security-watch:criticality': 'high',
      'security-watch:source-url': 'https://github.com/acme/checkout',
      'security-watch:source-revision': 'abc123',
    },
  });
  assert.equal(result.system.id, 'checkout-api');
});

test('options are checked, development dependencies can be left out, and a single file can be read', (t) => {
  const project = writeProject(temp(t));
  const production = generateSbom({ project, production: true, now: NOW });
  assert.ok(!production.bom.components.some((component) => component.scope === 'optional'));
  assert.ok(purls(production).includes('pkg:npm/express@4.21.2'));
  assert.ok(!purls(production).includes('pkg:npm/vitest@1.0.0'));

  const single = generateSbom({ project: join(project, 'py/requirements.txt'), now: NOW });
  assert.deepEqual(single.files, [
    { path: 'requirements.txt', ecosystem: 'PyPI', kind: 'lockfile', packages: 4 },
  ]);
  assert.equal(single.system.name, 'py');
  assert.throws(
    () => generateSbom({ project: join(project, 'README.md') }),
    /not a supported dependency file/,
  );
  assert.throws(
    () => generateSbom({ project, owner: 'Dana\nInjected: line' }),
    /Owner must be one line of at most 500 characters/,
  );
  assert.throws(() => generateSbom({ project, sourceUrl: 'http://example.com/repo' }), /HTTPS address/);
  assert.throws(
    () => generateSbom({ project, sourceUrl: 'https://user:pass@example.com/repo' }),
    /without credentials/,
  );
  // The name comes from the project's own manifest, the ID from the name.
  const named = generateSbom({ project: join(project, 'pep621') });
  assert.deepEqual(named.system, { id: 'acme-service', name: 'acme-service' });
  assert.deepEqual(generateSbom({ project: join(project, 'web') }).system, {
    id: 'acme-web',
    name: '@acme/web',
  });
  assert.equal(generateSbom({ project, systemId: '  ' }).system.id, generateSbom({ project }).system.id);
});

test('workspaces, damaged files, links and limits are handled without hiding the rest', (t) => {
  const project = writeProject(temp(t), {
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: { '': {}, 'node_modules/react': { version: '18.2.0' } },
    }),
    'packages/ui/package.json': JSON.stringify({ dependencies: { react: '^18.0.0', 'only-here': '^1.0.0' } }),
    'broken/package-lock.json': '{ not json',
    'broken/composer.lock': '[]',
    'pnpm10/pnpm-lock.yaml': `lockfileVersion: '9.0'
importers:
  .: {}
packages:
  '@pnpm/exe@10.0.0': {}
---
lockfileVersion: '9.0'
importers:
  .: {}
packages:
  koa@2.15.0: {}
  hono@4.0.0: {}
  'tarball@https://example.com/t.tgz': {}
`,
    'Package.swift': `let package = Package(dependencies: [
  .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),
  .package(url: "https://github.com/apple/swift-log.git", exact: "1.5.3"),
  .package(path: "../Local"),
])`,
    'app/pubspec.yaml': `name: app
dependencies:
  http: 1.1.0
  path: ^1.8.0
  flutter:
    sdk: flutter
  local:
    path: ../local
dev_dependencies:
  test: { version: 1.24.0 }
`,
  });
  writeProject(project, {
    'central/Directory.Packages.props': `<Project>
  <ItemGroup><PackageVersion Include="Azure.Identity" Version="1.10.4" /></ItemGroup>
  <ItemGroup><PackageVersion Include="Dapper" Version="2.1.24" /></ItemGroup>
</Project>`,
    'odd/Package.resolved': JSON.stringify({
      pins: [{ location: 'not a url', state: { version: '1.0.0' } }, 7],
    }),
    'odd/package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/fine': { version: '1.0.0' },
        'node_modules/bad': { name: 'Bad Name', version: '1.0.0' },
      },
    }),
    'odd/package.json': '{ broken',
  });
  mkdirSync(join(project, 'big'));
  writeFileSync(join(project, 'big', 'Cargo.lock'), '');
  truncateSync(join(project, 'big', 'Cargo.lock'), 21 * 1024 * 1024);
  mkdirSync(join(project, 'locked-out'));
  writeFileSync(join(project, 'locked-out', 'go.mod'), 'require a.b/c v1.0.0\n');
  chmodSync(join(project, 'locked-out'), 0o000);
  symlinkSync(join(project, 'packages'), join(project, 'linked'));
  const result = generateSbom({ project, now: NOW });
  chmodSync(join(project, 'locked-out'), 0o700);
  // The workspace member adds only what the lockfile lacks, and does not warn about its ranges.
  assert.ok(purls(result).includes('pkg:npm/react@18.2.0'));
  assert.ok(!purls(result).includes('pkg:npm/react'));
  assert.ok(purls(result).includes('pkg:npm/only-here'));
  assert.ok(!result.warnings.some((warning) => warning.startsWith('packages/ui/package.json')));
  // pnpm 10 writes its own lockfile first; the project's is the larger document.
  assert.ok(purls(result).includes('pkg:npm/koa@2.15.0'));
  assert.ok(!purls(result).some((purl) => purl.includes('%40pnpm')));
  assert.ok(purls(result).includes('pkg:swift/github.com/apple/swift-log@1.5.3'));
  assert.ok(purls(result).includes('pkg:swift/github.com/vapor/vapor'));
  assert.ok(purls(result).includes('pkg:pub/http@1.1.0'));
  assert.ok(purls(result).includes('pkg:pub/test@1.24.0'));
  assert.ok(purls(result).includes('pkg:pub/path'));
  // A file that cannot be read is reported and skipped; the others still count.
  assert.match(result.warnings.join('\n'), /broken\/package-lock\.json: could not be read/);
  assert.match(result.warnings.join('\n'), /broken\/composer\.lock: could not be read/);
  assert.ok(purls(result).includes('pkg:nuget/Azure.Identity@1.10.4'));
  assert.ok(purls(result).includes('pkg:nuget/Dapper@2.1.24'));
  assert.match(result.warnings.join('\n'), /odd\/Package\.resolved: 1 entry comes from Git/);
  assert.match(
    result.warnings.join('\n'),
    /odd\/package-lock\.json: 1 entry has a name that is not a valid npm package name/,
  );
  assert.match(result.warnings.join('\n'), /big\/Cargo\.lock: larger than 20 MiB; skipped\./);
  if (process.getuid?.() !== 0)
    assert.match(result.warnings.join('\n'), /locked-out: folder could not be read; skipped\./);
  assert.equal(generateSbom({ project: join(project, 'odd') }).system.name, 'odd');
  // The symbolic link is not followed, so the workspace member is read once.
  assert.ok(!result.files.some((file) => file.path.startsWith('linked/')));

  const huge = temp(t);
  const packages = { '': {} };
  for (let index = 0; index <= 20_000; index++) packages[`node_modules/p${index}`] = { version: '1.0.0' };
  writeFileSync(join(huge, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }));
  assert.throws(() => generateSbom({ project: huge }), /at most 20000 fit one system/);
});

test('Composer vendors whose name starts with "php" are packages, not platform requirements', (t) => {
  const project = mkdtempSync(join(tmpdir(), 'sw-composer-'));
  t.after(() => rmSync(project, { recursive: true, force: true }));
  writeFileSync(
    join(project, 'composer.lock'),
    JSON.stringify({
      packages: [
        { name: 'phpmailer/phpmailer', version: 'v6.8.0' },
        { name: 'phpseclib/phpseclib', version: '3.0.20' },
        { name: 'monolog/monolog', version: '3.4.0' },
      ],
      'packages-dev': [{ name: 'phpunit/phpunit', version: '10.0.0' }],
      platform: { php: '>=8.1', 'ext-json': '*' },
    }),
  );
  const purls = generateSbom({ project }).bom.components.map((component) => component.purl);
  assert.deepEqual(purls, [
    'pkg:composer/monolog/monolog@3.4.0',
    'pkg:composer/phpmailer/phpmailer@6.8.0',
    'pkg:composer/phpseclib/phpseclib@3.0.20',
    'pkg:composer/phpunit/phpunit@10.0.0',
  ]);
});

test('an unclosed .package( in Package.swift does not make reading slow', (t) => {
  const project = mkdtempSync(join(tmpdir(), 'sw-swift-'));
  t.after(() => rmSync(project, { recursive: true, force: true }));
  writeFileSync(join(project, 'Package.swift'), '.package('.repeat(200_000));
  const started = performance.now();
  generateSbom({ project });
  assert.ok(performance.now() - started < 5_000, 'read in under 5 seconds');
});

test('package URLs follow the purl specification for every ecosystem', () => {
  assert.equal(packageUrl('npm', '@scope/pkg', '1.0.0'), 'pkg:npm/%40scope/pkg@1.0.0');
  assert.equal(packageUrl('Maven', 'org.a:b', '1.0'), 'pkg:maven/org.a/b@1.0');
  assert.equal(
    packageUrl('Go', 'k8s.io/api', 'v0.29.0+incompatible'),
    'pkg:golang/k8s.io/api@v0.29.0%2Bincompatible',
  );
  assert.equal(packageUrl('SwiftURL', 'github.com/a/b'), 'pkg:swift/github.com/a/b');
  assert.deepEqual(Object.keys(DEPENDENCY_FILES).sort(), [...ECOSYSTEMS].sort());
});

test('SPDX documents, including GitHub dependency-graph exports, import like CycloneDX', (t) => {
  const directory = temp(t);
  const spdx = {
    spdxVersion: 'SPDX-2.3',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'com.github.acme/checkout',
    creationInfo: { created: '2026-11-15T10:00:00Z' },
    documentDescribes: ['SPDXRef-com.github.acme-checkout'],
    packages: [
      {
        SPDXID: 'SPDXRef-com.github.acme-checkout',
        name: 'com.github.acme/checkout',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: 'pkg:github/acme/checkout@main',
          },
        ],
      },
      {
        SPDXID: 'SPDXRef-npm-express-4.21.2',
        name: 'npm:express',
        versionInfo: '4.21.2',
        checksums: [{ algorithm: 'SHA256', checksumValue: 'b'.repeat(64) }],
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: 'pkg:npm/express@4.21.2',
          },
        ],
      },
      {
        SPDXID: 'SPDXRef-npm-lodash',
        name: 'npm:lodash',
        versionInfo: '^4.17.0',
        externalRefs: [
          { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/lodash' },
        ],
      },
      {
        SPDXID: 'SPDXRef-pip-requests',
        name: 'pip:requests',
        versionInfo: '2.31.0',
        checksums: [{ algorithm: 'SHA256', checksumValue: 'not-hex' }],
        externalRefs: [
          {
            referenceCategory: 'PACKAGE_MANAGER',
            referenceType: 'purl',
            referenceLocator: 'pkg:pypi/requests',
          },
        ],
      },
      { SPDXID: 'SPDXRef-no-purl', name: 'mystery', versionInfo: 'NOASSERTION' },
    ],
    relationships: [
      {
        spdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DESCRIBES',
        relatedSpdxElement: 'SPDXRef-com.github.acme-checkout',
      },
      {
        spdxElementId: 'SPDXRef-com.github.acme-checkout',
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: 'SPDXRef-npm-express-4.21.2',
      },
      {
        spdxElementId: 'SPDXRef-com.github.acme-checkout',
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: 'SPDXRef-npm-express-4.21.2',
      },
      {
        spdxElementId: 'SPDXRef-pip-requests',
        relationshipType: 'DEPENDENCY_OF',
        relatedSpdxElement: 'SPDXRef-npm-express-4.21.2',
      },
      {
        spdxElementId: 'SPDXRef-npm-express-4.21.2',
        relationshipType: 'CONTAINS',
        relatedSpdxElement: 'SPDXRef-npm-lodash',
      },
    ],
  };
  const file = join(directory, 'github.spdx.json');
  writeFileSync(file, JSON.stringify({ sbom: spdx }));
  const imported = importSbom(file);
  assert.equal(imported.source.format, 'SPDX');
  assert.equal(imported.source.spec_version, '2.3');
  assert.deepEqual(
    imported.components.map((component) => [component.ecosystem, component.name, component.version]),
    [
      ['npm', 'express', '4.21.2'],
      ['npm', 'lodash', undefined],
      ['PyPI', 'requests', '2.31.0'],
    ],
  );
  assert.equal(imported.components[0].digest, `sha256:${'b'.repeat(64)}`);
  assert.equal(imported.components[2].digest, undefined);
  assert.equal(imported.components[0].provenance.source, 'SPDX');
  assert.deepEqual(imported.dependencies, [
    { ref: 'SPDXRef-com.github.acme-checkout', depends_on: ['SPDXRef-npm-express-4.21.2'] },
    { ref: 'SPDXRef-npm-express-4.21.2', depends_on: ['SPDXRef-pip-requests'] },
  ]);
  assert.match(imported.warnings[0], /\^4\.17\.0 is a range; imported by name only/);
  assert.match(imported.warnings.join('\n'), /missing package URL; not imported/);
  assert.deepEqual(imported.subject, {
    name: 'com.github.acme/checkout',
    created: '2026-11-15T10:00:00Z',
    properties: {},
  });

  for (const [document, message] of [
    [{ spdxVersion: 'SPDX-3.0', packages: [] }, /SPDX JSON 2\.2 or 2\.3/],
    [{ spdxVersion: 'SPDX-2.3', packages: [{ SPDXID: 7 }] }, /Invalid SBOM component reference/],
    [{ spdxVersion: 'SPDX-2.3', packages: [7] }, /Invalid SBOM component/],
    [{ spdxVersion: 'SPDX-2.3', packages: [], relationships: {} }, /Invalid SPDX relationships/],
    [{ spdxVersion: 'SPDX-2.3', packages: [], relationships: [7] }, /Invalid SPDX relationships/],
    [
      {
        spdxVersion: 'SPDX-2.3',
        packages: [],
        relationships: [{ relationshipType: 'DEPENDS_ON', spdxElementId: 'a' }],
      },
      /Invalid SBOM dependency references/,
    ],
    [{ hello: 'world' }, /Expected a CycloneDX JSON .* or SPDX JSON/],
  ]) {
    writeFileSync(file, JSON.stringify(document));
    assert.throws(() => importSbom(file), message, JSON.stringify(document));
  }
  writeFileSync(file, 'not json');
  assert.throws(() => importSbom(file), /SBOM is not valid JSON/);
});

function sbomFolder(t) {
  const directory = temp(t, 'sw-sbom-folder-');
  const project = writeProject(join(directory, 'project'));
  const sboms = join(directory, 'sboms');
  mkdirSync(sboms);
  const generated = generateSbom({
    project,
    now: new Date(),
    systemId: 'checkout',
    name: 'Checkout API',
    owner: 'Dana, platform team',
    note: 'repository acme/checkout',
    exposure: 'internet',
    criticality: 'critical',
    sourceUrl: 'https://github.com/acme/checkout',
  });
  writeFileSync(join(sboms, 'anything.cdx.json'), JSON.stringify(generated.bom));
  // An image SBOM from another tool: no Security Watch properties, operating-system packages.
  writeFileSync(
    join(sboms, 'worker-image.cdx.json'),
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      metadata: { timestamp: '2026-11-01T00:00:00Z', component: { name: 'registry/worker:1.4' } },
      components: [
        { purl: 'pkg:deb/debian/openssl@3.0.11?arch=amd64' },
        { purl: 'pkg:deb/debian/zlib1g@1.2.13' },
        { purl: 'pkg:apk/alpine/musl@1.2.4' },
        { purl: 'pkg:pypi/celery@5.3.6', properties: [{ name: 'aquasecurity:trivy:FilePath', value: 'x' }] },
      ],
      dependencies: [{ ref: 'image', dependsOn: ['openssl-ref'] }],
    }),
  );
  writeFileSync(join(sboms, 'broken.json'), '{');
  writeFileSync(
    join(sboms, 'web-shop.json'),
    JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [] }),
  );
  writeFileSync(join(sboms, 'notes.txt'), 'ignored');
  writeFileSync(join(sboms, '.hidden.json'), '{');
  writeFileSync(
    join(directory, 'systems.yaml'),
    `sbom_directory: ./sboms
systems:
  - id: web-shop
    name: Web shop
    updated_at: '${new Date().toISOString()}'
    libraries: ['npm:express@4.21.2']
`,
  );
  return { directory, sboms, inventory: join(directory, 'systems.yaml') };
}

test('every SBOM in the SBOM folder becomes a system described by the SBOM', (t) => {
  const { sboms, inventory } = sbomFolder(t);
  const loaded = loadInventory(inventory);
  assert.deepEqual(
    loaded.systems.map((system) => system.id),
    ['web-shop', 'checkout', 'worker-image'],
  );
  const checkout = loaded.systems[1];
  assert.equal(checkout.name, 'Checkout API');
  assert.equal(checkout.owner, 'Dana, platform team');
  assert.equal(checkout.note, 'repository acme/checkout');
  assert.equal(checkout.exposure, 'internet');
  assert.equal(checkout.criticality, 'critical');
  assert.equal(checkout.source_url, 'https://github.com/acme/checkout');
  assert.equal(checkout.environment, 'unknown');
  assert.equal(checkout.components.length, EXPECTED.length);
  assert.match(checkout.provenance.reference, /^sha256:/);
  const worker = loaded.systems[2];
  assert.equal(worker.name, 'registry/worker:1.4');
  assert.equal(worker.note, 'SBOM sboms/worker-image.cdx.json');
  assert.equal(worker.updated_at, '2026-11-01T00:00:00Z');
  assert.deepEqual(
    worker.components.map((component) => component.name),
    ['celery'],
  );
  // Operating-system packages are a notice, not a fault; damaged and conflicting files are warnings.
  assert.deepEqual(loaded.name_notices, [
    'worker-image: 3 packages in sboms/worker-image.cdx.json are of a kind Security Watch does not match against advisories (apk, deb): operating-system packages and CI actions need your image or repository scanner. The other packages are watched.',
  ]);
  assert.equal(loaded.import_warnings.length, 2);
  assert.match(
    loaded.import_warnings[0],
    /^sboms\/broken\.json: SBOM is not valid JSON; this SBOM is not watched\.$/,
  );
  assert.match(loaded.import_warnings[1], /^sboms\/web-shop\.json: system ID web-shop is already used/);

  // Without a timestamp the file's modification time counts; an unusable property is ignored.
  rmSync(join(sboms, 'broken.json'));
  rmSync(join(sboms, 'web-shop.json'));
  writeFileSync(
    join(sboms, 'legacy.bom.json'),
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      metadata: { properties: [{ name: 'security-watch:exposure', value: 'everywhere' }] },
      components: [{ purl: 'pkg:npm/left-pad@1.3.0' }],
    }),
  );
  utimesSync(
    join(sboms, 'legacy.bom.json'),
    new Date('2026-10-01T00:00:00Z'),
    new Date('2026-10-01T00:00:00Z'),
  );
  writeFileSync(
    join(sboms, 'bad-id.json'),
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      metadata: { properties: [{ name: 'security-watch:owner', value: 'x'.repeat(600) }] },
      components: [],
    }),
  );
  const again = loadInventory(inventory);
  const legacy = again.systems.find((system) => system.id === 'legacy');
  assert.equal(legacy.updated_at, '2026-10-01T00:00:00.000Z');
  assert.equal(legacy.exposure, 'unknown');
  assert.deepEqual(again.import_warnings, [
    'sboms/bad-id.json: owner: Too big: expected string to have <=500 characters; this SBOM is not watched.',
  ]);
});

test('an SBOM folder must exist, and an inventory without one needs a system', (t) => {
  const directory = temp(t);
  const inventory = join(directory, 'systems.yaml');
  writeFileSync(inventory, 'sbom_directory: ./sboms\n');
  assert.throws(() => loadInventory(inventory), /ENOENT/);
  mkdirSync(join(directory, 'sboms'));
  // An empty folder is how a monitor fed by pipelines starts: nothing is watched, and it says so.
  const empty = loadInventory(inventory);
  assert.equal(empty.systems.length, 0);
  assert.match(
    empty.name_notices[0],
    /The SBOM folder \.\/sboms has no SBOM that could be imported, so nothing is watched yet/,
  );
  writeFileSync(join(directory, 'file'), '');
  writeFileSync(inventory, 'sbom_directory: ./file\n');
  assert.throws(() => loadInventory(inventory), /sbom_directory is not a folder/);
  writeFileSync(inventory, 'systems: []\n');
  assert.throws(() => loadInventory(inventory), /No systems: add at least one system/);
});

test('an alert about a package from an SBOM folder says where to look', async (t) => {
  const { directory, inventory } = sbomFolder(t);
  rmSync(join(directory, 'sboms', 'broken.json'));
  const config = join(directory, 'security-watch.yaml');
  writeFileSync(
    config,
    `version: 1
inventory: ./systems.yaml
database: ./watch.db
policy:
  library: { levels: [critical], channels: [slack] }
notifications:
  slack: { webhook_url_env: SLACK_TEST_WEBHOOK }
`,
  );
  process.env.SLACK_TEST_WEBHOOK = 'https://hooks.slack.com/services/T/B/X';
  t.after(() => delete process.env.SLACK_TEST_WEBHOOK);
  const store = new Store(':memory:');
  t.after(() => store.close());
  const now = Date.now();
  await runScan({
    config: loadConfig(config),
    inventory: loadInventory(inventory),
    store,
    now,
    fixture: [
      {
        id: 'DEMO-GIN',
        source: 'fixture',
        kind: 'advisory',
        title: 'Fictional gin advisory',
        url: 'https://example.com/gin',
        description: 'Synthetic.',
        aliases: [],
        severity: 'critical',
        modified_at: new Date(now).toISOString(),
        fetched_at: new Date(now).toISOString(),
        packages: [{ ecosystem: 'Go', name: 'github.com/gin-gonic/gin', versions: ['v1.9.1'] }],
      },
    ],
  });
  const texts = store.jobs().map((job) => notificationText(job).text);
  assert.equal(texts.length, 1);
  assert.match(
    texts[0],
    /^Where to look: Checkout API \(owner: Dana, platform team\) - repository acme\/checkout$/m,
  );
  assert.match(texts[0], /^Affected item: Go github\.com\/gin-gonic\/gin v1\.9\.1 - found in go\/go\.mod$/m);
});

test('the sbom command writes, replaces and describes an SBOM, and fills in the CI repository', (t) => {
  const directory = temp(t);
  const project = writeProject(join(directory, 'project'));
  const printed = run(['sbom', '--project', project], directory);
  assert.equal(printed.code, 0, printed.stderr);
  assert.equal(JSON.parse(printed.stdout).components.length, EXPECTED.length);
  assert.match(printed.stderr, /^project: 71 packages \(Go, Hackage/m);
  assert.match(printed.stderr, /^11 packages have no exact version and are watched by name only\.$/m);
  assert.match(printed.stderr, /^warning: web\/package-lock\.json: 2 entries come from Git/m);

  const output = join(directory, 'out.cdx.json');
  writeFileSync(output, 'old');
  const written = run(
    [
      'sbom',
      '--project',
      join(project, 'go'),
      '--output',
      output,
      '--system-id',
      'Go Service',
      '--owner',
      'Dana',
      '--exposure',
      'internal',
      '--criticality',
      'low',
      '--environment',
      'staging',
      '--production',
    ],
    directory,
    {
      GITHUB_ACTIONS: 'true',
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_REPOSITORY: 'acme/go-service',
      GITHUB_SHA: 'a'.repeat(40),
    },
  );
  assert.equal(written.code, 0, written.stderr);
  assert.equal(written.stdout, '');
  assert.match(written.stderr, /Wrote .*out\.cdx\.json\./);
  const bom = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(
    Object.fromEntries(bom.metadata.properties.map((property) => [property.name, property.value])),
    {
      'security-watch:system-id': 'go-service',
      'security-watch:owner': 'Dana',
      'security-watch:environment': 'staging',
      'security-watch:note': 'repository acme/go-service',
      'security-watch:exposure': 'internal',
      'security-watch:criticality': 'low',
      'security-watch:source-url': 'https://github.com/acme/go-service',
      'security-watch:source-revision': 'a'.repeat(40),
    },
  );
  const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
  assert.equal(bom.metadata.tools.components[0].version, version);
  assert.ok(!readdirNames(directory).some((name) => name.startsWith('.security-watch-')));

  // GitLab CI is recognised as well; an explicit source address replaces the detected one.
  const gitlab = run(['sbom', '--project', join(project, 'rust')], directory, {
    GITLAB_CI: 'true',
    CI_PROJECT_URL: 'https://gitlab.example.com/acme/rust',
    CI_COMMIT_SHA: 'b'.repeat(40),
  });
  const gitlabProperties = JSON.parse(gitlab.stdout).metadata.properties;
  assert.ok(gitlabProperties.some((p) => p.value === 'https://gitlab.example.com/acme/rust'));
  const explicit = run(
    ['sbom', '--project', join(project, 'rust'), '--source-url', 'https://example.com/other'],
    directory,
    {
      GITLAB_CI: 'true',
      CI_PROJECT_URL: 'https://gitlab.example.com/acme/rust',
      CI_COMMIT_SHA: 'b'.repeat(40),
    },
  );
  const explicitProperties = JSON.parse(explicit.stdout).metadata.properties.map((p) => p.name);
  assert.ok(!explicitProperties.includes('security-watch:source-revision'));
  assert.ok(!explicitProperties.includes('security-watch:note'));
  // A CI address that is not plain HTTPS is ignored rather than written.
  const insecure = run(['sbom', '--project', join(project, 'rust')], directory, {
    GITLAB_CI: 'true',
    CI_PROJECT_URL: 'http://gitlab.internal/acme/rust',
  });
  assert.equal(insecure.code, 0, insecure.stderr);
  assert.equal(JSON.parse(insecure.stdout).metadata.properties.length, 1);

  for (const [args, message] of [
    [['--project', join(directory, 'empty')], /No packages found in .*Supported files: package-lock\.json/],
    [
      ['--project', project, '--exposure', 'public'],
      /--exposure must be one of: internet, internal, unknown/,
    ],
    [['--project', project, '--criticality', 'severe'], /--criticality must be one of/],
    [['--project', project, '--project', project], /sbom takes one --project/],
    [['--project', project, '--output', directory], /--output must name a file/],
    [['--project', project, '--config', 'x'], /--config is not supported by sbom/],
  ]) {
    mkdirSync(join(directory, 'empty'), { recursive: true });
    const result = run(['sbom', ...args], directory);
    assert.equal(result.code, 1, args.join(' '));
    assert.match(result.stderr, message);
  }
  const help = run(['--help'], directory);
  assert.match(help.stdout, /security-watch sbom \[--project PATH\]/);
});

function readdirNames(directory) {
  return spawnSync('ls', ['-A', directory], { encoding: 'utf8' }).stdout.split('\n');
}

test('init --project creates a working monitor from code in one step', (t) => {
  const directory = temp(t);
  const project = writeProject(join(directory, 'project'));
  const npmOnly = join(directory, 'npm-only');
  writeProject(npmOnly, { 'package-lock.json': POLYGLOT['web/package-lock.json'] });
  const watch = join(directory, 'watch');
  const created = run(
    [
      'init',
      '--directory',
      watch,
      '--yes',
      '--project',
      project,
      '--project',
      join(project, 'web'),
      '--notifications',
      'slack',
    ],
    directory,
  );
  assert.equal(created.code, 0, created.stderr);
  assert.ok(existsSync(join(watch, 'sboms', 'project.cdx.json')));
  assert.ok(existsSync(join(watch, 'sboms', 'acme-web.cdx.json')));
  assert.match(created.stdout, /Refresh it when dependencies change/);
  assert.match(created.stdout, /warning: \d+ more; security-watch sbom --project lists them all\./);
  assert.match(created.stdout, /OSV is turned on/);
  assert.deepEqual(parse(readFileSync(join(watch, 'systems.yaml'), 'utf8')), {
    sbom_directory: './sboms',
    systems: [],
  });
  assert.equal(parse(readFileSync(join(watch, 'security-watch.yaml'), 'utf8')).sources.osv, true);
  writeFileSync(join(watch, '.env'), 'SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T/B/X\n', {
    mode: 0o600,
  });
  const doctor = run(
    ['doctor', '--config', join(watch, 'security-watch.yaml'), '--credentials-file', join(watch, '.env')],
    directory,
  );
  assert.equal(doctor.code, 0, doctor.stdout + doctor.stderr);
  const report = JSON.parse(doctor.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.systems, 2);
  assert.deepEqual(report.import_warnings, []);

  // Two projects with the same name get two IDs; npm alone leaves OSV off; templates can be added.
  const second = join(directory, 'second');
  const again = run(
    [
      'init',
      '--directory',
      second,
      '--yes',
      '--project',
      npmOnly,
      '--project',
      npmOnly,
      '--systems',
      'nodejs',
      '--production',
    ],
    directory,
  );
  assert.equal(again.code, 0, again.stderr);
  assert.ok(existsSync(join(second, 'sboms', 'npm-only.cdx.json')));
  const twin = JSON.parse(readFileSync(join(second, 'sboms', 'npm-only-2.cdx.json'), 'utf8'));
  assert.ok(
    twin.metadata.properties.some((p) => p.name === 'security-watch:system-id' && p.value === 'npm-only-2'),
  );
  assert.ok(!twin.components.some((component) => component.scope === 'optional'));
  assert.notEqual(parse(readFileSync(join(second, 'security-watch.yaml'), 'utf8')).sources.osv, true);
  const inventory = parse(readFileSync(join(second, 'systems.yaml'), 'utf8'));
  assert.equal(inventory.systems.length, 1);
  assert.equal(loadInventory(join(second, 'systems.yaml')).systems.length, 3);

  const occupied = join(directory, 'occupied');
  mkdirSync(join(occupied, 'sboms'), { recursive: true });
  writeFileSync(join(occupied, 'sboms', 'npm-only.cdx.json'), 'mine');
  const refused = run(['init', '--directory', occupied, '--yes', '--project', npmOnly], directory);
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /init never overwrites it/);
  assert.equal(readFileSync(join(occupied, 'sboms', 'npm-only.cdx.json'), 'utf8'), 'mine');
  assert.ok(!existsSync(join(occupied, 'security-watch.yaml')));

  for (const [args, message] of [
    [['--project', project, '--libraries', join(directory, 'x.txt')], /--project and --libraries/],
    [['--production'], /--production requires --project/],
    [['--project', join(directory, 'nothing-here')], /ENOENT/],
  ]) {
    writeFileSync(join(directory, 'x.txt'), 'npm:left-pad\n');
    const result = run(['init', '--directory', join(directory, 'never'), '--yes', ...args], directory);
    assert.equal(result.code, 1, args.join(' '));
    assert.match(result.stderr, message);
    assert.ok(!existsSync(join(directory, 'never', 'security-watch.yaml')));
  }
});

test('import-sbom reads SPDX as well as CycloneDX', (t) => {
  const directory = temp(t);
  const file = join(directory, 'repo.spdx.json');
  writeFileSync(
    file,
    JSON.stringify({
      spdxVersion: 'SPDX-2.2',
      packages: [
        {
          SPDXID: 'SPDXRef-a',
          externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:cargo/serde@1.0.193' }],
        },
      ],
    }),
  );
  const result = run(['import-sbom', '--input', file], directory);
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.source.format, 'SPDX');
  assert.deepEqual([report.components[0].ecosystem, report.components[0].name], ['crates.io', 'serde']);
});

test('the GitHub Action is pinned, matches the release and runs its script as documented', (t) => {
  const action = parse(readFileSync(join(root, 'action.yml'), 'utf8'));
  const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
  assert.equal(action.inputs['security-watch-version'].default, version);
  for (const step of action.runs.steps.filter((step) => step.uses))
    assert.match(step.uses, /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/, `${step.uses} is pinned to a commit`);
  // Inputs reach the script only through the environment, never inside the script text.
  for (const step of action.runs.steps.filter((step) => step.run))
    assert.ok(!step.run.includes('${{'), 'no expression inside a run script');
  const script = readFileSync(join(root, 'scripts/action-sbom.sh'), 'utf8');
  for (const name of Object.keys(action.inputs).filter(
    (name) =>
      ![
        'upload-artifact',
        'artifact-name',
        'retention-days',
        'security-watch-version',
        'upload-token',
      ].includes(name),
  )) {
    const variable = `SW_${name.replace(/-/g, '_').toUpperCase()}`;
    assert.ok(script.includes(variable), `${variable} is used`);
    assert.ok(
      action.runs.steps.some((step) => step.env?.[variable]),
      `${variable} is passed`,
    );
  }
  // The token reaches the CLI as the variable it reads, from the input, and nowhere else.
  assert.equal(
    action.runs.steps.find((step) => step.id === 'sbom').env.SECURITY_WATCH_INTAKE_TOKEN,
    '${{ inputs.upload-token }}',
  );
  const readme = readFileSync(join(root, 'README.md'), 'utf8');
  const guide = readFileSync(join(root, 'docs/sbom.md'), 'utf8');
  for (const text of [readme, guide]) {
    for (const [, tag] of text.matchAll(/ShieldaAI\/security-watch@v(\d+\.\d+\.\d+)/g))
      assert.equal(tag, version);
    for (const [, tag] of text.matchAll(/@shieldaai\/security-watch@(\d+\.\d+\.\d+)/g))
      assert.equal(tag, version);
  }

  const directory = temp(t);
  const project = writeProject(join(directory, 'project'));
  const outputs = join(directory, 'outputs');
  const summary = join(directory, 'summary');
  const action_run = (env) =>
    spawnSync('bash', [join(root, 'scripts/action-sbom.sh')], {
      cwd: directory,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        SW_PACKAGE: '@shieldaai/security-watch@0.0.0-never-installed',
        SW_CLI: `${process.execPath} ${cli}`,
        GITHUB_OUTPUT: outputs,
        GITHUB_STEP_SUMMARY: summary,
        ...env,
      },
    });
  const generated = action_run({
    SW_PROJECT: join(project, 'go'),
    SW_OUTPUT: 'go.cdx.json',
    SW_SYSTEM_ID: 'go-service',
    SW_NAME: 'Go service',
    SW_OWNER: 'Dana; rm -rf / $(touch pwned)',
    SW_ENVIRONMENT: 'production',
    SW_NOTE: 'cluster eu-1',
    SW_EXPOSURE: 'internet',
    SW_CRITICALITY: 'high',
    SW_PRODUCTION: 'true',
  });
  assert.equal(generated.status, 0, generated.stderr);
  assert.ok(!existsSync(join(directory, 'pwned')));
  assert.equal(readFileSync(outputs, 'utf8'), 'path=go.cdx.json\npackages=4\n');
  assert.match(readFileSync(summary, 'utf8'), /`go\.cdx\.json` with 4 packages/);
  const bom = JSON.parse(readFileSync(join(directory, 'go.cdx.json'), 'utf8'));
  assert.equal(bom.metadata.component.name, 'Go service');
  assert.ok(bom.metadata.properties.some((p) => p.value === 'Dana; rm -rf / $(touch pwned)'));

  // An SBOM from another tool is checked: warnings are fine, an unreadable file fails the step.
  writeFileSync(
    join(directory, 'image.cdx.json'),
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [{ purl: 'pkg:deb/debian/openssl@3.0.11' }, { purl: 'pkg:npm/express@4.21.2' }],
    }),
  );
  rmSync(outputs);
  const external = action_run({ SW_SBOM_FILE: 'image.cdx.json' });
  assert.equal(external.status, 0, external.stderr);
  assert.match(external.stdout, /image\.cdx\.json: Security Watch reads 1 packages from it \(1 warnings\)\./);
  assert.equal(readFileSync(outputs, 'utf8'), 'path=image.cdx.json\npackages=1\n');
  writeFileSync(join(directory, 'bad.json'), '{}');
  assert.equal(action_run({ SW_SBOM_FILE: 'bad.json' }).status, 1);
  assert.notEqual(action_run({ SW_PROJECT: join(directory, 'nowhere') }).status, 0);
});

test('a dependency file given as a symbolic link is refused; a linked project folder is still read', () => {
  const base = mkdtempSync(join(tmpdir(), 'sw-sbom-link-'));
  try {
    const outside = join(base, 'outside');
    mkdirSync(outside);
    writeFileSync(join(outside, 'secret.txt'), 'require a.b/c v1.0.0\n');
    const project = join(base, 'project');
    mkdirSync(project);
    symlinkSync(join(outside, 'secret.txt'), join(project, 'go.mod'));
    assert.throws(
      () => generateSbom({ project: join(project, 'go.mod'), now: NOW }),
      /go\.mod is a symbolic link; give the dependency file itself/,
    );
    const real = join(base, 'real');
    mkdirSync(real);
    writeFileSync(join(real, 'go.mod'), 'module x\n\nrequire a.b/c v1.0.0\n');
    symlinkSync(real, join(base, 'linked-folder'));
    const result = generateSbom({ project: join(base, 'linked-folder'), now: NOW });
    assert.ok(result.bom.components.some((component) => component.name === 'a.b/c'));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
