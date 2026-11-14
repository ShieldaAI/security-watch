// Guards that must refuse what they say they refuse: inventory spelling, SBOM entries, model
// version citations, plain-HTTP endpoints, an identical verification model, and the release tag.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseConfig } from '../dist/config.js';
import { privateAddress, safeHttp, validateDestination } from '../dist/http.js';
import { loadInventory } from '../dist/inventory.js';
import { importCycloneDx } from '../dist/sbom.js';
import { releaseProblem, releaseTag } from '../scripts/release-tag.mjs';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const root = fileURLToPath(new URL('../', import.meta.url));
const at = '2026-11-13T10:00:00.000Z';
function workspace(t) {
  const directory = mkdtempSync(join(tmpdir(), 'security-watch-guards-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('a capitalised npm name typed by hand is reported; legacy and imported names are not', (t) => {
  const directory = workspace(t);
  writeFileSync(
    join(directory, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: { '': {}, 'node_modules/OldCapitalName': { version: '1.0.0' } },
    }),
  );
  writeFileSync(
    join(directory, 'systems.json'),
    JSON.stringify({
      systems: [
        {
          id: 'api',
          name: 'API',
          updated_at: at,
          lockfile: 'package-lock.json',
          libraries: [
            'npm:Lodash@4.17.20',
            'npm:JSONStream@1.3.5',
            'npm:lodash@4.17.20',
            'python:Django==5.0',
          ],
          components: [{ id: 'typed', ecosystem: 'npm', name: 'Express', version: '4.19.0' }],
        },
      ],
    }),
  );
  const inventory = loadInventory(join(directory, 'systems.json'));
  // Every entry is kept: the legacy spelling is the real name of that package.
  assert.deepEqual(inventory.systems[0].components.map((component) => component.name).sort(), [
    'Express',
    'JSONStream',
    'Lodash',
    'OldCapitalName',
    'django',
    'lodash',
  ]);
  assert.equal(inventory.import_warnings.length, 2);
  assert.match(
    inventory.import_warnings.join('\n'),
    /api: npm package name Express contains capital letters/,
  );
  assert.match(inventory.import_warnings.join('\n'), /npm package name Lodash .* Write lodash unless/);

  writeFileSync(
    join(directory, 'security-watch.yaml'),
    'version: 1\ninventory: ./systems.json\nsources: { cve_now: false, hacker_news: false }\n',
  );
  const doctor = spawnSync(process.execPath, [cli, 'doctor', '--config', 'security-watch.yaml'], {
    cwd: directory,
    encoding: 'utf8',
    timeout: 15_000,
  });
  assert.equal(doctor.status, 0, doctor.stderr);
  assert.equal(JSON.parse(doctor.stdout).import_warnings.length, 2);
});

test('doctor exits with a failing status whenever it reports ok: false', (t) => {
  const directory = workspace(t);
  writeFileSync(
    join(directory, 'systems.json'),
    JSON.stringify({ systems: [{ id: 'api', name: 'API', updated_at: at }] }),
  );
  writeFileSync(
    join(directory, 'security-watch.yaml'),
    [
      'version: 1',
      'inventory: ./systems.json',
      'sources: { cve_now: false, hacker_news: false }',
      'policy: { health_channels: [email] }',
      'notifications: { email: { smtp_url_env: GUARD_SMTP, from: watch@example.org, to: [ops@example.org] } }',
    ].join('\n'),
  );
  const doctor = (address) =>
    spawnSync(process.execPath, [cli, 'doctor', '--config', 'security-watch.yaml'], {
      cwd: directory,
      encoding: 'utf8',
      timeout: 15_000,
      env: { ...process.env, GUARD_SMTP: address },
    });
  for (const address of ['smtps://alerts:pa%ss@mail.example.org', 'https://mail.example.org']) {
    const result = doctor(address);
    const report = JSON.parse(result.stdout);
    assert.equal(report.ok, false, address);
    assert.equal(report.problems.length, 1, address);
    assert.equal(result.status, 2, address);
  }
  const usable = doctor('smtps://alerts:secret@mail.example.org');
  assert.equal(JSON.parse(usable.stdout).ok, true);
  assert.equal(usable.status, 0);
});

test('an SBOM component this application cannot read is left out with a warning', (t) => {
  const directory = workspace(t);
  const sbom = (components) => {
    const path = join(directory, 'bom.json');
    writeFileSync(path, JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components }));
    const { components: imported, warnings } = importCycloneDx(path);
    return {
      components: imported.map((item) => `${item.ecosystem}:${item.name}@${item.version ?? ''}`),
      warnings,
    };
  };
  const good = { purl: 'pkg:npm/good@1.0.0' };
  // An empty version means "not known", and the package type is case-insensitive.
  assert.deepEqual(sbom([good, { purl: 'pkg:npm/noversion', version: '' }]), {
    components: ['npm:good@1.0.0', 'npm:noversion@'],
    warnings: [],
  });
  assert.deepEqual(sbom([good, { purl: 'pkg:NPM/foo@1.0.0' }]).components, [
    'npm:good@1.0.0',
    'npm:foo@1.0.0',
  ]);
  // Python reads 1.0 and 1.0.0 as the same release.
  assert.deepEqual(sbom([good, { purl: 'pkg:pypi/foo@1.0', version: '1.0.0' }]), {
    components: ['npm:good@1.0.0', 'PyPI:foo@1.0'],
    warnings: [],
  });
  for (const [bad, warning] of [
    [{ purl: 'pkg:npm/foo', version: 7 }, /version is not text; not imported/],
    [{ purl: 'not a package url' }, /package URL is not valid; not imported/],
  ]) {
    const result = sbom([good, bad, { purl: 'pkg:npm/after@2.0.0' }]);
    assert.deepEqual(result.components, ['npm:good@1.0.0', 'npm:after@2.0.0'], JSON.stringify(bad));
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0], warning);
  }
  // Two genuinely different versions for one component remain a contradiction in the document.
  for (const conflict of [
    { purl: 'pkg:npm/foo@1.0.0', version: '2.0.0' },
    { purl: 'pkg:pypi/foo@1.0', version: '1.0.1' },
  ])
    assert.throws(() => sbom([good, conflict]), /Conflicting SBOM package versions/);
});

test('plain HTTP is accepted only for private and local destinations', async () => {
  const model =
    (endpoint, allow = true) =>
    () =>
      parseConfig({
        version: 1,
        models: {
          enabled: true,
          analysis: { provider: 'openai-compatible', model: 'm', endpoint, allow_private_endpoint: allow },
        },
      });
  for (const endpoint of [
    'http://localhost:11434/v1',
    'http://localhost./v1',
    'http://127.0.0.1:11434/v1',
    'http://[::1]:11434/v1',
    'http://10.1.2.3:8000/v1',
    'http://100.100.1.1/v1',
    'http://[fd00::1]/v1',
    'http://ollama:11434/v1',
    'http://ollama.ml-tools:11434/v1',
    'http://ollama.default.svc.cluster.local/v1',
    'http://gpu.tailnet-1234.ts.net/v1',
    'http://gpu.home/v1',
    'http://gpu.test/v1',
  ])
    assert.doesNotThrow(model(endpoint), endpoint);
  for (const endpoint of [
    'http://8.8.8.8/v1',
    'http://134744072/v1',
    'http://[64:ff9b::808:808]/v1',
    'http://[2002:808:808::1]/v1',
    'http://[::ffff:8.8.8.8]/v1',
    'http://[2001:4860:4860::8888]/v1',
    'http://224.0.0.1/v1',
    'http://240.1.1.1/v1',
    'http://api.openai.com/v1',
    'http://example.com./v1',
    'http://1.1.1.1.nip.io/v1',
  ])
    assert.throws(model(endpoint), /only an explicit private or local endpoint may use HTTP/, endpoint);
  assert.throws(model('http://127.0.0.1:11434/v1', false), /private or local endpoint/);

  // The request itself is refused too, whatever the configuration accepted.
  for (const address of ['10.0.0.1', '127.0.0.1', '::1', 'fd00::1', '100.64.0.1', '169.254.1.1'])
    assert.equal(privateAddress(address), true, address);
  for (const address of [
    '8.8.8.8',
    '64:ff9b::808:808',
    '2002:808:808::1',
    '::ffff:8.8.8.8',
    '224.0.0.1',
    'x',
  ])
    assert.equal(privateAddress(address), false, address);
  assert.throws(() => validateDestination('http://8.8.8.8/v1', true), /DESTINATION_DENIED/);
  assert.throws(() => validateDestination('http://[64:ff9b::808:808]/v1', true), /DESTINATION_DENIED/);
  assert.doesNotThrow(() => validateDestination('http://127.0.0.1:1/v1', true));
  assert.doesNotThrow(() => validateDestination('https://8.8.8.8/v1', true));
  await assert.rejects(
    safeHttp('http://[2002:808:808::1]/v1', { allowPrivate: true, timeoutMs: 500 }),
    /DESTINATION_DENIED/,
  );
});

test('a verification model that is the analysis model in other words is refused', () => {
  const pair = (analysis, verification) => () =>
    parseConfig({ version: 1, models: { enabled: true, analysis, verification } });
  const openai = { provider: 'openai', model: 'gpt-x' };
  for (const verification of [
    openai,
    { ...openai, disclosure_profile: 'deployment-context' },
    { ...openai, endpoint: 'https://api.openai.com/v1/responses' },
    { ...openai, endpoint: 'https://API.openai.com/v1/responses/' },
    { ...openai, model: 'GPT-X' },
    { provider: 'openai-compatible', model: 'gpt-x', endpoint: 'https://api.openai.com/v1/responses' },
  ])
    assert.throws(
      pair(openai, verification),
      /must differ from the analysis model/,
      JSON.stringify(verification),
    );
  assert.doesNotThrow(pair(openai, { provider: 'openai', model: 'gpt-y' }));
  assert.doesNotThrow(pair(openai, { provider: 'anthropic', model: 'gpt-x' }));
});

test('settings left out get the same defaults as an empty section', () => {
  const omitted = parseConfig({ version: 1 });
  const empty = parseConfig({ version: 1, models: {}, sources: {}, policy: {} });
  assert.deepEqual(omitted.models, empty.models);
  assert.deepEqual(omitted.sources, empty.sources);
  assert.deepEqual(omitted.policy, empty.policy);
  assert.equal(omitted.models.daily_token_limit, 1_000_000);
});

test('the release check refuses a tag that is wrong for the version, and a publish that states none', () => {
  assert.equal(releaseTag('1.0.0-rc.1'), 'next');
  assert.equal(releaseTag('1.0.0'), 'latest');
  const candidate = { version: '1.0.0-rc.1', publishConfig: { tag: 'next' } };
  const stable = { version: '1.0.0', publishConfig: { tag: 'latest' } };
  // `npm publish` and `npm publish --tag latest` look the same to a lifecycle script: both refused.
  assert.match(releaseProblem(candidate, {}), /npm run release/);
  assert.match(releaseProblem(stable, {}), /npm run release/);
  assert.equal(releaseProblem(candidate, { SECURITY_WATCH_RELEASE_TAG: 'next' }), undefined);
  assert.equal(releaseProblem(stable, { SECURITY_WATCH_RELEASE_TAG: 'latest' }), undefined);
  assert.match(
    releaseProblem(candidate, { SECURITY_WATCH_RELEASE_TAG: 'latest' }),
    /under the next tag, not latest/,
  );
  assert.match(
    releaseProblem(stable, { SECURITY_WATCH_RELEASE_TAG: 'next' }),
    /under the latest tag, not next/,
  );
  assert.match(
    releaseProblem(candidate, { SECURITY_WATCH_RELEASE_TAG: 'next', npm_config_tag: 'beta' }),
    /not beta/,
  );
  assert.match(
    releaseProblem({ version: '1.0.0-rc.1', publishConfig: { tag: 'latest' } }, {}),
    /publishConfig\.tag must be next/,
  );
  assert.match(releaseProblem({ version: '1.0.0' }, {}), /publishConfig\.tag must be latest/);
  // The release command refuses a tag typed by hand before it starts npm.
  const release = spawnSync(process.execPath, [join(root, 'scripts/release.mjs'), '--tag', 'latest'], {
    encoding: 'utf8',
    env: { ...process.env, npm_execpath: '' },
  });
  assert.notEqual(release.status, 0);
  assert.match(release.stderr, /do not pass --tag/);
});

test('the published types compile together for a consumer', { timeout: 120_000 }, (t) => {
  const compiler = join(root, 'node_modules/typescript/bin/tsc');
  if (!existsSync(compiler)) {
    // The container test stage has no compiler; `npm run check` runs this through check-package.
    t.skip('TypeScript is not installed here');
    return;
  }
  const directory = mkdtempSync(join(tmpdir(), 'security-watch-types-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  writeFileSync(
    join(directory, 'consumer.mts'),
    `import { ModelAnalyzer, Store, parseConfig, safeHttp, deliverPending, attachLocation, type ModelState, type FindingLocation, type DeliveryOptions } from '${join(root, 'dist/index.js')}';
const config = parseConfig({ version: 1 });
const store = new Store(':memory:');
export const analyzer = new ModelAnalyzer(config, store, safeHttp);
const state: ModelState = { getMeta: () => undefined, setMeta: () => undefined, reserveBudget: () => true };
export const custom = new ModelAnalyzer(config, state, safeHttp);
const options: DeliveryOptions = { now: Date.now() };
export const delivered = await deliverPending(store, config, safeHttp, options);
export const revision: number = store.acknowledge('x', 1);
export const where: FindingLocation | undefined = attachLocation({} as never, { systems: [] }).location;
// Worker internals stay out of the published Store type.
// @ts-expect-error
store.claimDue();
`,
  );
  const result = spawnSync(
    process.execPath,
    [
      compiler,
      'consumer.mts',
      '--noEmit',
      '--module',
      'NodeNext',
      '--moduleResolution',
      'NodeNext',
      '--target',
      'ES2023',
      '--strict',
      '--skipLibCheck',
      'false',
      '--types',
      'node',
      '--typeRoots',
      join(root, 'node_modules/@types'),
    ],
    { cwd: directory, encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('a model must cite a version as the source wrote it, not a digit found inside another number', async () => {
  const { validateAnalysis } = await import('../dist/models.js');
  const quote = 'Example Database 4.0 through 4.5 are affected by CVE-2026-40001, fixed in 4.6.';
  const story = {
    id: 'feed:x:entry:1',
    source: 'feed:x',
    kind: 'news',
    title: 'Example Database remote code execution',
    url: 'https://example.com/s',
    description: quote,
    aliases: [],
    severity: 'unknown',
    modified_at: at,
    fetched_at: at,
    packages: [],
    content_status: 'full',
  };
  const analysis = (versions) => ({
    relevance: 'irrelevant',
    priority: 'low',
    summary: 'The installed version is outside the affected range.',
    evidence_ids: [story.id],
    quotes: [{ evidence_id: story.id, quote }],
    news_analysis: {
      classification: 'new_vulnerability',
      impact: 'not_affected',
      affected_products: ['Example Database'],
      affected_versions: versions,
      prerequisites: [],
      rationale: 'Version 4.7 is later than the fixed release.',
      quotes: [{ evidence_id: story.id, quote }],
    },
  });
  for (const versions of [['4.0 through 4.5'], ['4.0', '4.5'], ['4.6']])
    assert.doesNotThrow(() => validateAnalysis(analysis(versions), [story]), JSON.stringify(versions));
  // "4" and "0" occur only inside 4.0, 4.5 and the CVE number; "40001" only inside the identifier.
  for (const versions of [['4'], ['0'], ['5'], ['2026'], ['40001'], ['4.0', '4']])
    assert.throws(
      () => validateAnalysis(analysis(versions), [story]),
      /MODEL_UNSUPPORTED_NEWS_CLAIM/,
      JSON.stringify(versions),
    );
});
