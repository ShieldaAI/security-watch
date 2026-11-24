import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadInventory,
  parseConfig,
  parseLibraryList,
  importCycloneDx,
  ModelAnalyzer,
} from '../dist/index.js';
import { assess, decide } from '../dist/assessment.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const at = new Date(NOW).toISOString();
function workspace(t) {
  const directory = mkdtempSync(join(tmpdir(), 'watch-import-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return (name, content) => {
    const file = join(directory, name);
    writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content));
    return file;
  };
}
const bom = (components, extra = {}) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  components,
  ...extra,
});
const identities = (result) => result.components.map((item) => [item.ecosystem, item.name, item.version]);

test('a legacy npm name or one unreadable lockfile entry does not reject the whole inventory', (t) => {
  const write = workspace(t);
  write('package-lock.json', {
    lockfileVersion: 3,
    packages: {
      '': { name: 'app' },
      'node_modules/lodash': { version: '4.17.21' },
      'node_modules/JSONStream': { version: '1.3.5' },
      'node_modules/Bad Name': { version: '1.0.0' },
    },
  });
  const inventory = loadInventory(
    write(
      'systems.yaml',
      `systems:\n  - id: api\n    name: API\n    updated_at: ${at}\n    lockfile: ./package-lock.json\n    libraries: ["npm:JSONStream@1.3.5", "composer:Laravel/Framework@9.0.0"]\n`,
    ),
  );
  const names = inventory.systems[0].components.map((component) => component.name);
  // The library and the lockfile entry name the same version: one component (1.4.1).
  assert.deepEqual(names.sort(), ['JSONStream', 'laravel/framework', 'lodash'].sort());
  assert.deepEqual(inventory.import_warnings, [
    'api: Lockfile entry node_modules/Bad Name: unsupported package name or version; not imported.',
  ]);
  // npm names are case-sensitive: the legacy spelling is kept and scopes stay lower-case only.
  assert.equal(parseLibraryList('npm:JSONStream@1.3.5')[0].name, 'JSONStream');
  assert.throws(() => parseLibraryList('npm:@Scope/pkg@1.0.0'), /Invalid npm package name/);
  assert.throws(() => parseLibraryList('npm:bad!name'), /Invalid npm package name/);
});

test('CycloneDX documents that follow the schema are imported', (t) => {
  const write = workspace(t);
  const leaf = importCycloneDx(
    write(
      'leaf.json',
      bom(
        [
          { type: 'library', 'bom-ref': 'a', purl: 'pkg:npm/alpha@1.0.0' },
          { type: 'library', 'bom-ref': 'b', purl: 'pkg:npm/beta@1.0.0' },
        ],
        { dependencies: [{ ref: 'a', dependsOn: ['b'] }, { ref: 'b' }] },
      ),
    ),
  );
  assert.equal(leaf.components.length, 2);
  assert.deepEqual(leaf.dependencies, [
    { ref: 'a', depends_on: ['b'] },
    { ref: 'b', depends_on: [] },
  ]);

  const mixed = importCycloneDx(
    write(
      'mixed.json',
      bom([
        { type: 'library', purl: 'pkg:npm/@angular/core' },
        { type: 'library', purl: 'pkg:golang/github.com/gorilla/mux@v1.8.0', version: '1.8.0' },
        { type: 'library', purl: 'pkg:npm/JSONStream@1.3.5' },
        { type: 'library', purl: 'pkg:composer/Laravel/Framework@9.0.0' },
        { type: 'library', purl: 'pkg:npm/gitdep@git+https://example.com/x.git' },
      ]),
    ),
  );
  assert.deepEqual(identities(mixed), [
    ['npm', '@angular/core', undefined],
    ['Go', 'github.com/gorilla/mux', 'v1.8.0'],
    ['npm', 'JSONStream', '1.3.5'],
    ['Packagist', 'laravel/framework', '9.0.0'],
  ]);
  assert.equal(mixed.warnings.length, 1);
  assert.match(mixed.warnings[0], /^Component 5: .*not imported\.$/);

  // A document that contradicts itself is still refused.
  assert.throws(
    () =>
      importCycloneDx(
        write('conflict.json', bom([{ type: 'library', purl: 'pkg:npm/alpha@1.0.0', version: '2.0.0' }])),
      ),
    /Conflicting SBOM package versions/,
  );
  assert.throws(
    () => importCycloneDx(write('bad.json', bom([], { dependencies: [{ ref: 'a', dependsOn: 'b' }] }))),
    /Invalid SBOM dependency references/,
  );
});

const local = {
  provider: 'openai-compatible',
  model: 'analysis-model',
  api_key_env: 'IMPORT_MODEL_UNUSED',
  endpoint: 'http://127.0.0.1:1234/v1/chat/completions',
  allow_private_endpoint: true,
};
const modelConfig = (models = {}, policy = {}) =>
  parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false },
    models: { enabled: true, analysis: local, ...models },
    policy: { news: { levels: ['high', 'critical'], channels: ['slack'] }, ...policy },
    notifications: { slack: { webhook_url_env: 'IMPORT_SLACK_UNUSED' } },
  });

test('a verification model identical to the analysis model is refused', () => {
  assert.throws(() => modelConfig({ verification: { ...local } }), /must differ from the analysis model/);
  assert.equal(
    modelConfig({ verification: { ...local, model: 'second-model' } }).models.verification.model,
    'second-model',
  );
  const elsewhere = { ...local, endpoint: 'http://127.0.0.1:4321/v1/chat/completions' };
  assert.equal(modelConfig({ verification: elsewhere }).models.verification.endpoint, elsewhere.endpoint);
});

test('plain HTTP is accepted only for a local or private model endpoint', () => {
  const endpoint = (value, allow = true) =>
    modelConfig({ analysis: { ...local, endpoint: value, allow_private_endpoint: allow } });
  for (const value of [
    'http://127.0.0.1:1234/v1/chat/completions',
    'http://localhost:11434/v1/chat/completions',
    'http://10.1.2.3/v1/chat/completions',
    'http://[::1]:8080/v1/chat/completions',
    'http://ollama:11434/v1/chat/completions',
    'http://llm.internal/v1/chat/completions',
  ])
    assert.equal(endpoint(value).models.analysis.endpoint, value);
  for (const value of ['http://llm.example.com/v1/chat/completions', 'http://8.8.8.8/v1/chat/completions'])
    assert.throws(() => endpoint(value), /only an explicit private or local endpoint may use HTTP/, value);
  assert.throws(() => endpoint('http://127.0.0.1:1234/v1/chat/completions', false));
  assert.equal(endpoint('https://llm.example.com/v1/chat/completions').models.enabled, true);
});

test('the default token allowance covers the default number of daily requests', async () => {
  const config = modelConfig({ verification: { ...local, model: 'second-model' } });
  assert.equal(config.models.daily_request_limit, 100);
  const quote =
    'Example Database 4.0 through 4.5 are affected by a remote code execution flaw fixed in 4.6. ';
  const story = {
    id: 'feed:x:entry:1',
    source: 'feed:x',
    kind: 'news',
    title: 'Example Database remote code execution',
    url: 'https://example.com/s',
    description: quote.repeat(200).slice(0, 16_000),
    aliases: [],
    severity: 'unknown',
    modified_at: at,
    fetched_at: at,
    packages: [],
    content_status: 'full',
  };
  const system = {
    id: 'prod',
    name: 'Production',
    environment: 'production',
    exposure: 'internet',
    criticality: 'high',
    updated_at: at,
    components: [],
    products: [{ name: 'Example Database', version: '4.7', keywords: [] }],
    keywords: [],
  };
  const reserved = [];
  const state = new Map();
  const store = {
    getMeta: (key) => state.get(key),
    setMeta: (key, value) => state.set(key, value),
    reserveBudget: (...args) => {
      reserved.push(args[4]);
      return true;
    },
  };
  const [finding] = assess({ systems: [system] }, [story], config, NOW);
  await new ModelAnalyzer(
    config,
    store,
    async () => ({ status: 200, headers: {}, body: '{}' }),
    () => NOW,
    undefined,
    { IMPORT_MODEL_UNUSED: 'k' },
  ).analyze(finding, system, [story]);
  assert.ok(reserved.length >= 1);
  const largest = Math.max(...reserved);
  // The longest article the defaults allow, at the full default request count, fits the default limit.
  assert.ok(largest * config.models.daily_request_limit <= config.models.daily_token_limit, String(largest));
});

test('a decisive AI news claim needs a real version citation and a fully read article', async () => {
  const quote = 'Example Database 4.0 through 4.5 are affected by a remote code execution flaw fixed in 4.6.';
  const system = {
    id: 'prod',
    name: 'Production',
    environment: 'production',
    exposure: 'internet',
    criticality: 'high',
    updated_at: at,
    components: [],
    products: [{ name: 'Example Database', version: '4.7', keywords: [] }],
    keywords: [],
  };
  const config = modelConfig({}, { ai_dismissals: 'record' });
  const run = async (versions, contentStatus) => {
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
      ...(contentStatus ? { content_status: contentStatus } : {}),
    };
    const state = new Map();
    const store = {
      getMeta: (key) => state.get(key),
      setMeta: (key, value) => state.set(key, value),
      reserveBudget: () => true,
    };
    const http = async () => ({
      status: 200,
      headers: {},
      body: JSON.stringify({
        choices: [
          {
            finish_reason: 'stop',
            message: {
              content: JSON.stringify({
                relevance: 'irrelevant',
                priority: 'low',
                summary: 's',
                evidence_ids: [story.id],
                quotes: [{ excerpt_id: 'e0s0' }],
                news_analysis: {
                  classification_and_impact: 'new_vulnerability:not_affected',
                  affected_products: ['Example Database'],
                  affected_versions: versions,
                  prerequisites: [],
                  rationale: 'r',
                  quotes: [{ excerpt_id: 'e0s0' }],
                },
              }),
            },
          },
        ],
      }),
    });
    const [finding] = assess({ systems: [system] }, [story], config, NOW);
    const analysed = await new ModelAnalyzer(config, store, http, () => NOW, undefined, {
      IMPORT_MODEL_UNUSED: 'k',
    }).analyze(finding, system, [story]);
    return { impact: analysed.news_analysis?.impact, action: decide(analysed, config).action };
  };
  // The control: a real citation on a fully read article is accepted, and record mode stays quiet.
  assert.deepEqual(await run(['4.0 through 4.5'], 'full'), { impact: 'not_affected', action: 'record' });
  for (const versions of [[' '], ['a'], ['.'], ['through']]) {
    const result = await run(versions, 'full');
    assert.notEqual(result.impact, 'not_affected', JSON.stringify(versions));
    assert.notEqual(result.action, 'record', JSON.stringify(versions));
  }
  for (const status of ['excerpt', 'unavailable', undefined]) {
    const result = await run(['4.0 through 4.5'], status);
    assert.notEqual(result.impact, 'not_affected', String(status));
    assert.notEqual(result.action, 'record', String(status));
  }
});
