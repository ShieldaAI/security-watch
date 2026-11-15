import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ModelAnalyzer, loadInventory, parseConfig, assess } from '../dist/index.js';
import { PROMPT_VERSION } from '../dist/models.js';

const NOW = Date.parse('2026-11-04T10:00:00Z');
const AT = new Date(NOW).toISOString();
const QUOTE = 'The alpha package before version 2.0.0 has a security vulnerability.';
const evidence = {
  id: 'CVE-2026-12345',
  source: 'fixture',
  kind: 'advisory',
  title: 'Alpha security advisory',
  description: QUOTE,
  url: 'https://example.com/public-advisory',
  severity: 'critical',
  modified_at: AT,
  fetched_at: AT,
  aliases: [],
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
};
const canaries = {
  id: 'private-component-identity-canary',
  systemId: 'private-system-identity-canary',
  name: 'private-system-name-canary',
  owner: 'private-owner-canary',
  url: 'https://internal.example/private-repository-canary',
  origin: '/private/source-origin-canary',
  revision: 'private-source-revision-canary',
  purl: 'pkg:npm/private-package-url-canary@1.0.0',
  sbom: 'private-sbom-reference-canary',
  dependency: 'private-dependency-reference-canary',
  provenance: 'private-provenance-canary',
  observation: 'private-observation-canary',
  signature: 'private-signature-reference-canary',
  attestation: 'private-attestation-reference-canary',
  remediation: 'private-remediation-ticket-canary',
  operator: 'private-operator-canary',
  configuration: 'private-configuration-canary',
  keyword: 'private-unmatched-keyword-canary',
  productKeyword: 'private-product-keyword-canary',
  systemNote: 'private-system-note-canary',
  componentNote: 'private-component-note-canary',
  productNote: 'private-product-note-canary',
};
const environment = 'private-deployment-environment-canary';

function inventory(t) {
  const directory = mkdtempSync(join(tmpdir(), 'watch-model-disclosure-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = join(directory, 'inventory.json');
  const rich = {
    artifact_kind: 'mcp_server',
    source_url: canaries.url,
    source_revision: canaries.revision,
    origin: canaries.origin,
    purl: canaries.purl,
    digest: `sha256:${'a'.repeat(64)}`,
    sbom_ref: canaries.sbom,
    dependencies: [{ ref: canaries.dependency, component_id: canaries.id }],
    provenance: { source: canaries.provenance, reference: canaries.url, recorded_at: AT },
    observation: { observed_at: AT, method: canaries.observation, reference: canaries.url },
    signature_verification: {
      status: 'verified',
      reference: canaries.signature,
      recorded_by: canaries.operator,
      recorded_at: AT,
    },
    attestation_verification: {
      status: 'verified',
      reference: canaries.attestation,
      recorded_by: canaries.operator,
      recorded_at: AT,
    },
    remediation_evidence: [
      {
        event_id: evidence.id,
        stage: 'deployed',
        verification: 'supported',
        reference: canaries.remediation,
        recorded_by: canaries.operator,
        recorded_at: AT,
      },
    ],
  };
  writeFileSync(
    file,
    JSON.stringify({
      systems: [
        {
          ...rich,
          id: canaries.systemId,
          name: canaries.name,
          owner: canaries.owner,
          note: canaries.systemNote,
          environment,
          exposure: 'internet',
          criticality: 'critical',
          updated_at: AT,
          configuration: { feature: canaries.configuration },
          sbom_dependencies: [{ ref: canaries.sbom, depends_on: [canaries.dependency] }],
          components: [
            {
              ...rich,
              id: canaries.id,
              ecosystem: 'npm',
              name: 'alpha',
              version: '1.0.0',
              note: canaries.componentNote,
            },
          ],
          products: [
            {
              name: 'Alpha',
              version: '1.0.0',
              keywords: ['alpha', canaries.productKeyword],
              note: canaries.productNote,
            },
          ],
          keywords: ['alpha', canaries.keyword],
        },
      ],
    }),
  );
  return loadInventory(file);
}

function state() {
  const values = new Map();
  return {
    getMeta: (key) => values.get(key),
    setMeta: (key, value) => values.set(key, value),
    reserveBudget: () => true,
  };
}
function spec(provider, disclosure_profile) {
  return {
    provider,
    model: 'synthetic-fixture',
    api_key_env: 'SYNTHETIC_KEY',
    ...(disclosure_profile ? { disclosure_profile } : {}),
  };
}
function config(analysis = spec('openai'), verification) {
  return parseConfig({
    version: 1,
    models: { enabled: true, analysis, ...(verification ? { verification } : {}) },
  });
}
function fixtureTransport(requests) {
  return async (url, request) => {
    const body = JSON.parse(request.body);
    const context = JSON.parse(body.input ?? body.messages[0].content);
    requests.push({ url, body, context, serialized: request.body });
    const output = JSON.stringify({
      relevance: 'relevant',
      priority: 'critical',
      summary: 'The cited advisory describes the package vulnerability.',
      evidence_ids: [evidence.id],
      quotes: [{ excerpt_id: context.evidence[0].excerpts[0].id }],
      news_analysis: null,
    });
    return {
      status: 200,
      headers: {},
      body: JSON.stringify(
        body.input
          ? {
              status: 'completed',
              output: [{ type: 'message', content: [{ type: 'output_text', text: output }] }],
            }
          : { stop_reason: 'end_turn', content: [{ type: 'text', text: output }] },
      ),
    };
  };
}
function analyze(cfg, loaded, requests, store = state(), sources = [evidence]) {
  const finding = assess(loaded, sources, cfg, NOW).find((a) => a.category === 'library');
  return new ModelAnalyzer(cfg, store, fixtureTransport(requests), () => NOW, undefined, {
    SYNTHETIC_KEY: 'synthetic-not-a-real-credential',
  }).analyze(finding, loaded.systems[0], sources);
}
function assertMinimal(context) {
  assert.deepEqual(context.system, {
    inventory_status: 'current',
    components: [{ id: 'c0', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
    products: [{ id: 'p0', name: 'Alpha', version: '1.0.0' }],
  });
  assert.equal(context.target.component_id, 'c0');
  assert.equal(context.target.installed_version_known, true);
  assert.equal(context.disclosure_profile, 'minimal');
}
function assertNoPrivateMetadata(serialized) {
  for (const value of Object.values(canaries)) assert(!serialized.includes(value), `Leaked ${value}`);
  for (const field of [
    'source_url',
    'remediation_evidence',
    'recorded_by',
    'source_revision',
    'provenance',
    'sbom_ref',
    'dependencies',
    'signature_verification',
    'attestation_verification',
  ]) {
    assert(!serialized.includes(`\\"${field}\\"`), `Leaked field ${field}`);
  }
}

test('both providers use minimal loaded-inventory projections for analysis and verification', async (t) => {
  for (const [first, second] of [
    ['openai', 'anthropic'],
    ['anthropic', 'openai'],
  ])
    await t.test(`${first} then ${second}`, async (t) => {
      const loaded = inventory(t);
      const before = structuredClone(loaded);
      const requests = [];
      const cfg = config(spec(first), spec(second));
      const result = await analyze(cfg, loaded, requests);
      assert.equal(result.ai.status, 'complete');
      assert.equal(result.ai.prompt_version, PROMPT_VERSION);
      assert.equal(result.applicability, 'affected');
      assert.equal(requests.length, 2);
      for (const request of requests) {
        assertMinimal(request.context);
        assertNoPrivateMetadata(request.serialized);
        assert(!request.serialized.includes(environment));
        assert.match(
          request.body.instructions ?? request.body.system,
          /Undisclosed deployment context.*unknown/,
        );
        assert.deepEqual(request.context.evidence[0].packages, evidence.packages);
      }
      assert.deepEqual(loaded, before, 'Projection must not strip local operator evidence');
    });
});

test('deployment disclosure is opt-in separately for each model and never includes rich metadata', async (t) => {
  for (const first of ['openai', 'anthropic'])
    for (const liberalRole of ['analysis', 'verification'])
      await t.test(`${first} ${liberalRole}`, async (t) => {
        const second = first === 'openai' ? 'anthropic' : 'openai';
        const loaded = inventory(t),
          requests = [];
        const cfg = config(
          spec(first, liberalRole === 'analysis' ? 'deployment-context' : 'minimal'),
          spec(second, liberalRole === 'verification' ? 'deployment-context' : 'minimal'),
        );
        assert.equal((await analyze(cfg, loaded, requests)).ai.status, 'complete');
        assert.equal(requests.length, 2);
        requests.forEach((request, index) => {
          assertNoPrivateMetadata(request.serialized);
          if (index === (liberalRole === 'analysis' ? 0 : 1)) {
            assert.equal(request.context.system.environment, environment);
            assert.equal(request.context.system.exposure, 'internet');
            assert.equal(request.context.system.criticality, 'critical');
            assert.deepEqual(request.context.system.keywords, ['alpha']);
            assert.deepEqual(request.context.system.products[0].keywords, ['alpha']);
          } else {
            assertMinimal(request.context);
            assert(!request.serialized.includes(environment));
          }
        });
      });
});

test('future package-claim metadata cannot widen model disclosure', async (t) => {
  const loaded = inventory(t),
    requests = [];
  const enriched = {
    ...evidence,
    packages: [{ ...evidence.packages[0], source_url: canaries.url, recorded_by: canaries.operator }],
  };
  assert.equal((await analyze(config(), loaded, requests, state(), [enriched])).ai.status, 'complete');
  assertNoPrivateMetadata(requests[0].serialized);
  assert.deepEqual(requests[0].context.evidence[0].packages, evidence.packages);
});

test('disclosure cache keys normalize defaults and isolate profile changes and target versions', async (t) => {
  const loaded = inventory(t),
    requests = [],
    store = state();
  const cfg = config();
  delete cfg.models.analysis.disclosure_profile;
  await analyze(cfg, loaded, requests, store);
  cfg.models.analysis.disclosure_profile = 'minimal';
  await analyze(cfg, loaded, requests, store);
  assert.equal(requests.length, 1, 'Omitted and explicit minimal have the same contract');
  cfg.models.analysis.disclosure_profile = 'deployment-context';
  await analyze(cfg, loaded, requests, store);
  assert.equal(requests.length, 2, 'An opt-in does not reuse the minimal assessment');
  cfg.models.analysis.disclosure_profile = 'minimal';
  await analyze(cfg, loaded, requests, store);
  assert.equal(requests.length, 2, 'Reverting the policy can reuse only its matching cache');
  loaded.systems[0].components[0].version = '1.1.0';
  await analyze(cfg, loaded, requests, store);
  assert.equal(requests.length, 3, 'Version changes invalidate projected context');
});

test('model-off processing preserves deterministic findings and spends no provider budget', async (t) => {
  const loaded = inventory(t),
    cfg = config();
  cfg.models.enabled = false;
  const finding = assess(loaded, [evidence], cfg, NOW).find((a) => a.category === 'library');
  const fail = () => {
    throw new Error('Model-off processing must not access provider/cache/budget');
  };
  const result = await new ModelAnalyzer(
    cfg,
    { getMeta: fail, setMeta: fail, reserveBudget: fail },
    fail,
    () => NOW,
  ).analyze(finding, loaded.systems[0], [evidence]);
  assert.equal(result, finding);
  assert.equal(result.applicability, 'affected');
  assert.equal(result.priority, 'critical');
});

test('disclosure profiles reject typos, truthy values and arbitrary field grants', () => {
  assert.equal(config().models.analysis.disclosure_profile, 'minimal');
  for (const value of ['full', 'Minimal', '', true, null, { include: ['source_url'] }]) {
    assert.throws(() =>
      parseConfig({ version: 1, models: { analysis: { ...spec('openai'), disclosure_profile: value } } }),
    );
  }
});
