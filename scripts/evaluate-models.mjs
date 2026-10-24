import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { parseConfig } from '../dist/config.js';
import { safeHttp } from '../dist/http.js';
import { ModelAnalyzer, PROMPT_VERSION } from '../dist/models.js';
import { PROVIDERS, modelOutputFormat } from '../dist/providers.js';
import { memoryState } from './check-models.mjs';

const corpusText = readFileSync(new URL('../test/fixtures/model-evaluation.json', import.meta.url), 'utf8');
export const CORPUS = JSON.parse(corpusText);
export const CORPUS_SHA256 = createHash('sha256').update(corpusText).digest('hex');
const ratio = (value, total) => (total ? value / total : null);

export function scoreEvaluation(results) {
  const attempted = results.filter((row) => row.status !== 'skipped');
  const accepted = attempted.filter((row) => row.status === 'accepted');
  const exact = accepted.filter(
    (row) =>
      row.predicted.classification === row.expected.classification &&
      row.predicted.impact === row.expected.impact,
  ).length;
  const confusion = { classification: {}, impact: {} };
  for (const row of attempted)
    for (const field of ['classification', 'impact']) {
      const actual = row.status === 'accepted' ? row.predicted[field] : `[${row.status}]`;
      const key = `${row.expected[field]} -> ${actual}`;
      confusion[field][key] = (confusion[field][key] ?? 0) + 1;
    }
  const actionable = attempted.filter((row) => ['affected', 'unknown'].includes(row.expected.impact));
  const falseExclusions = actionable.filter(
    (row) => row.status === 'accepted' && ['not_affected', 'not_applicable'].includes(row.predicted.impact),
  ).length;
  const positives = attempted.filter((row) => row.expected.impact === 'affected');
  const binary = accepted.filter((row) => row.expected.impact !== 'unknown');
  const truePositives = binary.filter(
    (row) => row.expected.impact === 'affected' && row.predicted.impact === 'affected',
  ).length;
  const predictedPositives = binary.filter((row) => row.predicted.impact === 'affected').length;
  return {
    cases: results.length,
    attempted: attempted.length,
    skipped: results.length - attempted.length,
    accepted: accepted.length,
    rejected: attempted.filter((row) => row.status === 'rejected').length,
    conflicting: attempted.filter((row) => row.status === 'conflicting').length,
    output_acceptance_rate: ratio(accepted.length, attempted.length),
    coverage: ratio(accepted.length, results.length),
    exact_matches: exact,
    all_case_correct_ratio: ratio(exact, results.length),
    attempted_case_correct_ratio: ratio(exact, attempted.length),
    accepted_case_label_agreement: ratio(exact, accepted.length),
    false_exclusions: falseExclusions,
    false_exclusion_rate: ratio(falseExclusions, actionable.length),
    affected_precision: ratio(truePositives, predictedPositives),
    affected_recall: ratio(truePositives, positives.length),
    binary_precision_excludes_unknown_reference_labels: true,
    confusion,
  };
}

export function evaluationFixture(testCase, now = Date.now(), corpus = CORPUS) {
  const document = corpus.documents[testCase.document];
  if (!document) throw new Error('INVALID_CASE');
  const time = new Date(now).toISOString();
  const evidence = {
    id: `evaluation:${testCase.id}`,
    source: 'source-derived-synthetic-evaluation',
    kind: 'news',
    title: document.title,
    description: document.description,
    url: document.reference_url,
    content_status: testCase.content_status ?? 'full',
    aliases: document.aliases,
    severity: 'unknown',
    packages: [],
    published_at: `${document.reference_date}T00:00:00Z`,
    modified_at: time,
    fetched_at: time,
  };
  const system = {
    id: 'evaluation-system',
    name: testCase.system_context ?? 'Fictional evaluation inventory',
    environment: 'test',
    exposure: 'unknown',
    criticality: 'low',
    updated_at: time,
    components: [],
    products: [
      {
        name: testCase.product,
        ...(testCase.version ? { version: testCase.version } : {}),
        keywords: testCase.keywords ?? [],
      },
    ],
    keywords: [],
  };
  const assessment = {
    id: `evaluation-finding:${testCase.id}`,
    event_id: testCase.event_id ?? `EVALUATION-${testCase.id}`,
    system_id: system.id,
    component_id: `product:${testCase.product.toLowerCase()}`,
    category: 'product',
    news_only: true,
    news_candidate: true,
    applicability: 'unknown',
    source_severity: 'unknown',
    priority: 'low',
    title: evidence.title,
    summary: 'Assess the supplied source-derived synthetic scenario for this fictional inventory.',
    reasons: [],
    evidence_ids: [evidence.id],
    urls: [evidence.url],
    exploited: false,
    updated_at: time,
  };
  return { evidence, system, assessment };
}

export function parseEvaluationOptions(args) {
  const options = {
    live: false,
    providers: ['openai', 'anthropic'],
    cases: CORPUS.cases.map((item) => item.id),
    timeout: 45,
    maxTokens: 2048,
    maxRequests: 20,
  };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--live') options.live = true;
    else if (arg === '--help') options.help = true;
    else if (['--providers', '--cases', '--verification-provider'].includes(arg)) {
      const value = args[++index];
      if (!value) throw new Error('INVALID_OPTIONS');
      const ids = value.split(',');
      const allowed =
        arg === '--cases' ? CORPUS.cases.map((item) => item.id) : PROVIDERS.map((item) => item.id);
      if (ids.some((id) => !allowed.includes(id))) throw new Error('INVALID_OPTIONS');
      if (arg === '--verification-provider') {
        if (ids.length !== 1) throw new Error('INVALID_OPTIONS');
        options.verification = ids[0];
      } else options[arg === '--cases' ? 'cases' : 'providers'] = [...new Set(ids)];
    } else if (['--timeout-seconds', '--max-output-tokens', '--max-requests'].includes(arg)) {
      const value = Number(args[++index]);
      const bounds =
        arg === '--timeout-seconds' ? [1, 60] : arg === '--max-output-tokens' ? [128, 4096] : [1, 100];
      if (!Number.isInteger(value) || value < bounds[0] || value > bounds[1])
        throw new Error('INVALID_OPTIONS');
      options[
        arg === '--timeout-seconds' ? 'timeout' : arg === '--max-output-tokens' ? 'maxTokens' : 'maxRequests'
      ] = value;
    } else throw new Error('INVALID_OPTIONS');
  }
  return options;
}

function modelSpec(id, env) {
  const provider = PROVIDERS.find((entry) => entry.id === id);
  if (!provider) throw new Error('INVALID_OPTIONS');
  const suffix = id.toUpperCase().replaceAll('-', '_');
  const value = (name) =>
    env[`SECURITY_WATCH_EVAL_${suffix}_${name}`] ?? env[`SECURITY_WATCH_SMOKE_${suffix}_${name}`];
  const model = value('MODEL');
  const endpoint = value('ENDPOINT');
  const allowPrivate = value('ALLOW_PRIVATE') === '1';
  if (!env[provider.apiKeyEnv] && !(allowPrivate && (provider.local || id === 'openai-compatible')))
    return { missing: 'missing_credentials' };
  if (!model || (!provider.endpoint && !endpoint)) return { missing: 'missing_configuration' };
  return {
    spec: {
      provider: id,
      model,
      api_key_env: provider.apiKeyEnv,
      ...(endpoint ? { endpoint } : {}),
      allow_private_endpoint: allowPrivate,
      ...(value('OUTPUT_FORMAT') ? { output_format: value('OUTPUT_FORMAT') } : {}),
    },
  };
}

function failureCode(reasons) {
  const known = new Set([
    'MODEL_BUDGET_EXHAUSTED',
    'MODEL_CONTEXT_LIMIT',
    'MODEL_INCOMPLETE',
    'MODEL_REFUSAL',
    'MODEL_UNSUPPORTED_QUOTE',
    'MODEL_UNSUPPORTED_NEWS_QUOTE',
    'MODEL_UNSUPPORTED_NEWS_CLAIM',
    'MODEL_UNSUPPORTED_NEWS_IMPACT',
    'MODEL_INCONSISTENT_NEWS_ANALYSIS',
    'MODEL_AMBIGUOUS_NEWS_SUBJECT',
    'MODEL_UNEXPECTED_TOOL',
  ]);
  for (const reason of reasons ?? []) {
    const code = reason.split(';', 1)[0];
    if (known.has(code) || /^MODEL_HTTP_[1-5]\d{2}$/.test(code)) return code;
  }
  return 'MODEL_ANALYSIS_FAILED';
}

function modelDescription(spec) {
  if (!spec) return null;
  try {
    return { provider: spec.provider, model: spec.model, output_format: modelOutputFormat(spec) };
  } catch {
    return null;
  }
}

export async function evaluateModels(
  options,
  { env = process.env, http = safeHttp, now = Date.now, corpus = CORPUS } = {},
) {
  const results = [];
  const models = {};
  let requests = 0;
  const cases = options.cases.map((id) => corpus.cases.find((item) => item.id === id));
  if (cases.some((item) => !item)) throw new Error('INVALID_OPTIONS');
  for (const provider of options.providers) {
    const analysis = modelSpec(provider, env);
    const verification = options.verification ? modelSpec(options.verification, env) : undefined;
    models[provider] = {
      analysis: modelDescription(analysis.spec),
      verification: modelDescription(verification?.spec),
    };
    for (const testCase of cases) {
      const base = { provider, case: testCase.id, expected: testCase.expected };
      const skip =
        analysis.missing ?? verification?.missing ?? (!options.live ? 'live_not_requested' : undefined);
      if (skip) {
        results.push({ ...base, status: 'skipped', reason: skip, requests: 0 });
        continue;
      }
      const needed = verification ? 2 : 1;
      if (requests + needed > options.maxRequests) {
        results.push({ ...base, status: 'skipped', reason: 'request_cap', requests: 0 });
        continue;
      }
      let config;
      try {
        config = parseConfig({
          version: 1,
          sources: { cve_now: false, hacker_news: false },
          models: {
            enabled: true,
            analysis: analysis.spec,
            ...(verification ? { verification: verification.spec } : {}),
            daily_request_limit: needed,
            daily_token_limit: 100000,
            max_input_chars: 8000,
            max_output_tokens: options.maxTokens,
            timeout_seconds: options.timeout,
          },
        });
      } catch {
        results.push({ ...base, status: 'skipped', reason: 'invalid_configuration', requests: 0 });
        continue;
      }
      let caseRequests = 0;
      const boundedHttp = async (url, request = {}) => {
        if (
          caseRequests >= needed ||
          requests >= options.maxRequests ||
          Buffer.byteLength(request.body ?? '') > 65536
        )
          throw new Error('MODEL_CONTEXT_LIMIT');
        caseRequests++;
        requests++;
        return http(url, {
          ...request,
          redirects: 0,
          maxBytes: 262144,
          timeoutMs: Math.min(request.timeoutMs ?? Infinity, options.timeout * 1000),
        });
      };
      const fixture = evaluationFixture(testCase, now(), corpus);
      try {
        const result = await new ModelAnalyzer(
          config,
          memoryState(),
          boundedHttp,
          now,
          AbortSignal.timeout(needed * options.timeout * 1000),
          env,
        ).analyze(fixture.assessment, fixture.system, [fixture.evidence]);
        const status =
          result.ai?.status === 'complete' && result.news_analysis
            ? 'accepted'
            : result.ai?.status === 'conflicting'
              ? 'conflicting'
              : 'rejected';
        results.push({
          ...base,
          status,
          requests: caseRequests,
          ...(status === 'accepted'
            ? {
                predicted: {
                  classification: result.news_analysis.classification,
                  impact: result.news_analysis.impact,
                },
              }
            : { reason: status === 'conflicting' ? 'model_disagreement' : failureCode(result.reasons) }),
        });
      } catch {
        results.push({
          ...base,
          status: 'rejected',
          reason: 'MODEL_ANALYSIS_FAILED',
          requests: caseRequests,
        });
      }
    }
  }
  return {
    corpus_version: corpus.version,
    corpus_sha256:
      corpus === CORPUS ? CORPUS_SHA256 : createHash('sha256').update(JSON.stringify(corpus)).digest('hex'),
    label_status: corpus.label_status,
    scenario_type: 'source-derived synthetic; fictional inventory; not a production benchmark',
    live_requested: options.live,
    requests,
    request_cap: options.maxRequests,
    verification_provider: options.verification ?? null,
    run_configuration: {
      prompt_version: PROMPT_VERSION,
      max_output_tokens: options.maxTokens,
      timeout_seconds: options.timeout,
      models,
    },
    metrics: scoreEvaluation(results),
    providers: Object.fromEntries(
      options.providers.map((provider) => [
        provider,
        scoreEvaluation(results.filter((row) => row.provider === provider)),
      ]),
    ),
    results,
  };
}

export async function main(args = process.argv.slice(2)) {
  let options;
  try {
    options = parseEvaluationOptions(args);
  } catch {
    console.error('Invalid evaluation options. Run with --help.');
    return 2;
  }
  if (options.help) {
    console.log(`Usage: node scripts/evaluate-models.mjs [--live] [--providers openai,anthropic]
  [--cases ID,ID] [--verification-provider PROVIDER] [--max-requests 1..100]
  [--timeout-seconds 1..60] [--max-output-tokens 128..4096]

Build first. Set provider credentials and SECURITY_WATCH_EVAL_<PROVIDER>_MODEL.
EVAL settings fall back to matching SECURITY_WATCH_SMOKE settings. Optional
suffixes: _ENDPOINT, _OUTPUT_FORMAT, _ALLOW_PRIVATE=1. No model defaults.
Without --live, no requests are made. Defaults: 20 total requests, 45 seconds
per request, 2048 output tokens. Verification uses up to two requests per case.
Calls may incur charges; token caps are not dollar budgets. No notifications.

Reference labels are pending human review. Output acceptance measures the
production schema/evidence gates, not correctness. Agreement uses the supplied
synthetic reference labels. Coverage and all-case correctness include skipped,
rejected and conflicting cases; confusion tables show rejected/conflicting
outcomes separately. Unknown reference impacts are excluded only from binary
affected precision, not from exact agreement or false-exclusion reporting.
Exit: 0 completed without rejected/conflicting cases; 1 rejects/conflicts;
2 invalid options; 3 no attempted cases. Label mismatches remain in the report.`);
    return 0;
  }
  const report = await evaluateModels(options);
  console.log(JSON.stringify(report, null, 2));
  return report.metrics.rejected || report.metrics.conflicting ? 1 : report.metrics.attempted ? 0 : 3;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  process.exitCode = await main();
