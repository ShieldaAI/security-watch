import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { parseConfig } from '../dist/config.js';
import { safeHttp } from '../dist/http.js';
import { ModelAnalyzer } from '../dist/models.js';
import { PROVIDERS } from '../dist/providers.js';

const PREFIX = 'SECURITY_WATCH_SMOKE_';
const SAFE_CODES = new Set([
  'MODEL_CREDENTIAL_MISSING',
  'MODEL_BUDGET_EXHAUSTED',
  'MODEL_CONTEXT_LIMIT',
  'MODEL_INCOMPLETE',
  'MODEL_REFUSAL',
  'MODEL_ANALYSIS_FAILED',
  'MODEL_UNKNOWN_EVIDENCE',
  'MODEL_UNSUPPORTED_QUOTE',
  'MODEL_UNSUPPORTED_CITATION',
  'MODEL_NEWS_ANALYSIS_MISSING',
  'MODEL_UNSUPPORTED_NEWS_QUOTE',
  'MODEL_UNSUPPORTED_NEWS_CLAIM',
  'MODEL_INCONSISTENT_NEWS_ANALYSIS',
  'MODEL_UNSUPPORTED_NEWS_IMPACT',
  'MODEL_EMPTY_OUTPUT',
  'MODEL_PROVIDER_ERROR',
  'MODEL_UNEXPECTED_TOOL',
]);

export function smokeFixture(now = Date.now()) {
  const timestamp = new Date(now).toISOString();
  const quote = 'Fictional TestWidget version 1.0.0 has a vulnerability fixed in version 1.0.1.';
  const evidence = {
    id: 'smoke:fictional-bulletin',
    source: 'synthetic-smoke-test',
    kind: 'news',
    title: 'Synthetic TestWidget security bulletin',
    description: `${quote} This fictional bulletin is only a compatibility test, not a real advisory.`,
    url: 'https://example.invalid/synthetic-bulletin',
    content_status: 'full',
    aliases: [],
    severity: 'high',
    packages: [],
    modified_at: timestamp,
    fetched_at: timestamp,
    published_at: timestamp,
  };
  const system = {
    id: 'synthetic-system',
    name: 'Synthetic compatibility test',
    environment: 'test',
    exposure: 'internal',
    criticality: 'low',
    updated_at: timestamp,
    components: [],
    products: [{ name: 'Fictional TestWidget', version: '1.0.0', keywords: [] }],
    keywords: [],
  };
  const assessment = {
    id: 'synthetic-finding',
    event_id: 'SMOKE-NEWS-1',
    system_id: system.id,
    component_id: 'product:fictional testwidget',
    category: 'product',
    applicability: 'unknown',
    source_severity: 'high',
    priority: 'high',
    title: evidence.title,
    summary: 'Synthetic bulletin requires a model assessment.',
    reasons: [],
    evidence_ids: [evidence.id],
    urls: [evidence.url],
    exploited: false,
    updated_at: timestamp,
  };
  return { system, evidence, assessment, quote };
}

export function memoryState() {
  const metadata = new Map();
  let requests = 0;
  let reservedTokens = 0;
  return {
    getMeta: (key) => metadata.get(key),
    setMeta: (key, value) => metadata.set(key, value),
    reserveBudget(_day, maxRequests, maxTokens, _maxUsd, tokens) {
      if (requests >= maxRequests || tokens + reservedTokens > maxTokens) return false;
      requests++;
      reservedTokens += tokens;
      return true;
    },
  };
}

export function parseOptions(args) {
  const options = { live: false, providers: PROVIDERS.map((p) => p.id), timeout: 30, maxTokens: 1024 };
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--live') options.live = true;
    else if (argument === '--help') options.help = true;
    else if (argument === '--providers') {
      const value = args[++index];
      if (!value) throw new Error('INVALID_OPTIONS');
      const selected = value.split(',');
      if (selected.some((id) => !PROVIDERS.some((p) => p.id === id))) throw new Error('INVALID_OPTIONS');
      options.providers = [...new Set(selected)];
    } else if (argument === '--timeout-seconds' || argument === '--max-output-tokens') {
      const number = Number(args[++index]);
      const [minimum, maximum] = argument === '--timeout-seconds' ? [1, 60] : [128, 2048];
      if (!Number.isInteger(number) || number < minimum || number > maximum)
        throw new Error('INVALID_OPTIONS');
      if (argument === '--timeout-seconds') options.timeout = number;
      else options.maxTokens = number;
    } else throw new Error('INVALID_OPTIONS');
  }
  return options;
}

function failureCode(reasons = []) {
  for (const reason of reasons) {
    const code = reason.split(';', 1)[0];
    if (SAFE_CODES.has(code) || /^MODEL_HTTP_[1-5][0-9]{2}$/.test(code)) return code;
  }
  return 'MODEL_ANALYSIS_FAILED';
}

export async function checkModels(options, { env = process.env, http = safeHttp, now = Date.now } = {}) {
  const results = [];
  for (const id of options.providers) {
    const provider = PROVIDERS.find((entry) => entry.id === id);
    if (!provider) throw new Error('INVALID_OPTIONS');
    const prefix = PREFIX + id.toUpperCase().replaceAll('-', '_');
    const model = env[`${prefix}_MODEL`];
    const endpoint = env[`${prefix}_ENDPOINT`];
    const allowPrivate = env[`${prefix}_ALLOW_PRIVATE`] === '1';
    const missing = [];
    const missingCredential =
      !env[provider.apiKeyEnv] && !(allowPrivate && (provider.local || id === 'openai-compatible'));
    if (missingCredential) missing.push(provider.apiKeyEnv);
    if (!model) missing.push(`${prefix}_MODEL`);
    if (!provider.endpoint && !endpoint) missing.push(`${prefix}_ENDPOINT`);
    if (missing.length) {
      results.push({
        provider: id,
        status: 'skipped',
        reason: missingCredential ? 'missing_credentials' : 'missing_configuration',
        missing,
        requests: 0,
      });
      continue;
    }
    let config;
    try {
      config = parseConfig({
        version: 1,
        sources: { cve_now: false, hacker_news: false },
        models: {
          enabled: true,
          analysis: {
            provider: id,
            model,
            api_key_env: provider.apiKeyEnv,
            ...(endpoint ? { endpoint } : {}),
            allow_private_endpoint: allowPrivate,
            ...(env[`${prefix}_OUTPUT_FORMAT`] ? { output_format: env[`${prefix}_OUTPUT_FORMAT`] } : {}),
          },
          daily_request_limit: 1,
          daily_token_limit: 32768 + options.maxTokens,
          max_input_chars: 4096,
          max_output_tokens: options.maxTokens,
          timeout_seconds: options.timeout,
        },
      });
    } catch {
      results.push({ provider: id, status: 'failed', reason: 'invalid_configuration', requests: 0 });
      continue;
    }
    if (!options.live) {
      results.push({ provider: id, status: 'skipped', reason: 'live_not_requested', requests: 0 });
      continue;
    }
    const fixture = smokeFixture(now());
    let requests = 0;
    let httpStatus;
    const boundedHttp = async (url, request = {}) => {
      if (requests >= 1 || Buffer.byteLength(request.body ?? '') > 32768)
        throw new Error('MODEL_CONTEXT_LIMIT');
      requests++;
      const response = await http(url, {
        ...request,
        timeoutMs: Math.min(request.timeoutMs ?? Infinity, options.timeout * 1000),
        maxBytes: 131072,
        redirects: 0,
      });
      if (Number.isInteger(response.status) && response.status >= 100 && response.status <= 599)
        httpStatus = response.status;
      return response;
    };
    const started = Date.now();
    try {
      const result = await new ModelAnalyzer(
        config,
        memoryState(),
        boundedHttp,
        now,
        AbortSignal.timeout(options.timeout * 1000),
        env,
      ).analyze(fixture.assessment, fixture.system, [fixture.evidence]);
      const passed = result.ai?.status === 'complete' && result.news_analysis && requests === 1;
      results.push({
        provider: id,
        status: passed ? 'passed' : 'failed',
        reason: passed ? 'schema_and_evidence_quotes_validated' : failureCode(result.reasons),
        requests,
        http_status: httpStatus,
        elapsed_ms: Date.now() - started,
      });
    } catch {
      results.push({
        provider: id,
        status: 'failed',
        reason: 'MODEL_ANALYSIS_FAILED',
        requests,
        http_status: httpStatus,
        elapsed_ms: Date.now() - started,
      });
    }
  }
  return results;
}

export async function main(args = process.argv.slice(2)) {
  let options;
  try {
    options = parseOptions(args);
  } catch {
    console.error('Invalid smoke-test options. Run with --help.');
    return 2;
  }
  if (options.help) {
    console.log(`Usage: node scripts/check-models.mjs [--live] [--providers openai,anthropic]
       [--timeout-seconds 1..60] [--max-output-tokens 128..2048]

Build first with npm run build. Set each provider's documented API key variable
and SECURITY_WATCH_SMOKE_<PROVIDER>_MODEL (uppercase; replace hyphens with underscores).
Optional suffixes: _ENDPOINT, _OUTPUT_FORMAT, _ALLOW_PRIVATE=1.
Model IDs have no defaults. Choose a model available to your account.

Without --live, no network requests are made. With --live, each configured provider
receives one synthetic news assessment, no verification call, no tools and no
notifications. Output reports schema and evidence-quote validation, not model quality.
The output-token cap includes reasoning where the provider supports that limit;
it is not a dollar budget. A run may incur provider charges.
Exit status: 0 if at least one provider passed and none failed; 1 for failures;
2 for invalid options; 3 when every provider was skipped.`);
    return 0;
  }
  const results = await checkModels(options);
  const counts = Object.fromEntries(
    ['passed', 'failed', 'skipped'].map((status) => [
      status,
      results.filter((r) => r.status === status).length,
    ]),
  );
  console.log(JSON.stringify({ synthetic: true, live_requested: options.live, counts, results }, null, 2));
  return counts.failed ? 1 : counts.passed ? 0 : 3;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  process.exitCode = await main();
