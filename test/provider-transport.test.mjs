import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { parseConfig } from '../dist/config.js';
import { safeHttp } from '../dist/http.js';
import { ModelAnalyzer } from '../dist/models.js';
import { PROVIDERS } from '../dist/providers.js';
import { checkModels, memoryState, parseOptions, smokeFixture } from '../scripts/check-models.mjs';

const TOKEN = 'synthetic-test-credential-never-log';

function analysis(fixture) {
  const quote = { evidence_id: fixture.evidence.id, quote: fixture.quote };
  return {
    relevance: 'relevant',
    priority: 'high',
    summary: 'The fictional installed version appears in the synthetic bulletin.',
    evidence_ids: [fixture.evidence.id],
    quotes: [quote],
    news_analysis: {
      classification: 'new_vulnerability',
      impact: 'affected',
      affected_products: ['Fictional TestWidget'],
      affected_versions: ['1.0.0'],
      prerequisites: [],
      rationale: 'The synthetic inventory matches the exact affected version in the quote.',
      quotes: [quote],
    },
  };
}

function response(protocol, fixture, mode = 'complete') {
  const text = JSON.stringify(analysis(fixture));
  switch (protocol) {
    case 'openai-responses':
    case 'perplexity':
      return {
        status: mode === 'incomplete' ? 'incomplete' : 'completed',
        output: [
          { type: 'message', content: [{ type: mode === 'refusal' ? 'refusal' : 'output_text', text }] },
        ],
      };
    case 'anthropic':
      return {
        stop_reason: mode === 'incomplete' ? 'max_tokens' : mode === 'refusal' ? 'refusal' : 'end_turn',
        content: [{ type: 'text', text }],
      };
    case 'gemini':
      return {
        candidates: [
          {
            finishReason: mode === 'incomplete' ? 'MAX_TOKENS' : mode === 'refusal' ? 'SAFETY' : 'STOP',
            content: { parts: [{ text }] },
          },
        ],
      };
    case 'cohere':
      return {
        finish_reason: mode === 'incomplete' ? 'MAX_TOKENS' : 'COMPLETE',
        message: { content: [{ type: mode === 'refusal' ? 'refusal' : 'text', text }] },
      };
    default:
      return {
        choices: [
          {
            finish_reason: mode === 'incomplete' ? 'length' : mode === 'refusal' ? 'content_filter' : 'stop',
            message: { content: text },
          },
        ],
      };
  }
}

async function listener(t, handler) {
  const server = createServer(async (request, result) => {
    try {
      let body = '';
      for await (const chunk of request) body += chunk;
      const reply = await handler({
        path: request.url,
        method: request.method,
        headers: request.headers,
        body: JSON.parse(body),
      });
      result.writeHead(reply.status ?? 200, { 'content-type': 'application/json' });
      result.end(JSON.stringify(reply.body));
    } catch {
      result.writeHead(500);
      result.end('{}');
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

function credential(t, name) {
  const previous = process.env[name];
  process.env[name] = TOKEN;
  t.after(() => {
    if (previous === undefined) delete process.env[name];
    else process.env[name] = previous;
  });
}

function config(provider, endpoint) {
  return parseConfig({
    version: 1,
    models: {
      enabled: true,
      analysis: { provider: provider.id, model: 'synthetic-model', endpoint, allow_private_endpoint: true },
      daily_request_limit: 1,
      daily_token_limit: 32768,
      max_input_chars: 4096,
      max_output_tokens: 512,
      timeout_seconds: 2,
    },
  });
}

test('every provider profile completes through real loopback HTTP with bounded authenticated requests', async (t) => {
  const fixture = smokeFixture();
  const seen = [];
  const url = await listener(t, (request) => {
    seen.push(request);
    const provider = PROVIDERS.find((entry) => request.path === `/${entry.id}`);
    return { body: response(provider.protocol, fixture) };
  });
  for (const provider of PROVIDERS) {
    await t.test(provider.id, async (t) => {
      credential(t, provider.apiKeyEnv);
      const result = await new ModelAnalyzer(
        config(provider, `${url}/${provider.id}`),
        memoryState(),
        safeHttp,
      ).analyze(fixture.assessment, fixture.system, [fixture.evidence]);
      assert.equal(result.ai.status, 'complete');
      assert.equal(result.news_analysis.classification, 'new_vulnerability');
      assert.equal(result.news_analysis.impact, 'affected');
      const request = seen.at(-1);
      assert.equal(request.method, 'POST');
      assert.equal(request.headers['content-type'], 'application/json');
      if (provider.id === 'azure-openai') {
        assert.equal(request.headers['api-key'], TOKEN);
        assert.equal(request.headers.authorization, undefined);
      } else if (provider.protocol === 'anthropic') {
        assert.equal(request.headers['x-api-key'], TOKEN);
        assert.equal(request.headers['anthropic-version'], '2023-06-01');
        assert.equal(request.headers['anthropic-beta'], undefined);
        assert.equal(request.body.output_config.format.type, 'json_schema');
        assert.equal(request.body.output_config.format.schema.additionalProperties, false);
        assert.equal(request.headers.authorization, undefined);
      } else if (provider.protocol === 'gemini') {
        assert.equal(request.headers['x-goog-api-key'], TOKEN);
        assert.equal(request.headers.authorization, undefined);
      } else assert.equal(request.headers.authorization, `Bearer ${TOKEN}`);
      const body = request.body;
      assert.equal(
        body.max_tokens ??
          body.max_completion_tokens ??
          body.max_output_tokens ??
          body.generationConfig?.maxOutputTokens,
        512,
      );
      assert.ok(!body.tools || body.tools.length === 0);
      assert.ok(!JSON.stringify(body).includes(TOKEN));
      assert.ok(JSON.stringify(body).includes(fixture.quote));
      assert.ok(!request.path.includes(TOKEN));
    });
  }
  assert.equal(seen.length, PROVIDERS.length);
});

test('native protocols reject refusals, truncated generations and secret-bearing HTTP errors over real transport', async (t) => {
  const fixture = smokeFixture();
  const representatives = [...new Map(PROVIDERS.map((provider) => [provider.protocol, provider])).values()];
  let selected;
  let mode;
  let calls = 0;
  const url = await listener(t, () => {
    calls++;
    return mode === 'http-error'
      ? { status: 401, body: { error: { message: `Rejected credential ${TOKEN}`, request: TOKEN } } }
      : { body: response(selected.protocol, fixture, mode) };
  });
  for (const provider of representatives) {
    for (const failure of ['refusal', 'incomplete', 'http-error']) {
      await t.test(`${provider.protocol}: ${failure}`, async (t) => {
        credential(t, provider.apiKeyEnv);
        selected = provider;
        mode = failure;
        const before = calls;
        const result = await new ModelAnalyzer(config(provider, url), memoryState(), safeHttp).analyze(
          fixture.assessment,
          fixture.system,
          [fixture.evidence],
        );
        assert.equal(result.ai.status, 'unavailable');
        assert.equal(result.applicability, 'unknown');
        assert.equal(calls - before, 1);
        assert.ok(!JSON.stringify(result).includes(TOKEN));
        const code =
          failure === 'refusal'
            ? 'MODEL_REFUSAL'
            : failure === 'incomplete'
              ? 'MODEL_INCOMPLETE'
              : 'MODEL_HTTP_401';
        assert.ok(result.reasons.some((reason) => reason.startsWith(code)));
      });
    }
  }
});

test('live harness distinguishes missing credentials and model configuration without making requests', async () => {
  const options = parseOptions(['--live', '--providers', 'openai,ollama']);
  let calls = 0;
  const results = await checkModels(options, {
    env: {},
    http: async () => {
      calls++;
      throw new Error(TOKEN);
    },
  });
  assert.equal(calls, 0);
  assert.ok(results.every((result) => result.status === 'skipped'));
  assert.equal(results[0].reason, 'missing_credentials');
  assert.ok(results[0].missing.includes('OPENAI_API_KEY'));
  assert.ok(results[0].missing.includes('SECURITY_WATCH_SMOKE_OPENAI_MODEL'));
});

test('live harness uses production transport, makes one request and prints no raw provider errors', async (t) => {
  credential(t, 'OPENAI_API_KEY');
  const suppliedToken = 'synthetic-key-from-supplied-environment';
  const fixture = smokeFixture();
  let fail = false;
  let calls = 0;
  const url = await listener(t, ({ headers }) => {
    calls++;
    assert.equal(headers.authorization, `Bearer ${suppliedToken}`);
    return fail
      ? { status: 429, body: { error: { message: suppliedToken } } }
      : { body: response('openai-responses', fixture) };
  });
  const env = {
    OPENAI_API_KEY: suppliedToken,
    SECURITY_WATCH_SMOKE_OPENAI_MODEL: 'synthetic-model',
    SECURITY_WATCH_SMOKE_OPENAI_ENDPOINT: url,
    SECURITY_WATCH_SMOKE_OPENAI_ALLOW_PRIVATE: '1',
  };
  const dry = await checkModels(parseOptions(['--providers', 'openai']), { env });
  assert.equal(dry[0].reason, 'live_not_requested');
  assert.equal(calls, 0);
  const options = parseOptions(['--live', '--providers', 'openai']);
  const success = await checkModels(options, { env });
  assert.equal(success[0].status, 'passed');
  assert.equal(success[0].requests, 1);
  fail = true;
  const failure = await checkModels(options, { env });
  assert.equal(failure[0].status, 'failed');
  assert.equal(failure[0].reason, 'MODEL_HTTP_429');
  assert.equal(failure[0].requests, 1);
  assert.equal(calls, 2);
  assert.ok(!JSON.stringify([...success, ...failure]).includes(TOKEN));
  assert.ok(!JSON.stringify([...success, ...failure]).includes(suppliedToken));
});

test('smoke-test bounds and provider names reject invalid options before any request', () => {
  for (const args of [
    ['--providers', 'unknown'],
    ['--max-output-tokens', '0'],
    ['--max-output-tokens', '2049'],
    ['--timeout-seconds', '61'],
    ['--timeout-seconds', 'NaN'],
    ['--unknown'],
  ])
    assert.throws(() => parseOptions(args), /INVALID_OPTIONS/);
  assert.deepEqual(parseOptions(['--providers', 'openai,openai']).providers, ['openai']);
});

test('Anthropic sends native JSON schema by default and keeps prompt mode an explicit choice', async (t) => {
  const fixture = smokeFixture();
  const provider = PROVIDERS.find((item) => item.id === 'anthropic');
  const seen = [];
  const url = await listener(t, (request) => {
    seen.push(request);
    const context = JSON.parse(request.body.messages[0].content);
    const value = analysis(fixture);
    const refs = context.evidence[0].excerpts.map((excerpt) => ({ excerpt_id: excerpt.id }));
    value.quotes = refs;
    const { classification, impact, ...news } = value.news_analysis;
    value.news_analysis = { ...news, quotes: refs, classification_and_impact: `${classification}:${impact}` };
    return { body: { stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify(value) }] } };
  });
  credential(t, provider.apiKeyEnv);
  for (const output_format of ['auto', 'json_schema', 'prompt'])
    await t.test(output_format, async () => {
      const cfg = config(provider, url);
      cfg.models.analysis.output_format = output_format;
      const result = await new ModelAnalyzer(cfg, memoryState(), safeHttp).analyze(
        fixture.assessment,
        fixture.system,
        [fixture.evidence],
      );
      assert.equal(result.ai.status, 'complete');
      const request = seen.at(-1);
      assert.equal(request.headers['anthropic-beta'], undefined);
      if (output_format === 'prompt') assert.equal(request.body.output_config, undefined);
      else {
        assert.equal(request.body.output_config.format.type, 'json_schema');
        const schema = request.body.output_config.format.schema;
        assert.equal(schema.type, 'object');
        assert.deepEqual(schema.properties.quotes.items.properties.excerpt_id.enum, ['e0s0']);
        assert.equal(schema.additionalProperties, false);
      }
      assert(result.news_analysis.quotes.every((quote) => quote.quote.includes(fixture.quote)));
    });
  assert.equal(seen.length, 3);
});

test('Anthropic schema errors never trigger fallback and fenced or unsupported output remains invalid', async (t) => {
  const fixture = smokeFixture();
  const provider = PROVIDERS.find((item) => item.id === 'anthropic');
  let mode;
  let calls = 0;
  const url = await listener(t, () => {
    calls++;
    if (mode === 'schema-rejected')
      return { status: 400, body: { error: { message: 'Unsupported schema' } } };
    const body = response('anthropic', fixture);
    if (mode === 'fenced') body.content[0].text = '```json\n' + body.content[0].text + '\n```';
    else {
      const value = JSON.parse(body.content[0].text);
      value.quotes[0].quote = 'An invented quotation that does not occur in the evidence.';
      body.content[0].text = JSON.stringify(value);
    }
    return { body };
  });
  credential(t, provider.apiKeyEnv);
  for (const failure of ['schema-rejected', 'fenced', 'unsupported-quote'])
    await t.test(failure, async () => {
      mode = failure;
      const before = calls;
      const cfg = config(provider, url);
      if (failure === 'fenced') cfg.models.analysis.output_format = 'prompt';
      const result = await new ModelAnalyzer(cfg, memoryState(), safeHttp).analyze(
        fixture.assessment,
        fixture.system,
        [fixture.evidence],
      );
      assert.equal(result.ai.status, 'unavailable');
      assert.equal(calls - before, 1);
      assert(
        result.reasons.some((reason) =>
          reason.startsWith(
            failure === 'schema-rejected'
              ? 'MODEL_HTTP_400'
              : failure === 'unsupported-quote'
                ? 'MODEL_UNSUPPORTED_QUOTE'
                : 'MODEL_ANALYSIS_FAILED',
          ),
        ),
      );
    });
});
