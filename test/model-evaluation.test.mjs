import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CORPUS,
  evaluateModels,
  evaluationFixture,
  parseEvaluationOptions,
  scoreEvaluation,
} from '../scripts/evaluate-models.mjs';

const options = (extra = []) =>
  parseEvaluationOptions([
    '--providers',
    'openai-compatible',
    '--cases',
    'php-fixed,php-missing-version',
    ...extra,
  ]);
const env = {
  SECURITY_WATCH_EVAL_OPENAI_COMPATIBLE_MODEL: 'offline-fixture',
  SECURITY_WATCH_EVAL_OPENAI_COMPATIBLE_ENDPOINT: 'http://127.0.0.1:1234/v1/chat/completions',
  SECURITY_WATCH_EVAL_OPENAI_COMPATIBLE_ALLOW_PRIVATE: '1',
};
const NOW = Date.parse('2026-10-24T12:00:00Z');
function responseFor(id, impact) {
  const fixture = evaluationFixture(
    CORPUS.cases.find((item) => item.id === id),
    NOW,
  );
  const quote = { evidence_id: fixture.evidence.id, quote: fixture.evidence.description };
  return {
    status: 200,
    headers: {},
    body: JSON.stringify({
      choices: [
        {
          finish_reason: 'stop',
          message: {
            content: JSON.stringify({
              relevance: 'relevant',
              priority: 'high',
              summary: 'Review this PHP scenario.',
              evidence_ids: [fixture.evidence.id],
              quotes: [quote],
              news_analysis: {
                classification: 'new_vulnerability',
                impact,
                affected_products: ['PHP'],
                affected_versions: ['8.5.12'],
                prerequisites: [],
                rationale: 'The installed version is evaluated against the supplied release information.',
                quotes: [quote],
              },
            }),
          },
        },
      ],
    }),
  };
}

test('evaluation labels are explicit, source-backed and cover uncertainty and false exclusions', () => {
  assert.equal(CORPUS.label_status, 'pending_human_review');
  assert.equal(new Set(CORPUS.cases.map((item) => item.id)).size, CORPUS.cases.length);
  assert.equal(CORPUS.cases.length, 10);
  for (const item of CORPUS.cases) {
    assert(item.expected_reason.length > 20);
    assert(CORPUS.documents[item.document].reference_url.startsWith('https://'));
    assert(evaluationFixture(item, NOW).assessment.news_candidate);
  }
  assert(CORPUS.cases.some((item) => !item.version));
  assert(CORPUS.cases.some((item) => item.content_status === 'excerpt'));
  assert(CORPUS.cases.some((item) => item.expected.impact === 'not_affected'));
  assert(CORPUS.cases.some((item) => item.expected.classification === 'general_news'));
});

test('scoring reports rejection/conflict coverage and does not hide missed cases from correctness', () => {
  const expected = { classification: 'new_vulnerability', impact: 'affected' };
  const rows = [
    { status: 'accepted', expected, predicted: expected },
    { status: 'accepted', expected, predicted: { ...expected, impact: 'not_affected' } },
    { status: 'rejected', expected },
    { status: 'conflicting', expected },
    { status: 'skipped', expected },
    {
      status: 'accepted',
      expected: { ...expected, impact: 'unknown' },
      predicted: { ...expected, impact: 'not_applicable' },
    },
  ];
  const score = scoreEvaluation(rows);
  assert.equal(score.accepted, 3);
  assert.equal(score.output_acceptance_rate, 3 / 5);
  assert.equal(score.coverage, 3 / 6);
  assert.equal(score.all_case_correct_ratio, 1 / 6);
  assert.equal(score.accepted_case_label_agreement, 1 / 3);
  assert.equal(score.false_exclusions, 2);
  assert.equal(score.affected_precision, 1);
  assert.equal(score.affected_recall, 1 / 4);
  assert.equal(score.confusion.impact['affected -> [rejected]'], 1);
  assert.equal(score.confusion.impact['affected -> [conflicting]'], 1);
  assert.equal(scoreEvaluation([]).coverage, null);
});

test('dry-run and missing credentials never call a provider or count as passes', async () => {
  const http = async () => {
    throw new Error('Must not call provider');
  };
  const dry = await evaluateModels(options(), { env, http });
  assert.equal(dry.requests, 0);
  assert.equal(dry.metrics.accepted, 0);
  assert(dry.results.every((row) => row.reason === 'live_not_requested'));
  const missing = await evaluateModels(parseEvaluationOptions(['--live', '--providers', 'openai']), {
    env: {},
    http,
  });
  assert.equal(missing.metrics.skipped, 10);
  assert(missing.results.every((row) => row.reason === 'missing_credentials'));
  const changedCorpus = structuredClone(CORPUS);
  changedCorpus.description += ' Modified corpus.';
  const changed = await evaluateModels(options(), { env, http, corpus: changedCorpus });
  assert.notEqual(changed.corpus_sha256, dry.corpus_sha256);
});

test('evaluation exercises production analysis, caps requests and includes skipped cases in overall agreement', async () => {
  let requests = 0;
  const report = await evaluateModels(options(['--live', '--max-requests', '1']), {
    env,
    now: () => NOW,
    http: async (_url, request) => {
      requests++;
      assert.equal(request.redirects, 0);
      assert.equal(request.maxBytes, 262144);
      assert.equal(JSON.parse(request.body).tools, undefined);
      return responseFor('php-fixed', 'not_affected');
    },
  });
  assert.equal(requests, 1);
  assert.equal(report.results[0].status, 'accepted');
  assert.equal(report.results[1].reason, 'request_cap');
  assert.equal(report.metrics.all_case_correct_ratio, 0.5);
  assert.equal(report.metrics.false_exclusions, 0);
});

test('provider failure is a rejection with no leaked error or invented accuracy', async () => {
  const report = await evaluateModels(options(['--live']), {
    env,
    now: () => NOW,
    http: async () => {
      throw new Error('private-credential-in-transport-error');
    },
  });
  assert.equal(report.metrics.rejected, 2);
  assert.equal(report.metrics.all_case_correct_ratio, 0);
  assert.equal(report.metrics.accepted_case_label_agreement, null);
  assert(!JSON.stringify(report).includes('private-credential'));
});

test('evaluation reports model identity, effective format and prompt version without credentials or endpoints', async () => {
  const report = await evaluateModels(options(), {
    env: {
      ...env,
      OPENAI_API_KEY: 'private-key-value',
      SECURITY_WATCH_EVAL_OPENAI_COMPATIBLE_ENDPOINT: 'http://127.0.0.1:4567/private-endpoint',
    },
  });
  assert.equal(report.run_configuration.models['openai-compatible'].analysis.model, 'offline-fixture');
  assert.equal(typeof report.run_configuration.models['openai-compatible'].analysis.output_format, 'string');
  assert.match(report.run_configuration.prompt_version, /^security-watch-/);
  assert.equal(report.run_configuration.max_output_tokens, 2048);
  assert.equal(report.run_configuration.timeout_seconds, 45);
  assert(!JSON.stringify(report).includes('private-key-value'));
  assert(!JSON.stringify(report).includes('private-endpoint'));
});

test('evaluation refuses unknown cases/providers and unbounded request/token options', () => {
  for (const args of [
    ['--cases', 'missing'],
    ['--providers', 'missing'],
    ['--max-requests', '101'],
    ['--max-requests', '0'],
    ['--max-output-tokens', '999999'],
    ['--timeout-seconds', 'Infinity'],
  ])
    assert.throws(() => parseEvaluationOptions(args), /INVALID_OPTIONS/);
});
