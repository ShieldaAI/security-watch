import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import {
  ALERT_CORPUS,
  MODES,
  digest,
  validateCorpus,
  validateReference,
  parseAlertOptions,
  evaluateAlertOutcomes,
  alertGate,
  scoreAlertOutcomes,
  importFeedback,
  replayResponse,
} from '../scripts/evaluate-alerts.mjs';

const full = () => parseAlertOptions(['--repeats', '1']);
let reportPromise;
const report = () => (reportPromise ??= evaluateAlertOutcomes(full()));
function feedbackFor(cases = ALERT_CORPUS.cases) {
  return {
    version: 1,
    corpus_sha256: digest(ALERT_CORPUS),
    adjudications: [],
    reviews: cases.flatMap((item) =>
      ['analyst-a', 'analyst-b'].map((reviewer) => ({
        case_id: item.id,
        case_sha256: digest(item),
        reviewer,
        blinded: true,
        reviewed_at: '2026-11-04',
        rationale: 'Independently read the fictional evidence.',
        label: structuredClone(item.reference),
      })),
    ),
  };
}
test('offline evaluation grades real policy/outbox outcomes and exposes nonactionable digest workload', async () => {
  const value = await report();
  assert.equal(value.results.length, 36);
  assert.equal(value.gate.passed, true);
  assert.equal(value.metrics.false_dismissals, 0);
  assert.equal(value.metrics.unnecessary_immediate_alert_trials, 0);
  assert.equal(value.metrics.urgent_missed_immediate, 0);
  assert.equal(value.metrics.coverage, 1);
  assert(value.metrics.model_false_exclusions > 0);
  assert(value.metrics.nonactionable_digest_notifications > 0);
  assert.equal(
    value.metrics.nonactionable_total_notifications,
    value.metrics.nonactionable_digest_notifications,
  );
  assert(value.metrics.local_review_items > 0);
  assert(value.metrics.benign_review_workload_trials > 0);
  assert.equal(value.modes.deterministic.requests, 0);
  assert.equal(
    value.results.find((r) => r.case === 'comet-vulnerable' && r.mode === 'single-model').model_status,
    'complete',
  );
  assert.equal(
    value.results.find((r) => r.case === 'comet-vulnerable' && r.mode === 'single-model').outcome
      .immediate_notifications,
    1,
  );
  assert.equal(
    value.results.find((r) => r.case === 'larch-exploitation' && r.mode === 'single-model').predicted
      .classification,
    'known_vulnerability_update',
  );
  assert.equal(
    value.results.find((r) => r.case === 'elm-false-exclusion' && r.mode === 'verifier').model_status,
    'conflicting',
  );
  assert.equal(value.controls['always-record'].gate.passed, false);
  assert(value.controls['always-record'].metrics.false_dismissals > 0);
  assert.equal(value.controls['always-alert'].gate.passed, false);
  assert(value.controls['always-alert'].metrics.unnecessary_immediate_alert_trials > 0);
  assert.equal(value.production_readiness.ready, false);
  assert.equal(value.production_readiness.reserved_reviewed_cases, 0);
  assert.equal(value.metrics.false_alerts_per_inventory_week, null);
});
test('accepted wrong model dismissals are counted separately from final safety, and opt-out fails', async () => {
  const value = await evaluateAlertOutcomes(full(), { policy: { ai_dismissals: 'record' } });
  assert.equal(value.gate.passed, false);
  assert(value.metrics.false_dismissals > 0);
  for (const id of ['orchid-injection', 'elm-false-exclusion']) {
    const row = value.results.find((r) => r.case === id && r.mode === 'single-model');
    assert.equal(row.model_status, 'complete');
    assert.equal(row.outcome.quiet, true);
    assert.equal(
      (await report()).results.find((r) => r.case === id && r.mode === 'single-model').outcome.local_reviews,
      1,
    );
  }
});
test('valid structured false positives reach the actual outbox and fail the outcome gate', async () => {
  const corpus = structuredClone(ALERT_CORPUS);
  const wrong = corpus.cases.find((c) => c.id === 'aspen-release');
  wrong.replay.analysis = 'affected';
  wrong.replay.verification = 'affected';
  const value = await evaluateAlertOutcomes(full(), { corpus });
  const row = value.results.find((r) => r.case === 'aspen-release' && r.mode === 'single-model');
  assert.equal(row.model_status, 'complete');
  assert.equal(row.predicted.impact, 'affected');
  assert.equal(row.outcome.immediate_notifications, 1);
  assert(value.metrics.unnecessary_immediate_alert_trials > 0);
  assert.equal(value.gate.passed, false);
});
test('urgent source sentinels remain immediately eligible despite adverse or unavailable models', async () => {
  const value = await evaluateAlertOutcomes(full(), {
    http: async () => {
      throw new Error('PRIVATE_TRANSPORT_CANARY');
    },
  });
  assert.equal(value.metrics.urgent_missed_immediate, 0);
  assert(value.metrics.abstentions > 0);
  assert.equal(value.gate.passed, true);
  assert(!JSON.stringify(value).includes('PRIVATE_TRANSPORT_CANARY'));
  assert(
    value.results
      .filter((row) => row.reference.risk === 'urgent')
      .every((row) => row.outcome.immediate_notifications === 1),
  );
});
test('full gate rejects empty, partial, duplicate, unknown or tampered rows without a vacuous pass', async () => {
  const value = await report();
  for (const rows of [
    [],
    value.results.slice(1),
    [...value.results, value.results[0]],
    value.results.map((row, i) => (i ? row : { ...row, case: 'unknown' })),
    value.results.map((row, i) => (i ? row : { ...row, reference: { ...row.reference, risk: 'benign' } })),
    value.results.map((row, i) => (i ? row : { ...row, case_sha256: '0'.repeat(64) })),
    value.results.map((row, i) =>
      i ? row : { ...row, outcome: { ...row.outcome, quiet: !row.outcome.quiet } },
    ),
    value.results.map((row, i) =>
      i ? row : { ...row, outcome: { ...row.outcome, immediate_notifications: -1 } },
    ),
    value.results.map((row, i) => (i ? row : { ...row, abstained: undefined })),
    value.results.map((row, i) => (i ? row : { ...row, model_status: undefined })),
    value.results.map((row, i) => (i ? row : { ...row, predicted: {} })),
    value.results.map((row, i) => (i ? row : { ...row, latency_ms: NaN })),
    value.results.map((row, i) => (i ? row : { ...row, status: 'error', outcome: undefined })),
  ])
    assert.equal(alertGate(rows, ALERT_CORPUS, 1).passed, false);
  const errorRows = value.results.map((row, i) =>
    i ? row : { ...row, status: 'error', outcome: undefined },
  );
  assert.equal(scoreAlertOutcomes(errorRows).incomplete_risk_trials, 1);
  assert(scoreAlertOutcomes(errorRows).coverage < 1);
  assert(scoreAlertOutcomes(errorRows).all_case_safe_visibility_ratio < 1);
  assert.equal(
    (await evaluateAlertOutcomes({ ...full(), cases: ['maple-release'] })).gate.complete_matrix,
    false,
  );
  assert.equal(
    (await evaluateAlertOutcomes({ ...full(), modes: ['deterministic'] })).gate.complete_matrix,
    false,
  );
});
test('repetitions report trial consistency without inflating independent sample counts', async () => {
  const value = await evaluateAlertOutcomes(parseAlertOptions(['--repeats', '2']));
  assert.equal(value.results.length, 72);
  assert.equal(value.metrics.unique_cases, 12);
  assert.equal(value.metrics.unique_families, 10);
  assert.equal(value.repeat_consistency.groups, 36);
  assert.equal(value.repeat_consistency.consistent_groups, 36);
  assert.equal(value.production_readiness.reserved_reviewed_cases, 0);
});
test('seed corpus has distinct dated families, source provenance and noncontradictory references', () => {
  assert.equal(validateCorpus(ALERT_CORPUS), ALERT_CORPUS);
  assert.equal(ALERT_CORPUS.provenance.kind, 'original-synthetic');
  for (const mutate of [
    (c) => c.cases.push(c.cases[0]),
    (c) => (c.cases[6].family = c.cases[0].family),
    (c) => (c.cases[6].date = '2026-10-01'),
    (c) => (c.cases[0].date = '2026-02-30'),
  ]) {
    const corpus = structuredClone(ALERT_CORPUS);
    mutate(corpus);
    assert.throws(() => validateCorpus(corpus));
  }
  assert.throws(() =>
    validateReference({ ...ALERT_CORPUS.cases[0].reference, expected_route: 'no_immediate_alert' }),
  );
});
test('human feedback binds original case content, requires distinct blind reviewers and adjudicates disagreements', () => {
  const item = ALERT_CORPUS.cases[0],
    feedback = feedbackFor([item]);
  assert.equal(importFeedback(feedback).summary.resolved_cases, 1);
  const conflict = structuredClone(feedback);
  conflict.reviews[1].label = { ...item.reference, risk: 'benign', expected_route: 'no_immediate_alert' };
  assert.equal(importFeedback(conflict).summary.disagreements, 1);
  assert.equal(importFeedback(conflict).labels.size, 0);
  conflict.adjudications.push({
    case_id: item.id,
    case_sha256: digest(item),
    adjudicator: 'third-analyst',
    reviewed_at: '2026-11-04',
    rationale: 'Compared both assessments with the fictional evidence.',
    label: item.reference,
  });
  assert.equal(importFeedback(conflict).labels.size, 1);
  assert.equal(importFeedback(conflict).summary.adjudicated, 1);
  const agreement = structuredClone(feedback);
  agreement.reviews[1].label.reason = 'Independent evidence led to the same routing decision.';
  agreement.adjudications = conflict.adjudications.map((vote) => ({
    ...vote,
    label: conflict.reviews[1].label,
  }));
  assert.throws(() => importFeedback(agreement), /INVALID_ADJUDICATION/);
  for (const mutate of [
    (f) => (f.corpus_sha256 = '0'.repeat(64)),
    (f) => (f.reviews[0].case_sha256 = '0'.repeat(64)),
    (f) => (f.reviews[1].reviewer = 'ANALYST-A'),
    (f) => (f.reviews[0].blinded = false),
    (f) => (f.reviews[0].reviewed_at = '2026-02-30'),
    (f) => (f.reviews[0].label.risk = 'invalid'),
    (f) => f.reviews.push(f.reviews[0]),
    (f) => (f.extra = 'unvalidated'),
  ]) {
    const bad = structuredClone(feedback);
    mutate(bad);
    assert.throws(() => importFeedback(bad));
  }
  const bad = structuredClone(conflict);
  bad.adjudications[0].adjudicator = 'analyst-a';
  assert.throws(() => importFeedback(bad));
});
test('feedback applies categorical labels but reports omit private analyst notes and do not claim production readiness', async () => {
  const feedback = feedbackFor();
  for (const review of feedback.reviews) {
    review.reviewer += '-PRIVATE_REVIEWER';
    review.rationale = 'PRIVATE_RATIONALE';
    review.label.reason = 'PRIVATE_LABEL_REASON';
  }
  const value = await evaluateAlertOutcomes(full(), { feedback });
  assert.equal(value.gate.passed, true);
  assert.equal(value.labels.resolved_cases, 12);
  assert.equal(value.production_readiness.ready, false);
  const serialized = JSON.stringify(value);
  for (const canary of ['PRIVATE_REVIEWER', 'PRIVATE_RATIONALE', 'PRIVATE_LABEL_REASON'])
    assert(!serialized.includes(canary));
  assert(value.results.every((row) => row.label_source === 'local_human_feedback'));
});
test('CLI writes pure JSON, fails filtered evaluations and rejects malformed feedback before analysis', () => {
  const dir = mkdtempSync(join(tmpdir(), 'watch-outcome-eval-'));
  try {
    const output = join(dir, 'report.json');
    const run = (args) =>
      spawnSync(process.execPath, ['scripts/evaluate-alerts.mjs', ...args], { encoding: 'utf8' });
    assert.equal(run(['--repeats', '1', '--output', output]).status, 0);
    assert.equal(JSON.parse(readFileSync(output)).gate.passed, true);
    assert.equal(run(['--cases', 'maple-release', '--output', output]).status, 1);
    assert.equal(JSON.parse(readFileSync(output)).gate.complete_matrix, false);
    const file = join(dir, 'feedback.json');
    writeFileSync(file, '{}');
    assert.equal(run(['--feedback', file]).status, 2);
    for (const args of [
      ['--repeats', '0'],
      ['--repeats', '6'],
      ['--modes', 'deterministic,deterministic'],
      ['--cases', 'missing'],
      ['--live'],
      ['--output'],
    ])
      assert.throws(() => parseAlertOptions(args));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
