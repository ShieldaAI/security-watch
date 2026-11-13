import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assess, decide, parseConfig, Store, ModelAnalyzer } from '../dist/index.js';
import { PROMPT_VERSION } from '../dist/models.js';
import { memoryState } from './check-models.mjs';

export const MODES = Object.freeze(['deterministic', 'single-model', 'verifier']);
export const NOW = Date.parse('2026-11-04T12:00:00Z');
const canonical = (value) =>
  Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((key) => [key, canonical(value[key])]),
        )
      : value;
export const digest = (value) =>
  createHash('sha256')
    .update(JSON.stringify(canonical(value)))
    .digest('hex');
const freeze = (value) => {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
};
export const ALERT_CORPUS = freeze(
  JSON.parse(readFileSync(new URL('../evals/alert-outcomes/corpus.json', import.meta.url), 'utf8')),
);
const ratio = (n, d) => (d ? n / d : null);
const text = (value, max = 500) =>
  typeof value === 'string' &&
  value.trim() === value &&
  value.length > 0 &&
  value.length <= max &&
  !/[\u0000-\u001f\u007f]/u.test(value);
const date = (value) =>
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}$/.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString().startsWith(value);
const risks = ['benign', 'must_review', 'urgent'];
const replayKinds = ['affected', 'not_affected', 'general_news', 'unknown', 'unavailable'];
export function validateReference(label) {
  if (
    !label ||
    typeof label !== 'object' ||
    Array.isArray(label) ||
    Object.keys(label).sort().join(',') !==
      'authoritative_applicability,classification,evidence_support,expected_route,reason,risk' ||
    !risks.includes(label.risk) ||
    !['affected', 'not_affected', 'unknown', 'conflicting'].includes(label.authoritative_applicability) ||
    ![
      'new_vulnerability',
      'known_vulnerability_update',
      'general_news',
      'unknown',
      'not_applicable',
    ].includes(label.classification) ||
    !['synthetic_source', 'supported', 'unsupported', 'uncertain'].includes(label.evidence_support) ||
    !text(label.reason, 2000) ||
    label.expected_route !==
      { benign: 'no_immediate_alert', must_review: 'review_or_notify', urgent: 'notify' }[label.risk]
  )
    throw new Error('INVALID_REFERENCE');
  return label;
}
export function validateCorpus(corpus) {
  if (
    !corpus ||
    corpus.version !== 1 ||
    !Array.isArray(corpus.cases) ||
    corpus.cases.length < 1 ||
    corpus.cases.length > 1000 ||
    !date(corpus.split?.development_through) ||
    !date(corpus.split?.reserved_from) ||
    corpus.split.development_through >= corpus.split.reserved_from ||
    !text(corpus.provenance?.kind) ||
    !text(corpus.provenance?.license) ||
    !text(corpus.label_status)
  )
    throw new Error('INVALID_CORPUS');
  const ids = new Set(),
    families = new Map();
  for (const item of corpus.cases) {
    if (
      !text(item.id, 100) ||
      !/^[a-z0-9-]+$/.test(item.id) ||
      ids.has(item.id) ||
      !text(item.family, 100) ||
      !date(item.date) ||
      !['development', 'reserved'].includes(item.split) ||
      (item.split === 'development'
        ? item.date > corpus.split.development_through
        : item.date < corpus.split.reserved_from) ||
      (families.has(item.family) && families.get(item.family) !== item.split) ||
      !['advisory', 'news'].includes(item.kind) ||
      !text(item.product, 100) ||
      !(item.version === null || text(item.version, 100)) ||
      !text(item.text, 8000) ||
      !['low', 'high', 'critical', 'unknown'].includes(item.severity) ||
      typeof item.exploited !== 'boolean' ||
      !['full', 'excerpt'].includes(item.content_status) ||
      !replayKinds.includes(item.replay?.analysis) ||
      !replayKinds.includes(item.replay?.verification) ||
      (item.replay?.classification !== undefined &&
        !['new_vulnerability', 'known_vulnerability_update'].includes(item.replay.classification))
    )
      throw new Error('INVALID_CORPUS');
    validateReference(item.reference);
    ids.add(item.id);
    families.set(item.family, item.split);
  }
  if (
    !corpus.cases.some((c) => c.reference.risk === 'benign') ||
    !corpus.cases.some((c) => c.reference.risk === 'urgent') ||
    !corpus.cases.some((c) => c.reference.risk === 'must_review')
  )
    throw new Error('INVALID_CORPUS');
  return corpus;
}

/** Local analyst declarations; this validates provenance, not the identities or independence of people. */
export function importFeedback(feedback, corpus = ALERT_CORPUS) {
  validateCorpus(corpus);
  if (
    !feedback ||
    Object.keys(feedback).sort().join(',') !== 'adjudications,corpus_sha256,reviews,version' ||
    feedback.version !== 1 ||
    feedback.corpus_sha256 !== digest(corpus) ||
    !Array.isArray(feedback.reviews) ||
    feedback.reviews.length > 2000 ||
    !Array.isArray(feedback.adjudications) ||
    feedback.adjudications.length > 1000
  )
    throw new Error('INVALID_FEEDBACK');
  const byId = new Map(corpus.cases.map((c) => [c.id, c])),
    grouped = new Map(),
    adjudications = new Map();
  const identity = (value) => {
    if (!text(value, 100)) throw new Error('INVALID_FEEDBACK');
    return value.normalize('NFKC').toLowerCase();
  };
  const check = (row) => {
    const item = byId.get(row.case_id);
    if (!item || row.case_sha256 !== digest(item) || !date(row.reviewed_at))
      throw new Error('STALE_FEEDBACK');
    validateReference(row.label);
    return item;
  };
  for (const row of feedback.reviews) {
    if (
      !row ||
      Object.keys(row).sort().join(',') !== 'blinded,case_id,case_sha256,label,rationale,reviewed_at,reviewer'
    )
      throw new Error('INVALID_FEEDBACK');
    check(row);
    const reviewer = identity(row.reviewer);
    if (row.blinded !== true || !text(row.rationale, 2000)) throw new Error('INVALID_FEEDBACK');
    const reviews = grouped.get(row.case_id) ?? [];
    if (reviews.some((r) => r.identity === reviewer) || reviews.length >= 2)
      throw new Error('DUPLICATE_REVIEWER');
    reviews.push({ ...row, identity: reviewer });
    grouped.set(row.case_id, reviews);
  }
  for (const row of feedback.adjudications) {
    if (
      !row ||
      Object.keys(row).sort().join(',') !== 'adjudicator,case_id,case_sha256,label,rationale,reviewed_at'
    )
      throw new Error('INVALID_FEEDBACK');
    check(row);
    const adjudicator = identity(row.adjudicator),
      reviews = grouped.get(row.case_id) ?? [];
    if (
      adjudications.has(row.case_id) ||
      reviews.length !== 2 ||
      reviews.some((r) => r.identity === adjudicator) ||
      !text(row.rationale, 2000)
    )
      throw new Error('INVALID_ADJUDICATION');
    adjudications.set(row.case_id, row);
  }
  const labels = new Map();
  let agreements = 0,
    disagreements = 0;
  // Reasons can differ while the independently selected reference fields agree.
  const choices = (label) => {
    const { reason, ...rest } = label;
    return digest(rest);
  };
  for (const [id, reviews] of grouped) {
    if (reviews.length !== 2) continue;
    if (choices(reviews[0].label) === choices(reviews[1].label)) {
      if (adjudications.has(id)) throw new Error('INVALID_ADJUDICATION');
      agreements++;
      labels.set(id, reviews[0].label);
    } else {
      disagreements++;
      if (adjudications.has(id)) labels.set(id, adjudications.get(id).label);
    }
  }
  return {
    labels,
    summary: {
      feedback_sha256: digest(feedback),
      declared_blind_pairs: agreements + disagreements,
      agreements,
      disagreements,
      agreement_rate: ratio(agreements, agreements + disagreements),
      adjudicated: adjudications.size,
      resolved_cases: labels.size,
      unresolved_cases: corpus.cases.length - labels.size,
      identity_boundary:
        'Local declared analyst labels; identities and independent work are not authenticated by this importer.',
    },
  };
}

export function alertFixture(item) {
  const at = new Date(NOW).toISOString();
  const evidence = {
    id: `fixture:${item.id}`,
    source: 'synthetic-evaluation',
    kind: item.kind,
    title: `${item.product} advisory evaluation`,
    description: item.text,
    aliases: [],
    url: 'https://example.invalid/synthetic-advisory',
    severity: item.severity,
    exploited: item.exploited,
    content_status: item.content_status,
    packages: item.kind === 'advisory' ? [{ ecosystem: 'npm', name: item.product, range: '<2.0.0' }] : [],
    published_at: `${item.date}T00:00:00Z`,
    modified_at: at,
    fetched_at: at,
  };
  const system = {
    id: 'synthetic-inventory',
    name: 'Fictional evaluation system',
    environment: 'test',
    exposure: 'unknown',
    criticality: 'low',
    updated_at: at,
    components:
      item.kind === 'advisory'
        ? [
            {
              id: 'synthetic-component',
              ecosystem: 'npm',
              name: item.product,
              ...(item.version ? { version: item.version } : {}),
            },
          ]
        : [],
    products:
      item.kind === 'news'
        ? [{ name: item.product, ...(item.version ? { version: item.version } : {}), keywords: [] }]
        : [],
    keywords: [],
  };
  return { evidence, system, inventory: { version: 1, systems: [system] } };
}
export function replayResponse(item, evidence, kind) {
  if (kind === 'unavailable') throw new Error('SYNTHETIC_PROVIDER_OUTAGE');
  const quote = { evidence_id: evidence.id, quote: evidence.description };
  const news =
    item.kind === 'news'
      ? {
          classification:
            kind === 'general_news'
              ? 'general_news'
              : kind === 'unknown'
                ? 'unknown'
                : (item.replay.classification ?? 'new_vulnerability'),
          impact: kind === 'general_news' ? 'not_applicable' : kind,
          affected_products: kind === 'general_news' || kind === 'unknown' ? [] : [item.product],
          affected_versions:
            kind === 'general_news' || kind === 'unknown' || !item.version ? [] : [item.version],
          prerequisites: [],
          rationale: 'Synthetic response against the supplied evidence.',
          quotes: [quote],
        }
      : null;
  const result = {
    relevance:
      kind === 'not_affected' || kind === 'general_news'
        ? 'irrelevant'
        : kind === 'unknown'
          ? 'unknown'
          : 'relevant',
    priority: kind === 'affected' ? 'high' : 'low',
    summary: 'Synthetic evidence interpretation.',
    evidence_ids: [evidence.id],
    quotes: [quote],
    news_analysis: news,
  };
  return {
    status: 200,
    headers: {},
    body: JSON.stringify({
      choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(result) } }],
    }),
  };
}
export function recordAlertOutcome(assessment, config, evidence, now = NOW, { control = 'normal' } = {}) {
  const store = new Store(':memory:');
  try {
    store.saveEvidence(evidence, {});
    let decision = decide(assessment, config);
    if (control === 'always-record')
      decision = { action: 'record', channels: [], reason: 'Synthetic negative control' };
    if (control === 'always-alert')
      decision = { action: 'notify', channels: ['slack'], reason: 'Synthetic negative control' };
    store.saveAssessment(assessment, decision, now, 86_400_000, 'synthetic-evaluation');
    const jobs = store.jobs().filter((job) => job.status === 'pending');
    const immediate = jobs.filter(
      (job) => JSON.parse(job.payload).mode === 'notify' && job.available_at <= now,
    ).length;
    const digestJobs = jobs.filter((job) => JSON.parse(job.payload).mode === 'digest').length;
    const localReviews = store.reviews().length;
    return {
      decision: decision.action,
      immediate_notifications: immediate,
      digest_notifications: digestJobs,
      local_reviews: localReviews,
      visible: immediate + digestJobs + localReviews > 0,
      quiet: immediate + digestJobs + localReviews === 0,
    };
  } finally {
    store.close();
  }
}
function validOutcomeRow(row) {
  try {
    validateReference(row.reference);
  } catch {
    return false;
  }
  const o = row.outcome;
  return (
    row.status === 'complete' &&
    typeof row.abstained === 'boolean' &&
    ['complete', 'unavailable', 'conflicting', 'disabled'].includes(row.model_status) &&
    (row.predicted === null ||
      (row.predicted &&
        ['new_vulnerability', 'known_vulnerability_update', 'general_news', 'unknown'].includes(
          row.predicted.classification,
        ) &&
        ['affected', 'not_affected', 'not_applicable', 'unknown'].includes(row.predicted.impact))) &&
    o &&
    ['notify', 'digest', 'record'].includes(o.decision) &&
    ['immediate_notifications', 'digest_notifications', 'local_reviews'].every(
      (key) => Number.isSafeInteger(o[key]) && o[key] >= 0 && o[key] <= 1000,
    ) &&
    typeof o.visible === 'boolean' &&
    o.quiet === (o.immediate_notifications + o.digest_notifications + o.local_reviews === 0) &&
    o.visible === !o.quiet &&
    Number.isFinite(row.latency_ms) &&
    row.latency_ms >= 0 &&
    Number.isSafeInteger(row.requests) &&
    row.requests >= 0 &&
    row.requests <= 2
  );
}
export function scoreAlertOutcomes(results) {
  const complete = results.filter(validOutcomeRow),
    risk = complete.filter((r) => r.reference.risk !== 'benign'),
    benign = complete.filter((r) => r.reference.risk === 'benign'),
    urgent = complete.filter((r) => r.reference.risk === 'urgent');
  const falseDismissals = risk.filter((r) => r.outcome.quiet).length,
    unnecessary = benign.filter((r) => r.outcome.immediate_notifications > 0).length;
  const sum = (rows, key) => rows.reduce((n, r) => n + r.outcome[key], 0);
  const modelExclusions = risk.filter(
    (r) => r.predicted && ['not_affected', 'not_applicable'].includes(r.predicted.impact),
  ).length;
  const latency = complete.map((r) => r.latency_ms).sort((a, b) => a - b);
  const expectedRisk = results.filter((r) => r.reference?.risk && r.reference.risk !== 'benign'),
    expectedBenign = results.filter((r) => r.reference?.risk === 'benign');
  return {
    trials: results.length,
    complete: complete.length,
    errors: results.length - complete.length,
    unique_cases: new Set(results.map((r) => r.case)).size,
    unique_families: new Set(results.map((r) => r.family)).size,
    coverage: ratio(complete.length, results.length),
    must_review_or_urgent_trials: expectedRisk.length,
    scored_risk_trials: risk.length,
    incomplete_risk_trials: expectedRisk.length - risk.length,
    all_case_safe_visibility_ratio: ratio(risk.filter((r) => r.outcome.visible).length, expectedRisk.length),
    false_dismissals: falseDismissals,
    false_dismissal_rate: ratio(falseDismissals, risk.length),
    model_false_exclusions: modelExclusions,
    benign_trials: expectedBenign.length,
    scored_benign_trials: benign.length,
    unnecessary_immediate_alert_trials: unnecessary,
    unnecessary_immediate_alert_rate: ratio(unnecessary, benign.length),
    nonactionable_immediate_notifications: sum(benign, 'immediate_notifications'),
    nonactionable_digest_notifications: sum(benign, 'digest_notifications'),
    nonactionable_total_notifications:
      sum(benign, 'immediate_notifications') + sum(benign, 'digest_notifications'),
    urgent_trials: urgent.length,
    urgent_missed_immediate: urgent.filter((r) => r.outcome.immediate_notifications === 0).length,
    immediate_notifications: sum(complete, 'immediate_notifications'),
    digest_notifications: sum(complete, 'digest_notifications'),
    local_review_items: sum(complete, 'local_reviews'),
    review_workload_trials: complete.filter(
      (r) => r.outcome.digest_notifications + r.outcome.local_reviews > 0,
    ).length,
    benign_review_workload_trials: benign.filter(
      (r) => r.outcome.digest_notifications + r.outcome.local_reviews > 0,
    ).length,
    model_status_counts: Object.fromEntries(
      [...new Set(complete.map((r) => r.model_status))].map((status) => [
        status,
        complete.filter((r) => r.model_status === status).length,
      ]),
    ),
    abstentions: complete.filter((r) => r.abstained).length,
    requests: results.reduce((n, r) => n + (r.requests ?? 0), 0),
    p95_latency_ms: latency.length ? latency[Math.ceil(latency.length * 0.95) - 1] : null,
    cost: { paid_requests: 0, synthetic_transport_cost: 0, production_cost_per_useful_finding: null },
    false_alerts_per_inventory_week: null,
    uncertainty:
      'Deterministic synthetic trials; repetitions are not independent observations. Production rates and confidence bounds are unmeasured.',
  };
}
export function alertGate(results, corpus, repeats, modes = MODES) {
  const expected = new Set(
    corpus.cases.flatMap((c) =>
      MODES.flatMap((mode) => Array.from({ length: repeats }, (_, i) => JSON.stringify([c.id, mode, i + 1]))),
    ),
  );
  const seen = new Set(),
    byId = new Map(corpus.cases.map((c) => [c.id, c]));
  let valid =
    Number.isInteger(repeats) &&
    repeats >= 1 &&
    repeats <= 5 &&
    modes.length === MODES.length &&
    MODES.every((m) => modes.includes(m));
  for (const row of results) {
    const key = JSON.stringify([row.case, row.mode, row.trial]);
    if (
      !expected.has(key) ||
      seen.has(key) ||
      !validOutcomeRow(row) ||
      digest(row.reference) !== digest(byId.get(row.case)?.reference) ||
      row.family !== byId.get(row.case)?.family ||
      row.split !== byId.get(row.case)?.split ||
      row.case_sha256 !== (byId.get(row.case)?.source_sha256 ?? digest(byId.get(row.case)))
    )
      valid = false;
    seen.add(key);
  }
  valid &&= seen.size === expected.size;
  const metrics = scoreAlertOutcomes(results);
  return {
    passed:
      valid &&
      metrics.false_dismissals === 0 &&
      metrics.unnecessary_immediate_alert_trials === 0 &&
      metrics.urgent_missed_immediate === 0,
    complete_matrix: valid,
    expected_trials: expected.size,
    thresholds: { false_dismissals: 0, unnecessary_immediate_alert_trials: 0, urgent_missed_immediate: 0 },
    digest_and_review_burden_threshold: null,
    scope:
      'Synthetic regression gate; benign digest/review workload is reported but needs operational calibration.',
  };
}
export function parseAlertOptions(args) {
  const options = { repeats: 2, modes: [...MODES], cases: ALERT_CORPUS.cases.map((c) => c.id) };
  const seen = new Set();
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (seen.has(flag)) throw new Error('INVALID_OPTIONS');
    seen.add(flag);
    if (flag === '--help') {
      options.help = true;
      continue;
    }
    const value = args[++i];
    if (!value) throw new Error('INVALID_OPTIONS');
    if (flag === '--repeats') {
      options.repeats = Number(value);
      if (!Number.isInteger(options.repeats) || options.repeats < 1 || options.repeats > 5)
        throw new Error('INVALID_OPTIONS');
    } else if (flag === '--modes' || flag === '--cases') {
      const values = value.split(','),
        allowed = flag === '--modes' ? MODES : ALERT_CORPUS.cases.map((c) => c.id);
      if (new Set(values).size !== values.length || values.some((v) => !allowed.includes(v)))
        throw new Error('INVALID_OPTIONS');
      options[flag.slice(2)] = values;
    } else if (flag === '--output' || flag === '--feedback') options[flag.slice(2)] = value;
    else throw new Error('INVALID_OPTIONS');
  }
  return options;
}
export async function evaluateAlertOutcomes(
  options = parseAlertOptions([]),
  { corpus = ALERT_CORPUS, feedback, policy = {}, http } = {},
) {
  validateCorpus(corpus);
  if (
    !Number.isInteger(options.repeats) ||
    options.repeats < 1 ||
    options.repeats > 5 ||
    !Array.isArray(options.modes) ||
    !options.modes.length ||
    new Set(options.modes).size !== options.modes.length ||
    options.modes.some((m) => !MODES.includes(m)) ||
    !Array.isArray(options.cases) ||
    !options.cases.length ||
    new Set(options.cases).size !== options.cases.length ||
    options.cases.some((id) => !corpus.cases.some((c) => c.id === id))
  )
    throw new Error('INVALID_OPTIONS');
  const imported = feedback ? importFeedback(feedback, corpus) : undefined;
  const referenceFor = (item) =>
    imported?.labels.has(item.id)
      ? {
          ...imported.labels.get(item.id),
          reason: 'Local human reference; free-text notes remain in the feedback file.',
        }
      : item.reference;
  const rows = [];
  for (const item of corpus.cases.filter((c) => options.cases.includes(c.id)))
    for (const mode of options.modes)
      for (let trial = 1; trial <= options.repeats; trial++) {
        const started = performance.now();
        let requests = 0;
        const reference = referenceFor(item);
        const base = {
          case: item.id,
          family: item.family,
          split: item.split,
          mode,
          trial,
          reference,
          label_source: imported?.labels.has(item.id) ? 'local_human_feedback' : 'agent_authored_synthetic',
          case_sha256: digest(item),
        };
        try {
          const spec = {
            provider: 'openai-compatible',
            model: 'offline-fixture',
            endpoint: 'http://127.0.0.1:1/synthetic-never-connected',
            allow_private_endpoint: true,
          };
          const config = parseConfig({
            version: 1,
            sources: { cve_now: false, hacker_news: false },
            policy: {
              library: { channels: ['slack'], levels: ['high', 'critical'] },
              product: { channels: ['slack'], levels: ['high', 'critical'] },
              news: { channels: ['slack'], levels: ['high', 'critical'] },
              ...policy,
            },
            notifications: { slack: { webhook_url_env: 'SYNTHETIC_NEVER_READ' } },
            models: {
              enabled: mode !== 'deterministic',
              analysis: spec,
              ...(mode === 'verifier' ? { verification: { ...spec, model: 'offline-verifier' } } : {}),
              daily_request_limit: 2,
              daily_token_limit: 100000,
              max_input_chars: 8000,
              max_output_tokens: 1024,
              timeout_seconds: 1,
            },
          });
          const fixture = alertFixture(item),
            assessments = assess(fixture.inventory, [fixture.evidence], config, NOW);
          if (assessments.length !== 1) throw new Error('FIXTURE_MATCH_FAILED');
          let assessment = assessments[0];
          if (mode !== 'deterministic')
            assessment = await new ModelAnalyzer(
              config,
              memoryState(),
              async (url, request) => {
                requests++;
                if (requests > 2) throw new Error('REQUEST_CAP');
                return http
                  ? http({ item, mode, trial, request, request_index: requests, fixture, url })
                  : replayResponse(
                      item,
                      fixture.evidence,
                      requests === 1 ? item.replay.analysis : item.replay.verification,
                    );
              },
              () => NOW,
              AbortSignal.timeout(3000),
              {},
            ).analyze(assessment, fixture.system, [fixture.evidence]);
          const outcome = recordAlertOutcome(assessment, config, [fixture.evidence]);
          const controls = Object.fromEntries(
            ['always-record', 'always-alert'].map((control) => [
              control,
              recordAlertOutcome(assessment, config, [fixture.evidence], NOW, { control }),
            ]),
          );
          rows.push({
            ...base,
            status: 'complete',
            outcome,
            controls,
            requests,
            model_status: assessment.ai?.status ?? 'disabled',
            predicted: assessment.news_analysis
              ? {
                  classification: assessment.news_analysis.classification,
                  impact: assessment.news_analysis.impact,
                }
              : null,
            abstained:
              assessment.ai?.status === 'unavailable' ||
              assessment.ai?.status === 'conflicting' ||
              assessment.news_analysis?.impact === 'unknown' ||
              (mode === 'deterministic' &&
                (assessment.news_candidate || assessment.applicability === 'unknown')),
            latency_ms: performance.now() - started,
          });
        } catch {
          rows.push({
            ...base,
            status: 'error',
            error: 'EVALUATION_CASE_FAILED',
            requests,
            latency_ms: performance.now() - started,
          });
        }
      }
  const effectiveCorpus = {
    ...corpus,
    cases: corpus.cases.map((item) => ({
      ...item,
      reference: referenceFor(item),
      source_sha256: digest(item),
    })),
  };
  const gate = alertGate(rows, effectiveCorpus, options.repeats, options.modes);
  const controls = Object.fromEntries(
    ['always-record', 'always-alert'].map((control) => {
      const results = rows.map((row) =>
        row.status === 'complete' ? { ...row, outcome: row.controls[control] } : row,
      );
      return [
        control,
        {
          metrics: scoreAlertOutcomes(results),
          gate: alertGate(results, effectiveCorpus, options.repeats, options.modes),
        },
      ];
    }),
  );
  gate.controls_valid =
    !controls['always-record'].gate.passed &&
    !controls['always-alert'].gate.passed &&
    controls['always-record'].metrics.false_dismissals > 0 &&
    controls['always-alert'].metrics.unnecessary_immediate_alert_trials > 0;
  gate.passed &&= gate.controls_valid;
  const repetitions = Object.values(Object.groupBy(rows, (row) => JSON.stringify([row.case, row.mode]))).map(
    (group) => ({
      case: group[0].case,
      mode: group[0].mode,
      trials: group.length,
      distinct_outcomes: new Set(
        group.map((row) =>
          digest({
            status: row.status,
            outcome: row.outcome ?? null,
            predicted: row.predicted ?? null,
            model_status: row.model_status ?? null,
          }),
        ),
      ).size,
    }),
  );
  const reserved = corpus.cases.filter((c) => c.split === 'reserved' && imported?.labels.has(c.id)),
    reservedRisk = reserved.filter((c) => imported.labels.get(c.id).risk !== 'benign');
  return {
    version: 1,
    kind: 'offline-alert-outcome-evaluation',
    corpus_sha256: digest(corpus),
    corpus_version: corpus.version,
    prompt_version: PROMPT_VERSION,
    scenario_type:
      'Original synthetic cases with fictional inventories and deterministic model replays; not a production model accuracy benchmark.',
    run_configuration: {
      modes: options.modes,
      repeats: options.repeats,
      selected_cases: options.cases,
      model: 'offline-fixture',
      verification_model: 'offline-verifier',
      request_cap: options.cases.length * options.repeats * 3,
      now: new Date(NOW).toISOString(),
    },
    metrics: scoreAlertOutcomes(rows),
    modes: Object.fromEntries(
      MODES.map((mode) => [mode, scoreAlertOutcomes(rows.filter((r) => r.mode === mode))]),
    ),
    gate,
    controls,
    repeat_consistency: {
      groups: repetitions.length,
      consistent_groups: repetitions.filter((group) => group.distinct_outcomes === 1).length,
      results: repetitions,
    },
    labels: imported?.summary ?? {
      resolved_cases: 0,
      unresolved_cases: corpus.cases.length,
      status: 'agent_authored_pending_human_review',
    },
    production_readiness: {
      ready: false,
      reserved_reviewed_cases: reserved.length,
      reserved_reviewed_risk_cases: reservedRisk.length,
      required_cases: 100,
      required_risk_cases: 60,
      reasons: [
        ...(reserved.length < 100 ? ['fewer_than_100_independently_reviewed_reserved_cases'] : []),
        ...(reservedRisk.length < 60 ? ['fewer_than_60_reviewed_risk_cases'] : []),
        'reserved_synthetic_fixtures_are_not_a_sealed_holdout',
        'representative_inventory_time_cost_and_workload_targets_not_calibrated',
      ],
    },
    results: rows.map(({ controls, ...row }) => row),
  };
}
export async function main(args = process.argv.slice(2)) {
  try {
    const options = parseAlertOptions(args);
    if (options.help) {
      console.log(
        'Usage: node scripts/evaluate-alerts.mjs [--output FILE] [--repeats 1..5] [--modes deterministic,single-model,verifier] [--cases ID,ID] [--feedback FILE]\nOffline only: no provider credentials, network or notification delivery. Full regression gate requires all cases and modes. Exit 0 full pass, 1 incomplete/unsafe outcome, 2 invalid options/input. Human production readiness is reported separately and remains unproven by synthetic replays.',
      );
      return 0;
    }
    const feedback = options.feedback ? JSON.parse(readFileSync(options.feedback, 'utf8')) : undefined;
    const report = await evaluateAlertOutcomes(options, { feedback });
    const output = JSON.stringify(report, null, 2) + '\n';
    if (options.output) writeFileSync(options.output, output, { mode: 0o600 });
    else process.stdout.write(output);
    return report.gate.passed ? 0 : 1;
  } catch {
    console.error('Invalid evaluation options, corpus, feedback or output destination.');
    return 2;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  process.exitCode = await main();
