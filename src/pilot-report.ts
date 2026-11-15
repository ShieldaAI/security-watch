import type { DatabaseSync } from 'node:sqlite';
import { coverageFreshness } from './coverage.js';

/** Both dates are UTC dates. The end is exclusive. */
export interface PilotWindow {
  from: string;
  until: string;
}

const DAY = 86_400_000;
const MAX_ROWS = 100_000;
const states = () => ({ pending: 0, sending: 0, accepted: 0, failed: 0, unknown: 0 });
const decisions = () => ({ record: 0, digest: 0, notify: 0 });

const messages = {
  window: 'Choose 1 to 31 complete UTC days using YYYY-MM-DD dates and an exclusive end date.',
  database:
    'Could not read the pilot database. Choose an existing private monitor database or backup with the supported schema.',
  bounds: 'Pilot report size limit exceeded. See the documented database and window limits.',
  data: 'Pilot report could not validate the retained monitor records.',
  incidents:
    'Invalid independent incident reference. Check the date window, exact deployment targets, aliases and response deadlines.',
  responses:
    'Invalid pilot response register. Check the frozen evaluation, independent reviewer, evidence references and observation times.',
  labels:
    'Invalid pilot feedback. Check the snapshot, window, case references and independent reviewer declarations.',
} as const;

export class PilotReportError extends Error {
  constructor(code: keyof typeof messages) {
    super(messages[code]);
  }
}

function midnight(day: unknown): number {
  if (typeof day !== 'string' || !/^\d{4}-\d{2}-\d{2}$/u.test(day)) throw new PilotReportError('window');
  const time = Date.parse(day + 'T00:00:00Z');
  if (!Number.isSafeInteger(time) || time < 0 || new Date(time).toISOString().slice(0, 10) !== day)
    throw new PilotReportError('window');
  return time;
}

export function validatePilotWindow(input: PilotWindow, now: number) {
  const from = input?.from,
    until = input?.until;
  const start = midnight(from);
  const end = midnight(until);
  const days = (end - start) / DAY;
  if (days < 1 || days > 31 || end > Math.floor(now / DAY) * DAY) throw new PilotReportError('window');
  return { from, until, start, end, days };
}

function count(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0)
    throw new PilotReportError('data');
  return value;
}

function add<K extends string>(counts: Record<K, number>, key: unknown, value: unknown): void {
  if (typeof key !== 'string' || !Object.hasOwn(counts, key)) throw new PilotReportError('data');
  counts[key as K] += count(value);
}

function checkWork(db: DatabaseSync, start: number, end: number) {
  // OFFSET probes avoid materializing records. Both history tables have a recorded_at index.
  for (const table of ['finding_revisions', 'evidence_revisions']) {
    if (
      db
        .prepare(`SELECT 1 FROM ${table} WHERE recorded_at >= ? AND recorded_at < ? LIMIT 1 OFFSET ?`)
        .get(start, end, MAX_ROWS)
    )
      throw new PilotReportError('bounds');
  }
  for (const table of ['notifications', 'ai_reviews']) {
    if (db.prepare(`SELECT 1 FROM ${table} LIMIT 1 OFFSET ?`).get(MAX_ROWS))
      throw new PilotReportError('bounds');
  }
  if (
    db
      .prepare(
        'SELECT 1 FROM finding_revisions WHERE recorded_at>=? AND recorded_at<? AND length(CAST(decision AS BLOB))>16384 LIMIT 1',
      )
      .get(start, end)
  )
    throw new PilotReportError('bounds');
}

interface PilotCoverage {
  receipts: number;
  status: Record<'complete' | 'partial' | 'failed', number>;
  freshness: Record<'fresh' | 'stale' | 'never', number> | null;
}

function coverageSnapshot(db: DatabaseSync, now: number): PilotCoverage | null {
  const size = db
    .prepare("SELECT length(CAST(value AS BLOB)) AS bytes FROM metadata WHERE key='source:coverage'")
    .get();
  if (!size) return null;
  if (count(size.bytes) > 1024 * 1024) throw new PilotReportError('bounds');
  // Project only fields used for freshness; raw source names, URLs, error text and scope stay in SQLite.
  const shape = db
    .prepare(
      "SELECT json_type(value) AS kind, json_array_length(value) AS n FROM metadata WHERE key='source:coverage'",
    )
    .get()!;
  if (shape.kind !== 'array') throw new PilotReportError('data');
  if (count(shape.n) > 128) throw new PilotReportError('bounds');
  const rows = db
    .prepare(
      `SELECT json_extract(r.value,'$.status') AS status,
      json_extract(r.value,'$.last_success_at') AS last_success_at, json_extract(r.value,'$.fresh_until') AS fresh_until
    FROM metadata, json_each(metadata.value) r WHERE metadata.key='source:coverage'`,
    )
    .all();
  const status = { complete: 0, partial: 0, failed: 0 };
  const freshness = { fresh: 0, stale: 0, never: 0 };
  for (const row of rows) {
    add(status, row.status, 1);
    for (const value of [row.last_success_at, row.fresh_until]) {
      if (value !== null && (typeof value !== 'string' || !Number.isFinite(Date.parse(value))))
        throw new PilotReportError('data');
    }
    const state = coverageFreshness(
      {
        last_success_at: typeof row.last_success_at === 'string' ? row.last_success_at : undefined,
        fresh_until: typeof row.fresh_until === 'string' ? row.fresh_until : undefined,
      },
      now,
    );
    freshness[state]++;
  }
  return { receipts: rows.length, status, freshness };
}

function lastScan(db: DatabaseSync, now: number) {
  const size = db
    .prepare("SELECT length(CAST(value AS BLOB)) AS bytes FROM metadata WHERE key='last_scan'")
    .get();
  if (!size) return null;
  if (count(size.bytes) > 1024 * 1024) throw new PilotReportError('bounds');
  const row = db
    .prepare(
      `SELECT json_extract(value,'$.started_at') AS started,
    COALESCE(json_extract(value,'$.completed_at'),json_extract(value,'$.at')) AS completed,
    json_type(value,'$.degraded') AS degraded FROM metadata WHERE key='last_scan'`,
    )
    .get()!;
  const completed = typeof row.completed === 'string' ? Date.parse(row.completed) : NaN;
  const started = typeof row.started === 'string' ? Date.parse(row.started) : NaN;
  if (
    !Number.isFinite(completed) ||
    (row.degraded !== null && row.degraded !== 'true' && row.degraded !== 'false')
  )
    throw new PilotReportError('data');
  return {
    age_ms: completed <= now ? now - completed : null,
    duration_ms: Number.isFinite(started) && started <= completed ? completed - started : null,
    degraded: row.degraded === null ? null : row.degraded === 'true',
  };
}

function modelReservations(db: DatabaseSync, window: PilotWindow) {
  const rows = db
    .prepare(
      `SELECT substr(b.day,1,11) AS day, b.requests, b.tokens, b.usd,
        CASE WHEN length(CAST(m.value AS BLOB))>20 THEN 'invalid' ELSE m.value END AS unpriced
    FROM budgets b LEFT JOIN metadata m ON m.key='unpriced:' || b.day
    WHERE b.day>=? AND b.day<? ORDER BY b.day LIMIT 32`,
    )
    .all(window.from, window.until);
  if (rows.length > 31) throw new PilotReportError('data');
  let requests = 0,
    tokens = 0,
    knownUsd = 0,
    unpriced = 0;
  for (const row of rows) {
    midnight(row.day);
    const n = count(row.requests);
    const u = row.unpriced === null ? 0 : count(Number(row.unpriced));
    if (
      u > n ||
      (row.unpriced !== null && String(u) !== row.unpriced) ||
      typeof row.usd !== 'number' ||
      !Number.isFinite(row.usd) ||
      row.usd < 0
    )
      throw new PilotReportError('data');
    requests = count(requests + n);
    tokens = count(tokens + count(row.tokens));
    unpriced = count(unpriced + u);
    knownUsd += row.usd;
  }
  if (!Number.isFinite(knownUsd)) throw new PilotReportError('data');
  return {
    requests,
    tokens,
    unpriced_requests: unpriced,
    known_reserved_usd: knownUsd,
    reserved_usd: unpriced ? null : knownUsd,
  };
}

function reviewActivity(db: DatabaseSync, start: number, end: number) {
  const opened = db
    .prepare('SELECT COUNT(*) AS n FROM ai_reviews WHERE created_at>=? AND created_at<?')
    .get(start, end)!;
  // Each row stores the most recent operator action for one review revision. Later edits overwrite that timestamp.
  const responses = db
    .prepare(
      `SELECT created_at, reviewed_at FROM ai_reviews
    WHERE reviewed_at>=? AND reviewed_at<? ORDER BY reviewed_at-created_at`,
    )
    .iterate(start, end);
  let observed = 0,
    invalid = 0;
  const durations: number[] = [];
  for (const row of responses) {
    observed++;
    const elapsed = Number(row.reviewed_at) - Number(row.created_at);
    if (
      typeof row.created_at !== 'number' ||
      !Number.isSafeInteger(row.created_at) ||
      row.created_at < 0 ||
      typeof row.reviewed_at !== 'number' ||
      !Number.isSafeInteger(elapsed) ||
      elapsed < 0
    )
      invalid++;
    else durations.push(elapsed);
  }
  return {
    opened: count(opened.n),
    latest_response_rows: observed,
    latency_samples: durations.length,
    invalid_latency_rows: invalid,
    open_to_latest_response_p95_ms: durations[Math.ceil(durations.length * 0.95) - 1] ?? null,
  };
}

/** The caller owns a READONLY handle and a deferred read transaction covering every query. */
export function aggregatePilotReport(
  db: DatabaseSync,
  range: ReturnType<typeof validatePilotWindow>,
  asOf: number,
) {
  const { from, until, days, start, end } = range;
  checkWork(db, start, end);
  const daily = Array.from({ length: days }, (_, i) => ({
    date: new Date(start + i * DAY).toISOString().slice(0, 10),
    evidence_revisions: 0,
    finding_revisions: 0,
    decisions: decisions(),
  }));
  const routes = decisions();
  let findingRevisions = 0,
    evidenceRevisions = 0;
  for (const row of db
    .prepare(
      `SELECT CAST((recorded_at-?)/86400000 AS INTEGER) AS day,
        CASE json_extract(decision,'$.action') WHEN 'notify' THEN 'notify' WHEN 'digest' THEN 'digest' WHEN 'record' THEN 'record' ELSE 'invalid' END AS action,
        COUNT(*) AS n
     FROM finding_revisions WHERE recorded_at>0 AND recorded_at>=? AND recorded_at<? GROUP BY day, action`,
    )
    .all(start, start, end)) {
    const bucket = daily[count(row.day)]!;
    add(bucket.decisions, row.action, row.n);
    add(routes, row.action, row.n);
    bucket.finding_revisions += count(row.n);
    findingRevisions += count(row.n);
  }
  for (const row of db
    .prepare(
      `SELECT CAST((recorded_at-?)/86400000 AS INTEGER) AS day, COUNT(*) AS n
     FROM evidence_revisions WHERE recorded_at>0 AND recorded_at>=? AND recorded_at<? GROUP BY day`,
    )
    .all(start, start, end)) {
    daily[count(row.day)]!.evidence_revisions = count(row.n);
    evidenceRevisions += count(row.n);
  }
  const distinct = db
    .prepare(
      `SELECT COUNT(DISTINCT finding_id) AS n FROM finding_revisions
    WHERE recorded_at>0 AND recorded_at>=? AND recorded_at<?`,
    )
    .get(start, end)!;
  // available_at is a scheduling field. Cohort by finding revision, then report each associated job's state as read.
  const cohortStates = states();
  for (const row of db
    .prepare(
      `SELECT n.status, COUNT(*) AS n FROM finding_revisions r
    JOIN notifications n ON n.finding_id=r.finding_id AND n.revision=r.revision
    WHERE r.recorded_at>0 AND r.recorded_at>=? AND r.recorded_at<? GROUP BY n.status`,
    )
    .all(start, end))
    add(cohortStates, row.status, row.n);
  const allStates = states();
  for (const row of db.prepare('SELECT status, COUNT(*) AS n FROM notifications GROUP BY status').all())
    add(allStates, row.status, row.n);
  const review = db
    .prepare(
      `SELECT COUNT(*) FILTER(WHERE status='pending') AS pending,
    COUNT(*) FILTER(WHERE status='investigate') AS investigate,
    MIN(created_at) FILTER(WHERE status IN ('pending','investigate')) AS oldest FROM ai_reviews`,
    )
    .get()!;
  const oldest = review.oldest === null ? null : count(review.oldest);
  return {
    version: 1 as const,
    mode: 'pilot_report' as const,
    window: { from, until, days },
    activity: {
      finding_revisions: findingRevisions,
      distinct_findings: count(distinct.n),
      evidence_revisions: evidenceRevisions,
      days_with_retained_revisions: daily.filter((d) => d.finding_revisions || d.evidence_revisions).length,
      decisions: routes,
      daily,
      delivery_states_for_revisions: cohortStates,
      reviews: reviewActivity(db, start, end),
      model_reservations: modelReservations(db, range),
    },
    snapshot: {
      source: 'monitor_database' as 'monitor_database' | 'verified_backup',
      read_at: new Date(asOf).toISOString(),
      delivery_states: allStates,
      reviews: {
        pending: count(review.pending),
        investigate: count(review.investigate),
        oldest_open_age_ms: oldest === null || oldest > asOf ? null : asOf - oldest,
      },
      source_coverage: coverageSnapshot(db, asOf),
      last_scan: lastScan(db, asOf),
    },
    unmeasured: {
      urgent_recall: null,
      false_alert_rate: null,
      source_to_triage_p95_ms: null,
      monitored_days: null,
      actual_model_spend_usd: null,
    },
  };
}

export type PilotReport = ReturnType<typeof aggregatePilotReport>;
