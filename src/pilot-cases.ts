import { createHash } from 'node:crypto';
import { capturePilotWindow, dataArray, dataFields, readPrivatePilotJson } from './pilot-input.js';
import { DatabaseSync } from 'node:sqlite';
import { z } from 'zod';
import { withPrivatePilotBackup } from './maintenance.js';
import { PilotReportError, validatePilotWindow, type PilotWindow } from './pilot-report.js';

const MAX_REVISIONS = 1000;
const reference = z
  .string()
  .min(1)
  .max(512)
  .regex(/^[^\u0000-\u001f\u007f]+$/u);
const id = z.string().regex(/^[a-f0-9]{64}$/u);
// The pilot owner provisions one canonical opaque handle per person. Reject alternative spellings.
const reviewer = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/u);
const label = z.enum(['urgent', 'must_review', 'benign', 'abstain']);
const review = z.strictObject({ case_id: id, reviewer, blinded: z.literal(true), label });
const adjudication = z.strictObject({ case_id: id, adjudicator: reviewer, label });
const feedbackSchema = z.strictObject({
  version: z.literal(1),
  packet_id: id,
  reviews: z.array(review).max(2 * MAX_REVISIONS),
  adjudications: z.array(adjudication).max(MAX_REVISIONS),
});
export type PilotFeedback = z.infer<typeof feedbackSchema>;
type Label = z.infer<typeof label>;
const decision = z.object({
  action: z.enum(['notify', 'digest', 'record']),
  channels: z.array(z.enum(['slack', 'email'])).max(2),
  review: z.enum(['ai_general_news', 'ai_not_affected', 'ai_irrelevant']).optional(),
});
const lookup = z.strictObject({
  event_ref: reference,
  system_ref: reference,
  component_ref: reference.nullable(),
  evidence_refs: z.array(reference).max(64),
});
type Case = z.infer<typeof lookup> & { case_id: string; recorded_at: string };
export interface PilotCasePacket {
  version: 1;
  mode: 'private_pilot_cases';
  packet_id: string;
  window: PilotWindow;
  excluded_revisions: number;
  cases: Case[];
}
const deliveryJob = z.object({
  channel: z.enum(['slack', 'email']),
  mode: z.enum(['notify', 'digest']),
  status: z.enum(['pending', 'sending', 'accepted', 'unknown', 'failed']),
  accepted_at: z.number().int().nonnegative().max(8.64e15).nullable(),
});
type DeliveryRevision = Pick<Case, 'event_ref' | 'system_ref' | 'component_ref'> & {
  jobs: z.infer<typeof deliveryJob>[];
};
type Cohort = {
  packet: PilotCasePacket;
  routes: Map<string, { immediate: boolean; quiet: boolean }>;
  deliveryRevisions: DeliveryRevision[];
};
function invalidFeedback(): never {
  throw new PilotReportError('labels');
}

function readCohort(
  db: DatabaseSync,
  sourceHash: string,
  range: ReturnType<typeof validatePilotWindow>,
  includeDelivery: boolean,
): Cohort {
  const { start, end, from, until } = range;
  // A retry or digest for an older revision may first be accepted inside this study window.
  const priorRevisions = includeDelivery
    ? `UNION ALL SELECT r.finding_id,r.revision,r.recorded_at,r.payload,r.decision
       FROM (SELECT DISTINCT finding_id,revision FROM notifications WHERE accepted_at>=? AND accepted_at<?) n
       JOIN finding_revisions r USING(finding_id,revision) WHERE r.recorded_at>0 AND r.recorded_at<?`
    : '';
  const revisions = `SELECT finding_id,revision,recorded_at,payload,decision FROM finding_revisions
    WHERE recorded_at>0 AND recorded_at>=? AND recorded_at<? ${priorRevisions}`;
  const params = includeDelivery ? [start, end, start, end, start] : [start, end];
  if (
    includeDelivery &&
    db
      .prepare('SELECT 1 FROM notifications WHERE accepted_at>=? AND accepted_at<? LIMIT 1 OFFSET ?')
      .get(start, end, 2 * MAX_REVISIONS)
  )
    throw new PilotReportError('bounds');
  // Sample all eligible revisions in the chosen period or reject it. A truncated prefix biases scoring.
  const counted = db
    .prepare(
      `SELECT COUNT(*) AS n, MAX(bytes) AS max_bytes, SUM(bytes) AS total_bytes, MAX(decision_bytes) AS max_decision FROM (
     SELECT length(CAST(payload AS BLOB)) AS bytes, length(CAST(decision AS BLOB)) AS decision_bytes
     FROM (${revisions}) LIMIT ?)`,
    )
    .get(...params, MAX_REVISIONS + 1)!;
  if (
    Number(counted.n) > MAX_REVISIONS ||
    Number(counted.max_bytes) > 256 * 1024 ||
    Number(counted.total_bytes) > 32 * 1024 * 1024 ||
    Number(counted.max_decision) > 16384
  )
    throw new PilotReportError('bounds');
  const digest = (...parts: (string | number)[]) =>
    createHash('sha256').update(JSON.stringify(parts)).digest('hex');
  const packetId = digest('security-watch.pilot-cases.v1', sourceHash, from, until);
  const packet: PilotCasePacket = {
    version: 1,
    mode: 'private_pilot_cases',
    packet_id: packetId,
    window: { from, until },
    excluded_revisions: 0,
    cases: [],
  };
  const routes: Cohort['routes'] = new Map();
  const deliveryRevisions: DeliveryRevision[] = [];
  // Read only typed metadata for the two possible channels on each exact immutable revision.
  const jobsForRevision = includeDelivery
    ? db.prepare(
        `SELECT channel,status,accepted_at,length(CAST(payload AS BLOB)) AS bytes,
     CASE WHEN length(CAST(payload AS BLOB))<=524288 THEN json_extract(payload,'$.mode') END AS mode,
     CASE WHEN length(CAST(payload AS BLOB))<=524288 THEN
       json_extract(payload,'$.assessment.id') IS ? AND json_extract(payload,'$.assessment.event_id') IS ?
       AND json_extract(payload,'$.assessment.system_id') IS ? AND json_extract(payload,'$.assessment.component_id') IS ?
     END AS same_target
     FROM notifications WHERE finding_id=? AND revision=? AND (? OR (accepted_at>=? AND accepted_at<?)) LIMIT 3`,
      )
    : undefined;
  let notificationBytes = 0;
  // Only the coordinator's verified copy is opened. Actual model conclusions and reference labels never enter the packet.
  for (const row of db
    .prepare(
      `SELECT finding_id, revision, recorded_at,
    json_extract(decision,'$.action') AS action, json_extract(decision,'$.review') AS review,
    json_type(decision,'$.channels') AS channels_kind, json_extract(decision,'$.channels') AS channels,
    json_type(payload,'$.evidence_ids') AS evidence_kind,
    json_extract(payload,'$.id') AS saved_id, json_extract(payload,'$.category') AS category,
    json_type(payload,'$.active') AS active, json_type(payload,'$.withdrawn') AS withdrawn,
    json_extract(payload,'$.event_id') AS event_ref,json_extract(payload,'$.system_id') AS system_ref,
    json_extract(payload,'$.component_id') AS component_ref,json_extract(payload,'$.evidence_ids') AS evidence_refs
    FROM (${revisions}) ORDER BY recorded_at,finding_id,revision`,
    )
    .iterate(...params)) {
    if (
      typeof row.finding_id !== 'string' ||
      row.finding_id !== row.saved_id ||
      typeof row.revision !== 'number' ||
      !Number.isSafeInteger(row.revision) ||
      row.revision < 1 ||
      typeof row.recorded_at !== 'number' ||
      !Number.isSafeInteger(row.recorded_at) ||
      !['health', 'library', 'product', 'malware', 'news'].includes(String(row.category)) ||
      ![null, 'true', 'false'].includes(row.active as string | null) ||
      ![null, 'true', 'false'].includes(row.withdrawn as string | null)
    )
      throw new PilotReportError('data');
    if (row.category === 'health' || row.active === 'false' || row.withdrawn === 'true') {
      if (row.recorded_at >= start) packet.excluded_revisions++;
      continue;
    }
    if (row.evidence_kind !== 'array' || row.channels_kind !== 'array') throw new PilotReportError('data');
    const fields = lookup.safeParse({
      event_ref: row.event_ref,
      system_ref: row.system_ref,
      component_ref: row.component_ref,
      evidence_refs: JSON.parse(String(row.evidence_refs)),
    });
    const policy = decision.safeParse({
      action: row.action,
      channels: JSON.parse(String(row.channels)),
      review: row.review ?? undefined,
    });
    if (!fields.success || !policy.success) throw new PilotReportError('data');
    if (jobsForRevision) {
      const jobRows = jobsForRevision.all(
        row.finding_id,
        fields.data.event_ref,
        fields.data.system_ref,
        fields.data.component_ref,
        row.finding_id,
        row.revision,
        Number(row.recorded_at >= start),
        start,
        end,
      );
      if (new Set(jobRows.map((job) => job.channel)).size !== jobRows.length)
        throw new PilotReportError('data');
      const jobs = jobRows.map((job) => {
        notificationBytes += Number(job.bytes);
        if (Number(job.bytes) > 512 * 1024 || notificationBytes > 64 * 1024 * 1024)
          throw new PilotReportError('bounds');
        const parsed = deliveryJob.safeParse(job);
        if (
          job.same_target !== 1 ||
          !parsed.success ||
          (parsed.data.status !== 'accepted' && parsed.data.accepted_at !== null)
        )
          throw new PilotReportError('data');
        // A backwards wall clock cannot establish when this job was accepted.
        if (parsed.data.accepted_at !== null && parsed.data.accepted_at < Number(row.recorded_at))
          parsed.data.accepted_at = null;
        return parsed.data;
      });
      const { event_ref, system_ref, component_ref } = fields.data;
      if (jobs.length) deliveryRevisions.push({ event_ref, system_ref, component_ref, jobs });
    }
    if (row.recorded_at < start) continue;
    const caseId = digest('security-watch.pilot-case.v1', packetId, row.finding_id, row.revision);
    const action = policy.data;
    routes.set(caseId, {
      immediate: action.action === 'notify' && action.channels.length > 0,
      quiet: (action.action === 'record' || action.channels.length === 0) && action.review === undefined,
    });
    packet.cases.push({
      case_id: caseId,
      recorded_at: new Date(row.recorded_at).toISOString(),
      ...fields.data,
    });
  }
  return { packet, routes, deliveryRevisions };
}
export async function loadPilotCohort(
  backup: string,
  window: PilotWindow,
  includeDelivery = false,
): Promise<Cohort> {
  const range = capturePilotWindow(window);
  return withPrivatePilotBackup(backup, (path, digest) => {
    const db = new DatabaseSync(path, { readOnly: true });
    try {
      db.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN');
      return readCohort(db, digest, range, includeDelivery);
    } finally {
      db.close();
    }
  });
}

/** Private local research pointers suitable for blinded review by authorized analysts. */
export async function createPilotCasePacket(backup: string, window: PilotWindow): Promise<PilotCasePacket> {
  return (await loadPilotCohort(backup, window)).packet;
}

export function readPilotFeedback(path: string): PilotFeedback {
  return validateFeedback(readPrivatePilotJson(path, 'labels'));
}
function validateFeedback(input: unknown): PilotFeedback {
  const fields = dataFields(input, Object.keys(feedbackSchema.shape), 'labels');
  if (fields.version !== 1 || typeof fields.packet_id !== 'string' || fields.packet_id.length !== 64)
    invalidFeedback();
  function captureRows(rows: unknown, max: number, names: string[]) {
    return dataArray(rows, max, 'labels').map((row) => {
      const captured = dataFields(row, names, 'labels');
      for (const value of Object.values(captured))
        if (typeof value !== 'boolean' && (typeof value !== 'string' || value.length > 64)) invalidFeedback();
      return captured;
    });
  }
  fields.reviews = captureRows(fields.reviews, 2 * MAX_REVISIONS, Object.keys(review.shape));
  fields.adjudications = captureRows(fields.adjudications, MAX_REVISIONS, Object.keys(adjudication.shape));
  const parsed = feedbackSchema.safeParse(fields);
  if (!parsed.success) invalidFeedback();
  return parsed.data;
}
export function metric(numerator: number, denominator: number) {
  return { numerator, denominator, rate: denominator ? numerator / denominator : null };
}
export function latencySummary(samples: number[]) {
  samples.sort((a, b) => a - b);
  const middle = Math.floor(samples.length / 2);
  return {
    count: samples.length,
    median_ms: samples.length
      ? (samples[middle]! + samples[Math.floor((samples.length - 1) / 2)]!) / 2
      : null,
    p95_ms: samples[Math.ceil(samples.length * 0.95) - 1] ?? null,
  };
}
type RouteScope = Pick<PilotCasePacket, 'packet_id' | 'window' | 'excluded_revisions'>;

function grade(
  packet: RouteScope,
  routes: Cohort['routes'],
  feedback: PilotFeedback,
  evidenceDisagreements?: ReadonlySet<string>,
) {
  if (feedback.packet_id !== packet.packet_id) invalidFeedback();
  const pairs = new Map<string, PilotFeedback['reviews']>();
  for (const row of feedback.reviews) {
    const pair = pairs.get(row.case_id) ?? [];
    if (!routes.has(row.case_id) || pair.length >= 2 || pair.some((other) => other.reviewer === row.reviewer))
      invalidFeedback();
    pair.push(row);
    pairs.set(row.case_id, pair);
  }
  const resolutions = new Map<string, Label>();
  for (const row of feedback.adjudications) {
    const pair = pairs.get(row.case_id);
    if (
      !pair ||
      pair.length !== 2 ||
      (pair[0]!.label === pair[1]!.label && !evidenceDisagreements?.has(row.case_id)) ||
      pair.some((r) => r.reviewer === row.adjudicator) ||
      resolutions.has(row.case_id)
    )
      invalidFeedback();
    resolutions.set(row.case_id, row.label);
  }
  const coverage = {
    eligible: routes.size,
    excluded: packet.excluded_revisions,
    unreviewed: 0,
    single_review: 0,
    agreements: 0,
    disagreements: 0,
    adjudicated: resolutions.size,
    unresolved_conflicts: 0,
    abstained: 0,
    scored: 0,
  };
  let urgent = 0,
    risk = 0,
    benign = 0,
    immediateUrgent = 0,
    quietRisk = 0,
    immediateBenign = 0;
  for (const [caseId, route] of routes) {
    const pair = pairs.get(caseId);
    if (!pair) {
      coverage.unreviewed++;
      continue;
    }
    if (pair.length === 1) {
      coverage.single_review++;
      continue;
    }
    let referenceLabel = pair[0]!.label;
    if (referenceLabel === pair[1]!.label && !evidenceDisagreements?.has(caseId)) coverage.agreements++;
    else {
      coverage.disagreements++;
      const resolution = resolutions.get(caseId);
      if (!resolution) {
        coverage.unresolved_conflicts++;
        continue;
      }
      referenceLabel = resolution;
    }
    if (referenceLabel === 'abstain') {
      coverage.abstained++;
      continue;
    }
    coverage.scored++;
    if (referenceLabel === 'benign') {
      benign++;
      if (route.immediate) immediateBenign++;
    } else {
      risk++;
      if (route.quiet) quietRisk++;
      if (referenceLabel === 'urgent') {
        urgent++;
        if (route.immediate) immediateUrgent++;
      }
    }
  }
  return {
    version: 1 as const,
    mode: 'pilot_score' as const,
    window: packet.window,
    coverage,
    policy: {
      urgent_immediate: metric(immediateUrgent, urgent),
      quiet_risk: metric(quietRisk, risk),
      unnecessary_immediate: metric(immediateBenign, benign),
    },
    unmeasured: { population_urgent_recall: null, delivered_false_alert_rate: null },
  };
}
export type PilotScore = ReturnType<typeof grade>;

/** Internal replay hook for a frozen external roster. The caller accounts for every enrolled target. */
export function gradePilotRoutes(
  scope: RouteScope,
  routes: Cohort['routes'],
  feedback: PilotFeedback,
  evidenceDisagreements: ReadonlySet<string>,
) {
  return grade(scope, routes, validateFeedback(feedback), evidenceDisagreements);
}
/** Aggregate policy quality on the resolved subset of a frozen, explicitly accounted-for revision cohort. */
export async function scorePilotCases(
  backup: string,
  window: PilotWindow,
  feedback: PilotFeedback,
): Promise<PilotScore> {
  const captured = validateFeedback(feedback);
  const { packet, routes } = await loadPilotCohort(backup, window);
  return grade(packet, routes, captured);
}
