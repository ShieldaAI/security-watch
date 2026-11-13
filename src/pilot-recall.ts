import { createHash } from 'node:crypto';
import { normalizeEventId } from './assessment.js';
import { latencySummary, loadPilotCohort, metric } from './pilot-cases.js';
import {
  capturePilotWindow,
  dataArray,
  dataFields,
  pilotInstant,
  readPrivatePilotJson,
} from './pilot-input.js';
import { PilotReportError, type PilotWindow } from './pilot-report.js';

interface UrgentIncident {
  incident_id: string;
  event_refs: string[];
  system_ref: string;
  component_ref: string | null;
  available_at: string;
  deadline_at: string;
}
export interface PilotIncidentReference {
  version: 1;
  window: PilotWindow;
  curator: string;
  selected_independently: true;
  incidents: UrgentIncident[];
}

function invalid(): never {
  throw new PilotReportError('incidents');
}
function referenceText(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > 512 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  )
    invalid();
  return value;
}
function target(system: string, component: string | null, event: string): string {
  return JSON.stringify([system, component, event]);
}

/** Copy and validate the whole external denominator before starting asynchronous backup verification. */
export function capturePilotIncidentReference(input: unknown): PilotIncidentReference {
  const ref = dataFields(
    input,
    ['version', 'window', 'curator', 'selected_independently', 'incidents'],
    'incidents',
  );
  if (
    ref.version !== 1 ||
    ref.selected_independently !== true ||
    typeof ref.curator !== 'string' ||
    !/^[a-z][a-z0-9_-]{0,63}$/u.test(ref.curator)
  )
    invalid();
  const window = dataFields(ref.window, ['from', 'until'], 'incidents');
  if (typeof window.from !== 'string' || typeof window.until !== 'string') invalid();
  const { from, until, start, end } = capturePilotWindow({ from: window.from, until: window.until });
  const ids = new Set<string>(),
    targets = new Set<string>();
  let totalBytes = 0;
  const incidents = dataArray(ref.incidents, 1000, 'incidents').map((item) => {
    const row = dataFields(
      item,
      ['incident_id', 'event_refs', 'system_ref', 'component_ref', 'available_at', 'deadline_at'],
      'incidents',
    );
    const incident_id = referenceText(row.incident_id),
      system_ref = referenceText(row.system_ref);
    const component_ref = row.component_ref === null ? null : referenceText(row.component_ref);
    const available_at = pilotInstant(row.available_at, 'incidents'),
      deadline_at = pilotInstant(row.deadline_at, 'incidents');
    if (
      Date.parse(available_at) < start ||
      Date.parse(deadline_at) > end ||
      available_at >= deadline_at ||
      ids.has(incident_id)
    )
      invalid();
    ids.add(incident_id);
    const event_refs = dataArray(row.event_refs, 16, 'incidents')
      .map((alias) => {
        const event = normalizeEventId(referenceText(alias));
        const key = target(system_ref, component_ref, event);
        if (targets.has(key)) invalid();
        targets.add(key);
        return event;
      })
      .sort();
    if (!event_refs.length) invalid();
    const incident = { incident_id, event_refs, system_ref, component_ref, available_at, deadline_at };
    totalBytes += Buffer.byteLength(JSON.stringify(incident));
    if (totalBytes > 1024 * 1024) invalid();
    return incident;
  });
  incidents.sort((a, b) => (a.incident_id < b.incident_id ? -1 : a.incident_id > b.incident_id ? 1 : 0));
  return {
    version: 1,
    window: { from, until },
    curator: ref.curator,
    selected_independently: true,
    incidents,
  };
}

export function readPilotIncidentReference(path: string): PilotIncidentReference {
  return capturePilotIncidentReference(readPrivatePilotJson(path, 'incidents'));
}

const receiptCounts = () => ({
  on_time: 0,
  before_availability: 0,
  at_or_after_deadline: 0,
  accepted_time_unknown: 0,
  pending: 0,
  sending: 0,
  unknown: 0,
  failed: 0,
});

/** Evaluate each independently enumerated incident against retained decisions and transport receipts. */
export async function evaluatePilotReference(
  backup: string,
  window: PilotWindow,
  reference: PilotIncidentReference,
) {
  const range = capturePilotWindow(window);
  if (range.from !== reference.window.from || range.until !== reference.window.until) invalid();
  const { packet, routes, deliveryRevisions } = await loadPilotCohort(backup, reference.window, true);
  const outcomes = {
    on_time_immediate: 0,
    on_time_other: 0,
    late_only: 0,
    prior_and_late: 0,
    prior_only: 0,
    no_retained_match: 0,
  };
  const observations = reference.incidents.map((incident) => ({
    incident,
    prior: false,
    late: false,
    onTime: false,
    immediate: false,
    availableAt: Date.parse(incident.available_at),
    deadlineAt: Date.parse(incident.deadline_at),
    receipts: new Set<keyof ReturnType<typeof receiptCounts>>(),
    onTimeImmediateReceipt: false,
    firstLatencyMs: null as number | null,
  }));
  const byTarget = new Map<string, (typeof observations)[number]>();
  for (const item of observations) {
    for (const event of item.incident.event_refs)
      byTarget.set(target(item.incident.system_ref, item.incident.component_ref, event), item);
  }
  for (const c of packet.cases) {
    const match = byTarget.get(target(c.system_ref, c.component_ref, normalizeEventId(c.event_ref)));
    if (!match) continue;
    // Both timestamps are canonical UTC ISO strings with the same precision.
    if (c.recorded_at < match.incident.available_at) match.prior = true;
    else if (c.recorded_at >= match.incident.deadline_at) match.late = true;
    else {
      match.onTime = true;
      if (routes.get(c.case_id)!.immediate) match.immediate = true;
    }
  }
  for (const revision of deliveryRevisions) {
    const match = byTarget.get(
      target(revision.system_ref, revision.component_ref, normalizeEventId(revision.event_ref)),
    );
    if (!match) continue;
    for (const job of revision.jobs) {
      if (job.status !== 'accepted') match.receipts.add(job.status);
      else if (job.accepted_at === null) match.receipts.add('accepted_time_unknown');
      else if (job.accepted_at < match.availableAt) match.receipts.add('before_availability');
      else {
        const delay = job.accepted_at - match.availableAt;
        match.firstLatencyMs = Math.min(delay, match.firstLatencyMs ?? delay);
        if (job.accepted_at >= match.deadlineAt) match.receipts.add('at_or_after_deadline');
        else {
          match.receipts.add('on_time');
          if (job.mode === 'notify') match.onTimeImmediateReceipt = true;
        }
      }
    }
  }
  const incidentsWith = receiptCounts();
  const latencies: number[] = [];
  let withoutRetainedJob = 0,
    onTimeImmediate = 0;
  for (const observation of observations) {
    if (observation.immediate) outcomes.on_time_immediate++;
    else if (observation.onTime) outcomes.on_time_other++;
    else if (observation.late && observation.prior) outcomes.prior_and_late++;
    else if (observation.late) outcomes.late_only++;
    else if (observation.prior) outcomes.prior_only++;
    else outcomes.no_retained_match++;
    if (!observation.receipts.size) withoutRetainedJob++;
    for (const state of observation.receipts) incidentsWith[state]++;
    if (observation.onTimeImmediateReceipt) onTimeImmediate++;
    if (observation.firstLatencyMs !== null) latencies.push(observation.firstLatencyMs);
  }
  const denominator = observations.length;
  const report = {
    version: 1 as const,
    mode: 'pilot_recall' as const,
    window: reference.window,
    evaluation_id: createHash('sha256')
      .update(JSON.stringify(['security-watch.pilot-recall.v1', packet.packet_id, reference]))
      .digest('hex'),
    reference_incidents: denominator,
    outcomes,
    metrics: {
      on_time_observed: metric(outcomes.on_time_other + outcomes.on_time_immediate, denominator),
      on_time_immediate: metric(outcomes.on_time_immediate, denominator),
    },
    provider_acceptance: {
      on_time: metric(incidentsWith.on_time, denominator),
      on_time_immediate: metric(onTimeImmediate, denominator),
      incidents_with: incidentsWith,
      without_retained_job: withoutRetainedJob,
      first_acceptance_after_availability: latencySummary(latencies),
    },
    unmeasured: {
      population_urgent_recall: null,
      delivered_alert_recall: null,
      monitor_window_completeness: null,
    },
  };
  const onTimeProvider = new Set(
    observations.filter((o) => o.receipts.has('on_time')).map((o) => o.incident.incident_id),
  );
  return { report, onTimeProvider };
}
export async function scorePilotRecall(backup: string, window: PilotWindow, input: PilotIncidentReference) {
  return (await evaluatePilotReference(backup, window, capturePilotIncidentReference(input))).report;
}
export type PilotRecallScore = Awaited<ReturnType<typeof scorePilotRecall>>;

/** Prepare a blind worksheet for the independent reviewer of this exact backup and incident list. */
export async function createPilotResponseTemplate(
  backup: string,
  window: PilotWindow,
  input: PilotIncidentReference,
) {
  const reference = capturePilotIncidentReference(input);
  const { report } = await evaluatePilotReference(backup, window, reference);
  const blankStage = () => ({ status: 'unreviewed' as const, at: null, evidence_ref: null });
  return {
    version: 1 as const,
    recall_evaluation_id: report.evaluation_id,
    reviewer: null,
    reviewed_independently: false as const,
    reviewed_through: null,
    responses: reference.incidents.map(({ incident_id }) => ({
      incident_id,
      acknowledgement: blankStage(),
      triage: blankStage(),
    })),
  };
}
