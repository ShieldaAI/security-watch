import { createHash } from 'node:crypto';
import { latencySummary, metric } from './pilot-cases.js';
import { dataArray, dataFields, pilotInstant, readPrivatePilotJson } from './pilot-input.js';
import {
  capturePilotIncidentReference,
  evaluatePilotReference,
  type PilotIncidentReference,
} from './pilot-recall.js';
import { PilotReportError, type PilotWindow } from './pilot-report.js';

type ResponseEvidence =
  | { status: 'observed'; at: string; evidence_ref: string }
  | { status: 'no_record'; at: null; evidence_ref: string }
  | { status: 'unresolved' | 'unreviewed'; at: null; evidence_ref: null };
interface IncidentResponse {
  incident_id: string;
  acknowledgement: ResponseEvidence;
  triage: ResponseEvidence;
}
export interface PilotResponseRegister {
  version: 1;
  recall_evaluation_id: string;
  reviewer: string;
  reviewed_independently: true;
  reviewed_through: string;
  responses: IncidentResponse[];
}

function invalid(): never {
  throw new PilotReportError('responses');
}

function captureEvidence(value: unknown): ResponseEvidence {
  const { status, at, evidence_ref } = dataFields(value, ['status', 'at', 'evidence_ref'], 'responses');
  if (status === 'unresolved' || status === 'unreviewed') {
    if (at !== null || evidence_ref !== null) invalid();
    return { status, at, evidence_ref };
  }
  if (typeof evidence_ref !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(evidence_ref))
    invalid();
  if (status === 'no_record' && at === null) return { status, at, evidence_ref };
  if (status !== 'observed') invalid();
  return { status, at: pilotInstant(at, 'responses'), evidence_ref };
}

function captureRegister(input: unknown): PilotResponseRegister {
  const fields = dataFields(
    input,
    [
      'version',
      'recall_evaluation_id',
      'reviewer',
      'reviewed_independently',
      'reviewed_through',
      'responses',
    ],
    'responses',
  );
  if (
    fields.version !== 1 ||
    fields.reviewed_independently !== true ||
    typeof fields.recall_evaluation_id !== 'string' ||
    !/^[a-f0-9]{64}$/u.test(fields.recall_evaluation_id) ||
    typeof fields.reviewer !== 'string' ||
    !/^[a-z][a-z0-9_-]{0,63}$/u.test(fields.reviewer)
  )
    invalid();
  const reviewed_through = pilotInstant(fields.reviewed_through, 'responses');
  if (Date.parse(reviewed_through) > Date.now()) invalid();
  const ids = new Set<string>();
  const observedSources = new Map<string, string>();
  let totalBytes = 0;
  const responses = dataArray(fields.responses, 1000, 'responses').map((item) => {
    const row = dataFields(item, ['incident_id', 'acknowledgement', 'triage'], 'responses');
    const id = row.incident_id;
    if (typeof id !== 'string' || !id || id.length > 512 || ids.has(id)) invalid();
    ids.add(id);
    const result = {
      incident_id: id,
      acknowledgement: captureEvidence(row.acknowledgement),
      triage: captureEvidence(row.triage),
    };
    for (const action of [result.acknowledgement, result.triage]) {
      if (action.status !== 'observed') continue;
      if (action.at > reviewed_through) invalid();
      // One underlying record can document both stages for the same target.
      const owner = observedSources.get(action.evidence_ref);
      if (owner !== undefined && owner !== id) invalid();
      observedSources.set(action.evidence_ref, id);
    }
    totalBytes += Buffer.byteLength(JSON.stringify(result));
    if (totalBytes > 2 * 1024 * 1024) invalid();
    return result;
  });
  responses.sort((a, b) => (a.incident_id < b.incident_id ? -1 : a.incident_id > b.incident_id ? 1 : 0));
  return {
    version: 1,
    recall_evaluation_id: fields.recall_evaluation_id,
    reviewer: fields.reviewer,
    reviewed_independently: true,
    reviewed_through,
    responses,
  };
}

export function readPilotResponseRegister(path: string): PilotResponseRegister {
  return captureRegister(readPrivatePilotJson(path, 'responses'));
}

function scoreStage(
  stage: 'acknowledgement' | 'triage',
  incidents: PilotIncidentReference['incidents'],
  responses: Map<string, IncidentResponse>,
  onTimeProvider: Set<string>,
) {
  const outcomes = { on_time: 0, late: 0, no_record: 0, unresolved: 0, unreviewed: 0 };
  const pairs = { both: 0, provider_only_confirmed: 0, human_only_confirmed: 0, neither_confirmed: 0 };
  const delays: number[] = [];
  for (const incident of incidents) {
    const answer = responses.get(incident.incident_id)?.[stage];
    const timely = answer?.status === 'observed' && answer.at < incident.deadline_at;
    if (!answer) outcomes.unreviewed++;
    else if (answer.status === 'observed') {
      delays.push(Date.parse(answer.at) - Date.parse(incident.available_at));
      if (timely) outcomes.on_time++;
      else outcomes.late++;
    } else outcomes[answer.status]++;
    if (onTimeProvider.has(incident.incident_id)) {
      if (timely) pairs.both++;
      else pairs.provider_only_confirmed++;
    } else if (timely) pairs.human_only_confirmed++;
    else pairs.neither_confirmed++;
  }
  const n = incidents.length;
  return {
    on_time: metric(outcomes.on_time, n),
    reviewed: metric(n - outcomes.unreviewed, n),
    resolved: metric(n - outcomes.unreviewed - outcomes.unresolved, n),
    outcomes,
    first_response_after_availability: latencySummary(delays),
    paired_with_on_time_provider: pairs,
  };
}

/** Compare independent human records with provider receipt evidence on the exact same frozen incidents. */
export async function scorePilotResponses(
  backup: string,
  window: PilotWindow,
  input: PilotIncidentReference,
  register: PilotResponseRegister,
) {
  const reference = capturePilotIncidentReference(input);
  const evidence = captureRegister(register);
  if (
    evidence.reviewer === reference.curator ||
    Date.parse(evidence.reviewed_through) < Date.parse(reference.window.until)
  )
    invalid();
  const responses = new Map(evidence.responses.map((row) => [row.incident_id, row]));
  const byId = new Map(reference.incidents.map((incident) => [incident.incident_id, incident]));
  for (const row of evidence.responses) {
    const incident = byId.get(row.incident_id);
    if (!incident) invalid();
    for (const action of [row.acknowledgement, row.triage]) {
      if (action.status === 'observed' && action.at < incident.available_at) invalid();
    }
  }
  const { report, onTimeProvider } = await evaluatePilotReference(backup, window, reference);
  if (evidence.recall_evaluation_id !== report.evaluation_id) invalid();
  return {
    version: 1 as const,
    mode: 'pilot_responses' as const,
    window: reference.window,
    recall_evaluation_id: report.evaluation_id,
    evaluation_id: createHash('sha256')
      .update(JSON.stringify(['security-watch.pilot-responses.v1', evidence]))
      .digest('hex'),
    reviewed_through: evidence.reviewed_through,
    reference_incidents: reference.incidents.length,
    acknowledgement: scoreStage('acknowledgement', reference.incidents, responses, onTimeProvider),
    triage: scoreStage('triage', reference.incidents, responses, onTimeProvider),
  };
}
export type PilotResponseScore = Awaited<ReturnType<typeof scorePilotResponses>>;
