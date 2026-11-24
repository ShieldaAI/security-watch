import { createHmac, randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  fstatSync,
  mkdtempSync,
  openSync,
  readSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { z } from 'zod';
import { parseConfig } from './config.js';
import { deliverPending, type EmailSender } from './delivery.js';
import { evidenceSchema, runScan } from './engine.js';
import { inventorySnapshotSchema } from './inventory.js';
import { verifyBackup } from './maintenance.js';
import { Store } from './store.js';
import { canonicalHash } from './util.js';
import type { Config, Evidence, HttpClient, Inventory } from './types.js';

const MAX_BYTES = 8 * 1024 * 1024;
const sinkSchema = z.enum(['disabled', 'accepted', 'failed', 'unknown']);
const rehearsalEvidence = evidenceSchema.refine(
  (item) =>
    item.id.length <= 500 &&
    item.source.length <= 500 &&
    item.title.length <= 500 &&
    item.description.length <= 16_000 &&
    item.url.length <= 2048 &&
    item.aliases.length <= 100 &&
    item.aliases.every((alias) => alias.length <= 500) &&
    item.packages.length <= 500 &&
    item.packages.every(
      (claim) =>
        claim.name.length <= 500 &&
        claim.ecosystem.length <= 100 &&
        (claim.range?.length ?? 0) <= 2000 &&
        (claim.fixed?.length ?? 0) <= 2000 &&
        [claim.versions, claim.matched_versions].every(
          (values) => !values || (values.length <= 1000 && values.every((value) => value.length <= 500)),
        ),
    ),
  'Evidence bounds exceeded',
);
const scenarioSchema = z
  .strictObject({
    version: z.literal(1),
    frames: z
      .array(
        z.strictObject({
          at: z.iso.datetime({ offset: true }),
          evidence: z.array(rehearsalEvidence).max(1000),
          inventory: inventorySnapshotSchema.optional(),
        }),
      )
      .min(1)
      .max(12),
  })
  .refine(
    ({ frames }) =>
      frames.every(
        (frame, index) =>
          Date.parse(frame.at) >= 0 &&
          (index === 0 || Date.parse(frame.at) > Date.parse(frames[index - 1]!.at)),
      ),
    'Times must increase',
  )
  .refine(
    ({ frames }) => Date.parse(frames.at(-1)!.at) - Date.parse(frames[0]!.at) <= 31 * 86_400_000,
    'At most 31 scenario days',
  )
  .refine(
    ({ frames }) => frames.reduce((count, frame) => count + frame.evidence.length, 0) <= 1000,
    'At most 1000 supplied evidence records',
  )
  .refine(({ frames }) => frames.some((frame) => frame.evidence.length > 0), 'Evidence is required')
  .refine(({ frames }) => {
    const sources = new Map<string, string>();
    for (const frame of frames)
      for (const item of frame.evidence) {
        if (sources.has(item.id) && sources.get(item.id) !== item.source) return false;
        sources.set(item.id, item.source);
      }
    return true;
  }, 'Ambiguous evidence identity');

export type RehearsalScenario = z.infer<typeof scenarioSchema>;
export type RehearsalSink = z.infer<typeof sinkSchema>;

/** Errors intentionally omit paths, parser diagnostics and source-controlled strings. */
export function readRehearsal(path: string): RehearsalScenario {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > MAX_BYTES) throw new Error();
    const input = Buffer.alloc(MAX_BYTES + 1);
    let bytes = 0;
    while (bytes < input.length) {
      const received = readSync(descriptor, input, bytes, input.length - bytes, null);
      if (!received) break;
      bytes += received;
    }
    if (bytes > MAX_BYTES) throw new Error();
    return scenarioSchema.parse(JSON.parse(input.subarray(0, bytes).toString('utf8')));
  } catch {
    throw new Error('Invalid rehearsal scenario; check the documented schema and bounds.');
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        throw new Error('Rehearsal input could not be closed.');
      }
    }
  }
}

const decisions = () => ({ record: 0, digest: 0, notify: 0 });
const deliveryStates = () => ({ pending: 0, sending: 0, accepted: 0, failed: 0, unknown: 0 });
const age = (value: string, now: number) => {
  const at = Date.parse(value);
  return Number.isFinite(at) && at <= now ? now - at : null;
};
type Reference = (domain: string, value: unknown) => string;
function projectFrame(
  store: Store,
  input: Evidence[],
  ref: Reference,
  index: number,
  now: number,
  elapsed: number,
  degraded: boolean,
) {
  const evidence = store.evidence();
  const evidenceRef = (item: Evidence) => {
    const { fetched_at: _fetch, ...content } = item;
    return ref('evidence', content);
  };
  const evidenceRefs = new Map(evidence.map((item) => [item.id, evidenceRef(item)]));
  const allEvidence = new Map([...input, ...evidence].map((item) => [evidenceRef(item), item]));
  const counts = decisions();
  const states = deliveryStates();
  const findings = store.findings().map((finding) => {
    const history = store.history(finding.id).at(-1)!;
    counts[history.decision.action]++;
    return {
      ref: ref('finding', finding.id),
      revision: history.revision,
      active: finding.active !== false,
      category: finding.category,
      applicability: finding.applicability,
      source_severity: finding.source_severity,
      priority: finding.priority,
      evidence_refs: finding.evidence_ids
        .map((id) => evidenceRefs.get(id))
        .filter((id): id is string => !!id),
      decision: history.decision.action,
      channels: history.decision.channels,
    };
  });
  const deliveries = store.jobs().map((job) => {
    states[job.status]++;
    return {
      ref: ref('delivery', job.id),
      finding_ref: ref('finding', job.finding_id),
      revision: job.revision!,
      channel: job.channel,
      status: job.status,
      attempts: job.attempts,
      scheduled_in_ms: Math.max(0, job.available_at - now),
    };
  });
  return {
    index,
    ingest: { kind: 'fixture' as const, ref: ref('ingest', index), evidence_refs: input.map(evidenceRef) },
    scan_ms: Math.max(0, Math.round(elapsed)),
    degraded,
    evidence: [...allEvidence.values()].map((item) => ({
      ref: evidenceRef(item),
      kind: item.kind,
      retained: evidenceRefs.get(item.id) === evidenceRef(item),
      fetched_age_ms: age(item.fetched_at, now),
      modified_age_ms: age(item.modified_at, now),
    })),
    findings,
    deliveries,
    counters: {
      findings: findings.length,
      active_findings: findings.filter((item) => item.active).length,
      decisions: counts,
      delivery_states: states,
    },
    review_backlog: store.reviewSummary(now).pending + store.reviewSummary(now).investigate,
    oldest_review_age_ms: store.reviewSummary(now).oldest_open_age_ms,
  };
}

export interface RehearsalReport {
  version: 1;
  mode: 'offline_rehearsal';
  sink: RehearsalSink;
  safety: {
    models_disabled: true;
    sources_disabled: true;
    network_requests: 0;
    external_deliveries: 0;
    live_database_opened: false;
    credentials_loaded: false;
  };
  frames: ReturnType<typeof projectFrame>[];
  summary: ReturnType<typeof projectFrame>['counters'] & {
    sink_calls: number;
    model_requests: 0;
    model_usd: 0;
  };
  recovery: {
    reopened: true;
    backup_verified: true;
    restored: true;
    receipts_preserved: true;
    automatically_dispatched: 0;
    dispatcher_probe: 'passed' | 'disabled';
    terminal_receipts_not_retried: true;
    probe_sink_calls: number;
  };
  unmeasured: {
    source_coverage: null;
    ai_shadow: null;
    urgent_recall: null;
    false_alert_rate: null;
    analyst_latency_ms: null;
  };
}

/** Offline rehearsal only: never opens the configured live database or resolves its credentials. */
export async function runRehearsal(options: {
  config: Config;
  inventory: Inventory;
  scenario: RehearsalScenario;
  sink?: RehearsalSink;
}): Promise<RehearsalReport> {
  let config: Config, inventory: Inventory, scenario: RehearsalScenario, sink: RehearsalSink;
  try {
    // Bound direct JS callers as well as file input; schema validation rejects unknown model-like fields.
    if (Buffer.byteLength(JSON.stringify(options), 'utf8') > MAX_BYTES) throw new Error();
    config = parseConfig(options.config);
    inventory = inventorySnapshotSchema.parse(options.inventory);
    scenario = scenarioSchema.parse(options.scenario);
    sink = sinkSchema.parse(options.sink ?? 'disabled');
    let current = inventory;
    let work = 0;
    const retained = new Map<string, number>();
    for (const frame of scenario.frames) {
      current = frame.inventory ?? current;
      const targets = current.systems.reduce(
        (sum, system) => sum + system.components.length + system.products.length + 1,
        0,
      );
      if (current.systems.length > 20 || targets > 500) throw new Error();
      for (const item of frame.evidence)
        retained.set(
          item.id,
          Math.max(
            retained.get(item.id) ?? 0,
            1 +
              item.packages.reduce(
                (sum, claim) =>
                  sum + 1 + (claim.versions?.length ?? 0) + (claim.matched_versions?.length ?? 0),
                0,
              ),
          ),
        );
      work += targets * [...retained.values()].reduce((sum, count) => sum + count, 0);
    }
    if (work > 100_000) throw new Error();
  } catch {
    throw new Error('Invalid rehearsal input; check the documented schema and bounds.');
  }

  // Clone validated objects before changing effective runtime settings. No source/provider path can run.
  config.models.enabled = false;
  // A rehearsal reads no live state: not the operator's mitigation exports either.
  delete config.mitigations;
  config.sources = {
    ...config.sources,
    cve_now: false,
    hacker_news: false,
    osv: false,
    github: false,
    kev: false,
    feeds: [],
    vendor_feeds: [],
  };
  config.notifications = {
    max_attempts: config.notifications.max_attempts,
    slack: { webhook_url_env: 'REHEARSAL_SLACK' },
    email: {
      smtp_url_env: 'REHEARSAL_SMTP',
      from: 'rehearsal@example.invalid',
      to: ['sink@example.invalid'],
    },
  };
  const credentials = Object.freeze({
    REHEARSAL_SLACK: 'https://hooks.slack.com/services/REHEARSAL/LOCAL/SINK',
    REHEARSAL_SMTP: 'smtps://rehearsal.invalid:465',
  });
  let sinkCalls = 0;
  const http: HttpClient = async (url, request) => {
    if (url !== credentials.REHEARSAL_SLACK || request?.method !== 'POST')
      throw new Error('Unexpected rehearsal transport call');
    sinkCalls++;
    return {
      status: sink === 'failed' ? 400 : 200,
      headers: {},
      body: sink === 'unknown' ? 'simulated ambiguous receipt' : 'ok',
    };
  };
  const email: EmailSender = async (message) => {
    if (
      message.url !== credentials.REHEARSAL_SMTP ||
      message.to.length !== 1 ||
      message.to[0] !== 'sink@example.invalid'
    )
      throw new Error('Unexpected rehearsal email call');
    sinkCalls++;
    if (sink === 'unknown') throw new Error('Simulated ambiguous receipt');
    return sink === 'failed'
      ? { accepted: [], rejected: [...message.to] }
      : { accepted: [...message.to], rejected: [] };
  };
  const key = randomBytes(32);
  const ref: Reference = (domain, value) =>
    createHmac('sha256', key)
      .update(JSON.stringify([domain, value]))
      .digest('hex');
  let temporary: string;
  try {
    temporary = mkdtempSync(join(tmpdir(), 'security-watch-rehearsal-'));
  } catch {
    key.fill(0);
    throw new Error('Could not create private rehearsal state.');
  }
  const database = join(temporary, 'rehearsal.db');
  let store: Store | undefined;
  try {
    store = new Store(database);
    const frames: RehearsalReport['frames'] = [];
    for (const [index, frame] of scenario.frames.entries()) {
      inventory = frame.inventory ?? inventory;
      const now = Date.parse(frame.at);
      const started = performance.now();
      const scan = await runScan({
        config,
        inventory,
        store,
        fixture: frame.evidence,
        now,
        http: async () => {
          throw new Error('Rehearsal source access forbidden');
        },
      });
      const elapsed = performance.now() - started;
      if (sink !== 'disabled') await deliverPending(store, config, http, now, email, undefined, credentials);
      if (store.findings().length > 2000 || store.jobs().length > 4000 || store.evidence().length > 1000)
        throw new Error();
      frames.push(projectFrame(store, frame.evidence, ref, index, now, elapsed, scan.degraded));
    }
    const lastTime = Date.parse(scenario.frames.at(-1)!.at);
    const snapshot = (value: Store) =>
      canonicalHash({
        evidence: value.evidence(),
        findings: value.findings(),
        jobs: value.jobs(),
        budgets: value.budgets(),
        histories: value.findings().map((item) => value.history(item.id)),
        controls: value.findings().map((item) => value.controls(item.id, lastTime)),
        reviews: value.reviews({ includeResolved: true, limit: 1000 }),
      });
    const before = snapshot(store);
    store.close();
    store = undefined;
    store = new Store(database);
    if (snapshot(store) !== before) throw new Error();
    const backup = join(temporary, 'backup.db');
    await store.backup(backup);
    const verified = await verifyBackup(backup, { max_bytes: 64 * 1024 * 1024 });
    if (!verified.ok) throw new Error();
    store.close();
    store = undefined;
    const restored = join(temporary, 'restored.db');
    copyFileSync(backup, restored, constants.COPYFILE_EXCL);
    chmodSync(restored, 0o600);
    store = new Store(restored);
    store.recoverSending(lastTime);
    if (snapshot(store) !== before) throw new Error();
    const beforeProbeCalls = sinkCalls;
    const terminal = store.jobs().filter((job) => job.status !== 'pending');
    if (sink !== 'disabled')
      await deliverPending(store, config, http, lastTime, email, undefined, credentials);
    const afterProbe = new Map(store.jobs().map((job) => [job.id, job]));
    if (terminal.some((job) => canonicalHash(job) !== canonicalHash(afterProbe.get(job.id))))
      throw new Error();
    const report: RehearsalReport = {
      version: 1,
      mode: 'offline_rehearsal',
      sink,
      safety: {
        models_disabled: true,
        sources_disabled: true,
        network_requests: 0,
        external_deliveries: 0,
        live_database_opened: false,
        credentials_loaded: false,
      },
      frames,
      summary: { ...frames.at(-1)!.counters, sink_calls: beforeProbeCalls, model_requests: 0, model_usd: 0 },
      recovery: {
        reopened: true,
        backup_verified: true,
        restored: true,
        receipts_preserved: true,
        automatically_dispatched: 0,
        dispatcher_probe: sink === 'disabled' ? 'disabled' : 'passed',
        terminal_receipts_not_retried: true,
        probe_sink_calls: sinkCalls - beforeProbeCalls,
      },
      unmeasured: {
        source_coverage: null,
        ai_shadow: null,
        urgent_recall: null,
        false_alert_rate: null,
        analyst_latency_ms: null,
      },
    };
    if (Buffer.byteLength(JSON.stringify(report), 'utf8') > MAX_BYTES) throw new Error();
    return report;
  } catch {
    throw new Error('Rehearsal failed; no external delivery was attempted.');
  } finally {
    let cleanupFailed = false;
    try {
      store?.close();
    } catch {
      cleanupFailed = true;
    } finally {
      key.fill(0);
      try {
        rmSync(temporary, { recursive: true, force: true });
      } catch {
        cleanupFailed = true;
      }
    }
    if (cleanupFailed)
      throw new Error('Rehearsal cleanup failed; inspect private temporary storage locally.');
  }
}
