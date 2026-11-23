import { readFileSync, statSync } from 'node:fs';
import { z } from 'zod';
import { cvssV4BaseScore } from './cvss4.js';
import { assess, decide } from './assessment.js';
import { collectSources } from './sources.js';
import { attachEpss, findingCves, readEpssCache, refreshEpss } from './epss.js';
import { attachLocation, attachRemediation, compareInventories } from './inventory-evidence.js';
import { ModelAnalyzer, PROMPT_VERSION } from './models.js';
import { Store } from './store.js';
import { safeHttp } from './http.js';
import { missingCredentials } from './config.js';
import { canonicalHash, hash, severityRank, timestamp } from './util.js';
import type {
  Assessment,
  Config,
  Decision,
  Evidence,
  HttpClient,
  Inventory,
  CoverageReceipt,
  InventoryDrift,
} from './types.js';

export interface ScanReport {
  at: string;
  completed_at: string;
  findings: Assessment[];
  decisions: Record<string, Decision>;
  degraded: boolean;
  errors: { source: string; message: string }[];
  /** Information about how the monitor is set up. A notice is not a fault and does not degrade a scan. */
  notices: string[];
  evidence_count: number;
  coverage: CoverageReceipt[];
  inventory_drift: InventoryDrift[];
}
export const evidenceSchema = z
  .object({
    id: z.string().min(1),
    source: z.string().min(1),
    kind: z.enum(['advisory', 'news', 'kev', 'health']),
    title: z.string(),
    url: z.string(),
    description: z.string(),
    aliases: z.array(z.string()),
    severity: z.enum(['unknown', 'low', 'medium', 'high', 'critical']),
    cvss_v4: z
      .strictObject({
        base_scores: z
          .array(
            z
              .strictObject({
                vector: z.string().max(1024),
                base_vector: z.string().max(1024),
                score: z.number().min(0).max(10),
                context_removed: z.boolean(),
              })
              .refine((item) => {
                const actual = cvssV4BaseScore(item.vector);
                return (
                  actual?.score === item.score &&
                  actual.base_vector === item.base_vector &&
                  actual.context_removed === item.context_removed
                );
              }, 'Invalid CVSS v4 base projection'),
          )
          .max(32),
        unsupported_vectors: z.number().int().min(0).max(32),
      })
      .refine(
        (value) => value.base_scores.length + value.unsupported_vectors <= 32,
        'CVSS v4 candidate limit exceeded',
      )
      .optional(),
    modified_at: z.iso.datetime(),
    fetched_at: z.iso.datetime(),
    published_at: z.iso.datetime().optional(),
    content_status: z.enum(['full', 'excerpt', 'unavailable']).optional(),
    packages: z.array(
      z
        .object({
          ecosystem: z.string(),
          name: z.string(),
          range: z.string().optional(),
          versions: z.array(z.string()).optional(),
          matched_versions: z.array(z.string()).optional(),
          fixed: z.string().optional(),
        })
        .strict(),
    ),
    withdrawn: z.boolean().optional(),
    exploited: z.boolean().optional(),
    malware: z.boolean().optional(),
  })
  .strict();
export function readFixture(path: string): Evidence[] {
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > 8_388_608) throw new Error('Fixture must be a file of at most 8 MiB');
  return z
    .array(evidenceSchema)
    .max(5000)
    .parse(JSON.parse(readFileSync(path, 'utf8')));
}
export function healthFinding(source: string, message: string, now = Date.now()): Assessment {
  return {
    id: `health-${hash(source).slice(0, 20)}`,
    event_id: `health:${source}`,
    system_id: 'monitor',
    category: 'health',
    applicability: 'unknown',
    source_severity: 'high',
    priority: 'high',
    title: `Monitoring needs attention: ${source}`,
    summary: message,
    reasons: ['Monitoring is incomplete; this is not a clean security result.'],
    evidence_ids: [],
    urls: [],
    exploited: false,
    updated_at: timestamp(now),
  };
}
function checkCancellation(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('Scan canceled', 'AbortError');
}
function canRetainPriority(previous: Assessment | undefined, current: Assessment): previous is Assessment {
  return Boolean(
    previous &&
    previous.active !== false &&
    current.applicability !== 'not_affected' &&
    !current.withdrawn &&
    (previous.applicability === current.applicability ||
      current.applicability === 'unknown' ||
      current.applicability === 'conflicting') &&
    severityRank[previous.priority] > severityRank[current.priority],
  );
}
function generalNews(assessment: Assessment | undefined): boolean {
  return Boolean(
    assessment?.active !== false &&
    assessment?.ai?.status === 'complete' &&
    assessment.news_analysis?.classification === 'general_news' &&
    assessment.news_analysis.impact === 'not_applicable',
  );
}

// An exclusion rests on the version ranges of its own advisory records. While they were read
// within the last two poll intervals it holds, whatever else a source missed; after that the
// assessment treats them as stale evidence and the finding becomes `unknown` (assessment.ts).

/** When stored evidence was last collected: the start of the last scan, or its newest fetch time. */
function lastCollection(store: Store, cached: Evidence[]): number {
  try {
    const started = Date.parse(
      (JSON.parse(store.getMeta('last_scan') ?? '{}') as { started_at?: string }).started_at ?? '',
    );
    if (Number.isFinite(started)) return started;
  } catch {
    /* An unreadable record falls back to the evidence itself. */
  }
  return cached.reduce((latest, item) => {
    const fetched = Date.parse(item.fetched_at);
    return Number.isFinite(fetched) && fetched > latest ? fetched : latest;
  }, 0);
}

export async function runScan(options: {
  config: Config;
  inventory: Inventory;
  store: Store;
  http?: HttpClient;
  fixture?: Evidence[];
  now?: number;
  onUrgent?: () => Promise<void>;
  signal?: AbortSignal;
}): Promise<ScanReport> {
  const { config, inventory, store, signal } = options;
  checkCancellation(signal);
  const now = options.now ?? Date.now();
  const transport = options.http ?? safeHttp;
  const http: HttpClient = (url, request) => {
    checkCancellation(signal);
    return transport(url, { ...request, ...(signal ? { signal } : {}) });
  };
  const priorInventory = store.getMeta('inventory:baseline');
  const drift = compareInventories(
    priorInventory ? (JSON.parse(priorInventory) as Inventory) : undefined,
    inventory,
  );
  const previousById = new Map(store.findings().map((a) => [a.id, a]));
  // Events of findings still reported keep their identifier when a record gains an alias.
  const knownEvents = new Set(
    [...previousById.values()]
      .filter((finding) => finding.active !== false && finding.category !== 'health')
      .map((finding) => finding.event_id),
  );
  const knownFindings = new Set(
    [...previousById.values()].filter((finding) => finding.active !== false).map((finding) => finding.id),
  );
  const decisions: Record<string, Decision> = {};
  let remediationEvidence = store.evidence();
  // EPSS is attached when a finding is saved, after its analysis basis is taken, and is left out of
  // its revision and review: a score that changes daily must not re-send, reopen or re-analyse.
  let epssCache = config.sources.epss ? readEpssCache(store.getMeta('epss:cache')) : {};
  let epssEvidence = new Map(remediationEvidence.map((item) => [item.id, item]));
  const persist = (assessment: Assessment) => {
    assessment = attachEpss(
      attachLocation(attachRemediation(assessment, inventory, remediationEvidence, config, now), inventory),
      epssCache,
      findingCves(assessment, epssEvidence),
    );
    const decision = decide(assessment, config);
    decisions[assessment.id] = decision;
    store.saveAssessment(
      assessment,
      decision,
      now,
      config.digest_interval_hours * 3_600_000,
      decision.review
        ? canonicalHash({
            system: reviewSystemHashes.get(assessment.system_id),
            models: config.models,
            policy: config.policy.ai_dismissals ?? config.policy.review_before_news_suppression ?? 'review',
          })
        : undefined,
    );
  };
  const retire = (previous: Assessment) => {
    // A retired finding is not looked up any more; an ageing score would only mislead.
    const { epss: _epss, ...assessment } = previous;
    store.saveAssessment(
      {
        ...assessment,
        active: false,
        updated_at: timestamp(now),
        reasons: [
          ...assessment.reasons,
          'No longer in the current assessment. This does not establish remediation.',
        ],
      },
      {
        action: 'record',
        channels: [],
        reason: 'No current inventory/evidence match or monitoring issue recovered',
      },
      now,
    );
  };
  // Notes and the owner say where to look. They are shown in notifications and never reach a model,
  // so they are left out of everything that decides analysis reuse, reviews, revisions or alerts.
  const context = (system: Inventory['systems'][number]) => {
    const { updated_at: _updated, note: _note, owner: _owner, ...rest } = system;
    return {
      ...rest,
      components: system.components.map(({ note: _componentNote, ...component }) => component),
      products: system.products.map(({ note: _productNote, ...product }) => product),
    };
  };
  const systemHashes = new Map(inventory.systems.map((system) => [system.id, hash(context(system))]));
  const reviewSystemHashes = new Map(
    inventory.systems.map((system) => [system.id, canonicalHash(context(system))]),
  );
  const basis = (finding: Assessment, evidenceById: Map<string, Evidence>, evidenceAsOf = now): string => {
    const { updated_at: _updated, ...assessment } = finding;
    return hash({
      assessment,
      system: systemHashes.get(finding.system_id),
      analysis: {
        model: config.models.analysis,
        verification: config.models.verification,
        prompt: PROMPT_VERSION,
        max_input_chars: config.models.max_input_chars,
      },
      evidence: finding.evidence_ids.map((id) => {
        const item = evidenceById.get(id);
        if (!item) return null;
        const { fetched_at: _fetched, ...content } = item;
        const fetched = Date.parse(item.fetched_at);
        return {
          ...content,
          fresh:
            generalNews(previousById.get(finding.id)) ||
            (Number.isFinite(fetched) &&
              fetched <= now + 300_000 &&
              evidenceAsOf - fetched <= Math.max(120_000, config.poll_interval_minutes * 120_000)),
        };
      }),
    });
  };
  const interim = (finding: Assessment, basisHash: string): Assessment => {
    const previous = previousById.get(finding.id);
    if (!config.models.enabled || !previous || previous.active === false) return finding;
    if (store.getMeta(`assessment-basis:${finding.id}`) === basisHash && previous.ai) {
      // Retain unchanged analysis until reassessment; don't alternate record/digest/notify on every scan.
      return {
        ...finding,
        priority: previous.priority,
        applicability: previous.applicability,
        ...(previous.relevance ? { relevance: previous.relevance } : {}),
        ...(previous.news_analysis ? { news_analysis: previous.news_analysis } : {}),
        summary: previous.summary,
        reasons: previous.reasons,
        ai: previous.ai,
      };
    }
    return canRetainPriority(previous, finding) ? { ...finding, priority: previous.priority } : finding;
  };
  // Before analysis, a news finding whose basis changed loses its previous analysis. Saving it so
  // would make a new revision, and the same conclusion after analysis would be sent again.
  const reconcile = (finding: Assessment, basisHash: string): void => {
    const current = interim(finding, basisHash);
    const previous = previousById.get(finding.id);
    if (
      !config.models.enabled ||
      !previous?.ai ||
      previous.active === false ||
      current.ai ||
      !(current.news_candidate || current.news_only) ||
      current.applicability === 'not_affected' ||
      current.withdrawn
    )
      return persist(current);
    const decision = decide(current, config);
    // Its routing waits for the model: hold its queued notifications, so that an old conclusion
    // cannot escape meanwhile, and send them if analysis confirms it.
    if (decision.action === 'record') return store.holdPending(finding.id);
    // Routing that does not depend on the model (an override, a source severity) is applied at
    // once; the previous analysis is shown until it is redone.
    const kept: Assessment = {
      ...current,
      ...(previous.applicability === 'unknown' ? { applicability: 'unknown' } : {}),
      ...(previous.relevance ? { relevance: previous.relevance } : {}),
      ...(previous.news_analysis ? { news_analysis: previous.news_analysis } : {}),
      ai: previous.ai,
    };
    persist(decide(kept, config).action === decision.action ? kept : current);
  };

  const cached = store.evidence();
  if (!options.fixture && previousById.size) {
    // Apply known inventory changes before yielding to network I/O. The worker can deliver concurrently.
    const cachedById = new Map(cached.map((e) => [e.id, e]));
    // This pass applies inventory changes to evidence that is about to be refreshed. Judge the age
    // of that evidence as of the last collection: time that passed while the monitor was stopped
    // must not turn an exclusion into an urgent "unknown" that the refresh then takes back.
    const collectedAt = Math.min(now, lastCollection(store, cached));
    const current = assess(inventory, cached, config, now, collectedAt, knownEvents, knownFindings);
    const ids = new Set(current.map((a) => a.id));
    for (const finding of current)
      if (previousById.has(finding.id)) reconcile(finding, basis(finding, cachedById, collectedAt));
    for (const previous of previousById.values())
      if (previous.category !== 'health' && previous.active !== false && !ids.has(previous.id))
        retire(previous);
  }
  const result = options.fixture
    ? { evidence: options.fixture, errors: [], checkpoints: {}, coverage: [] as CoverageReceipt[] }
    : await collectSources(
        inventory,
        config,
        store.checkpoints(),
        http,
        now,
        cached,
        JSON.parse(store.getMeta('source:coverage') ?? '[]') as CoverageReceipt[],
      );
  checkCancellation(signal);
  store.saveEvidence(result.evidence, result.checkpoints);
  const evidence = store.evidence();
  remediationEvidence = evidence;
  const evidenceById = new Map(evidence.map((e) => [e.id, e]));
  epssEvidence = evidenceById;
  const findings = assess(inventory, evidence, config, now, now, knownEvents, knownFindings);
  const bases = new Map(findings.map((a) => [a.id, basis(a, evidenceById)]));
  const errors = [
    ...result.errors,
    ...(inventory.import_warnings ?? []).map((message) => ({ source: 'inventory:sbom', message })),
  ];
  const notices: string[] = [...(inventory.name_notices ?? [])];
  if (!options.fixture && missingCredentials(config).length)
    errors.push({
      source: 'credentials',
      message:
        'Configured model or delivery credentials are missing. Structured advisory matching continues; run doctor to see required variable names.',
    });
  if (!inventory.systems.length)
    errors.push({
      source: 'inventory',
      message: 'Inventory is empty; add systems before enabling monitoring.',
    });
  if (
    !config.sources.cve_now &&
    !config.sources.hacker_news &&
    !config.sources.osv &&
    !config.sources.github &&
    !config.sources.kev &&
    !config.sources.feeds.length &&
    !config.sources.vendor_feeds?.length &&
    !options.fixture
  )
    errors.push({ source: 'sources', message: 'All sources are disabled.' });
  if (
    !options.fixture &&
    (config.sources.hacker_news || config.sources.feeds.length || config.sources.vendor_feeds?.length) &&
    !config.models.enabled
  )
    // Running without a model is a supported setup, not a fault: say what it means and carry on.
    notices.push(
      'AI is disabled. System news receives candidate matching only; enable an analysis model to distinguish vulnerability impact from general system coverage.',
    );
  if (config.sources.epss && !options.fixture) {
    const refreshed = await refreshEpss(
      findings
        .filter((finding) => finding.category !== 'health')
        .flatMap((finding) => findingCves(finding, evidenceById)),
      epssCache,
      http,
      now,
    );
    checkCancellation(signal);
    epssCache = refreshed.cache;
    store.setMeta('epss:cache', JSON.stringify(epssCache));
    // Shown only, so a failed lookup is a notice, not degraded monitoring.
    if (refreshed.failed)
      notices.push(
        'EPSS scores could not be refreshed from api.first.org; findings keep the scores of the last successful lookup.',
      );
  }
  for (const system of inventory.systems) {
    const updated = Date.parse(system.updated_at);
    if (
      !Number.isFinite(updated) ||
      updated > now + 300_000 ||
      now - updated > config.inventory_stale_days * 86_400_000
    )
      errors.push({
        source: `inventory:${system.id}`,
        message:
          'Inventory timestamp is stale or in the future; verify installed versions and deployment context.',
      });
  }
  // Reconcile every finding before delivery, including exclusions, withdrawals and removals.
  // Otherwise an old pending alert could be sent while unrelated AI analysis is running.
  findings.forEach((finding) => reconcile(finding, bases.get(finding.id)!));
  const currentIds = new Set(findings.map((a) => a.id));
  for (const previous of store.findings())
    if (previous.category !== 'health' && previous.active !== false && !currentIds.has(previous.id))
      retire(previous);
  if (options.onUrgent) {
    try {
      await options.onUrgent();
    } catch {
      checkCancellation(signal);
      errors.push({
        source: 'delivery',
        message: 'Urgent delivery did not complete. The scan continued; inspect deliveries before retrying.',
      });
    }
  }
  checkCancellation(signal);
  const analyzer = new ModelAnalyzer(
    config,
    store,
    http,
    options.now === undefined ? Date.now : () => now,
    signal,
  );
  const analyzed: Assessment[] = [];
  for (const finding of findings.sort((a, b) => severityRank[b.priority] - severityRank[a.priority])) {
    checkCancellation(signal);
    const system = inventory.systems.find((s) => s.id === finding.system_id);
    // An unchanged conference/announcement does not become a vulnerability just
    // because it leaves the rolling RSS window. Inventory/content changes still
    // invalidate its basis; affected/excluded impact claims always check freshness.
    const keepGeneral =
      config.models.enabled &&
      generalNews(previousById.get(finding.id)) &&
      store.getMeta(`assessment-basis:${finding.id}`) === bases.get(finding.id);
    let enriched =
      keepGeneral && !options.fixture
        ? interim(finding, bases.get(finding.id)!)
        : system && !options.fixture
          ? await analyzer.analyze(finding, system, evidence)
          : finding;
    checkCancellation(signal);
    const previous = previousById.get(finding.id);
    if (
      (enriched.ai?.status === 'unavailable' || enriched.ai?.status === 'conflicting') &&
      canRetainPriority(previous, enriched)
    ) {
      enriched = {
        ...enriched,
        priority: previous.priority,
        reasons: [...enriched.reasons, 'Previous priority retained pending valid AI reassessment.'],
      };
    }
    if (enriched.ai?.status === 'unavailable' || enriched.ai?.status === 'conflicting') {
      const code =
        enriched.reasons.find((r) => r.startsWith('MODEL_'))?.split(';')[0] ?? 'Analysis disagreement';
      if (!errors.some((e) => e.source === 'models' && e.message === code))
        errors.push({ source: 'models', message: code });
    }
    // After analysis, so a model never receives it and a new score never asks for a new one.
    enriched = attachEpss(
      attachRemediation(enriched, inventory, evidence, config, now),
      epssCache,
      findingCves(enriched, evidenceById),
    );
    analyzed.push(enriched);
    persist(enriched);
    store.setMeta(`assessment-basis:${finding.id}`, bases.get(finding.id)!);
  }
  const groupedErrors = new Map<string, string[]>();
  for (const error of errors)
    groupedErrors.set(error.source, [...(groupedErrors.get(error.source) ?? []), error.message]);
  const healthFindings = [...groupedErrors].map(([source, messages]) =>
    healthFinding(source, [...new Set(messages)].join(' '), now),
  );
  healthFindings.forEach(persist);
  const active = new Set([...analyzed, ...healthFindings].map((a) => a.id));
  for (const previous of store.findings())
    if (!active.has(previous.id) && previous.active !== false) retire(previous);
  const report = {
    at: timestamp(now),
    completed_at: timestamp(options.now ?? Date.now()),
    findings: [...analyzed, ...healthFindings],
    decisions,
    degraded: errors.length > 0,
    errors,
    notices,
    evidence_count: evidence.length,
    coverage: result.coverage,
    inventory_drift: drift,
  };
  store.setMeta('inventory:baseline', JSON.stringify(inventory));
  store.setMeta('inventory:last_drift', JSON.stringify(drift));
  store.setMeta('source:coverage', JSON.stringify(result.coverage));
  store.setMeta(
    'last_scan',
    JSON.stringify({
      at: report.completed_at,
      started_at: report.at,
      completed_at: report.completed_at,
      degraded: report.degraded,
      errors: report.errors,
      findings: report.findings.length,
      coverage: report.coverage,
      inventory_drift: report.inventory_drift,
    }),
  );
  return report;
}
