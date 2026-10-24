import { readFileSync, statSync } from 'node:fs';
import { z } from 'zod';
import { assess, decide } from './assessment.js';
import { collectSources } from './sources.js';
import { ModelAnalyzer, PROMPT_VERSION } from './models.js';
import { Store } from './store.js';
import { safeHttp } from './http.js';
import { missingCredentials } from './config.js';
import { hash, severityRank, timestamp } from './util.js';
import type { Assessment, Config, Decision, Evidence, HttpClient, Inventory } from './types.js';

export interface ScanReport {
  at: string;
  completed_at: string;
  findings: Assessment[];
  decisions: Record<string, Decision>;
  degraded: boolean;
  errors: { source: string; message: string }[];
  evidence_count: number;
}
const evidenceSchema = z
  .object({
    id: z.string().min(1),
    source: z.string().min(1),
    kind: z.enum(['advisory', 'news', 'kev', 'health']),
    title: z.string(),
    url: z.string(),
    description: z.string(),
    aliases: z.array(z.string()),
    severity: z.enum(['unknown', 'low', 'medium', 'high', 'critical']),
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
  const previousById = new Map(store.findings().map((a) => [a.id, a]));
  const decisions: Record<string, Decision> = {};
  const persist = (assessment: Assessment) => {
    const decision = decide(assessment, config);
    decisions[assessment.id] = decision;
    store.saveAssessment(assessment, decision, now, config.digest_interval_hours * 3_600_000);
  };
  const retire = (assessment: Assessment) => {
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
  const systemHashes = new Map(
    inventory.systems.map((system) => {
      const { updated_at: _updated, ...context } = system;
      return [system.id, hash(context)];
    }),
  );
  const basis = (finding: Assessment, evidenceById: Map<string, Evidence>): string => {
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
              now - fetched <= Math.max(120_000, config.poll_interval_minutes * 120_000)),
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

  const cached = store.evidence();
  if (!options.fixture && previousById.size) {
    // Apply known inventory changes before yielding to network I/O. The worker can deliver concurrently.
    const cachedById = new Map(cached.map((e) => [e.id, e]));
    const current = assess(inventory, cached, config, now);
    const ids = new Set(current.map((a) => a.id));
    for (const finding of current)
      if (previousById.has(finding.id)) persist(interim(finding, basis(finding, cachedById)));
    for (const previous of previousById.values())
      if (previous.category !== 'health' && previous.active !== false && !ids.has(previous.id))
        retire(previous);
  }
  const result = options.fixture
    ? { evidence: options.fixture, errors: [], checkpoints: {} }
    : await collectSources(inventory, config, store.checkpoints(), http, now, cached);
  checkCancellation(signal);
  store.saveEvidence(result.evidence, result.checkpoints);
  const evidence = store.evidence();
  const evidenceById = new Map(evidence.map((e) => [e.id, e]));
  const findings = assess(inventory, evidence, config, now);
  const bases = new Map(findings.map((a) => [a.id, basis(a, evidenceById)]));
  const errors = [...result.errors];
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
    !options.fixture
  )
    errors.push({ source: 'sources', message: 'All sources are disabled.' });
  if (
    !options.fixture &&
    (config.sources.hacker_news || config.sources.feeds.length) &&
    !config.models.enabled
  )
    errors.push({
      source: 'models',
      message:
        'AI is disabled. System news receives candidate matching only; enable an analysis model to distinguish vulnerability impact from general system coverage.',
    });
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
  findings.forEach((finding) => persist(interim(finding, bases.get(finding.id)!)));
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
    evidence_count: evidence.length,
  };
  store.setMeta(
    'last_scan',
    JSON.stringify({
      at: report.completed_at,
      started_at: report.at,
      completed_at: report.completed_at,
      degraded: report.degraded,
      errors: report.errors,
      findings: report.findings.length,
    }),
  );
  return report;
}
