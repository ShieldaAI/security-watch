import type {
  AdvisoryReference,
  Assessment,
  Component,
  EpssScore,
  Evidence,
  FindingLocation,
  FixCommit,
  Inventory,
  Severity,
} from './types.js';
import type { RuntimeShieldStatus } from './shirudo.js';
import { severityRank, timestamp } from './util.js';

/**
 * Findings worth a temporary runtime shield (for example a Shirudo upatch) while the real fix is
 * deployed, with what is known that a person or an agent needs to write one.
 *
 * A shield blocks one code path, so it can only be written when the vulnerable code can be found.
 * `readiness` says how far the sources get there; `missing` says what is not known yet. This is a
 * handoff, not advice that a shield is safe: whoever writes it tests it, and the operator approves it.
 */
export type ShieldReadiness = 'fix_known' | 'fixed_version_known' | 'advisory_only' | 'news_only';
const READINESS_RANK: Record<ShieldReadiness, number> = {
  fix_known: 0,
  fixed_version_known: 1,
  advisory_only: 2,
  news_only: 3,
};

export interface ShieldCandidate {
  finding_id: string;
  revision?: number;
  readiness: ShieldReadiness;
  /** What is not known yet, in plain words. Empty only when nothing listed below is missing. */
  missing: string[];
  event_id: string;
  /** The event and the CVE, GHSA and other identifiers of the advisories behind it. */
  identifiers: string[];
  title: string;
  category: Assessment['category'];
  applicability: Assessment['applicability'];
  source_severity: Severity;
  priority: Severity;
  /** Listed in a known-exploited catalog (CISA KEV) or marked exploited by an advisory source. */
  exploited: boolean;
  /** A news article reports exploitation; not a catalog entry. */
  exploitation_reported: boolean;
  /** Published exploit code reported by a source (`exploit-db`, `github-poc`, ...) or by news (`news`). */
  public_exploit: string[];
  epss?: EpssScore;
  /** Left out with `omitLocation`: a system ID is often its name. */
  system_id?: string;
  location?: FindingLocation;
  package?: { ecosystem: string; name: string; installed?: string; fixed?: string; purl?: string };
  /** Links that are code changes: fix commits, pull requests, patches. The best input for a shield. */
  fix_links: string[];
  fix_commits: FixCommit[];
  /** Other links the advisories publish: advisories, reports, exploit evidence. */
  references: AdvisoryReference[];
  weaknesses: string[];
  /** Conditions for exploitation quoted from articles by the analysis model, when one ran. */
  prerequisites?: string[];
  advisories: { id: string; source: string; url: string }[];
  /** Runtime shield status read from Shirudo, when configured. */
  runtime_shield?: RuntimeShieldStatus;
  acknowledged?: boolean;
  suppressed_until?: string;
}

export interface ShieldCandidateReport {
  generated_at: string;
  selection: 'urgent' | 'all';
  location: 'included' | 'omitted';
  counts: Record<ShieldReadiness, number>;
  candidates: ShieldCandidate[];
  notes: string[];
}

export interface FindingControls {
  revision: number;
  acknowledged: boolean;
  suppressed: boolean;
  suppressed_until: number | null;
}

export interface ShieldCandidateInput {
  findings: Assessment[];
  evidence: (ids: readonly string[]) => Evidence[];
  /** The inventory as it is now, for package versions. Without it the stored location is used. */
  inventory?: Inventory;
  controls?: (id: string) => FindingControls | undefined;
  all?: boolean;
  omitLocation?: boolean;
  /** `shirudo.max_age_minutes`: a saved shield status older than this is marked out of date. */
  shirudoMaxAgeMinutes?: number;
  now?: number;
}

const MAX_IDENTIFIERS = 20;

/** A finding that matters enough to consider a shield: critical, or exploited in any reported way. */
export function urgent(finding: Assessment): boolean {
  return (
    finding.exploited ||
    Boolean(finding.news_signals?.exploitation) ||
    finding.priority === 'critical' ||
    finding.source_severity === 'critical'
  );
}

function eligible(finding: Assessment): boolean {
  return (
    finding.active !== false &&
    !finding.withdrawn &&
    finding.category !== 'health' &&
    // A malicious package is removed, not shielded.
    finding.category !== 'malware' &&
    finding.applicability !== 'not_affected' &&
    finding.relevance !== 'irrelevant'
  );
}

function componentOf(finding: Assessment, inventory?: Inventory): Component | undefined {
  if (!inventory || !finding.component_id) return undefined;
  return inventory.systems
    .find((system) => system.id === finding.system_id)
    ?.components.find((component) => component.id === finding.component_id);
}

export function shieldCandidates(input: ShieldCandidateInput): ShieldCandidateReport {
  const now = input.now ?? Date.now();
  const candidates: ShieldCandidate[] = [];
  for (const finding of input.findings) {
    if (!eligible(finding)) continue;
    const controls = input.controls?.(finding.id);
    if (!input.all && (!urgent(finding) || controls?.suppressed)) continue;
    candidates.push(candidate(finding, input.evidence(finding.evidence_ids), input, controls));
  }
  candidates.sort(
    (a, b) =>
      READINESS_RANK[a.readiness] - READINESS_RANK[b.readiness] ||
      Number(b.exploited) - Number(a.exploited) ||
      Number(b.exploitation_reported) - Number(a.exploitation_reported) ||
      severityRank[b.priority] - severityRank[a.priority] ||
      a.finding_id.localeCompare(b.finding_id),
  );
  const counts: Record<ShieldReadiness, number> = {
    fix_known: 0,
    fixed_version_known: 0,
    advisory_only: 0,
    news_only: 0,
  };
  for (const item of candidates) counts[item.readiness]++;
  return {
    generated_at: timestamp(now),
    selection: input.all ? 'all' : 'urgent',
    location: input.omitLocation ? 'omitted' : 'included',
    counts,
    candidates,
    notes: [
      'A shield blocks one code path. It can be written only when the vulnerable code can be found: fix_known gives the fix itself, fixed_version_known the two releases to compare. advisory_only and news_only findings need more information first.',
      'This list is input for a person or an agent. Test every shield against the fix and, where one exists, the public exploit, run it in a trial mode first, and keep the finding open until the real fix is deployed.',
      ...(input.omitLocation
        ? []
        : [
            'System IDs, names, owners and notes from your inventory are included. Use --omit-location before handing this file to a service outside your network.',
          ]),
    ],
  };
}

function candidate(
  finding: Assessment,
  evidence: Evidence[],
  input: ShieldCandidateInput,
  controls: FindingControls | undefined,
): ShieldCandidate {
  const current = evidence.filter((item) => !item.withdrawn);
  const advisories = current.filter((item) => item.kind === 'advisory' || item.kind === 'kev');
  const references = new Map<string, AdvisoryReference>();
  const commits = new Map<string, FixCommit>();
  const weaknesses = new Set<string>();
  const exploitSources = new Set<string>();
  for (const item of advisories) {
    for (const reference of item.references ?? []) {
      const known = references.get(reference.url);
      if (!known || (reference.type === 'fix' && known.type !== 'fix'))
        references.set(reference.url, reference);
    }
    for (const commit of item.fix_commits ?? []) commits.set(`${commit.repo} ${commit.commit}`, commit);
    for (const weakness of item.weaknesses ?? []) weaknesses.add(weakness);
    for (const source of item.exploit_sources ?? []) exploitSources.add(source);
  }
  if (finding.news_signals?.public_exploit) exploitSources.add('news');
  const fixLinks = [...references.values()].filter((r) => r.type === 'fix').map((r) => r.url);
  const otherReferences = [...references.values()].filter((r) => r.type !== 'fix');

  const component = componentOf(finding, input.inventory);
  const claims = advisories
    .flatMap((item) => item.packages)
    .filter((claim) => claim.matched_versions?.length);
  // Without the inventory entry (the inventory changed or cannot be read), a library finding's package
  // is the one the advisories matched by exact version, when they matched exactly one.
  const matchedPackages = [
    ...new Map(claims.map((claim) => [`${claim.ecosystem}\u0000${claim.name}`, claim])).values(),
  ];
  const fallback =
    !component && finding.category === 'library' && matchedPackages.length === 1
      ? matchedPackages[0]
      : undefined;
  const identity =
    component ?? (fallback ? { ecosystem: fallback.ecosystem, name: fallback.name } : undefined);
  const matchedVersion = claims.find((claim) => identity && claim.name === identity.name)
    ?.matched_versions?.[0];
  const installed = component?.version ?? matchedVersion;
  const packageConfirmed =
    finding.category === 'library' && finding.applicability === 'affected' && installed !== undefined;
  const hasAdvisory = advisories.length > 0;
  const fixKnown = fixLinks.length > 0 || commits.size > 0;

  const readiness: ShieldReadiness = !hasAdvisory
    ? 'news_only'
    : packageConfirmed && fixKnown
      ? 'fix_known'
      : packageConfirmed && finding.fix
        ? 'fixed_version_known'
        : 'advisory_only';

  const missing: string[] = [];
  if (!hasAdvisory)
    missing.push(
      'No advisory yet. A news report rarely names the vulnerable code or the fixed version; wait for an advisory or a vendor bulletin.',
    );
  if (!packageConfirmed) {
    if (finding.category === 'library' && installed === undefined)
      missing.push(
        'The installed version is unknown, so it is not confirmed that this system runs an affected version.',
      );
    else if (finding.category === 'library')
      missing.push(
        `Applicability is ${finding.applicability}: the installed version is not confirmed affected.`,
      );
    else if (hasAdvisory)
      missing.push(
        'Matched by product or keyword, not by package and version: the installed version is not confirmed affected.',
      );
  }
  if (hasAdvisory && !fixKnown)
    missing.push(
      finding.fix
        ? 'No fix commit or patch link in the advisories; compare the installed and fixed releases, or find the fix in the project history.'
        : 'No fix commit, patch link or fixed version published yet; a shield would have to be built from the description alone.',
    );
  if (hasAdvisory && !finding.fix) missing.push('No fixed version published.');
  if (!exploitSources.size)
    missing.push(
      'No public exploit code reported by the sources read, so a shield cannot be tested against a real attack; test it against the fix instead.',
    );

  const identifiers = [
    ...new Set([finding.event_id, ...advisories.flatMap((item) => [...item.aliases])]),
  ].slice(0, MAX_IDENTIFIERS);
  const location = finding.location;
  const omit = Boolean(input.omitLocation);
  // A package URL's qualifiers can name a private registry (`?repository_url=...`).
  const purl = component?.purl ? (omit ? component.purl.split(/[?#]/)[0] : component.purl) : undefined;
  let shield = finding.runtime_shield;
  if (shield && input.shirudoMaxAgeMinutes !== undefined) {
    // The saved status is as old as the last scan: when scans have stopped, it is out of date now.
    const exported = Date.parse(shield.exported_at);
    const stale =
      !Number.isFinite(exported) ||
      (input.now ?? Date.now()) - exported > input.shirudoMaxAgeMinutes * 60_000;
    if (stale !== shield.stale) shield = { ...shield, stale };
  }
  return {
    finding_id: finding.id,
    ...(controls ? { revision: controls.revision } : {}),
    readiness,
    missing,
    event_id: finding.event_id,
    identifiers,
    title: finding.title,
    category: finding.category,
    applicability: finding.applicability,
    source_severity: finding.source_severity,
    priority: finding.priority,
    exploited: finding.exploited,
    exploitation_reported: Boolean(finding.news_signals?.exploitation),
    public_exploit: [...exploitSources].sort(),
    ...(finding.epss ? { epss: finding.epss } : {}),
    // A system ID is often its name (an SBOM file name, a Shirudo image ID).
    ...(omit ? {} : { system_id: finding.system_id }),
    ...(location && !omit ? { location } : {}),
    ...(identity
      ? {
          package: {
            ecosystem: identity.ecosystem,
            name: identity.name,
            ...(installed ? { installed } : {}),
            ...(finding.fix ? { fixed: finding.fix } : {}),
            ...(purl ? { purl } : {}),
          },
        }
      : {}),
    fix_links: fixLinks,
    fix_commits: [...commits.values()],
    references: otherReferences,
    weaknesses: [...weaknesses].sort((a, b) => Number(a.slice(4)) - Number(b.slice(4))),
    ...(finding.news_analysis?.prerequisites?.length
      ? { prerequisites: finding.news_analysis.prerequisites }
      : {}),
    // A news article can come from a feed on an internal address; advisories are public records.
    advisories: current
      .filter((item) => !omit || item.kind === 'advisory' || item.kind === 'kev')
      .map((item) => ({ id: item.id, source: item.source, url: item.url })),
    ...(shield ? { runtime_shield: shield } : {}),
    ...(controls?.acknowledged ? { acknowledged: true } : {}),
    ...(controls?.suppressed && controls.suppressed_until
      ? { suppressed_until: timestamp(controls.suppressed_until) }
      : {}),
  };
}
