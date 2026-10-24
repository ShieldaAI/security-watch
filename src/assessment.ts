import { satisfies, valid, validRange } from 'semver';
import type {
  Applicability,
  Assessment,
  Config,
  Decision,
  Evidence,
  Inventory,
  PackageClaim,
  Severity,
  System,
} from './types.js';
import { hash, highest, severityRank, timestamp } from './util.js';

function identity(id: string): string {
  return /^(?:CVE-|GHSA-)/i.test(id) ? id.toUpperCase() : id;
}
function identifiers(evidence: Evidence): string[] {
  return [...new Set([evidence.id, ...evidence.aliases].map(identity))];
}
function advisoryIdentifier(value: string): boolean {
  return /^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/i.test(value);
}
function newestEvidence(evidence: Evidence[]): Evidence[] {
  const byOrigin = new Map<string, Evidence>();
  for (const item of evidence) {
    const key = `${item.source}\u0000${item.id}`;
    const old = byOrigin.get(key);
    const modified = Date.parse(item.modified_at);
    const previousModified = old ? Date.parse(old.modified_at) : -Infinity;
    if (
      !old ||
      modified > previousModified ||
      (modified === previousModified && Date.parse(item.fetched_at) > Date.parse(old.fetched_at))
    )
      byOrigin.set(key, item);
  }
  return [...byOrigin.values()].sort((a, b) => a.id.localeCompare(b.id) || a.source.localeCompare(b.source));
}

interface Group {
  event: string;
  evidence: Evidence[];
}
function eventId(ids: string[]): string {
  return [...ids].sort((a, b) => {
    const rank = (id: string) => (id.startsWith('GHSA-') ? 0 : id.startsWith('CVE-') ? 1 : 2);
    return rank(a) - rank(b) || a.localeCompare(b);
  })[0]!;
}

/** Only advisory alias claims merge events. A multi-CVE news story must not merge its subjects. */
function groupEvidence(input: Evidence[]): Group[] {
  const evidence = newestEvidence(input);
  const parents = new Map<string, string>();
  const find = (value: string): string => {
    let root = value;
    while (parents.has(root) && parents.get(root) !== root) root = parents.get(root)!;
    let cursor = value;
    while (parents.has(cursor) && parents.get(cursor) !== root) {
      const next = parents.get(cursor)!;
      parents.set(cursor, root);
      cursor = next;
    }
    if (!parents.has(root)) parents.set(root, root);
    return root;
  };
  const advisory = evidence.filter((item) => item.kind === 'advisory');
  for (const item of advisory) {
    const ids = identifiers(item);
    for (const id of ids.slice(1)) parents.set(find(id), find(ids[0]!));
  }
  const groups = new Map<string, Group>();
  for (const item of advisory) {
    const root = find(identity(item.id));
    if (!groups.has(root)) groups.set(root, { event: '', evidence: [] });
    groups.get(root)!.evidence.push(item);
  }
  const aliasGroups = new Map<string, Group>();
  for (const group of groups.values()) {
    const ids = [...new Set(group.evidence.flatMap(identifiers))];
    group.event = eventId(ids);
    for (const id of ids) aliasGroups.set(id, group);
  }
  const news = new Map<string, Group>();
  for (const item of evidence.filter((item) => item.kind === 'news' || item.kind === 'kev')) {
    const matches = new Set(
      identifiers(item)
        .map((id) => aliasGroups.get(id))
        .filter((group): group is Group => group !== undefined),
    );
    for (const group of matches) group.evidence.push(item);
    if (item.kind === 'news') {
      // A matched subject must not consume other, still-unstructured subjects in a roundup.
      // News mentions cannot establish that two CVEs/GHSAs are aliases of the same event.
      const advisoryIds = identifiers(item).filter(advisoryIdentifier);
      const residual = advisoryIds.filter((id) => !aliasGroups.has(id));
      for (const event of advisoryIds.length ? residual : matches.size ? [] : [item.id]) {
        if (!news.has(event)) news.set(event, { event, evidence: [] });
        news.get(event)!.evidence.push(item);
      }
    }
  }
  return [...groups.values(), ...news.values()];
}

/** Word/identifier boundaries prevent "express" matching "expressions" or another npm scope. */
function mentions(text: string, needle: string): boolean {
  if (needle.trim().length < 3) return false;
  const escaped = needle.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?<![\\p{L}\\p{N}_@/\\-])${escaped}(?![\\p{L}\\p{N}_@/\\-])`, 'iu').test(text);
}

function stale(system: System, config: Config, now: number): boolean {
  const updated = Date.parse(system.updated_at);
  return (
    !Number.isFinite(updated) ||
    updated > now + 5 * 60_000 ||
    now - updated > config.inventory_stale_days * 86_400_000
  );
}

function claimStatus(claim: PackageClaim, version: string | undefined): Applicability {
  if (!version || !valid(version)) return 'unknown';
  if (claim.matched_versions?.includes(version) || claim.versions?.includes(version)) return 'affected';
  if (!claim.range) return 'unknown';
  // GitHub renders some npm range intersections with commas; semver uses spaces.
  const range = claim.range.replace(/,\s*/g, ' ');
  if (!range.trim() || !validRange(range)) return 'unknown';
  const matches = satisfies(version, range);
  // npm semver deliberately excludes most prereleases: that is not evidence of safety.
  if (version.includes('-') && !matches) return 'unknown';
  return matches ? 'affected' : 'not_affected';
}

function recordStatus(claims: PackageClaim[], version?: string): Applicability {
  const states = claims.map((claim) => claimStatus(claim, version));
  if (states.includes('affected')) return 'affected';
  if (states.every((state) => state === 'not_affected')) return 'not_affected';
  return 'unknown';
}

function contextualPriority(severity: Severity, system: System, exploited: boolean): Severity {
  if (exploited) return highest(severity, 'high');
  if (severity === 'high' && system.exposure === 'internet' && system.criticality === 'critical')
    return 'critical';
  return severity;
}

function base(
  group: Group,
  system: System,
  now: number,
  category: Assessment['category'],
  component?: string,
): Assessment {
  const sourceSeverity = highest(
    ...group.evidence.filter((item) => !item.withdrawn).map((item) => item.severity),
  );
  const exploited = group.evidence.some((item) => item.exploited || item.kind === 'kev');
  const title =
    group.evidence.find((item) => item.kind === 'advisory' && !item.withdrawn)?.title ??
    group.evidence[0]!.title;
  return {
    id: hash([group.event, system.id, component ?? null]),
    event_id: group.event,
    system_id: system.id,
    ...(component ? { component_id: component } : {}),
    category,
    news_only: group.evidence.every((item) => item.kind === 'news'),
    news_candidate:
      group.evidence.every((item) => item.kind === 'news') ||
      (category === 'product' && group.evidence.some((item) => item.kind === 'news')),
    applicability: 'unknown',
    source_severity: sourceSeverity,
    priority: contextualPriority(sourceSeverity, system, exploited),
    title,
    summary: '',
    reasons: [],
    evidence_ids: [...new Set(group.evidence.map((item) => item.id))].sort(),
    urls: [...new Set(group.evidence.map((item) => item.url).filter(Boolean))].sort(),
    exploited,
    updated_at: timestamp(now),
  };
}

/** Assess each deployment independently using positive identity/version evidence. AI cannot establish safety. */
export function assess(
  inventory: Inventory,
  evidence: Evidence[],
  config: Config,
  now = Date.now(),
): Assessment[] {
  const output: Assessment[] = [];
  for (const group of groupEvidence(evidence)) {
    const advisories = group.evidence.filter((item) => item.kind === 'advisory');
    const isNews = advisories.length === 0;
    const identifiedNews =
      isNews && group.evidence.some((item) => identifiers(item).some(advisoryIdentifier));
    const text = group.evidence
      .filter((item) => item.kind !== 'kev')
      .map((item) => `${item.title}\n${item.description}`)
      .join('\n');
    for (const system of inventory.systems) {
      let componentMatched = false;
      for (const component of system.components) {
        const matching = advisories
          .map((item) => ({
            item,
            claims: item.packages.filter(
              (claim) =>
                claim.ecosystem.toLowerCase() === component.ecosystem && claim.name === component.name,
            ),
          }))
          .filter((item) => item.claims.length);
        if (!matching.length) {
          if (identifiedNews && mentions(text, component.name)) {
            componentMatched = true;
            const result = base(group, system, now, 'library', component.id);
            result.reasons.push(
              `News identifies an advisory and mentions the exact npm name ${component.name}; no structured affected-version evidence is available yet.`,
            );
            if (stale(system, config, now))
              result.reasons.push(
                'Inventory is stale; confirm the installed version before assessing applicability.',
              );
            result.summary = `Reported advisory for ${component.name}${component.version ? `@${component.version}` : ''} in ${system.name}: applicability unknown.`;
            output.push(result);
          }
          continue;
        }
        componentMatched = true;
        const applicableEvidence = group.evidence.filter(
          (item) => item.kind !== 'advisory' || matching.some((match) => match.item === item),
        );
        const selected = { ...group, evidence: applicableEvidence };
        const result = base(
          selected,
          system,
          now,
          matching.some((match) => match.item.malware) ? 'malware' : 'library',
          component.id,
        );
        const active = matching.filter((match) => !match.item.withdrawn);
        const states = active.map((match) => recordStatus(match.claims, component.version));
        const withdrewSome = active.length !== matching.length;
        result.withdrawn = active.length === 0;
        if (result.withdrawn) {
          result.reasons.push(
            'All matched advisory sources withdrew this finding; withdrawal alone does not prove this installation safe.',
          );
        } else if (withdrewSome || (states.includes('affected') && states.includes('not_affected'))) {
          result.applicability = 'conflicting';
          result.reasons.push(
            'Advisory sources disagree about affected versions or withdrawal; investigate the conflicting evidence.',
          );
        } else if (states.includes('affected')) {
          result.applicability = 'affected';
          result.reasons.push(
            `The exact npm identity ${component.name} and installed version ${component.version} match affected advisory evidence.`,
          );
        } else if (states.every((state) => state === 'not_affected')) {
          result.applicability = 'not_affected';
          result.reasons.push(
            `Installed ${component.name}@${component.version} is excluded by every matched advisory's supported affected version ranges.`,
          );
        } else {
          result.reasons.push(
            `The npm identity ${component.name} matches, but a missing version or unsupported affected-version constraint prevents a conclusion.`,
          );
        }
        if (!result.withdrawn && stale(system, config, now)) {
          if (result.applicability !== 'conflicting') result.applicability = 'unknown';
          result.reasons.push(
            'Inventory is stale or has an invalid/future timestamp; confirm the currently installed version before relying on this assessment.',
          );
        }
        const fixes = [
          ...new Set(
            active.flatMap((match) =>
              match.claims.map((claim) => claim.fixed).filter((value): value is string => Boolean(value)),
            ),
          ),
        ];
        if (fixes.length) result.fix = fixes.sort().join('; ');
        result.summary = `${component.name}${component.version ? `@${component.version}` : ''} in ${system.name}: ${result.applicability}.`;
        output.push(result);
      }

      // News linked to an advisory enriches the component finding and cannot evade its category policy.
      if (componentMatched && !isNews) continue;
      let productMatched = false;
      for (const product of system.products) {
        if (![product.name, ...product.keywords].some((keyword) => mentions(text, keyword))) continue;
        productMatched = true;
        const result = base(
          group,
          system,
          now,
          isNews ? 'news' : 'product',
          `product:${product.name.toLowerCase()}`,
        );
        result.applicability = isNews ? 'relevant' : 'unknown';
        result.withdrawn = !isNews && advisories.every((item) => item.withdrawn);
        if (!isNews && advisories.some((item) => item.withdrawn) && !result.withdrawn)
          result.applicability = 'conflicting';
        result.reasons.push(
          `The product name or an explicit keyword matches ${product.name}; no supported product adapter establishes version or backport applicability.`,
        );
        if (stale(system, config, now)) {
          result.applicability = 'unknown';
          result.reasons.push('Inventory is stale; confirm the product and deployment details.');
        }
        result.summary = `${product.name}${product.version ? ` ${product.version}` : ''} in ${system.name}: ${result.applicability}.`;
        output.push(result);
      }
      if (componentMatched || productMatched || !isNews) continue;
      const keywords = [...system.keywords, ...system.components.map((component) => component.name)];
      if (!keywords.some((keyword) => mentions(text, keyword))) continue;
      const result = base(group, system, now, 'news');
      result.applicability = stale(system, config, now) ? 'unknown' : 'relevant';
      result.reasons.push(
        'An explicit system keyword or installed package name matches this news; relevance does not establish vulnerability applicability.',
      );
      result.summary = `Security news relevant to ${system.name}; review the linked evidence.`;
      output.push(result);
    }
  }
  return output.sort((a, b) => a.id.localeCompare(b.id));
}

/** The source severity is always a floor; AI-proposed priority reductions cannot suppress it. */
export function decide(assessment: Assessment, config: Config): Decision {
  const policy = config.policy;
  if (assessment.category === 'health')
    return {
      action: policy.health_channels.length ? 'notify' : 'record',
      channels: policy.health_channels,
      reason: 'Monitoring health policy.',
    };
  const rule = policy[assessment.category === 'malware' ? 'library' : assessment.category];
  const channels = [...new Set(rule.channels)];
  if (assessment.withdrawn)
    return {
      action: 'record',
      channels: [],
      reason: 'All matched advisory sources withdrew this finding; retained in history.',
    };
  if (assessment.applicability === 'not_affected')
    return {
      action: 'record',
      channels: [],
      reason: 'Supported advisory version ranges exclude this installed version.',
    };
  const uncertain = assessment.applicability === 'unknown' || assessment.applicability === 'conflicting';
  const severity =
    rule.basis === 'source_severity'
      ? assessment.source_severity
      : highest(assessment.source_severity, assessment.priority);
  if (!channels.length)
    return { action: 'record', channels: [], reason: 'This category has no configured delivery channels.' };
  if (assessment.category === 'malware' && policy.malware_override)
    return {
      action: 'notify',
      channels,
      reason: 'Malicious-package override; investigate immediately even without a severity score.',
    };
  if (assessment.exploited && policy.exploited_override)
    return { action: 'notify', channels, reason: 'Known-exploitation override; investigate immediately.' };
  if ((assessment.news_candidate || assessment.news_only) && assessment.source_severity !== 'critical') {
    const news = assessment.news_analysis;
    if (assessment.ai?.status === 'complete' && news) {
      if (news.classification === 'general_news' && news.impact === 'not_applicable')
        return {
          action: 'record',
          channels: [],
          reason:
            'AI reviewed this as general system news, with no newly reported vulnerability or actionable vulnerability update.',
        };
      if (news.impact === 'not_affected')
        return {
          action: 'record',
          channels: [],
          reason:
            'AI found that the reported news does not affect this deployment; this is a news assessment, not a verified safety conclusion.',
        };
      if (
        news.impact === 'affected' &&
        ['new_vulnerability', 'known_vulnerability_update'].includes(news.classification)
      )
        return rule.levels.includes(severity)
          ? {
              action: 'notify',
              channels,
              reason: `AI reports an impacted system in ${news.classification}; matched ${assessment.category} rule at ${severity}. Verify the cited versions and prerequisites.`,
            }
          : {
              action: 'record',
              channels: [],
              reason: `${severity} does not match the configured ${assessment.category} severity levels.`,
            };
    }
    if (config.models.enabled && !assessment.ai)
      return {
        action: 'record',
        channels: [],
        reason: 'News candidate awaiting AI classification before delivery.',
      };
    if (policy.urgent_unknown && highest(assessment.source_severity, assessment.priority) === 'critical')
      return {
        action: 'notify',
        channels,
        reason: 'Potentially critical news impact remains uncertain; investigation required.',
      };
    return {
      action: 'digest',
      channels,
      reason: 'News impact is unclassified, incomplete or uncertain; included in the review digest.',
    };
  }
  if (
    assessment.category === 'news' &&
    assessment.relevance === 'irrelevant' &&
    assessment.source_severity !== 'critical'
  )
    return {
      action: 'record',
      channels: [],
      reason: 'Evidence-backed news relevance assessment found no relevant deployment context.',
    };
  if (uncertain) {
    if (
      policy.urgent_unknown &&
      severityRank[highest(assessment.source_severity, assessment.priority)] >= severityRank.critical
    ) {
      return {
        action: 'notify',
        channels,
        reason:
          'Investigation required: potentially critical finding with uncertain or conflicting applicability.',
      };
    }
    return {
      action: 'digest',
      channels,
      reason: 'Uncertain applicability requires review; included in the review digest.',
    };
  }
  if (rule.levels.includes(severity))
    return {
      action: 'notify',
      channels,
      reason: `Matched ${assessment.category} rule at ${severity} severity; source severity remains the minimum.`,
    };
  return {
    action: 'record',
    channels: [],
    reason: `${severity} does not match the configured ${assessment.category} severity levels.`,
  };
}
