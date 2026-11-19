import { satisfies, valid } from 'semver';
import { pythonRangeStatus } from './python-version.js';
import type {
  Applicability,
  Assessment,
  Component,
  Config,
  Decision,
  Evidence,
  Inventory,
  PackageClaim,
  Severity,
  System,
} from './types.js';
import { hash, highest, severityRank, timestamp } from './util.js';
import { exactLibraryVersion, normalizeEcosystem, packageKey } from './ecosystems.js';
import { mentions, packageMentioned } from './matching.js';
import { newsSignals, signalLevel } from './news-signals.js';

export function normalizeEventId(id: string): string {
  return /^(?:CVE-|GHSA-)/i.test(id) ? id.toUpperCase() : id;
}
function identifiers(evidence: Evidence): string[] {
  return [...new Set([evidence.id, ...evidence.aliases].map(normalizeEventId))];
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
  /** Identifiers of this event that earlier findings were reported under, the preferred first. */
  reported?: string[];
}
function eventId(ids: string[]): string {
  return [...ids].sort((a, b) => {
    const rank = (id: string) => (id.startsWith('GHSA-') ? 0 : id.startsWith('CVE-') ? 1 : 2);
    return rank(a) - rank(b) || a.localeCompare(b);
  })[0]!;
}

/** Only advisory alias claims merge events. A multi-CVE news story must not merge its subjects. */
function groupEvidence(input: Evidence[], knownEvents: ReadonlySet<string> = new Set()): Group[] {
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
    const root = find(normalizeEventId(item.id));
    if (!groups.has(root)) groups.set(root, { event: '', evidence: [] });
    groups.get(root)!.evidence.push(item);
  }
  const aliasGroups = new Map<string, Group>();
  for (const group of groups.values()) {
    const ids = [...new Set(group.evidence.flatMap(identifiers))];
    // An event already reported under one of its identifiers keeps it: a record that gains a GHSA
    // alias, or is re-filed under another identifier, is the same vulnerability and must not be
    // retired and raised again as a new finding.
    const known = ids.filter((id) => knownEvents.has(id));
    group.event = eventId(known.length ? known : ids);
    if (known.length > 1)
      group.reported = [...known].sort((a, b) =>
        a === group.event ? -1 : b === group.event ? 1 : a.localeCompare(b),
      );
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
      // Keep unmatched CVEs in a roundup as separate candidates for review.
      // News mentions cannot establish that two CVEs/GHSAs are aliases of the same event.
      const advisoryIds = identifiers(item).filter(advisoryIdentifier);
      const residual = advisoryIds.filter((id) => !aliasGroups.has(id));
      for (const event of advisoryIds.length ? residual : matches.size ? [] : [item.id]) {
        if (!news.has(event)) news.set(event, { event, evidence: [] });
        news.get(event)!.evidence.push(item);
      }
    }
  }
  // Known exploitation applies to a cited CVE whether or not an advisory record has arrived yet.
  for (const item of evidence.filter((item) => item.kind === 'kev'))
    for (const event of new Set(identifiers(item))) news.get(event)?.evidence.push(item);
  return [...groups.values(), ...news.values()];
}

function stale(system: System, config: Config, now: number): boolean {
  const updated = Date.parse(system.updated_at);
  return (
    !Number.isFinite(updated) ||
    updated > now + 5 * 60_000 ||
    now - updated > config.inventory_stale_days * 86_400_000
  );
}

/**
 * Advisory sources publish plain comparator sets. The wider npm grammar (carets, tildes, hyphen and
 * x-ranges) is not theirs, and npm reads `> 1.2` as `>= 1.3.0` where a source means `> 1.2.0`.
 * Anything outside the comparator subset is unsupported and must not produce an exclusion.
 */
function comparatorRange(input: string): string | undefined {
  const alternatives: string[] = [];
  for (const alternative of input.split('||')) {
    // GitHub renders intersections with commas and a space after the operator; semver uses spaces.
    const tokens = alternative
      .replace(/,/g, ' ')
      .replace(/(<=|>=|<|>|=)\s+/g, '$1')
      .trim()
      .split(/\s+/);
    // OSV collection renders an unbounded range as a lone `*`.
    if (tokens.length === 1 && tokens[0] === '*') {
      alternatives.push('*');
      continue;
    }
    const comparators: string[] = [];
    for (const token of tokens) {
      const match = /^(<=|>=|<|>|=)?(\d\S*)$/.exec(token);
      if (!match) return undefined;
      const operator = match[1] ?? '=';
      const version = match[2]!;
      if (valid(version) === version) comparators.push(`${operator}${version}`);
      // `>= 1.2` and `< 1.2` mean the same bound in both readings; other partial forms do not.
      else if (/^\d+(?:\.\d+)?$/.test(version) && (operator === '>=' || operator === '<'))
        comparators.push(`${operator}${[...version.split('.'), '0', '0'].slice(0, 3).join('.')}`);
      else return undefined;
    }
    alternatives.push(comparators.join(' '));
  }
  return alternatives.join(' || ');
}

function claimStatus(claim: PackageClaim, version: string | undefined): Applicability {
  if (!version) return 'unknown';
  const ecosystem = normalizeEcosystem(claim.ecosystem);
  try {
    version = exactLibraryVersion(version, ecosystem);
  } catch {
    return 'unknown';
  }
  if (claim.matched_versions?.includes(version) || claim.versions?.includes(version)) return 'affected';
  if (ecosystem === 'PyPI') return pythonRangeStatus(version, claim.range);
  // Other registries have their own ordering, epochs and prerelease rules.
  // Exact positive queries/listed versions are evidence; a missing match is not an exclusion.
  if (ecosystem !== 'npm') return 'unknown';
  if (!claim.range) return 'unknown';
  const range = comparatorRange(claim.range);
  if (!range) return 'unknown';
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
  knownFindings: ReadonlySet<string> = new Set(),
): Assessment {
  // Two events reported separately can turn out to be one (a GHSA that lists both CVEs). Each
  // finding keeps the identifier it was reported under, so neither is retired and raised again.
  const event =
    group.reported?.find((id) => knownFindings.has(hash([id, system.id, component ?? null]))) ?? group.event;
  const sourceSeverity = highest(
    ...group.evidence.filter((item) => !item.withdrawn).map((item) => item.severity),
  );
  const exploited = group.evidence.some((item) => item.exploited || item.kind === 'kev');
  // A KEV entry adds an exploitation fact; it does not turn a news report into an advisory.
  const reports = group.evidence.filter((item) => item.kind !== 'kev');
  const title =
    group.evidence.find((item) => item.kind === 'advisory' && !item.withdrawn)?.title ??
    (reports[0] ?? group.evidence[0]!).title;
  return {
    id: hash([event, system.id, component ?? null]),
    event_id: event,
    system_id: system.id,
    ...(component ? { component_id: component } : {}),
    category,
    news_only: reports.every((item) => item.kind === 'news'),
    news_candidate:
      reports.every((item) => item.kind === 'news') ||
      (category === 'product' && reports.some((item) => item.kind === 'news')),
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

/** Assess each deployment independently against package identity and version evidence. */
export function assess(
  inventory: Inventory,
  evidence: Evidence[],
  config: Config,
  now = Date.now(),
  /**
   * The time against which the age of advisory evidence is judged; `now` unless given. A scan that
   * reconciles stored evidence before refreshing it passes the time of the last collection, so
   * evidence does not count as stale merely because the refresh has not happened yet.
   */
  evidenceAsOf = now,
  /** Event identifiers of findings already reported; an event keeps the one it was reported under. */
  knownEvents: ReadonlySet<string> = new Set(),
  /** Identifiers of findings already reported, for an event that merges two reported ones. */
  knownFindings: ReadonlySet<string> = new Set(),
): Assessment[] {
  const output: Assessment[] = [];
  const index = new Map<System, Map<string, Component[]>>();
  for (const system of inventory.systems) {
    const byKey = new Map<string, Component[]>();
    for (const component of system.components) {
      const key = packageKey(component);
      if (!key) continue;
      if (!byKey.has(key)) byKey.set(key, []);
      byKey.get(key)!.push(component);
    }
    index.set(system, byKey);
  }
  for (const group of groupEvidence(evidence, knownEvents)) {
    const firstOfGroup = output.length;
    const advisories = group.evidence.filter((item) => item.kind === 'advisory');
    const isNews = advisories.length === 0;
    const identifiedNews =
      isNews && group.evidence.some((item) => identifiers(item).some(advisoryIdentifier));
    const text = group.evidence
      .filter((item) => item.kind !== 'kev')
      .map((item) => `${item.title}\n${item.description}`)
      .join('\n');
    const newsText = group.evidence
      .filter((item) => item.kind === 'news')
      .map((item) => `${item.title}\n${item.description}`)
      .join('\n');
    // An advisory record without a usable package claim identifies the event but says nothing about
    // which inventory packages it concerns, so it must not retire a candidate the linked news already
    // raised. A claim for an ecosystem or a name this application cannot match is no claim at all.
    const unclaimedNews =
      !isNews &&
      newsText.length > 0 &&
      advisories.every((item) => item.packages.every((claim) => packageKey(claim) === undefined));
    // Index the group's claims once; a scan compares every group with every component.
    const claimed = new Map<string, { item: Evidence; claims: PackageClaim[] }[]>();
    for (const item of advisories) {
      const byKey = new Map<string, PackageClaim[]>();
      for (const claim of item.packages) {
        const key = packageKey(claim);
        if (!key) continue;
        if (!byKey.has(key)) byKey.set(key, []);
        byKey.get(key)!.push(claim);
      }
      for (const [key, claims] of byKey) {
        if (!claimed.has(key)) claimed.set(key, []);
        claimed.get(key)!.push({ item, claims });
      }
    }
    const hasCandidates = identifiedNews || unclaimedNews;
    for (const system of inventory.systems) {
      let componentMatched = false;
      // Without news candidates only components named by a claim can produce a finding.
      const components = hasCandidates
        ? system.components
        : [...claimed.keys()].flatMap((key) => index.get(system)!.get(key) ?? []);
      for (const component of components) {
        const key = claimed.size ? packageKey(component) : undefined;
        const matching = (key && claimed.get(key)) || [];
        if (!matching.length) {
          if (hasCandidates && packageMentioned(newsText, component)) {
            componentMatched = true;
            const result = base(group, system, now, 'library', component.id, knownFindings);
            result.news_candidate = true;
            result.reasons.push(
              unclaimedNews
                ? `News about this advisory mentions the ${component.ecosystem} package name ${component.name}; the advisory record carries no structured package evidence.`
                : `News identifies an advisory and mentions the ${component.ecosystem} package name ${component.name}; no structured affected-version evidence is available yet.`,
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
          knownFindings,
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
            `The exact ${component.ecosystem} identity ${component.name} and installed version ${component.version} match affected advisory evidence.`,
          );
        } else if (states.every((state) => state === 'not_affected')) {
          result.applicability = 'not_affected';
          result.reasons.push(
            `Installed ${component.name}@${component.version} is excluded by every matched advisory's supported affected version ranges.`,
          );
        } else {
          result.reasons.push(
            `The ${component.ecosystem} identity ${component.name} matches, but a missing version or unsupported affected-version constraint prevents a conclusion.`,
          );
        }
        if (!result.withdrawn && stale(system, config, now)) {
          if (result.applicability !== 'conflicting') result.applicability = 'unknown';
          result.reasons.push(
            'Inventory is stale or has an invalid/future timestamp; confirm the currently installed version before relying on this assessment.',
          );
        }
        const staleEvidence = active.some(({ item }) => {
          const fetched = Date.parse(item.fetched_at);
          return (
            !Number.isFinite(fetched) ||
            fetched > now + 300_000 ||
            evidenceAsOf - fetched > Math.max(120_000, config.poll_interval_minutes * 120_000)
          );
        });
        if (staleEvidence) {
          if (result.applicability === 'not_affected') {
            result.applicability = 'unknown';
            result.stale_exclusion = true;
          }
          result.reasons.push(
            'Advisory evidence is stale; retained positive matches are historical and cannot prove current exclusion.',
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

      // Apply the component's policy to linked news as well as the advisory itself.
      if (componentMatched && !isNews && !unclaimedNews) continue;
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
          knownFindings,
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
      if (componentMatched || productMatched || (!isNews && !unclaimedNews)) continue;
      if (
        !system.keywords.some((keyword) => mentions(newsText, keyword)) &&
        !system.components.some((component) => packageMentioned(newsText, component))
      )
        continue;
      const result = base(group, system, now, 'news');
      result.news_candidate = true;
      result.applicability = stale(system, config, now) ? 'unknown' : 'relevant';
      result.reasons.push(
        'An explicit system keyword or installed package name matches this news; relevance does not establish vulnerability applicability.',
      );
      result.summary = `Security news relevant to ${system.name}; review the linked evidence.`;
      output.push(result);
    }
    if (config.policy?.news_signals !== false) applyNewsSignals(group, output.slice(firstOfGroup), inventory);
  }
  return output.sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * Raises the priority of news findings that have no advisory severity by what the articles state
 * about their subject: a CVSS score, a vendor's word rating or a report of exploitation. Never
 * lowers anything; the source severity stays what advisory sources said.
 */
function applyNewsSignals(group: Group, results: Assessment[], inventory: Inventory): void {
  const articles = group.evidence.filter((item) => item.kind === 'news');
  if (!articles.length) return;
  const ids = [
    ...new Set(
      [group.event, ...group.evidence.filter((item) => item.kind !== 'news').flatMap(identifiers)].filter(
        advisoryIdentifier,
      ),
    ),
  ];
  const cache = new Map<string, ReturnType<typeof newsSignals>>();
  for (const result of results) {
    if (result.source_severity !== 'unknown' || !(result.news_candidate || result.news_only)) continue;
    const system = inventory.systems.find((item) => item.id === result.system_id);
    if (!system) continue;
    const names = targetNames(result, system, articles);
    const key = JSON.stringify(names);
    if (!cache.has(key)) cache.set(key, newsSignals(articles, { identifiers: ids, names }));
    const signals = cache.get(key);
    if (!signals) continue;
    const { level, reasons } = signalLevel(signals);
    result.news_signals = signals;
    result.reasons.push(...reasons);
    if (level !== 'unknown')
      result.priority = highest(result.priority, contextualPriority(level, system, false));
  }
}

/** The inventory names a finding was matched by, for tying article statements to it. */
function targetNames(result: Assessment, system: System, articles: Evidence[]): string[] {
  const product = result.component_id?.startsWith('product:')
    ? system.products.find((item) => `product:${item.name.toLowerCase()}` === result.component_id)
    : undefined;
  if (product) return [product.name, ...product.keywords];
  const component = system.components.find((item) => item.id === result.component_id);
  if (component) return [component.name];
  // A system-level news finding: its keywords and the installed packages the news names.
  const text = articles.map((item) => `${item.title}\n${item.description}`).join('\n');
  return [
    ...system.keywords,
    ...system.components.filter((item) => packageMentioned(text, item)).map((item) => item.name),
  ];
}

/** The source severity is always a floor; AI-proposed priority reductions cannot suppress it. */
export function decide(assessment: Assessment, config: Config): Decision {
  const policy = config.policy;
  const reviewAi = policy.review_before_news_suppression ?? policy.ai_dismissals !== 'record';
  if (assessment.category === 'health')
    return {
      action: policy.health_channels.length ? 'notify' : 'record',
      channels: policy.health_channels,
      reason: 'Monitoring health policy.',
    };
  const rule = policy[assessment.category === 'malware' ? 'library' : assessment.category];
  const channels = [...new Set(rule.channels)];
  if (assessment.active === false)
    return { action: 'record', channels: [], reason: 'Finding is no longer active.' };
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
  const quietAi =
    reviewAi &&
    assessment.ai?.status === 'complete' &&
    assessment.source_severity !== 'critical' &&
    !(assessment.exploited && policy.exploited_override) &&
    (((assessment.news_candidate || assessment.news_only) &&
      (assessment.news_analysis?.impact === 'not_affected' ||
        (assessment.news_analysis?.classification === 'general_news' &&
          assessment.news_analysis.impact === 'not_applicable'))) ||
      (assessment.category === 'news' && assessment.relevance === 'irrelevant'));
  if (!channels.length && !quietAi)
    return { action: 'record', channels: [], reason: 'This category has no configured delivery channels.' };
  // Every supported range excludes the installed version; only the age of the evidence is in
  // question. That is a source outage, which the source's health finding reports on its own
  // channels: an urgent alert for every exclusion would repeat it on every outage. As for a current
  // exclusion, no override applies: an exploited or malicious advisory for other versions is not
  // about the installed one.
  if (assessment.stale_exclusion)
    return {
      action: 'digest',
      channels,
      reason:
        'The advisory ranges exclude this installed version, but the advisory evidence is out of date (see the source health finding); included in the review digest.',
    };
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
      if (news.classification === 'general_news' && news.impact === 'not_applicable') {
        if (reviewAi)
          return {
            action: 'digest',
            channels,
            review: 'ai_general_news',
            reason: 'AI classifies this as general news; policy requires operator review before dismissal.',
          };
        return {
          action: 'record',
          channels: [],
          reason:
            'AI reviewed this as general system news, with no newly reported vulnerability or actionable vulnerability update.',
        };
      }
      if (news.impact === 'not_affected') {
        if (reviewAi)
          return {
            action: 'digest',
            channels,
            review: 'ai_not_affected',
            reason:
              'AI reports no deployment impact; policy requires operator review before suppressing this news finding.',
          };
        return {
          action: 'record',
          channels: [],
          reason:
            'AI found that the reported news does not affect this deployment; this is a news assessment, not a verified safety conclusion.',
        };
      }
      if (
        news.impact === 'affected' &&
        ['new_vulnerability', 'known_vulnerability_update'].includes(news.classification)
      ) {
        // News carries no source severity, so the validated priority is the only level available.
        // A positive impact claim must never be quieter than an uncertain or unclassified one.
        const level = highest(severity, assessment.priority);
        return rule.levels.includes(level) || (policy.urgent_unknown && level === 'critical')
          ? {
              action: 'notify',
              channels,
              reason: `AI reports an impacted system in ${news.classification}; matched ${assessment.category} rule at ${level}. Verify the cited versions and prerequisites.`,
            }
          : {
              action: 'digest',
              channels,
              reason: `AI reports an impacted system in ${news.classification}; ${level} is below the configured ${assessment.category} severity levels, so it is included in the review digest.`,
            };
      }
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
  ) {
    if (reviewAi && assessment.ai?.status === 'complete')
      return {
        action: 'digest',
        channels,
        review: 'ai_irrelevant',
        reason:
          'AI reports no relevant deployment context; policy requires operator review before dismissal.',
      };
    return {
      action: 'record',
      channels: [],
      reason: 'Evidence-backed news relevance assessment found no relevant deployment context.',
    };
  }
  if (!channels.length)
    return { action: 'record', channels: [], reason: 'This category has no configured delivery channels.' };
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
