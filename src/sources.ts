import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { defaultTreeAdapter, parse, parseFragment, type DefaultTreeAdapterTypes } from 'parse5';
import { compare, valid } from 'semver';
import { cvssV4BaseScore } from './cvss4.js';
import type {
  Config,
  CoverageReceipt,
  Evidence,
  HttpClient,
  Inventory,
  PackageClaim,
  Severity,
  SourceResult,
} from './types.js';
import { cleanText, hash, highest, singleLine, timestamp } from './util.js';
import { collectCveNow, evidenceRelevant, type CveNowState } from './cve-now.js';
import { VENDOR_FEEDS, vendorArticleBody, vendorArticleTarget, type VendorFeed } from './vendor-sources.js';
import {
  exactLibraryVersion,
  normalizeEcosystem,
  normalizePackageName,
  osvPackageNames,
  samePackage,
  type Ecosystem,
} from './ecosystems.js';
import {
  PartialSourceError,
  SourceError,
  SourceHttpError,
  SourceItemFailures,
  sourceCanceled,
  throwSourceFailure,
} from './source-error.js';

const OSV = 'https://api.osv.dev/v1';
const GITHUB = 'https://api.github.com/advisories';
const KEV = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
const HACKER_NEWS = 'https://feeds.feedburner.com/TheHackersNews';
const MAX_PAGES = 50;
const MAX_ADVISORIES = 5_000;
const MAX_FEED_ENTRIES = 500;
const LATE_ENTRY_DAYS = 7;
const HOUR = 3_600_000;
/** How long a GitHub record that cannot be read is asked for again before it can be given up on. */
const UNREADABLE_HOLD_HOURS = 24;
/** Failed reads, in runs that read other records, before such a record is given up on. */
const OWED_GITHUB_ATTEMPTS = 3;
/** How many such records are remembered, and how many are asked for by identifier in one run. */
const MAX_UNREADABLE = 10_000;
const REFETCH_PER_RUN = 10;
const REFETCH_WITHOUT_TOKEN = 2;
/** Without a token, rows listed beyond which a row without an identifier no longer holds the listing. */
const HOLD_ROWS_WITHOUT_TOKEN = 300;
/** Update times of rows without an identifier remembered per package, the latest kept. */
const ROW_VERSIONS = 50;
type RecordValue = Record<string, unknown>;

function record(value: unknown): RecordValue {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new SourceError('Invalid source schema.');
  return value as RecordValue;
}
function array(value: unknown, optional = false): unknown[] {
  if (value === undefined && optional) return [];
  if (!Array.isArray(value)) throw new SourceError('Invalid source schema.');
  return value;
}
function string(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) throw new SourceError('Invalid source schema.');
  return value;
}
function optionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  return string(value);
}
function date(value: unknown): string {
  const input = string(value);
  if (!Number.isFinite(Date.parse(input))) throw new SourceError('Invalid source date.');
  return new Date(input).toISOString();
}
/** A news story is linked to at most this many advisories: the first identifiers it cites. */
const MAX_STORY_IDENTIFIERS = 100;
/**
 * The advisory identifiers a story cites, in the order they appear. A roundup can list hundreds;
 * each one becomes a lookup and a candidate finding, so only the first ones are followed.
 */
function citedIdentifiers(text: string): string[] {
  // The number has a bounded length: a longer run of digits is not an identifier.
  return aliases(
    text.match(/\b(?:CVE-\d{4}-\d{4,19}|GHSA-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4})\b/gi) ?? [],
  ).slice(0, MAX_STORY_IDENTIFIERS);
}
function aliases(values: unknown[]): string[] {
  return [
    ...new Set(
      values
        .filter((v): v is string => typeof v === 'string' && v.length > 0)
        .map((v) =>
          /^cve-/i.test(v) ? v.toUpperCase() : /^ghsa-/i.test(v) ? `GHSA-${v.slice(5).toLowerCase()}` : v,
        ),
    ),
  ];
}
function aliasStrings(value: unknown): string[] {
  return array(value, true).map(string);
}
function severity(value: unknown): Severity {
  const normalized = typeof value === 'string' ? value.toLowerCase() : '';
  if (normalized === 'moderate') return 'medium';
  return normalized === 'critical' || normalized === 'high' || normalized === 'medium' || normalized === 'low'
    ? normalized
    : 'unknown';
}
function scoreSeverity(score: unknown): Severity {
  if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 10) return 'unknown';
  return score >= 9
    ? 'critical'
    : score >= 7
      ? 'high'
      : score >= 4
        ? 'medium'
        : score > 0
          ? 'low'
          : 'unknown';
}

// FIRST CVSS 3.0/3.1 base equations only. Unsupported vectors remain unknown.
function vectorSeverity(vector: unknown): Severity {
  if (typeof vector !== 'string') return 'unknown';
  if (/^(?:\d|10)(?:\.\d+)?$/.test(vector)) return scoreSeverity(Number(vector));
  if (!/^CVSS:3\.[01]\//.test(vector)) return 'unknown';
  const metrics: Record<string, string> = {};
  for (const part of vector.split('/').slice(1)) {
    const pieces = part.split(':');
    if (pieces.length !== 2 || !pieces[0] || !pieces[1] || metrics[pieces[0]]) return 'unknown';
    metrics[pieces[0]] = pieces[1];
  }
  if (metrics.S !== 'U' && metrics.S !== 'C') return 'unknown';
  const pick = (key: string, weights: Record<string, number>) => weights[metrics[key] ?? ''];
  const av = pick('AV', { N: 0.85, A: 0.62, L: 0.55, P: 0.2 });
  const ac = pick('AC', { L: 0.77, H: 0.44 });
  const pr = pick('PR', { N: 0.85, L: metrics.S === 'C' ? 0.68 : 0.62, H: metrics.S === 'C' ? 0.5 : 0.27 });
  const ui = pick('UI', { N: 0.85, R: 0.62 });
  const c = pick('C', { N: 0, L: 0.22, H: 0.56 });
  const i = pick('I', { N: 0, L: 0.22, H: 0.56 });
  const a = pick('A', { N: 0, L: 0.22, H: 0.56 });
  if (
    av === undefined ||
    ac === undefined ||
    pr === undefined ||
    ui === undefined ||
    c === undefined ||
    i === undefined ||
    a === undefined
  )
    return 'unknown';
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = metrics.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  if (impact <= 0) return 'unknown';
  const raw = Math.min((metrics.S === 'C' ? 1.08 : 1) * (impact + 8.22 * av * ac * pr * ui), 10);
  const integer = Math.round(raw * 100_000);
  const rounded = integer % 10_000 === 0 ? integer / 100_000 : (Math.floor(integer / 10_000) + 1) / 10;
  return scoreSeverity(rounded);
}

/** At most 32 v4 candidates per advisory. Overflow fails collection instead of truncating a severity floor. */
function vectorCollector(): {
  score: (vector: unknown, declaredType?: unknown) => Severity;
  details: () => Pick<Evidence, 'cvss_v4'>;
} {
  const details: NonNullable<Evidence['cvss_v4']> = { base_scores: [], unsupported_vectors: 0 };
  let candidates = 0;
  return {
    score(vector, declaredType) {
      const v4 = declaredType === 'CVSS_V4' || (typeof vector === 'string' && vector.startsWith('CVSS:4'));
      if (!v4) return vectorSeverity(vector);
      if (++candidates > 32)
        throw new SourceError('CVSS v4 candidate limit exceeded; advisory not accepted.');
      const scored =
        declaredType === undefined || declaredType === 'CVSS_V4' ? cvssV4BaseScore(vector) : undefined;
      if (!scored) {
        details.unsupported_vectors++;
        return 'unknown';
      }
      if (!details.base_scores.some((item) => item.vector === scored.vector))
        details.base_scores.push(scored);
      return scoreSeverity(scored.score);
    },
    details() {
      return candidates ? { cvss_v4: details } : {};
    },
  };
}
function optionalRecord(value: unknown): RecordValue {
  return value === undefined || value === null ? {} : record(value);
}
function publicUrl(input: unknown, fallback: string): string {
  if (typeof input !== 'string') return fallback;
  try {
    const url = new URL(input, fallback);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return fallback;
    return url.href;
  } catch {
    return fallback;
  }
}
function retainNewest(target: Map<string, Evidence>, item: Evidence): void {
  const previous = target.get(item.id);
  if (!previous || Date.parse(item.modified_at) >= Date.parse(previous.modified_at))
    target.set(item.id, item);
}
async function json(
  http: HttpClient,
  url: string,
  options: Parameters<HttpClient>[1] = {},
): Promise<unknown> {
  const response = await http(url, { maxBytes: 8_000_000, ...options });
  if (response.status !== 200) throw new SourceHttpError('Source', response.status);
  try {
    return JSON.parse(response.body);
  } catch {
    throw new SourceError('Source returned invalid JSON.');
  }
}

interface OsvQuery {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
  page_token?: string;
  seen: Set<string>;
}
function sourcePackage(ecosystem: string, name: string): { ecosystem: string; name: string } {
  let normalized: Ecosystem;
  try {
    normalized = normalizeEcosystem(ecosystem);
  } catch {
    return { ecosystem, name };
  }
  try {
    return { ecosystem: normalized, name: normalizePackageName(normalized, name) };
  } catch {
    // Keep the published spelling. A name this application cannot normalise matches no inventory
    // entry; rejecting it would discard the advisory's other packages and hold back the checkpoint.
    return { ecosystem: normalized, name };
  }
}
function osvRanges(value: unknown): string | undefined {
  const ranges = array(value, true);
  if (!ranges.length) return undefined;
  const expressions: string[] = [];
  for (const raw of ranges) {
    const range = record(raw);
    if (range.type !== 'SEMVER') return undefined;
    const events = array(range.events);
    if (!events.length) throw new SourceError('Invalid OSV version range.');
    const timeline: { field: string; version: string }[] = [];
    const limits: string[] = [];
    for (const rawEvent of events) {
      const event = record(rawEvent);
      const fields = ['introduced', 'fixed', 'last_affected', 'limit'].filter(
        (field) => event[field] !== undefined,
      );
      if (fields.length !== 1) throw new SourceError('Invalid OSV version range.');
      const field = fields[0]!;
      const version = string(event[field]);
      if (field === 'limit' && version.includes('*')) {
        limits.push('*');
        continue;
      }
      const normalized = version === '0' && field === 'introduced' ? '0' : valid(version);
      if (!normalized) return undefined;
      if (field === 'limit') limits.push(normalized);
      else timeline.push({ field, version: normalized });
    }
    if (!timeline.some((event) => event.field === 'introduced'))
      throw new SourceError('Invalid OSV version range.');
    const versionOrder = (left: string, right: string) =>
      left === right ? 0 : left === '0' ? -1 : right === '0' ? 1 : compare(left, right);
    // OSV recommends sorted events but does not require source order. Limits apply
    // independently to the whole range; they are not fix transitions.
    timeline.sort((a, b) => versionOrder(a.version, b.version));
    const maximum = limits.includes('*') ? undefined : limits.sort(versionOrder).at(-1);
    let lower: string | undefined;
    let open = false;
    const expression = (upper?: string) =>
      [lower && `>=${lower}`, upper, maximum && `<${maximum}`].filter(Boolean).join(' ') || '*';
    for (let index = 0; index < timeline.length; index++) {
      const event = timeline[index]!;
      const previous = timeline[index - 1];
      // Conflicting transitions at one normalized version have no unambiguous order.
      if (previous && versionOrder(event.version, previous.version) === 0 && event.field !== previous.field)
        return undefined;
      if (event.field === 'introduced') {
        if (!open) lower = event.version === '0' ? undefined : event.version;
        open = true;
      } else if (open) {
        expressions.push(expression(`${event.field === 'last_affected' ? '<=' : '<'}${event.version}`));
        open = false;
      }
    }
    if (open) expressions.push(expression());
  }
  return expressions.length ? expressions.join(' || ') : undefined;
}
function osvRecord(raw: unknown, expectedId: string, matches: OsvQuery[], now: number): Evidence {
  const data = record(raw);
  if (string(data.id) !== expectedId) throw new SourceError('OSV returned a mismatched advisory ID.');
  const packageClaims: PackageClaim[] = [];
  const vectors = vectorCollector();
  const severities: Severity[] = [severity(optionalRecord(data.database_specific).severity)];
  for (const rawSeverity of array(data.severity, true)) {
    const item = record(rawSeverity);
    severities.push(vectors.score(item.score, item.type));
  }
  for (const rawAffected of array(data.affected, true)) {
    const affected = record(rawAffected);
    // OSV can include a separate Git-only entry beside registry package entries.
    if (affected.package === undefined) {
      const ranges = array(affected.ranges);
      if (
        !ranges.length ||
        !ranges.every((rawRange) => {
          const range = record(rawRange);
          return range.type === 'GIT' && typeof range.repo === 'string' && range.repo.length > 0;
        })
      )
        throw new SourceError('OSV returned an affected entry without a package identity.');
      continue;
    }
    const pkg = record(affected.package);
    const { ecosystem, name } = sourcePackage(string(pkg.ecosystem), string(pkg.name));
    const range = ecosystem === 'npm' ? osvRanges(affected.ranges) : undefined;
    const versions = array(affected.versions, true).map(string);
    const matched_versions = [
      ...new Set(
        matches
          .filter((query) => samePackage(query, { ecosystem, name }))
          .map((query) => query.version)
          .filter((version): version is string => version !== undefined),
      ),
    ];
    const fixed = array(affected.ranges, true)
      .flatMap((rawRange) => array(record(rawRange).events, true))
      // Kept whole on one line: the notification's Fix line shows a version whole or counts it as
      // too long to show, never a cut one, which would be another version.
      .map((rawEvent) => singleLine(optionalString(record(rawEvent).fixed) ?? ''))
      .filter((v) => v.length > 0);
    packageClaims.push({
      ecosystem,
      name,
      ...(range ? { range } : {}),
      ...(versions.length ? { versions } : {}),
      ...(matched_versions.length ? { matched_versions } : {}),
      ...(fixed.length ? { fixed: [...new Set(fixed)].join(', ') } : {}),
    });
    severities.push(severity(optionalRecord(affected.database_specific).severity));
    for (const rawSeverity of array(affected.severity, true)) {
      const item = record(rawSeverity);
      severities.push(vectors.score(item.score, item.type));
    }
  }
  // Queries identify the package even when details omit it. Only a versioned query proves impact.
  for (const query of matches)
    if (!packageClaims.some((claim) => samePackage(claim, query))) {
      const versions = [
        ...new Set(
          matches
            .filter((match) => samePackage(match, query))
            .map((match) => match.version)
            .filter((version): version is string => version !== undefined),
        ),
      ];
      packageClaims.push({
        ecosystem: query.ecosystem,
        name: query.name,
        ...(versions.length ? { matched_versions: versions } : {}),
      });
    }
  const canonical = `https://osv.dev/vulnerability/${encodeURIComponent(expectedId)}`;
  return {
    id: `osv:${expectedId}`,
    source: 'osv',
    kind: 'advisory',
    title: cleanText(optionalString(data.summary) ?? expectedId, 500),
    url: canonical,
    description: cleanText(
      optionalString(data.details) ?? optionalString(data.summary) ?? expectedId,
      16_000,
    ),
    aliases: aliases([expectedId, ...aliasStrings(data.aliases)]),
    severity: highest(...severities),
    ...vectors.details(),
    modified_at: date(data.modified),
    fetched_at: timestamp(now),
    ...(data.published ? { published_at: date(data.published) } : {}),
    packages: packageClaims,
    withdrawn: data.withdrawn === undefined || data.withdrawn === null ? false : !!date(data.withdrawn),
    malware: /^MAL-/.test(expectedId),
  };
}
async function osv(
  inventory: Inventory,
  previous: Evidence[],
  http: HttpClient,
  now: number,
): Promise<Evidence[]> {
  const unique = new Map<string, OsvQuery>();
  for (const system of inventory.systems)
    for (const component of system.components) {
      const ecosystem = normalizeEcosystem(component.ecosystem);
      let version: string | undefined;
      // Imported lockfiles may describe an unresolved Git/URL dependency instead of a registry version.
      // Query its package name conservatively without turning that text into an exact-version match.
      if (component.version) {
        try {
          version = exactLibraryVersion(component.version, ecosystem);
        } catch {
          /* Applicability remains unknown. */
        }
      }
      for (const name of osvPackageNames(ecosystem, component.name)) {
        const key = JSON.stringify([ecosystem, name, version ?? null]);
        unique.set(key, {
          ecosystem,
          name,
          ...(version ? { version } : {}),
          seen: new Set(),
        });
      }
    }
  const queries = [...unique.values()];
  if (queries.length > 10_000)
    throw new SourceError('OSV inventory exceeds the 10,000 unique package queries limit.');
  const results: Evidence[] = [];
  const invalid = new SourceItemFailures();
  try {
    const matched = new Map<string, OsvQuery[]>();
    for (let offset = 0; offset < queries.length; offset += 100) {
      let pending = queries.slice(offset, offset + 100);
      for (let page = 0; pending.length; page++) {
        if (page >= MAX_PAGES)
          throw new SourceError('OSV pagination limit reached; collection is incomplete.');
        const body = JSON.stringify({
          queries: pending.map((query) => ({
            package: { ecosystem: query.ecosystem, name: query.name },
            ...(query.version ? { version: query.version } : {}),
            ...(query.page_token ? { page_token: query.page_token } : {}),
          })),
        });
        const data = record(
          await json(http, `${OSV}/querybatch`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body,
          }),
        );
        const results = array(data.results);
        if (results.length !== pending.length)
          throw new SourceError('OSV batch result count did not match the request.');
        const next: OsvQuery[] = [];
        for (let index = 0; index < results.length; index++) {
          const result = invalid.read(() => record(results[index]));
          if (!result) continue;
          const query = pending[index]!;
          const vulns = invalid.read(() => array(result.vulns, true));
          for (const rawVuln of vulns ?? []) {
            const id = invalid.read(() => {
              const vuln = record(rawVuln);
              if (vuln.modified !== undefined) date(vuln.modified);
              return string(vuln.id);
            });
            if (!id) continue;
            if (!matched.has(id)) matched.set(id, []);
            if (
              !matched.get(id)!.some((match) => samePackage(match, query) && match.version === query.version)
            )
              matched.get(id)!.push(query);
            if (matched.size > MAX_ADVISORIES)
              throw new SourceError('OSV advisory limit reached; collection is incomplete.');
          }
          const token = optionalString(result.next_page_token);
          if (token) {
            if (query.seen.has(token)) throw new SourceError('OSV returned a repeated pagination token.');
            query.seen.add(token);
            next.push({ ...query, page_token: token });
          }
        }
        pending = next;
      }
    }
    const ids = new Set(matched.keys());
    // Stored records are refreshed while their package is in the inventory: one for a package that
    // was removed concerns no finding, and re-reading all of history would grow without end.
    const names = new Set(queries.map((query) => query.name.toLowerCase()));
    for (const item of previous)
      if (
        item.source === 'osv' &&
        item.id.startsWith('osv:') &&
        (item.packages ?? []).some((claim) => names.has(claim.name.toLowerCase()))
      )
        ids.add(item.id.slice(4));
    if (ids.size > MAX_ADVISORIES)
      throw new SourceError('OSV historical advisory limit reached; collection is incomplete.');
    // Bounded parallelism; historical IDs are refreshed even when they disappear from exact-version queries.
    const allIds = [...ids];
    let failures = 0;
    let firstFailure: string | undefined;
    // A stored record that OSV no longer serves is gone, not a failed request: it must not stop the
    // refresh of the records after it, and, as with cve.now, its last known content stays current.
    // Letting it age out would turn every exclusion resting on it into an urgent "unknown" on every
    // scan while OSV itself answers normally.
    const gone = (id: string, reason: unknown) =>
      !matched.has(id) && reason instanceof SourceHttpError && reason.status === 404;
    const storedCopy = new Map(
      previous.filter((item) => item.source === 'osv').map((item) => [item.id.slice(4), item]),
    );
    for (let index = 0; index < allIds.length; index += 4) {
      const batch = allIds.slice(index, index + 4);
      const settled = await Promise.allSettled(
        batch.map(async (id) =>
          osvRecord(
            await json(http, `${OSV}/vulns/${encodeURIComponent(id)}`),
            id,
            matched.get(id) ?? [],
            now,
          ),
        ),
      );
      const rejected = settled.filter(
        (item, position): item is PromiseRejectedResult =>
          item.status === 'rejected' && !gone(batch[position]!, item.reason),
      );
      const canceled = settled.find(
        (item): item is PromiseRejectedResult => item.status === 'rejected' && sourceCanceled(item.reason),
      );
      if (canceled) throw canceled.reason;
      for (const [position, item] of settled.entries()) {
        if (item.status === 'fulfilled') results.push(item.value);
        else if (gone(batch[position]!, item.reason)) {
          const copy = storedCopy.get(batch[position]!);
          if (copy) results.push({ ...copy, fetched_at: timestamp(now) });
        } else {
          failures++;
          firstFailure ??=
            item.reason instanceof SourceError ? item.reason.message : 'Source request failed.';
        }
      }
      if (
        rejected.length === batch.length ||
        failures >= 8 ||
        rejected.some(
          ({ reason }) => reason instanceof SourceHttpError && [401, 403, 429].includes(reason.status),
        )
      )
        break;
    }
    if (failures)
      throw new SourceError(
        `${failures} OSV advisory detail request(s) failed; collection is incomplete. ${firstFailure}`,
      );
    return invalid.finish('OSV', results);
  } catch (error) {
    throwSourceFailure(error, results);
  }
}

/**
 * A GitHub advisory's identifier: its `ghsa_id`, or else the identifier its own links end with, so a
 * renamed or reshaped `ghsa_id` field does not leave a record without one.
 */
function githubIdentifier(raw: unknown): string | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
  const data = raw as Record<string, unknown>;
  const id = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i;
  if (typeof data.ghsa_id === 'string' && id.test(data.ghsa_id)) return data.ghsa_id;
  for (const link of [data.html_url, data.url])
    if (typeof link === 'string') {
      const match = /\/advisories\/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})(?:[/?#]|$)/i.exec(link);
      if (match) return match[1];
    }
  return undefined;
}
/** The package names a GitHub row names, normalised as stored claims are and in lower case, read as far as the row allows. */
function githubPackageNames(raw: unknown): string[] {
  const vulnerabilities =
    typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>).vulnerabilities : undefined;
  if (!Array.isArray(vulnerabilities)) return [];
  return vulnerabilities.flatMap((vulnerability: unknown) => {
    const pkg =
      typeof vulnerability === 'object' && vulnerability !== null
        ? (vulnerability as Record<string, unknown>).package
        : undefined;
    const fields = typeof pkg === 'object' && pkg !== null ? (pkg as Record<string, unknown>) : {};
    const name = fields.name;
    if (typeof name !== 'string' || !name.trim()) return [];
    const ecosystem = typeof fields.ecosystem === 'string' ? fields.ecosystem : '';
    return [sourcePackage(ecosystem, name.trim()).name.toLowerCase()];
  });
}

function githubRecord(raw: unknown, type: 'reviewed' | 'malware', now: number): Evidence {
  const data = record(raw);
  const id = githubIdentifier(data);
  if (!id) throw new SourceError('Invalid GitHub advisory identifier.');
  if (data.type !== undefined && data.type !== type)
    throw new SourceError('GitHub returned an unexpected advisory type.');
  const modified = date(data.updated_at);
  if (Date.parse(modified) > now + 5 * 60_000)
    throw new SourceError('Source returned a future modification timestamp; collection is incomplete.');
  const packages = array(data.vulnerabilities).map((rawVulnerability) => {
    const vulnerability = record(rawVulnerability);
    const pkg = record(vulnerability.package);
    const range = optionalString(vulnerability.vulnerable_version_range);
    const patched = vulnerability.first_patched_version;
    const fixed = singleLine(
      (typeof patched === 'object' && patched !== null
        ? optionalString(record(patched).identifier)
        : optionalString(patched)) ?? '',
    );
    return {
      ...sourcePackage(string(pkg.ecosystem), string(pkg.name)),
      ...(range ? { range } : {}),
      ...(fixed ? { fixed } : {}),
    };
  });
  const cvss = optionalRecord(data.cvss);
  const cvssVersions = optionalRecord(data.cvss_severities);
  const vectors = vectorCollector();
  const ratings = [severity(data.severity), scoreSeverity(cvss.score), vectors.score(cvss.vector_string)];
  for (const [version, value] of Object.entries(cvssVersions))
    if (value) {
      const item = record(value);
      ratings.push(scoreSeverity(item.score));
      ratings.push(
        vectors.score(
          item.vector_string,
          version === 'cvss_v4' ? 'CVSS_V4' : version === 'cvss_v3' ? 'CVSS_V3' : version,
        ),
      );
    }
  return {
    id: `github:${id}`,
    source: `github:${type}`,
    kind: 'advisory',
    title: cleanText(string(data.summary), 500),
    url: `https://github.com/advisories/${encodeURIComponent(id)}`,
    description: cleanText(optionalString(data.description) ?? string(data.summary), 16_000),
    aliases: aliases([
      id,
      data.cve_id,
      ...array(data.identifiers, true).map((item) => string(record(item).value)),
    ]),
    severity: highest(...ratings),
    ...vectors.details(),
    modified_at: modified,
    fetched_at: timestamp(now),
    published_at: date(data.published_at),
    packages,
    withdrawn:
      data.withdrawn_at === undefined || data.withdrawn_at === null ? false : !!date(data.withdrawn_at),
    malware: type === 'malware',
  };
}
function nextGithubLink(link: string | undefined): string | undefined {
  if (!link) return undefined;
  for (const part of link.split(',')) {
    const parsed = part.match(/^\s*<([^>]+)>\s*;\s*rel\s*=\s*"?([a-z]+)"?\s*$/i);
    if (!parsed?.[1] || !parsed[2]) throw new SourceError('GitHub returned invalid pagination.');
    if (parsed[2].toLowerCase() !== 'next') continue;
    let url: URL;
    try {
      url = new URL(parsed[1]);
    } catch {
      throw new SourceError('GitHub returned invalid pagination.');
    }
    if (
      url.origin !== 'https://api.github.com' ||
      url.pathname !== '/advisories' ||
      url.username ||
      url.password ||
      url.hash
    )
      throw new SourceError('GitHub returned an untrusted pagination destination.');
    return url.href;
  }
  return undefined;
}
/**
 * Where a GitHub scan's window starts, and since when every modification has been read through an
 * unbroken chain of scans. A catch-up over more updates than one scan reads moves the window start on
 * from scan to scan; the chain still covers everything since the scan that began it.
 */
function githubWindow(
  checkpoint: string | undefined,
  since: string | undefined,
  now: number,
): { start: number; chainStart: number } {
  const saved = checkpoint === undefined ? undefined : Date.parse(checkpoint);
  if (saved !== undefined && !Number.isFinite(saved))
    throw new SourceError('Invalid source checkpoint; reset it before collecting.');
  // A checkpoint ahead of the clock (a clock that was wrong, then corrected) would never be reached:
  // collection starts as on a new installation, as cve.now does.
  const previous = saved === undefined || saved > now ? now - 7 * 24 * HOUR : saved;
  const start = Math.max(0, previous - HOUR);
  const chained = since ? Date.parse(since) : NaN;
  return { start, chainStart: Number.isFinite(chained) && chained <= start ? chained : start };
}

async function github(
  type: 'reviewed' | 'malware',
  checkpoint: string | undefined,
  config: Config,
  http: HttpClient,
  now: number,
  inventory: Inventory,
  stored: Evidence[],
  since: string | undefined,
  /**
   * Records GitHub served in a form that cannot be read, remembered by identifier
   * (`pending`: [id, first met, failed attempts]) and those given up on (`skipped`); the next
   * values are set for the following run.
   */
  unreadable: {
    pending?: string;
    skipped?: string;
    nextPending?: string;
    nextSkipped?: string;
    /**
     * Package names (lower case, "*" for a row that names none) of rows met without any identifier,
     * with when they were last met: a stored record for such a package read before then may have been
     * replaced by that row, so it is not confirmed as current until it is read again.
     */
    unconfirmed?: string;
    nextUnconfirmed?: string;
  } = {},
): Promise<Evidence[]> {
  const { start, chainStart } = githubWindow(checkpoint, since, now);
  const url = new URL(GITHUB);
  url.searchParams.set('type', type);
  // GitHub's search-date parser rejects fractional seconds, unlike checkpoint timestamps.
  const queryTime = (value: number) => timestamp(value).replace(/\.\d{3}Z$/, 'Z');
  url.searchParams.set('modified', `${queryTime(start)}..${queryTime(now)}`);
  url.searchParams.set('sort', 'updated');
  url.searchParams.set('direction', 'asc');
  url.searchParams.set('per_page', '100');
  const headers: Record<string, string> = {
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2026-03-10',
  };
  const token = process.env[config.sources.github_token_env];
  if (token) headers.authorization = `Bearer ${token}`;
  let next: string | undefined = url.href;
  const seen = new Set<string>();
  const evidence = new Map<string, Evidence>();
  const invalid = new SourceItemFailures();
  // A record that cannot be read is remembered by its identifier, as cve.now remembers the records
  // it still owes, so the checkpoint keeps moving. It is asked for by identifier on later runs and
  // given up on only after OWED_GITHUB_ATTEMPTS failed reads in runs that read other records and a
  // day after it was first met. A stored copy of a record whose newer version could not be read is
  // never confirmed as current: it ages, and exclusions resting on it go to review. A run that can
  // read nothing is a format outage: the checkpoint waits, so that the whole window is listed again
  // once GitHub serves the usual format.
  const key = (id: string) => id.toUpperCase();
  type Remembered = { id: string; firstMet: number; attempts: number; updated: number };
  const pending = new Map<string, Remembered>();
  /** Records stored from this type, by key: a given-up record with a stored copy matters most. */
  const withCopy = new Set(
    stored.filter((item) => item.source === `github:${type}`).map((item) => key(item.id.slice(7))),
  );
  /** Records given up on, by key, with the identifier as GitHub wrote it. */
  const skipped = new Map<string, string>();
  try {
    for (const entry of JSON.parse(unreadable.pending ?? '[]') as unknown[])
      if (
        Array.isArray(entry) &&
        typeof entry[0] === 'string' &&
        typeof entry[1] === 'number' &&
        typeof entry[2] === 'number'
      )
        pending.set(key(entry[0]), {
          id: entry[0],
          firstMet: Math.min(entry[1], now),
          attempts: entry[2],
          updated: typeof entry[3] === 'number' && entry[3] <= now ? entry[3] : NaN,
        });
    for (const id of JSON.parse(unreadable.skipped ?? '[]') as unknown[])
      if (typeof id === 'string') skipped.set(key(id), id);
  } catch {
    // An unreadable list only means those records are found again when GitHub next updates them.
  }
  /** Records met in this run that could not be read: the identifier as GitHub wrote it, and when it was updated. */
  const unreadableNow = new Map<string, { id: string; updated: number }>();
  /**
   * Records that could not be read and give no identifier at all, and whether one was updated within
   * the last day. Such a record cannot be asked for by name: the packages it names are remembered, and
   * stored records for them are not confirmed as current until each is read again.
   */
  let unidentified = 0;
  let unidentifiedRecent = false;
  /**
   * The earliest update among such rows updated within the last day: the listing is read again from
   * it, so a row that regains its identifier is read. Each row holds for at most a day after its own
   * update, and never once a run reaches the page limit.
   */
  let unidentifiedHold = Infinity;
  /**
   * By package: when a row without an identifier naming it was first seen (`at`), the exact update
   * times of such rows seen (`versions`, the latest ROW_VERSIONS) and the latest of them (`updated`;
   * Infinity when a row had none). Saved as `at` (no times) or `[at, ...versions]`.
   */
  const blocked = new Map<string, { at: number; updated: number; versions: number[] }>();
  /** Packages named by such rows in this run: kept while their rows are still listed. */
  const seenNow = new Set<string>();
  /** The update times of such rows listed in this run, by package: never trimmed away. */
  const listedNow = new Map<string, Set<number>>();
  try {
    const saved: unknown = JSON.parse(unreadable.unconfirmed || '{}');
    if (typeof saved === 'object' && saved !== null && !Array.isArray(saved))
      for (const [name, value] of Object.entries(saved)) {
        // `at` alone (a row without an update time), or `[at, ...the updates of its rows]`.
        const [at, ...rest] = Array.isArray(value) ? value : [value];
        const versions = rest.filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
        if (typeof at === 'number' && Number.isFinite(at))
          blocked.set(name, {
            at: Math.min(at, now),
            updated: versions.length && versions.length === rest.length ? Math.max(...versions) : Infinity,
            versions,
          });
      }
  } catch {
    // An unreadable list only means those records are confirmed as before.
  }
  /**
   * The update times kept for a package: every one listed in this run, then the latest others, up to
   * ROW_VERSIONS (more when more were listed), without repeats. A time listed now is never evicted,
   * or its row would look new on every run.
   */
  const trimVersions = (name: string, all: number[]) => {
    const unique = [...new Set(all)];
    const listed = listedNow.get(name) ?? new Set<number>();
    const others = unique.filter((v) => !listed.has(v));
    const room = Math.max(0, ROW_VERSIONS - unique.filter((v) => listed.has(v)).length);
    // slice(-0) would keep them all.
    const keep = new Set([...unique.filter((v) => listed.has(v)), ...(room ? others.slice(-room) : [])]);
    return unique.filter((v) => keep.has(v));
  };
  /**
   * Whether a stored record may have been replaced by such a row: read before the row was first
   * seen, and not already at the row's version (its own update is earlier than the row's).
   */
  const waits = (item: Evidence, only?: string) =>
    [...(only ? [only] : ['*', ...item.packages.map((claim) => claim.name.toLowerCase())])].some((name) => {
      const entry = blocked.get(name);
      if (!entry) return false;
      if (only && only !== '*' && !item.packages.some((claim) => claim.name.toLowerCase() === only))
        return false;
      return Date.parse(item.fetched_at) < entry.at && !(Date.parse(item.modified_at) >= entry.updated);
    });
  const names = new Set(
    inventory.systems.flatMap((system) => system.components.map((component) => component.name.toLowerCase())),
  );
  /** Rows of the listing, readable or not, and the latest update time among them. */
  let rows = 0;
  let readableRows = 0;
  let reachedRow = -Infinity;
  /**
   * A format outage: the listing had rows and none of them could be read, and some were first met
   * within the last day. A window that has held only records that cannot be read for longer than
   * that holds bad records, not an outage, so the checkpoint may move again.
   */
  const outage = () =>
    rows > 0 &&
    readableRows === 0 &&
    (unidentifiedRecent ||
      [...unreadableNow.keys()].some((k) => {
        const entry = pending.get(k);
        return !entry || now - entry.firstMet <= UNREADABLE_HOLD_HOURS * HOUR;
      }));
  const updatedAt = (item: unknown) => {
    const updated =
      typeof item === 'object' && item !== null
        ? Date.parse(String((item as Record<string, unknown>).updated_at))
        : NaN;
    return Number.isFinite(updated) && updated <= now ? updated : NaN;
  };
  const ghsaId = githubIdentifier;
  const read = (item: unknown) => {
    const parsed = invalid.read(() => githubRecord(item, type, now));
    const id = ghsaId(item);
    if (parsed) {
      retainNewest(evidence, parsed);
      // Read now: what earlier runs could not read is settled. Another revision of it in this run
      // that cannot be read is still reported.
      if (id) {
        pending.delete(key(id));
        skipped.delete(key(id));
      }
    } else if (id) unreadableNow.set(key(id), { id, updated: updatedAt(item) });
    else {
      unidentified++;
      // Without a usable update time it has no day of its own: it makes a listing that can read
      // nothing a format outage, but beside readable rows it does not hold the listing.
      const updated = updatedAt(item);
      if (!Number.isFinite(updated)) unidentifiedRecent = true;
      else if (now - updated <= UNREADABLE_HOLD_HOURS * HOUR) {
        unidentifiedRecent = true;
        unidentifiedHold = Math.min(unidentifiedHold, updated);
      }
      // Held back from when the row is first seen, not from its update: GitHub may list a row late,
      // after a stored record was confirmed. A row seen before (its exact update time is among those
      // remembered for the package) keeps that time, so listing it again does not make records read
      // since wait again.
      const named = githubPackageNames(item);
      const version = Number.isFinite(updated) ? updated : Infinity;
      if (Number.isFinite(version))
        for (const name of named.length ? named : ['*'])
          listedNow.set(name, (listedNow.get(name) ?? new Set()).add(version));
      for (const name of named.length ? named : ['*']) {
        seenNow.add(name);
        const entry = blocked.get(name);
        // Seen before only if a row with exactly this update was seen for the package.
        const seen = entry?.versions.includes(version) ?? false;
        blocked.set(name, {
          at: entry && seen ? entry.at : now,
          updated: Math.max(entry?.updated ?? -Infinity, version),
          // Trimmed only when saved, once every row of the run is known.
          versions:
            Number.isFinite(version) && !seen
              ? [...(entry?.versions ?? []), version]
              : (entry?.versions ?? []),
        });
      }
    }
    return parsed;
  };
  /** Records given up on in this run. */
  let passed = 0;
  /** Records asked for by identifier and read in this run. */
  let recovered = 0;
  /** By-identifier requests refused for this client (rate limit), and requests that failed. */
  let refused = false;
  let requestsFailed = 0;
  /**
   * Settles the remembered records for the next run, and says where the next run must start when
   * the listing has to be read again: during a format outage, for remembered records beyond the cap,
   * and once records can be read again while some are still remembered.
   */
  const settle = (readSomething: boolean, holdUnidentified = true): number | undefined => {
    const nextPending = new Map<string, Remembered>(pending);
    for (const [k, { id, updated }] of unreadableNow) {
      const before = pending.get(k) ?? { id, firstMet: now, attempts: 0, updated };
      // A run whose listing could read nothing is a format outage, not a bad record.
      const attempts = before.attempts + (readSomething ? 1 : 0);
      if (attempts >= OWED_GITHUB_ATTEMPTS && now - before.firstMet > UNREADABLE_HOLD_HOURS * HOUR) {
        nextPending.delete(k);
        skipped.set(k, before.id);
        passed++;
      } else {
        // Listed again: it is remembered, so it no longer waits for a turn among those given up on.
        skipped.delete(k);
        nextPending.set(k, {
          id: before.id,
          firstMet: before.firstMet,
          attempts,
          updated: Number.isFinite(updated) ? updated : before.updated,
        });
      }
    }
    let rewind: number | undefined;
    const earliest = (entries: Remembered[]) =>
      Math.min(...entries.map((entry) => entry.updated).filter(Number.isFinite));
    // Bounded: the records first met longest ago are kept. The rest are not given up on: the
    // listing is read again from the oldest of them.
    const ordered = [...nextPending].sort((a, b) => a[1].firstMet - b[1].firstMet);
    // Beyond the cap the records whose day has passed are given up on first, then the newest: the
    // checkpoint must always be able to move.
    const overdue = (entry: Remembered) => now - entry.firstMet > UNREADABLE_HOLD_HOURS * HOUR;
    const byPriority = [...ordered].sort(
      (a, b) => Number(overdue(a[1])) - Number(overdue(b[1])) || a[1].firstMet - b[1].firstMet,
    );
    for (const [k, entry] of byPriority.slice(MAX_UNREADABLE)) {
      skipped.set(k, entry.id);
      passed++;
    }
    const keptKeys = new Set(byPriority.slice(0, MAX_UNREADABLE).map(([k]) => k));
    const kept = ordered.filter(([k]) => keptKeys.has(k));
    // Records read again by identifier: the format is back. What is still remembered is listed again.
    if (recovered && kept.length)
      rewind = Math.min(rewind ?? Infinity, earliest(kept.map(([, entry]) => entry)));
    // Nothing in the listing could be read: the window is listed again on the next run.
    if (!readSomething) rewind = start;
    // Without a token, a long window is not listed again for it: GitHub allows 60 requests an hour.
    if (holdUnidentified && Number.isFinite(unidentifiedHold) && (token || rows <= HOLD_ROWS_WITHOUT_TOKEN))
      rewind = Math.min(rewind ?? Infinity, unidentifiedHold);
    // A package stays remembered while a stored record for it, read before its row was met, waits to
    // be read again.
    const waitingFor = (name: string) =>
      stored.some(
        (item) =>
          item.source === `github:${type}` &&
          !evidence.has(item.id) &&
          item.packages.some((claim) => names.has(claim.name.toLowerCase())) &&
          waits(item, name),
      );
    unreadable.nextUnconfirmed = JSON.stringify(
      Object.fromEntries(
        [...blocked]
          .filter(([name]) => seenNow.has(name) || waitingFor(name))
          .sort((a, b) => b[1].at - a[1].at)
          .slice(0, MAX_UNREADABLE)
          .map(([name, { at, updated, versions }]) => [
            name,
            Number.isFinite(updated) ? [at, ...trimVersions(name, versions)] : at,
          ]),
      ),
    );
    unreadable.nextPending = JSON.stringify(
      kept.map(([, { id, firstMet, attempts, updated }]) => [
        id,
        firstMet,
        attempts,
        ...(Number.isFinite(updated) ? [updated] : []),
      ]),
    );
    // A record given up on that still has a stored copy is never forgotten, or that copy would be
    // confirmed again. Beyond the cap, the oldest without one are dropped; the order, which is the
    // order of turns for asking again, is kept.
    const list = [...skipped];
    let excess = list.filter(([k]) => !withCopy.has(k)).length - MAX_UNREADABLE;
    const keep = list.filter(([k]) => withCopy.has(k) || excess-- <= 0);
    unreadable.nextSkipped = JSON.stringify(keep.map(([, id]) => id));
    return rewind !== undefined && Number.isFinite(rewind) ? rewind : undefined;
  };
  const problems = (rewind: number | undefined) => {
    const parts: string[] = [];
    if (unreadableNow.size)
      parts.push(
        `GitHub: ${unreadableNow.size} record(s) could not be read; each is asked for again by identifier on later runs.`,
      );
    if (passed)
      parts.push(
        `GitHub: ${passed} record(s) could not be read three times over a day and were given up on; their stored copies are no longer confirmed as current.`,
      );
    if (unidentified)
      parts.push(
        `GitHub: ${unidentified} record(s) could not be read and give no identifier; stored records for the packages they name are not confirmed as current until each is read again${Number.isFinite(unidentifiedHold) ? ', and the listing is read again from the earliest updated within the last day' : ''}.`,
      );
    if (refused)
      parts.push('GitHub refused requests for single records (rate limit); they are asked for again later.');
    if (requestsFailed)
      parts.push(
        `GitHub: ${requestsFailed} request(s) for single records failed; they are asked for again later.`,
      );
    if (rewind !== undefined)
      parts.push('The next run lists the records since the oldest that could not be read again.');
    return parts.join(' ');
  };
  try {
    for (let page = 0; next; page++) {
      if (page >= MAX_PAGES) {
        // Records arrive oldest update first, so everything up to the last one read is complete.
        // The next start is the checkpoint minus an hour: continue exactly from that record. Rows
        // that could not be read count as progress: they are remembered by identifier.
        if (rows < MAX_PAGES * 90 || !Number.isFinite(reachedRow) || reachedRow <= start)
          throw new SourceError('GitHub pagination limit reached; collection is incomplete.');
        const rewind = settle(!outage(), false);
        const note = problems(rewind);
        throw new PartialSourceError(
          `GitHub returned more updated advisories than one run reads; the oldest were collected and the next run continues from there.${note ? ` ${note}` : ''}`,
          [...evidence.values()],
          timestamp(Math.min(now, (rewind ?? reachedRow) + HOUR)),
        );
      }
      if (seen.has(next)) throw new SourceError('GitHub returned repeated pagination.');
      seen.add(next);
      const response = await http(next, { headers, maxBytes: 8_000_000, redirects: 0 });
      if (response.status !== 200) throw new SourceError(`Source returned HTTP ${response.status}.`);
      let data: unknown;
      try {
        data = JSON.parse(response.body);
      } catch {
        throw new SourceError('Source returned invalid JSON.');
      }
      const items = array(data);
      if (items.length > 100)
        throw new SourceError('GitHub returned more records than the requested page limit.');
      for (const item of items) {
        rows++;
        const updated = updatedAt(item);
        if (Number.isFinite(updated)) reachedRow = Math.max(reachedRow, updated);
        if (read(item)) readableRows++;
      }
      const link = Object.entries(response.headers).find(([key]) => key.toLowerCase() === 'link')?.[1];
      next = nextGithubLink(link);
    }
    // Remembered records that this window did not list are asked for by identifier, the longest
    // waiting first, a few per run: two without a token, whose requests GitHub limits to 60 an hour.
    const asked = [...pending.values()]
      .filter((entry) => !unreadableNow.has(key(entry.id)) && !evidence.has(`github:${entry.id}`))
      .sort((a, b) => a.firstMet - b.firstMet)
      .slice(0, token ? REFETCH_PER_RUN : REFETCH_WITHOUT_TOKEN);
    // With room left, up to two records given up on are asked for again per run, so a record lost
    // to a long partial format change is found again once GitHub serves it readably.
    const budget = token ? REFETCH_PER_RUN : REFETCH_WITHOUT_TOKEN;
    // Records given up on are asked for in turn. With two requests to spare, one goes to the next
    // record with a stored copy (its copy is never confirmed until it is read) and one to the next
    // record in turn, so neither kind can take every turn; with one, they simply take turns.
    const room = budget - asked.length;
    // Stored records for the inventory that a row without an identifier may have replaced, the
    // longest unread first: read again by identifier, so that they can be confirmed again. One that
    // cannot be read is remembered like any other. They keep one request of the room left.
    const stale = stored
      .filter((item) => {
        const k = key(item.id.slice(7));
        return (
          item.source === `github:${type}` &&
          !evidence.has(item.id) &&
          !unreadableNow.has(k) &&
          !pending.has(k) &&
          !skipped.has(k) &&
          waits(item) &&
          item.packages.some((claim) => names.has(claim.name.toLowerCase()))
        );
      })
      .sort((a, b) => Date.parse(a.fetched_at) - Date.parse(b.fetched_at));
    const turns = room - (stale.length && room >= 1 ? 1 : 0);
    const waiting = [...skipped].filter(([k]) => !unreadableNow.has(k) && !pending.has(k));
    const picks: [string, string][] = [];
    const copyFirst = turns >= 2 ? waiting.find(([k]) => withCopy.has(k)) : undefined;
    if (copyFirst) picks.push(copyFirst);
    for (const entry of waiting) {
      if (picks.length >= Math.min(turns, 2)) break;
      if (!picks.includes(entry)) picks.push(entry);
    }
    const again: Remembered[] = picks.map(([, id]) => ({ id, firstMet: now, attempts: 0, updated: NaN }));
    // To the back of the queue, so the next run asks others.
    for (const [k, id] of picks) {
      skipped.delete(k);
      skipped.set(k, id);
    }
    const refresh: Remembered[] = stale
      .slice(0, Math.max(0, room - picks.length))
      .map((item) => ({ id: item.id.slice(7), firstMet: now, attempts: 0, updated: NaN }));
    for (const entry of [...asked, ...again, ...refresh]) {
      const givenUp = again.includes(entry);
      try {
        const response = await http(`${GITHUB}/${encodeURIComponent(entry.id)}`, {
          headers,
          maxBytes: 1_000_000,
          redirects: 0,
        });
        // GitHub answers that it has no such record, or serves it in a form that cannot be read: a
        // failed read. A refusal for this client ends the requests; any other failure says nothing
        // about the record.
        // A record given up on that still cannot be read stays given up on, without a new report.
        if (response.status === 404) {
          if (!givenUp) unreadableNow.set(key(entry.id), { id: entry.id, updated: NaN });
        } else if (response.status === 403 || response.status === 429) {
          refused = true;
          break;
        } else if (response.status !== 200) throw new SourceError(`Source returned HTTP ${response.status}.`);
        else {
          const body = JSON.parse(response.body) as unknown;
          // An answer without an identifier is a failed read of the record asked for, not a row of
          // the listing without one.
          if (ghsaId(body) && read(body)) {
            if (!refresh.includes(entry)) recovered++;
          } else if (givenUp) unreadableNow.delete(key(entry.id));
          else unreadableNow.set(key(entry.id), { id: entry.id, updated: NaN });
        }
      } catch (error) {
        if (sourceCanceled(error)) throw error;
        // A failed request says nothing about the record: it is reported and asked for again.
        requestsFailed++;
      }
    }
    const rewind = settle(!outage());
    // Every record modified since the window's start has been read. A stored record fetched after
    // that start and not among them is unchanged, so it is confirmed as current: without this an
    // exclusion drawn from it would turn into an "unknown" two poll intervals after it was first
    // read, while GitHub answers normally. Only records for the inventory's packages matter, and
    // never one whose newer version could not be read.
    const unconfirmed = new Set([...unreadableNow.keys(), ...pending.keys(), ...skipped.keys()]);
    // A record that could not be read and has no identifier may be the new version of a stored one
    // for a package it names.
    for (const item of stored)
      if (
        item.source === `github:${type}` &&
        !evidence.has(item.id) &&
        !unconfirmed.has(key(item.id.slice(7))) &&
        Date.parse(item.fetched_at) >= chainStart &&
        !waits(item) &&
        Date.parse(item.fetched_at) <= now &&
        item.packages.some((claim) => names.has(claim.name.toLowerCase()))
      )
        evidence.set(item.id, { ...item, fetched_at: timestamp(now) });
    const note = problems(rewind);
    // The checkpoint moves on, unless the listing must be read again from an earlier point.
    if (note)
      throw new PartialSourceError(
        note,
        [...evidence.values()],
        timestamp(rewind === undefined ? now : Math.min(now, rewind + HOUR)),
      );
    return [...evidence.values()];
  } catch (error) {
    throwSourceFailure(error, [...evidence.values()]);
  }
}

async function kev(http: HttpClient, now: number, previous: Evidence[]): Promise<Evidence[]> {
  const data = record(await json(http, KEV));
  const entries = array(data.vulnerabilities);
  if (!Number.isSafeInteger(data.count) || data.count !== entries.length || entries.length > 20_000)
    throw new SourceError('Invalid or incomplete CISA KEV catalog.');
  const released = date(data.dateReleased);
  if (Date.parse(released) > now + 5 * 60_000)
    throw new SourceError('Source returned a future modification timestamp; collection is incomplete.');
  const old = new Map<string, Evidence>();
  for (const item of previous) if (item.source === 'kev') retainNewest(old, item);
  const invalid = new SourceItemFailures();
  const results: Evidence[] = [];
  for (const raw of entries) {
    const parsed = invalid.read(() => {
      const item = record(raw);
      const cve = string(item.cveID);
      if (!/^CVE-\d{4}-\d{4,}$/i.test(cve)) throw new SourceError('Invalid CISA KEV identifier.');
      const vendor = string(item.vendorProject);
      const product = string(item.product);
      const description = `${vendor} ${product}\n${string(item.shortDescription)}\nRequired action: ${string(item.requiredAction)}`;
      const evidence: Evidence = {
        id: `kev:${cve.toUpperCase()}`,
        source: 'kev',
        kind: 'kev',
        title: cleanText(string(item.vulnerabilityName), 500),
        url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(cve)}`,
        description: cleanText(description, 16_000),
        aliases: aliases([cve]),
        severity: 'unknown',
        modified_at: released,
        fetched_at: timestamp(now),
        published_at: date(item.dateAdded),
        packages: [],
        exploited: true,
      };
      // KEV has a catalog release time, not entry modification times. An unchanged
      // entry retains its content revision while fetched_at records this refresh.
      const existing = old.get(evidence.id);
      const content = (item: Evidence) =>
        hash([item.title, item.description, item.url, item.aliases, item.published_at, item.exploited]);
      if (existing && content(existing) === content(evidence)) evidence.modified_at = existing.modified_at;
      return evidence;
    });
    if (parsed) results.push(parsed);
  }
  return invalid.finish('CISA KEV', results);
}

function xmlText(value: unknown): string {
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  if (!value || typeof value !== 'object') return '';
  if (Array.isArray(value)) return value.map(xmlText).join(' ');
  return Object.entries(value)
    .filter(([key]) => !key.startsWith('@_') && !HIDDEN_HTML_ELEMENTS.has(key.toLowerCase()))
    .map(([, child]) => xmlText(child))
    .join(' ');
}
const HIDDEN_HTML_ELEMENTS = new Set(['script', 'style', 'template', 'noscript']);
const MAX_HTML_BYTES = 2_000_000;
const MAX_HTML_NODES = 100_000;
const MAX_HTML_DEPTH = 256;
type HtmlNode = DefaultTreeAdapterTypes.Node;

function parseHtml(html: string, document = false): HtmlNode {
  if (Buffer.byteLength(html) > MAX_HTML_BYTES) throw new SourceError('HTML input exceeds the size limit.');
  let nodes = 0;
  let depth = 0;
  const account = () => {
    if (++nodes > MAX_HTML_NODES) throw new SourceError('HTML structure exceeds the node limit.');
  };
  const treeAdapter: typeof defaultTreeAdapter = {
    ...defaultTreeAdapter,
    createDocument() {
      account();
      return defaultTreeAdapter.createDocument();
    },
    createDocumentFragment() {
      account();
      return defaultTreeAdapter.createDocumentFragment();
    },
    createElement(...args) {
      account();
      return defaultTreeAdapter.createElement(...args);
    },
    createCommentNode(...args) {
      account();
      return defaultTreeAdapter.createCommentNode(...args);
    },
    insertText(parent, text) {
      if (parent.childNodes.at(-1)?.nodeName !== '#text') account();
      defaultTreeAdapter.insertText(parent, text);
    },
    insertTextBefore(parent, text, reference) {
      if (parent.childNodes[parent.childNodes.indexOf(reference) - 1]?.nodeName !== '#text') account();
      defaultTreeAdapter.insertTextBefore(parent, text, reference);
    },
    onItemPush() {
      if (++depth > MAX_HTML_DEPTH) throw new SourceError('HTML structure exceeds the depth limit.');
    },
    onItemPop() {
      depth--;
    },
  };
  // parse5 builds an inert tree: it does not execute scripts or fetch resources.
  return document
    ? parse(html, { sourceCodeLocationInfo: true, scriptingEnabled: true, treeAdapter })
    : parseFragment(html, { scriptingEnabled: true, treeAdapter });
}
function* visibleHtmlNodes(root: HtmlNode): Generator<HtmlNode> {
  const pending: { node: HtmlNode; depth: number }[] = [{ node: root, depth: 0 }];
  let visited = 0;
  while (pending.length) {
    const { node, depth } = pending.pop()!;
    if (++visited > MAX_HTML_NODES || depth > MAX_HTML_DEPTH)
      throw new SourceError('HTML structure exceeds the traversal limit.');
    if (
      node.nodeName === '#comment' ||
      ('tagName' in node && HIDDEN_HTML_ELEMENTS.has(node.tagName.toLowerCase()))
    )
      continue;
    yield node;
    if ('childNodes' in node) {
      if (visited + pending.length + node.childNodes.length > MAX_HTML_NODES)
        throw new SourceError('HTML structure exceeds the traversal limit.');
      for (let index = node.childNodes.length - 1; index >= 0; index--)
        pending.push({ node: node.childNodes[index]!, depth: depth + 1 });
    }
  }
}
function htmlText(root: HtmlNode, limit = 16_000): string {
  const parts: string[] = [];
  for (const node of visibleHtmlNodes(root)) if ('value' in node) parts.push(node.value);
  // Entity references have already been decoded once by the HTML parser.
  return cleanText(parts.join(' ').replace(/\s+/g, ' ').trim(), limit);
}
/**
 * A feed value read as plain text. Only for values parsed by `feed()`, which leaves entity
 * references alone (`processEntities: false`), so the HTML parser decodes them once.
 *
 * With `html`, the field carries HTML (RSS `description` and `content:encoded`, Atom `content` and
 * `summary` with `type="html"`). A publisher may escape that HTML with entities (`&lt;p&gt;`)
 * instead of wrapping it in CDATA; escaped XML text can never hold a raw `<`, so a value without
 * one is unescaped once as XML before it is read as HTML. Plain-text fields (titles, Atom text
 * content) are read as before: `&lt;script&gt;` in a title is text, not a tag.
 */
function plainText(value: unknown, limit = 16_000, html = false): string {
  const raw = xmlText(value);
  return htmlText(parseHtml(html && !raw.includes('<') ? xmlUnescape(raw) : raw), limit);
}
/** Whether a feed field carries HTML: its `type` attribute when it has one (Atom), else the default. */
function htmlField(value: unknown, otherwise: boolean): boolean {
  const type =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as RecordValue)['@_type']
      : undefined;
  return typeof type === 'string' ? type.toLowerCase() === 'html' : otherwise;
}
/** The five predefined XML entities and character references; nothing that a DTD could declare. */
function xmlUnescape(value: string): string {
  return value.replace(
    /&(?:(lt|gt|amp|quot|apos)|#(\d{1,7})|#x([\da-f]{1,6}));/gi,
    (match, name: string | undefined, decimal: string | undefined, hex: string | undefined) => {
      if (name) return { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" }[name.toLowerCase()]!;
      const point = decimal ? Number(decimal) : Number.parseInt(hex!, 16);
      return point > 0 && point <= 0x10ffff && (point < 0xd800 || point > 0xdfff)
        ? String.fromCodePoint(point)
        : match;
    },
  );
}
function list(value: unknown): unknown[] {
  return value === undefined ? [] : Array.isArray(value) ? value : [value];
}
function feedDate(value: unknown): string | undefined {
  const input = xmlText(value);
  return input && Number.isFinite(Date.parse(input)) ? timestamp(Date.parse(input)) : undefined;
}
interface NewsWindow {
  cutoff: number;
  /** Every entry the feed listed at the last poll. Absent on a first run or after an upgrade. */
  listed?: Set<string>;
  lateCutoff: number;
  tracked: Set<string>;
  previous: Map<string, Evidence>;
}
interface FeedResult {
  evidence: Evidence[];
  undated: Set<string>;
  /** Every entry the feed lists now, whether or not it was collected. */
  listed: string[];
  failure?: string;
}
function listedEntries(value: string | undefined): Set<string> | undefined {
  if (value === undefined) return undefined;
  try {
    const ids: unknown = JSON.parse(value);
    if (Array.isArray(ids) && ids.every((id) => typeof id === 'string')) return new Set(ids as string[]);
  } catch {
    /* An unreadable memory behaves like a first run. */
  }
  return undefined;
}
function newsWindow(
  source: string,
  checkpoint: string | undefined,
  listed: string | undefined,
  lookbackMinutes: number,
  previous: Evidence[],
  inventory: Inventory,
  now: number,
): NewsWindow {
  const lookback = lookbackMinutes * 60_000;
  const last = checkpoint === undefined ? now : Date.parse(checkpoint);
  if (!Number.isFinite(last) || last > now)
    throw new SourceError('Invalid news checkpoint; reset it before collecting.');
  return {
    // Revisit a small checkpoint overlap after an outage, even when the normal window is shorter.
    cutoff: Math.max(0, Math.min(now - lookback, last - Math.min(5 * 60_000, lookback))),
    ...(checkpoint === undefined ? {} : { listed: listedEntries(listed) }),
    lateCutoff: Math.max(0, last - LATE_ENTRY_DAYS * 24 * HOUR),
    tracked: new Set(
      previous
        .filter((item) => item.source === source && item.kind === 'news' && evidenceRelevant(item, inventory))
        .map((item) => item.id),
    ),
    previous: new Map(previous.filter((item) => item.source === source).map((item) => [item.id, item])),
  };
}
function stabilizeUndated(result: FeedResult, previous: Map<string, Evidence>): void {
  const content = (item: Evidence) =>
    hash([
      item.title,
      item.url,
      item.description,
      item.aliases,
      item.severity,
      item.published_at,
      item.content_status,
    ]);
  for (const item of result.evidence) {
    const old = previous.get(item.id);
    if (result.undated.has(item.id) && old && content(old) === content(item))
      item.modified_at = old.modified_at;
  }
}
async function feed(
  url: string,
  source: string,
  http: HttpClient,
  now: number,
  window: NewsWindow,
  entryLimit = MAX_FEED_ENTRIES,
): Promise<FeedResult> {
  const response = await http(url, { maxBytes: 2_000_000 });
  if (response.status !== 200) throw new SourceError(`Source returned HTTP ${response.status}.`);
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(response.body))
    throw new SourceError('Feed DTDs and entity declarations are not allowed.');
  if (XMLValidator.validate(response.body) !== true) throw new SourceError('Feed returned invalid XML.');
  let parsed: RecordValue;
  try {
    parsed = record(
      new XMLParser({
        ignoreAttributes: false,
        processEntities: false,
        parseTagValue: false,
        parseAttributeValue: false,
        removeNSPrefix: true,
      }).parse(response.body),
    );
  } catch {
    throw new SourceError('Feed returned invalid XML.');
  }
  let entries: unknown[];
  if (parsed.rss !== undefined) entries = list(record(record(parsed.rss).channel).item);
  else if (parsed.feed !== undefined) entries = list(record(parsed.feed).entry);
  else throw new SourceError('Unsupported feed format; RSS 2.0 or Atom is required.');
  if (entries.length > entryLimit)
    throw new SourceError('Feed entry limit reached; collection is incomplete.');
  const fallback = new URL(url);
  fallback.username = '';
  fallback.password = '';
  fallback.search = '';
  fallback.hash = '';
  const results = new Map<string, Evidence>();
  const undated = new Set<string>();
  const listed: string[] = [];
  const invalid = new SourceItemFailures();
  for (const rawEntry of entries) {
    const parsed = invalid.read(() => {
      const entry = record(rawEntry);
      const title = plainText(entry.title, 500);
      if (!title) throw new SourceError('Feed entry is missing its title.');
      // The first field that holds text. An element can be present and empty: `<media:content>`
      // (an image, read as `content` once namespace prefixes are removed) beside the article in
      // `<description>`, or an empty `<content:encoded>`.
      let description = '';
      for (const [field, html] of [
        [entry.encoded, true],
        [entry.content, htmlField(entry.content, false)],
        [entry.description, true],
        [entry.summary, htmlField(entry.summary, false)],
      ] as const) {
        description = plainText(field, 16_000, html);
        if (description) break;
      }
      const links = list(entry.link);
      const selectedLink = links.find(
        (link) => typeof link === 'string' || !record(link)['@_rel'] || record(link)['@_rel'] === 'alternate',
      );
      const rawLink =
        typeof selectedLink === 'object' && selectedLink !== null
          ? (record(selectedLink)['@_href'] ?? xmlText(selectedLink))
          : selectedLink;
      const link = publicUrl(rawLink, fallback.href);
      const externalId = xmlText(entry.id ?? entry.guid).trim() || (link !== fallback.href ? link : '');
      if (!externalId) throw new SourceError('Feed entry is missing a stable ID or link.');
      const published = feedDate(entry.published ?? entry.pubDate);
      const sourceModified = feedDate(entry.updated) ?? published;
      if ([sourceModified, published].some((value) => value && Date.parse(value) > now + 5 * 60_000))
        throw new SourceError('Feed returned a future timestamp; collection is incomplete.');
      const modified = sourceModified ?? timestamp(now);
      const id = `${source}:entry:${hash(externalId).slice(0, 32)}`;
      listed.push(id);
      if (sourceModified && Date.parse(sourceModified) < window.cutoff && !window.tracked.has(id)) {
        // A feed can list an entry after the time it is stamped with (publication lag, or a date
        // without a time). An entry that was not listed at the last poll is new to this monitor,
        // whatever its stamp says; one that was listed and left out stays out.
        const late =
          window.listed !== undefined &&
          !window.listed.has(id) &&
          !window.previous.has(id) &&
          Date.parse(sourceModified) >= window.lateCutoff;
        if (!late) return undefined;
      }
      const evidence: Evidence = {
        id,
        source,
        kind: 'news',
        title,
        url: link,
        description,
        aliases: citedIdentifiers(`${title}\n${description}\n${link}`),
        severity: severity(xmlText(entry.severity)),
        modified_at: modified,
        fetched_at: timestamp(now),
        ...(published ? { published_at: published } : {}),
        packages: [],
        content_status: description ? 'excerpt' : 'unavailable',
      };
      return { evidence, dated: Boolean(sourceModified) };
    });
    if (!parsed) continue;
    const { evidence, dated } = parsed;
    const id = evidence.id;
    const modified = evidence.modified_at;
    const old = results.get(id);
    if (!old || Date.parse(modified) >= Date.parse(old.modified_at)) {
      results.set(id, evidence);
      if (dated) undated.delete(id);
      else undated.add(id);
    }
  }
  return { evidence: [...results.values()], undated, listed, failure: invalid.message('Feed') };
}

function hackerNewsUrl(value: string): string | undefined {
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'https:' ||
      url.username ||
      url.password ||
      url.port ||
      !['thehackernews.com', 'www.thehackernews.com'].includes(url.hostname) ||
      !/^\/\d{4}\/\d{2}\/[^/]+\.html$/.test(url.pathname)
    )
      return undefined;
    url.hash = '';
    url.search = '';
    return url.href;
  } catch {
    return undefined;
  }
}

/** Extract only the marked article body, never navigation/related-story text.
 * Missing or malformed wrappers leave the feed excerpt explicitly incomplete. */
function articleBody(html: string): DefaultTreeAdapterTypes.Element | undefined {
  for (const node of visibleHtmlNodes(parseHtml(html, true))) {
    if (
      !('tagName' in node) ||
      node.namespaceURI !== 'http://www.w3.org/1999/xhtml' ||
      !['div', 'article', 'section'].includes(node.tagName)
    )
      continue;
    const attributes = new Map(node.attrs.map(({ name, value }) => [name, value]));
    if (
      !(attributes.get('itemprop') ?? '').split(/\s+/).includes('articleBody') &&
      !(attributes.get('class') ?? '')
        .split(/\s+/)
        .some((value) => ['articlebody', 'post-body'].includes(value))
    )
      continue;
    // Parser recovery can create or implicitly close nodes. Only an explicit
    // source wrapper establishes that the complete article body was received.
    return node.sourceCodeLocation?.startTag && node.sourceCodeLocation.endTag ? node : undefined;
  }
  return undefined;
}

async function hackerNews(http: HttpClient, now: number, window: NewsWindow): Promise<FeedResult> {
  const result = await feed(HACKER_NEWS, 'hacker_news', http, now, window);
  const entries = result.evidence;
  // RSS is a finite current window. Articles outside the fetch budget remain
  // visible as excerpts; models cannot use them as complete dismissal evidence.
  for (let offset = 0; offset < Math.min(entries.length, 50); offset += 4)
    await Promise.all(
      entries.slice(offset, Math.min(offset + 4, 50)).map(async (entry) => {
        const url = hackerNewsUrl(entry.url);
        if (!url) return;
        try {
          const response = await http(url, {
            maxBytes: 2_000_000,
            redirects: 3,
            allowedRedirectOrigins: ['https://thehackernews.com', 'https://www.thehackernews.com'],
          });
          if (response.status !== 200) return;
          const body = articleBody(response.body);
          if (!body) return;
          const full = htmlText(body, 16_001);
          if (!full || full.length < entry.description.length) return;
          entry.description = full.slice(0, 16_000);
          entry.content_status = full.length <= 16_000 ? 'full' : 'excerpt';
          entry.url = url;
          entry.aliases = citedIdentifiers(`${entry.title}\n${entry.description}`);
        } catch (error) {
          if (sourceCanceled(error)) throw error;
          // Fetch/parse failures must not erase the headline and feed excerpt.
          // No transport exception text is persisted or exposed to model prompts.
        }
      }),
    );
  stabilizeUndated(result, window.previous);
  return result;
}

async function vendorFeed(
  vendor: VendorFeed,
  http: HttpClient,
  now: number,
  window: NewsWindow,
): Promise<FeedResult> {
  const profile = VENDOR_FEEDS[vendor];
  // PHP's feed includes years of release history.
  // Keep its larger item allowance separate from generic feeds and the shared 2 MB cap.
  const result = await feed(
    profile.feed,
    `vendor:${vendor}`,
    http,
    now,
    window,
    vendor === 'php' ? 2000 : MAX_FEED_ENTRIES,
  );
  const entries = result.evidence.slice(0, 20);
  for (let offset = 0; offset < entries.length; offset += 4)
    await Promise.all(
      entries.slice(offset, offset + 4).map(async (entry) => {
        const target = vendorArticleTarget(vendor, entry.url);
        if (!target) return;
        try {
          const response = await http(target.url, {
            maxBytes: MAX_HTML_BYTES,
            timeoutMs: 15_000,
            minIntervalMs: 500,
            redirects: 3,
            allowedRedirectOrigins: [profile.origin],
            headers: { accept: 'text/html' },
          });
          if (response.status !== 200) return;
          const body = vendorArticleBody(
            vendor,
            visibleHtmlNodes(parseHtml(response.body, true)),
            target.anchor,
          );
          if (!body) return;
          const text = htmlText(body, 16_001);
          const normalize = (value: string) => value.replace(/\s+/g, ' ').trim().toLowerCase();
          // A complete wrapper on an unrelated redirect/error page is not the requested article.
          const visible = normalize(text);
          const title = normalize(entry.title);
          if (!visible.includes(title) || visible.replaceAll(title, '').trim().length < 40) return;
          entry.description = text.slice(0, 16_000);
          entry.content_status = text.length <= 16_000 ? 'full' : 'excerpt';
          entry.aliases = citedIdentifiers(`${entry.title}\n${entry.description}`);
        } catch (error) {
          if (sourceCanceled(error)) throw error;
          // Keep the validated feed excerpt when the vendor page cannot be read safely.
        }
      }),
    );
  stabilizeUndated(result, window.previous);
  return result;
}

/** Collect source evidence and report failures without advancing failed sources' checkpoints. */
export async function collectSources(
  inventory: Inventory,
  config: Config,
  checkpoints: Record<string, string>,
  http: HttpClient,
  now = Date.now(),
  previousEvidence: Evidence[] = [],
  previousCoverage: CoverageReceipt[] = [],
): Promise<SourceResult> {
  const result: SourceResult = { evidence: [], errors: [], checkpoints: { ...checkpoints }, coverage: [] };
  const jobs: { source: string; run: () => Promise<Evidence[] | FeedResult> }[] = [];
  const githubUnreadable: Record<
    'reviewed' | 'malware',
    {
      pending?: string;
      skipped?: string;
      nextPending?: string;
      nextSkipped?: string;
      unconfirmed?: string;
      nextUnconfirmed?: string;
    }
  > = {
    reviewed: {},
    malware: {},
  };
  const window = (source: string) =>
    newsWindow(
      source,
      checkpoints[source],
      checkpoints[`${source}:listed`],
      config.news_lookback_minutes ?? 60,
      previousEvidence,
      inventory,
      now,
    );
  if (config.sources.hacker_news)
    jobs.push({ source: 'hacker_news', run: () => hackerNews(http, now, window('hacker_news')) });
  if (config.sources.osv)
    jobs.push({ source: 'osv', run: () => osv(inventory, previousEvidence, http, now) });
  if (config.sources.github)
    for (const type of ['reviewed', 'malware'] as const) {
      githubUnreadable[type].pending = checkpoints[`github:${type}:unreadable`];
      githubUnreadable[type].skipped = checkpoints[`github:${type}:skipped`];
      githubUnreadable[type].unconfirmed = checkpoints[`github:${type}:unconfirmed`];
      jobs.push({
        source: `github:${type}`,
        run: () =>
          github(
            type,
            checkpoints[`github:${type}`],
            config,
            http,
            now,
            inventory,
            previousEvidence,
            checkpoints[`github:${type}:since`],
            githubUnreadable[type],
          ),
      });
    }
  if (config.sources.kev) jobs.push({ source: 'kev', run: () => kev(http, now, previousEvidence) });
  for (const vendor of new Set(config.sources.vendor_feeds ?? [])) {
    const source = `vendor:${vendor}`;
    jobs.push({ source, run: () => vendorFeed(vendor, http, now, window(source)) });
  }
  for (const url of new Set(config.sources.feeds)) {
    const source = `feed:${hash(url).slice(0, 16)}`;
    jobs.push({
      source,
      run: async () => {
        const current = window(source);
        const result = await feed(url, source, http, now, current);
        stabilizeUndated(result, current.previous);
        return result;
      },
    });
  }
  const cveNowState: CveNowState = {
    missing: checkpoints['cve_now:missing'],
    troubled: checkpoints['cve_now:troubled'],
    owed: checkpoints['cve_now:owed'],
    lookups: checkpoints['cve_now:lookups'],
    refusedSince: Number(checkpoints['cve_now:refused_since']) || undefined,
  };
  if (config.sources.cve_now)
    jobs.push({
      source: 'cve_now',
      run: () =>
        collectCveNow(
          inventory,
          checkpoints.cve_now,
          previousEvidence,
          result.evidence,
          http,
          now,
          cveNowState,
        ),
    });
  for (const job of jobs) {
    const errorStart = result.errors.length;
    let collected: Evidence[] | FeedResult = [];
    let failure: unknown;
    let incomplete = false;
    let packageResults: 'complete' | undefined;
    try {
      collected = await job.run();
      if (!Array.isArray(collected) && collected.failure) {
        failure = new SourceError(collected.failure);
        incomplete = true;
      }
    } catch (error) {
      if (sourceCanceled(error)) throw error;
      failure = error;
      incomplete = true;
      if (error instanceof PartialSourceError) {
        collected = error.evidence;
        // An ordered source that ran out of room continues from the last record it processed.
        if (error.resume) {
          result.checkpoints[job.source] = error.resume;
          // A GitHub catch-up goes on next time; remember where its chain of scans began.
          if (job.source.startsWith('github:'))
            result.checkpoints[`${job.source}:since`] = timestamp(
              githubWindow(checkpoints[job.source], checkpoints[`${job.source}:since`], now).chainStart,
            );
        }
        packageResults = error.packageResults;
      }
    }
    // Identifiers cve.now did not have, and when each was last asked for.
    if (job.source === 'cve_now' && cveNowState.next !== undefined)
      result.checkpoints['cve_now:missing'] = cveNowState.next;
    // Identifiers whose requests failed, so that the next poll asks for them last.
    if (job.source === 'cve_now' && cveNowState.nextTroubled !== undefined)
      result.checkpoints['cve_now:troubled'] = cveNowState.nextTroubled;
    // New records still to be read, so that the checkpoint can move on without them.
    if (job.source === 'cve_now' && cveNowState.nextOwed !== undefined)
      result.checkpoints['cve_now:owed'] = cveNowState.nextOwed;
    if (job.source === 'cve_now' && cveNowState.nextLookups !== undefined)
      result.checkpoints['cve_now:lookups'] = cveNowState.nextLookups;
    if (job.source === 'github:reviewed' || job.source === 'github:malware') {
      const state = githubUnreadable[job.source === 'github:reviewed' ? 'reviewed' : 'malware'];
      if (state.nextPending !== undefined) result.checkpoints[`${job.source}:unreadable`] = state.nextPending;
      if (state.nextSkipped !== undefined) result.checkpoints[`${job.source}:skipped`] = state.nextSkipped;
      if (state.nextUnconfirmed !== undefined)
        result.checkpoints[`${job.source}:unconfirmed`] = state.nextUnconfirmed;
    }
    if (job.source === 'cve_now' && cveNowState.nextRefusedSince !== undefined)
      result.checkpoints['cve_now:refused_since'] = String(cveNowState.nextRefusedSince ?? '');
    const evidence = (Array.isArray(collected) ? collected : collected.evidence).filter((item) => {
      const modified = Date.parse(item.modified_at);
      if (Number.isFinite(modified) && modified <= now + 5 * 60_000) return true;
      failure ??= new SourceError(
        'Source returned an invalid or future modification timestamp; collection is incomplete.',
      );
      incomplete = true;
      // The record left out here may be one for an inventory package.
      packageResults = undefined;
      return false;
    });
    result.evidence.push(...evidence);
    if (!incomplete) {
      result.checkpoints[job.source] = timestamp(now);
      if (job.source.startsWith('github:')) result.checkpoints[`${job.source}:since`] = '';
    }
    // Remember what the feed listed, so the next poll can tell a late arrival from an old entry.
    if (!Array.isArray(collected) && !incomplete)
      result.checkpoints[`${job.source}:listed`] = JSON.stringify(collected.listed.slice(0, 2_000));
    if (!Array.isArray(collected) && collected.undated.size)
      result.errors.push({
        source: `${job.source}:timestamps`,
        message: `${collected.undated.size} news item(s) have no valid publication or update time; included as first-seen evidence because their age cannot be verified.`,
      });
    if (job.source === 'hacker_news') {
      const missing = evidence.filter(
        (item) => item.content_status !== 'full' && evidenceRelevant(item, inventory),
      ).length;
      if (missing)
        result.errors.push({
          source: 'hacker_news:articles',
          message: `${missing} relevant The Hacker News article(s) could not be read in full; excerpts remain available for cautious review.`,
        });
    }
    if (job.source.startsWith('vendor:')) {
      const missing = evidence.filter(
        (item) => item.content_status !== 'full' && evidenceRelevant(item, inventory),
      ).length;
      if (missing)
        result.errors.push({
          source: `${job.source}:articles`,
          message: `${missing} relevant vendor article(s) could not be read in full; excerpts remain available for cautious review.`,
        });
    }
    if (incomplete)
      result.errors.push({
        source: job.source,
        // Transport errors can contain feed tokens or HTTP headers.
        message:
          failure instanceof SourceError
            ? failure.message
            : 'Source request failed; cached evidence was retained and its checkpoint was not advanced.',
      });
    const errors = result.errors.slice(errorStart).map((error) => error.message);
    const complete = !incomplete && errors.length === 0;
    const previousReceipt = previousCoverage.find((receipt) => receipt.source === job.source);
    const lastSuccess = complete
      ? timestamp(now)
      : previousReceipt
        ? previousReceipt.last_success_at
        : checkpoints[job.source];
    const successTime = lastSuccess ? Date.parse(lastSuccess) : NaN;
    result.coverage.push({
      source: job.source,
      attempted_at: timestamp(now),
      ...(lastSuccess ? { last_success_at: lastSuccess } : {}),
      ...(Number.isFinite(successTime)
        ? {
            fresh_until: timestamp(
              successTime + Math.max(120_000, (config.poll_interval_minutes ?? 30) * 120_000),
            ),
          }
        : {}),
      status: complete ? 'complete' : evidence.length ? 'partial' : 'failed',
      ...(!complete && packageResults ? { package_results: packageResults } : {}),
      freshness: !Number.isFinite(successTime)
        ? 'never'
        : successTime <= now + 300_000 &&
            now - successTime <= Math.max(120_000, (config.poll_interval_minutes ?? 30) * 120_000)
          ? 'fresh'
          : 'stale',
      evidence_count: evidence.length,
      errors,
      scope:
        job.source === 'osv'
          ? 'Configured package identities/versions and tracked advisories; no absence-of-vulnerability guarantee.'
          : job.source === 'cve_now'
            ? 'Recent, tracked and news-cited CVEs plus exact npm queries; not exhaustive historical coverage.'
            : 'Configured bounded feed/advisory collection; not exhaustive vulnerability coverage.',
    });
  }
  return result;
}
