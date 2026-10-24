import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { defaultTreeAdapter, parse, parseFragment, type DefaultTreeAdapterTypes } from 'parse5';
import { compare, valid } from 'semver';
import type {
  Config,
  Evidence,
  HttpClient,
  Inventory,
  PackageClaim,
  Severity,
  SourceResult,
} from './types.js';
import { cleanText, hash, highest, timestamp } from './util.js';
import { collectCveNow, evidenceRelevant } from './cve-now.js';
import { PartialSourceError, SourceError } from './source-error.js';

const OSV = 'https://api.osv.dev/v1';
const GITHUB = 'https://api.github.com/advisories';
const KEV = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
const HACKER_NEWS = 'https://feeds.feedburner.com/TheHackersNews';
const MAX_PAGES = 50;
const MAX_ADVISORIES = 5_000;
const MAX_FEED_ENTRIES = 500;
const HOUR = 3_600_000;
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
  if (response.status !== 200) throw new SourceError(`Source returned HTTP ${response.status}.`);
  try {
    return JSON.parse(response.body);
  } catch {
    throw new SourceError('Source returned invalid JSON.');
  }
}

interface OsvQuery {
  name: string;
  version: string;
  page_token?: string;
  seen: Set<string>;
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
  const severities: Severity[] = [severity(optionalRecord(data.database_specific).severity)];
  for (const rawSeverity of array(data.severity, true))
    severities.push(vectorSeverity(record(rawSeverity).score));
  for (const rawAffected of array(data.affected, true)) {
    const affected = record(rawAffected);
    const pkg = record(affected.package);
    const ecosystem = string(pkg.ecosystem);
    const name = string(pkg.name);
    const range = osvRanges(affected.ranges);
    const versions = array(affected.versions, true).map(string);
    const matched_versions = [
      ...new Set(
        matches.filter((query) => ecosystem === 'npm' && query.name === name).map((query) => query.version),
      ),
    ];
    const fixed = array(affected.ranges, true)
      .flatMap((rawRange) => array(record(rawRange).events, true))
      .map((rawEvent) => optionalString(record(rawEvent).fixed))
      .filter((v): v is string => !!v);
    packageClaims.push({
      ecosystem,
      name,
      ...(range ? { range } : {}),
      ...(versions.length ? { versions } : {}),
      ...(matched_versions.length ? { matched_versions } : {}),
      ...(fixed.length ? { fixed: [...new Set(fixed)].join(', ') } : {}),
    });
    severities.push(severity(optionalRecord(affected.database_specific).severity));
    for (const rawSeverity of array(affected.severity, true))
      severities.push(vectorSeverity(record(rawSeverity).score));
  }
  // A query match is independent positive evidence, even if upstream omits an affected entry.
  for (const name of new Set(matches.map((query) => query.name)))
    if (!packageClaims.some((p) => p.ecosystem === 'npm' && p.name === name))
      packageClaims.push({
        ecosystem: 'npm',
        name,
        matched_versions: [
          ...new Set(matches.filter((query) => query.name === name).map((query) => query.version)),
        ],
      });
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
    for (const component of system.components)
      if (component.ecosystem === 'npm' && component.version) {
        const key = JSON.stringify([component.name, component.version]);
        unique.set(key, { name: component.name, version: component.version, seen: new Set() });
      }
  const queries = [...unique.values()];
  if (queries.length > 10_000)
    throw new SourceError('OSV inventory exceeds the 10,000 unique package-version limit.');
  const matched = new Map<string, OsvQuery[]>();
  for (let offset = 0; offset < queries.length; offset += 100) {
    let pending = queries.slice(offset, offset + 100);
    for (let page = 0; pending.length; page++) {
      if (page >= MAX_PAGES) throw new SourceError('OSV pagination limit reached; collection is incomplete.');
      const body = JSON.stringify({
        queries: pending.map((query) => ({
          package: { ecosystem: 'npm', name: query.name },
          version: query.version,
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
        const result = record(results[index]);
        const query = pending[index]!;
        for (const rawVuln of array(result.vulns, true)) {
          const vuln = record(rawVuln);
          const id = string(vuln.id);
          if (vuln.modified !== undefined) date(vuln.modified);
          if (!matched.has(id)) matched.set(id, []);
          if (!matched.get(id)!.some((match) => match.name === query.name && match.version === query.version))
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
  for (const item of previous)
    if (item.source === 'osv' && item.id.startsWith('osv:')) ids.add(item.id.slice(4));
  if (ids.size > MAX_ADVISORIES)
    throw new SourceError('OSV historical advisory limit reached; collection is incomplete.');
  const results: Evidence[] = [];
  // Bounded parallelism; historical IDs are refreshed even when they disappear from exact-version queries.
  const allIds = [...ids];
  for (let index = 0; index < allIds.length; index += 4) {
    const part = await Promise.all(
      allIds
        .slice(index, index + 4)
        .map(async (id) =>
          osvRecord(
            await json(http, `${OSV}/vulns/${encodeURIComponent(id)}`),
            id,
            matched.get(id) ?? [],
            now,
          ),
        ),
    );
    results.push(...part);
  }
  return results;
}

function githubRecord(raw: unknown, type: 'reviewed' | 'malware', now: number): Evidence {
  const data = record(raw);
  const id = string(data.ghsa_id);
  if (!/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i.test(id))
    throw new SourceError('Invalid GitHub advisory identifier.');
  if (data.type !== undefined && data.type !== type)
    throw new SourceError('GitHub returned an unexpected advisory type.');
  const packages = array(data.vulnerabilities).map((rawVulnerability) => {
    const vulnerability = record(rawVulnerability);
    const pkg = record(vulnerability.package);
    const range = optionalString(vulnerability.vulnerable_version_range);
    const patched = vulnerability.first_patched_version;
    const fixed =
      typeof patched === 'object' && patched !== null
        ? optionalString(record(patched).identifier)
        : optionalString(patched);
    return {
      ecosystem: string(pkg.ecosystem),
      name: string(pkg.name),
      ...(range ? { range } : {}),
      ...(fixed ? { fixed } : {}),
    };
  });
  const cvss = optionalRecord(data.cvss);
  const cvssVersions = optionalRecord(data.cvss_severities);
  const ratings = [severity(data.severity), scoreSeverity(cvss.score), vectorSeverity(cvss.vector_string)];
  for (const value of Object.values(cvssVersions))
    if (value) ratings.push(scoreSeverity(record(value).score));
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
    modified_at: date(data.updated_at),
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
async function github(
  type: 'reviewed' | 'malware',
  checkpoint: string | undefined,
  config: Config,
  http: HttpClient,
  now: number,
): Promise<Evidence[]> {
  const previous = checkpoint === undefined ? now - 7 * 24 * HOUR : Date.parse(checkpoint);
  if (!Number.isFinite(previous) || previous > now)
    throw new SourceError('Invalid source checkpoint; reset it before collecting.');
  const start = Math.max(0, previous - HOUR);
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
  for (let page = 0; next; page++) {
    if (page >= MAX_PAGES)
      throw new SourceError('GitHub pagination limit reached; collection is incomplete.');
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
      const parsed = githubRecord(item, type, now);
      retainNewest(evidence, parsed);
    }
    const link = Object.entries(response.headers).find(([key]) => key.toLowerCase() === 'link')?.[1];
    next = nextGithubLink(link);
  }
  return [...evidence.values()];
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
  return entries.map((raw) => {
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
function plainText(value: unknown, limit = 16_000): string {
  return htmlText(parseHtml(xmlText(value)), limit);
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
  tracked: Set<string>;
  previous: Map<string, Evidence>;
}
interface FeedResult {
  evidence: Evidence[];
  undated: Set<string>;
}
function newsWindow(
  source: string,
  checkpoint: string | undefined,
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
  if (entries.length > MAX_FEED_ENTRIES)
    throw new SourceError('Feed entry limit reached; collection is incomplete.');
  const fallback = new URL(url);
  fallback.username = '';
  fallback.password = '';
  fallback.search = '';
  fallback.hash = '';
  const results = new Map<string, Evidence>();
  const undated = new Set<string>();
  for (const rawEntry of entries) {
    const entry = record(rawEntry);
    const title = plainText(entry.title, 500);
    if (!title) throw new SourceError('Feed entry is missing its title.');
    const description = plainText(entry.encoded ?? entry.content ?? entry.description ?? entry.summary ?? '');
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
    if (sourceModified && Date.parse(sourceModified) < window.cutoff && !window.tracked.has(id)) continue;
    const foundAliases =
      `${title}\n${description}\n${link}`.match(
        /\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4})\b/gi,
      ) ?? [];
    const evidence: Evidence = {
      id,
      source,
      kind: 'news',
      title,
      url: link,
      description,
      aliases: aliases(foundAliases),
      severity: severity(xmlText(entry.severity)),
      modified_at: modified,
      fetched_at: timestamp(now),
      ...(published ? { published_at: published } : {}),
      packages: [],
      content_status: description ? 'excerpt' : 'unavailable',
    };
    const old = results.get(id);
    if (!old || Date.parse(modified) >= Date.parse(old.modified_at)) {
      results.set(id, evidence);
      if (sourceModified) undated.delete(id);
      else undated.add(id);
    }
  }
  return { evidence: [...results.values()], undated };
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
          entry.aliases = aliases(
            `${entry.title}\n${entry.description}`.match(
              /\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4})\b/gi,
            ) ?? [],
          );
        } catch {
          // Fetch/parse failures must not erase the headline and feed excerpt.
          // No transport exception text is persisted or exposed to model prompts.
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
): Promise<SourceResult> {
  const result: SourceResult = { evidence: [], errors: [], checkpoints: { ...checkpoints } };
  const jobs: { source: string; run: () => Promise<Evidence[] | FeedResult> }[] = [];
  const window = (source: string) =>
    newsWindow(
      source,
      checkpoints[source],
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
    for (const type of ['reviewed', 'malware'] as const)
      jobs.push({
        source: `github:${type}`,
        run: () => github(type, checkpoints[`github:${type}`], config, http, now),
      });
  if (config.sources.kev) jobs.push({ source: 'kev', run: () => kev(http, now, previousEvidence) });
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
  if (config.sources.cve_now)
    jobs.push({
      source: 'cve_now',
      run: () => collectCveNow(inventory, checkpoints.cve_now, previousEvidence, result.evidence, http, now),
    });
  for (const job of jobs) {
    try {
      const collected = await job.run();
      const evidence = Array.isArray(collected) ? collected : collected.evidence;
      if (evidence.some((item) => Date.parse(item.modified_at) > now + 5 * 60_000))
        throw new SourceError('Source returned a future modification timestamp; collection is incomplete.');
      result.evidence.push(...evidence);
      result.checkpoints[job.source] = timestamp(now);
      if (!Array.isArray(collected) && collected.undated.size)
        result.errors.push({
          source: `${job.source}:timestamps`,
          message: `${collected.undated.size} news item(s) have no valid publication or update time; included as first-seen evidence because their age cannot be verified.`,
        });
      if (job.source === 'hacker_news') {
        const incomplete = evidence.filter(
          (item) => item.content_status !== 'full' && evidenceRelevant(item, inventory),
        ).length;
        if (incomplete)
          result.errors.push({
            source: 'hacker_news:articles',
            message: `${incomplete} relevant The Hacker News article(s) could not be read in full; excerpts remain available for cautious review.`,
          });
      }
    } catch (error) {
      if (error instanceof PartialSourceError) result.evidence.push(...error.evidence);
      // Never expose exception text from transports/parsers: it can contain feed tokens or HTTP headers.
      result.errors.push({
        source: job.source,
        message:
          error instanceof SourceError
            ? error.message
            : 'Source request failed; cached evidence was retained and its checkpoint was not advanced.',
      });
    }
  }
  return result;
}
