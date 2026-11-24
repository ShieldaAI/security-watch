import type { AdvisoryReference, Evidence, FixCommit, ReferenceType } from './types.js';

/**
 * What an advisory publishes beyond its text that helps someone write a fix or a temporary runtime
 * shield: typed links, the commits that fixed it, weakness (CWE) identifiers and public exploit code.
 *
 * These parsers never throw. A malformed link is dropped; it must never cost the advisory itself.
 * The fields are kept out of the evidence content hash and the analysis basis (see `evidenceContent`),
 * so an upgrade that starts reading them neither records new evidence revisions nor asks a model again,
 * and they are never sent to a model.
 */

export const MAX_REFERENCES = 40;
export const MAX_FIX_COMMITS = 20;
export const MAX_WEAKNESSES = 20;
const MAX_URL = 2_048;

/** Evidence without its fetch time and without the shield inputs: what revisions and analysis compare. */
export function evidenceContent(
  evidence: Evidence,
): Omit<Evidence, 'fetched_at' | 'references' | 'fix_commits' | 'weaknesses' | 'exploit_sources'> {
  const {
    fetched_at: _fetched,
    references: _references,
    fix_commits: _commits,
    weaknesses: _weaknesses,
    exploit_sources: _exploits,
    ...content
  } = evidence;
  return content;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/** Names that only resolve inside a network: never a public advisory link. */
const PRIVATE_NAME =
  /(?:^|\.)(?:localhost|localdomain|local|internal|intranet|lan|home|corp|private|test|invalid|example|arpa)$/i;
/** Names that resolve to the address written inside them (10.0.0.1.nip.io), or to this machine. */
const ADDRESS_NAME =
  /(?:^|[.-])(?:\d{1,3}[.-]){3}\d{1,3}(?:[.-]|$)|(?:^|\.)(?:nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me)$/i;

/**
 * An https URL to a public name, without credentials, of bounded length, or nothing. These links are
 * handed to people and agents that may open them, so an address inside a network (an IP literal in any
 * notation, a private name) is dropped, and so is a value with whitespace or control characters
 * inside it, which a URL parser would silently remove, keeping a different address.
 */
export function safeHttpsUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value || value.length > MAX_URL) return undefined;
  const text = value.trim();
  if (/[\s\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(text)) return undefined;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return undefined;
  }
  // The parser normalises 0x7f.1, 2130706433 and [::1] to literal addresses; a trailing dot is dropped.
  const host = url.hostname.replace(/\.$/, '');
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    !host.includes('.') ||
    host.startsWith('[') ||
    /^[\d.]+$/.test(host) ||
    PRIVATE_NAME.test(host) ||
    ADDRESS_NAME.test(host)
  )
    return undefined;
  url.hostname = host;
  // A fragment points inside the same page: one link, not two.
  url.hash = '';
  return url.href.length > MAX_URL ? undefined : url.href;
}

/** At most this many entries of a source list are looked at; the rest cannot add anything kept. */
const MAX_SCANNED = 1_000;

/**
 * Runs a parser and returns an empty list if it throws. The inputs are optional extras: a malformed
 * or hostile value (a nesting or a list too deep or long for the runtime) must never cost the advisory.
 */
function neverThrows<A extends unknown[], T>(parse: (...args: A) => T[]): (...args: A) => T[] {
  return (...args: A) => {
    try {
      return parse(...args);
    } catch {
      return [];
    }
  };
}
function firstItems(value: unknown): unknown[] {
  return Array.isArray(value) ? value.slice(0, MAX_SCANNED) : [];
}

/** Repositories of advisory databases: a change there records the problem, it does not fix it. */
const ADVISORY_DATABASES =
  /^\/(?:github\/advisory-database|pypa\/advisory-database|rustsec\/advisory-db|golang\/vulndb|nodejs\/security-wg|google\/osv\.dev|ossf\/malicious-packages|FriendsOfPHP\/security-advisories|rubysec\/ruby-advisory-db|CVEProject\/cvelist(?:V5)?)\//i;

/** A link that is a code change: a commit, a pull or merge request, a compare view or a patch file. */
export function codeChangeUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  const path = parsed.pathname;
  if (ADVISORY_DATABASES.test(path)) return false;
  const query = parsed.search;
  return (
    /\/commits?\/[0-9a-f]{7,64}\/?$/i.test(path) ||
    /\/pull\/\d+(?:\/(?:commits|files)(?:\/[0-9a-f]{7,64})?)?\/?$/i.test(path) ||
    /\/-\/merge_requests\/\d+(?:\/diffs)?\/?$/i.test(path) ||
    // Bitbucket pull requests and commits.
    /\/pull-requests\/\d+(?:\/(?:diff|commits))?\/?$/i.test(path) ||
    // A compare of two releases or commits, not of two branches.
    /\/compare\/[^/]*\d[^/]*\.\.\.?[^/]*\d[^/]*$/i.test(path) ||
    /\.(?:patch|diff)$/i.test(path) ||
    // googlesource (Android, Chromium): /+/<commit>.
    /\/\+\/[0-9a-f]{7,64}(?:%5E!)?\/?$/i.test(path) ||
    // Mercurial.
    /\/rev\/[0-9a-f]{12,40}\/?$/i.test(path) ||
    // cgit and gitweb, as used by kernel.org, sourceware and savannah, and kernel.org's short links.
    (/\/commit\/?$/i.test(path) && /^[0-9a-f]{7,64}$/i.test(parsed.searchParams.get('id') ?? '')) ||
    (/(?:^\?|;|&)a=commit(?:diff)?(?:;|&|$)/i.test(query) &&
      /(?:^\?|;|&)h=[0-9a-f]{7,64}(?:;|&|$)/i.test(query)) ||
    (parsed.hostname === 'git.kernel.org' && /^\/(?:stable|linus)\/c\/[0-9a-f]{7,64}\/?$/i.test(path))
  );
}

const OSV_TYPES: Record<string, ReferenceType> = {
  FIX: 'fix',
  ADVISORY: 'advisory',
  REPORT: 'report',
  EVIDENCE: 'evidence',
  PACKAGE: 'package',
  ARTICLE: 'web',
  WEB: 'web',
  DISCUSSION: 'web',
  DETECTION: 'detection',
  INTRODUCED: 'introduced',
  GIT: 'source',
};
/** The more specific of two kinds for the same link: a fix outranks a generic web page. */
const TYPE_RANK: Record<ReferenceType, number> = {
  fix: 0,
  evidence: 1,
  advisory: 2,
  report: 3,
  detection: 4,
  introduced: 5,
  package: 6,
  source: 7,
  web: 8,
};

function merged(references: AdvisoryReference[]): AdvisoryReference[] {
  const byUrl = new Map<string, AdvisoryReference>();
  for (const reference of references) {
    const known = byUrl.get(reference.url);
    if (!known || TYPE_RANK[reference.type] < TYPE_RANK[known.type]) byUrl.set(reference.url, reference);
  }
  return [...byUrl.values()].sort((a, b) => TYPE_RANK[a.type] - TYPE_RANK[b.type]).slice(0, MAX_REFERENCES);
}

/**
 * OSV `references`: typed. A code-change link typed only as a web page is a fix link; one the
 * advisory types as evidence, a report or an advisory (a proof-of-concept commit, say) keeps its type.
 */
export const osvReferences = neverThrows((raw: unknown): AdvisoryReference[] => {
  const references: AdvisoryReference[] = [];
  for (const item of firstItems(raw)) {
    if (!isRecord(item)) continue;
    const url = safeHttpsUrl(item.url);
    if (!url) continue;
    const given = typeof item.type === 'string' ? OSV_TYPES[item.type.toUpperCase()] : undefined;
    const code = codeChangeUrl(url);
    // A fix link is a code change. A page typed FIX that is not one (a vendor bulletin, release notes,
    // a change to an advisory database) describes the fix; it is kept as an advisory.
    const type: ReferenceType =
      given === 'fix'
        ? code
          ? 'fix'
          : 'advisory'
        : given === undefined || given === 'web'
          ? code
            ? 'fix'
            : 'web'
          : given;
    references.push({ type, url });
  }
  return merged(references);
});

/** GitHub's `references`: plain URLs. Code changes are fix links, advisory databases are advisories. */
export const githubReferences = neverThrows((raw: unknown): AdvisoryReference[] => {
  const references: AdvisoryReference[] = [];
  for (const item of firstItems(raw)) {
    const url = safeHttpsUrl(isRecord(item) ? item.url : item);
    if (!url) continue;
    const host = new URL(url).hostname;
    const type: ReferenceType = codeChangeUrl(url)
      ? 'fix'
      : host === 'nvd.nist.gov' || /\/advisories\/GHSA-/i.test(url) || /\/security\/advisories\//i.test(url)
        ? 'advisory'
        : 'web';
    references.push({ type, url });
  }
  return merged(references);
});

/** The commits OSV records as fixing the problem: `GIT` ranges with a repository and `fixed` events. */
export const osvFixCommits = neverThrows((affected: unknown): FixCommit[] => {
  const commits = new Map<string, FixCommit>();
  for (const entry of firstItems(affected)) {
    if (!isRecord(entry)) continue;
    for (const range of firstItems(entry.ranges)) {
      if (!isRecord(range) || range.type !== 'GIT') continue;
      const repo = safeHttpsUrl(range.repo);
      if (!repo) continue;
      for (const event of firstItems(range.events)) {
        if (!isRecord(event) || typeof event.fixed !== 'string') continue;
        const commit = event.fixed.trim().toLowerCase();
        if (!/^[0-9a-f]{7,64}$/.test(commit)) continue;
        commits.set(`${repo} ${commit}`, { repo, commit });
        if (commits.size >= MAX_FIX_COMMITS) return [...commits.values()];
      }
    }
  }
  return [...commits.values()];
});

function weakness(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 20) return undefined;
  const match = value.trim().match(/^CWE-(\d{1,5})$/i);
  return match ? `CWE-${Number(match[1])}` : undefined;
}
function weaknessList(values: unknown[]): string[] {
  const found = new Set<string>();
  for (const value of values) {
    const item = weakness(value);
    if (item) found.add(item);
    if (found.size >= MAX_WEAKNESSES) break;
  }
  return [...found];
}

/** OSV: `database_specific.cwe_ids`, as GitHub-reviewed records carry, on the record or an entry. */
export const osvWeaknesses = neverThrows((data: Record<string, unknown>): string[] => {
  const values: unknown[] = [];
  const collect = (specific: unknown) => {
    if (isRecord(specific)) for (const value of firstItems(specific.cwe_ids)) values.push(value);
  };
  collect(data.database_specific);
  for (const entry of firstItems(data.affected)) if (isRecord(entry)) collect(entry.database_specific);
  return weaknessList(values);
});

/** GitHub: `cwes: [{cwe_id, name}]`. */
export const githubWeaknesses = neverThrows((raw: unknown): string[] =>
  weaknessList(firstItems(raw).map((item) => (isRecord(item) ? item.cwe_id : item))),
);

const CVE_NOW_EXPLOITS: [key: string, label: string][] = [
  ['exploitDb', 'exploit-db'],
  ['metasploit', 'metasploit'],
  ['nuclei', 'nuclei'],
  ['githubPoc', 'github-poc'],
];
const PLACEHOLDER = /^(?:false|no|none|null|n\/a|na|0|-|unknown)$/i;
/**
 * Whether a cve.now entry names an exploit: a non-empty list (`{"ids": [...]}`, `{"modules": [...]}`),
 * a link or name, or a positive count. A flag or a date beside an empty list (`{"ids": [], "checked":
 * true}`) names nothing, and neither do placeholders such as "none". cve.now nests two levels; deeper
 * values are not looked at.
 */
function present(value: unknown, depth = 0): boolean {
  if (typeof value === 'string') return value.trim() !== '' && !PLACEHOLDER.test(value.trim());
  if (typeof value === 'number') return Number.isFinite(value) && value > 0;
  if (value === true) return depth === 0;
  if (depth >= 3) return false;
  if (Array.isArray(value))
    return firstItems(value).some((item) => present(item, depth + 1) || isRecord(item));
  if (isRecord(value))
    return Object.values(value).some((item) =>
      Array.isArray(item) || typeof item === 'number' ? present(item, depth + 1) : false,
    );
  return false;
}
/**
 * cve.now's public exploit entries: Exploit-DB, Metasploit, Nuclei and GitHub proof-of-concept code.
 * Published code, not exploitation in the wild; that is `exploited` (the KEV catalog).
 */
export const cveNowExploitSources = neverThrows((exploitation: unknown): string[] => {
  if (!isRecord(exploitation)) return [];
  return CVE_NOW_EXPLOITS.filter(([key]) => present(exploitation[key])).map(([, label]) => label);
});

/** The shield inputs to spread into an Evidence record; empty lists are left out. */
export function shieldInputs(parts: {
  references?: AdvisoryReference[];
  fix_commits?: FixCommit[];
  weaknesses?: string[];
  exploit_sources?: string[];
}): Pick<Evidence, 'references' | 'fix_commits' | 'weaknesses' | 'exploit_sources'> {
  return {
    ...(parts.references?.length ? { references: parts.references } : {}),
    ...(parts.fix_commits?.length ? { fix_commits: parts.fix_commits } : {}),
    ...(parts.weaknesses?.length ? { weaknesses: parts.weaknesses } : {}),
    ...(parts.exploit_sources?.length ? { exploit_sources: parts.exploit_sources } : {}),
  };
}
