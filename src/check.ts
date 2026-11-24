import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { coerce, gt, major, minor, valid } from 'semver';
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { parseConfig } from './config.js';
import { runScan } from './engine.js';
import { normalizeEcosystem, normalizePackageName, exactLibraryVersion, ECOSYSTEMS } from './ecosystems.js';
import { safeHttp } from './http.js';
import { foldDuplicateComponents, systemFromSbom } from './inventory.js';
import { generateSbom, isDependencyFilePath, type DependencyFile } from './manifests.js';
import { importCycloneDxValue, importSbom, type SbomImport } from './sbom.js';
import { osvEvidence } from './sources.js';
import { Store } from './store.js';
import type {
  Assessment,
  Component,
  EpssScore,
  Evidence,
  HttpClient,
  HttpResult,
  Inventory,
  Severity,
  System,
} from './types.js';
import { cleanText } from './util.js';

/**
 * One-shot checks for a project, a package, an advisory or a dependency change, for people and AI
 * agents who need an answer now rather than an alert later. They run the monitor's own engine on an
 * in-memory database, with OSV and the CISA known-exploited catalog (and EPSS when asked), so a
 * check and the monitor agree. Nothing is stored and nothing is sent anywhere but those sources:
 * OSV receives package names and versions, never file contents.
 */

const OSV = 'https://api.osv.dev/v1';
const SEVERITY_ORDER: readonly Severity[] = ['unknown', 'low', 'medium', 'high', 'critical'];
const MAX_GIT_FILES = 2_000;
const MAX_GIT_BYTES = 20 * 1024 * 1024;
const MAX_GIT_TOTAL = 200 * 1024 * 1024;
const ADVISORY_ID = /^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9.:_]+)+$/;

export interface CheckOptions {
  /** Mark CISA known-exploited entries. Default: true. */
  kev?: boolean;
  /** Add FIRST EPSS scores to findings with a CVE. Sends CVE IDs to api.first.org. Default: false. */
  epss?: boolean;
  http?: HttpClient;
  now?: number;
  signal?: AbortSignal;
}

export interface ProjectCheckOptions extends CheckOptions {
  /** A project folder or one dependency file. */
  project?: string;
  /** A CycloneDX or SPDX JSON SBOM to check instead of reading a project. */
  sbom?: string;
  /** Leave out development-only dependencies where the dependency file says which they are. */
  production?: boolean;
}

export interface CheckFinding {
  /** The advisory's own identifier (GHSA-, PYSEC-, RUSTSEC-, MAL- ...). */
  id: string;
  /** Other identifiers of the same problem, such as its CVE. */
  aliases: string[];
  title: string;
  /** Severity the advisory gives. */
  severity: Severity;
  /** Security Watch's priority: the severity, raised for known exploitation, malware or an unknown version. */
  priority: Severity;
  /** `affected`: the installed version is in an affected range. `unknown`: no exact version to compare. */
  applicability: 'affected' | 'unknown';
  /** Listed in CISA's Known Exploited Vulnerabilities catalog. */
  exploited: boolean;
  /** An OSV malicious-package record: the package itself is malware. */
  malware: boolean;
  package: { ecosystem: string; name: string; version?: string };
  /** Dependency files the package was found in, relative to the project. */
  files: string[];
  /** Versions that fix it, as the advisory gives them. */
  fixed?: string;
  url?: string;
  epss?: EpssScore;
  reasons: string[];
}

export interface CheckReport {
  /** A project's dependency files, an SBOM file, or packages named in the request. */
  kind: 'project' | 'sbom' | 'packages';
  checked_at: string;
  /** What was checked: a project folder, a file, an SBOM or a package list. */
  target: string;
  packages: number;
  /** Packages without an exact version (a manifest without a lockfile): checked by name only. */
  unversioned: number;
  files: DependencyFile[];
  ecosystems: string[];
  findings: CheckFinding[];
  /** Sources asked. */
  sources: string[];
  /** A source failed or answered in part: the findings may be incomplete. */
  degraded: boolean;
  errors: string[];
  /** Dependency files that could not be read. Their packages were not checked, so `degraded` is set. */
  warnings: string[];
  /** Notes about what was read: version ranges, entries from Git or local paths, SBOM notices. */
  notices: string[];
}

interface Target {
  kind: CheckReport['kind'];
  label: string;
  system: System;
  files: DependencyFile[];
  ecosystems: string[];
  packages: number;
  unversioned: number;
  /** Dependency files (or folders) that could not be read: the check is incomplete. */
  unreadable: string[];
  notices: string[];
  /** Package URL to the files it was found in. */
  locations: Map<string, string[]>;
}

/** The reader's warnings that mean a file's packages are missing, rather than notes about them. */
export const isUnreadableWarning = (warning: string): boolean =>
  UNREADABLE.test(warning) || UNREADABLE_LINK.test(warning);
const UNREADABLE_LINK = /: reached through a link that leads outside the project; skipped\.$/;
const UNREADABLE = /: (?:folder could not be read|could not be read \(.*\)|larger than 20 MiB); skipped\.$/;

const EMPTY_PROJECT = /no supported dependency files|no dependency files|found no/i;

function digestOf(value: unknown): string {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

function projectTarget(options: ProjectCheckOptions): Target {
  if (options.sbom) {
    const path = resolve(options.sbom);
    const imported = importSbom(path);
    const loaded = systemFromSbom(path, basename(path), basename(path), imported);
    return {
      kind: 'sbom',
      label: basename(path),
      system: loaded.system,
      files: [],
      ecosystems: [...new Set(imported.components.map((component) => component.ecosystem))].sort(),
      packages: imported.components.length,
      unversioned: imported.components.filter((component) => !component.version).length,
      unreadable: [],
      notices: [...loaded.warnings, ...loaded.notices],
      locations: new Map(),
    };
  }
  const project = resolve(options.project ?? '.');
  let generated;
  try {
    generated = generateSbom({ project, ...(options.production ? { production: true } : {}) });
  } catch (error) {
    if (error instanceof Error && EMPTY_PROJECT.test(error.message)) return emptyTarget(project);
    throw error;
  }
  const locations = new Map<string, string[]>();
  for (const component of (generated.bom.components ?? []) as Array<{
    purl?: string;
    evidence?: { occurrences?: Array<{ location?: string }> };
  }>)
    if (component.purl)
      locations.set(
        component.purl,
        (component.evidence?.occurrences ?? []).flatMap((item) => (item.location ? [item.location] : [])),
      );
  const imported: SbomImport = importCycloneDxValue(generated.bom, digestOf(generated.bom));
  const loaded = systemFromSbom(project, basename(project), basename(project), imported);
  return {
    kind: 'project',
    label: project,
    system: loaded.system,
    files: generated.files,
    ecosystems: generated.ecosystems,
    packages: generated.packages,
    unversioned: generated.unversioned,
    unreadable: generated.warnings.filter((warning) => UNREADABLE.test(warning)),
    notices: [
      ...generated.warnings.filter((warning) => !UNREADABLE.test(warning)),
      ...loaded.warnings,
      ...loaded.notices,
    ],
    locations,
  };
}

function emptyTarget(label: string): Target {
  return {
    kind: 'project',
    label,
    system: blankSystem(basename(label) || 'project', []),
    files: [],
    ecosystems: [],
    packages: 0,
    unversioned: 0,
    unreadable: [],
    notices: [],
    locations: new Map(),
  };
}

function blankSystem(name: string, components: Component[]): System {
  return {
    id: 'check',
    name,
    environment: 'unknown',
    exposure: 'unknown',
    criticality: 'unknown',
    updated_at: new Date().toISOString(),
    components,
    products: [],
    keywords: [],
  };
}

/** A GET cache for the sources' static files (KEV, EPSS, OSV records), shared by checks in one session. */
export function cachingHttp(inner: HttpClient = safeHttp, ttlMs = 15 * 60_000): HttpClient {
  const cache = new Map<string, { at: number; result: Promise<HttpResult> }>();
  return (url, options = {}) => {
    if ((options.method ?? 'GET') !== 'GET') return inner(url, options);
    const now = Date.now();
    const hit = cache.get(url);
    if (hit && now - hit.at < ttlMs) return hit.result;
    const { signal: _signal, ...rest } = options;
    const result = inner(url, rest).then(
      (response) => {
        if (response.status !== 200) cache.delete(url);
        return response;
      },
      (error: unknown) => {
        cache.delete(url);
        throw error;
      },
    );
    cache.set(url, { at: now, result });
    if (cache.size > 2_000) cache.delete(cache.keys().next().value!);
    return result;
  };
}

async function run(target: Target, options: CheckOptions): Promise<CheckReport> {
  const now = options.now ?? Date.now();
  const kev = options.kev ?? true;
  const epss = options.epss ?? false;
  const sources = ['osv', ...(kev ? ['kev'] : []), ...(epss ? ['epss'] : [])];
  const report: CheckReport = {
    kind: target.kind,
    checked_at: new Date(now).toISOString(),
    target: target.label,
    packages: target.packages,
    unversioned: target.unversioned,
    files: target.files,
    ecosystems: target.ecosystems,
    findings: [],
    sources,
    // A file that could not be read hides its packages: no answer about them is a complete answer.
    degraded: target.unreadable.length > 0,
    errors: [],
    warnings: target.unreadable,
    notices: target.notices,
  };
  if (!target.system.components.length) return report;
  // A check is about the versions on disk now, whatever date an SBOM file carries.
  const system = { ...target.system, updated_at: new Date(now).toISOString() };
  const inventory: Inventory = { systems: [system] };
  const config = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev, epss },
  });
  const store = new Store(':memory:');
  try {
    const scan = await runScan({
      config,
      inventory,
      store,
      now,
      ...(options.http ? { http: options.http } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
    });
    const evidence = new Map(store.evidence().map((item) => [item.id, item]));
    const components = new Map(system.components.map((component) => [component.id, component]));
    report.degraded ||= scan.degraded;
    report.errors = scan.errors.map((error) => `${error.source}: ${error.message}`);
    for (const finding of scan.findings) {
      if (finding.category === 'health') {
        if (!report.errors.includes(finding.summary)) report.errors.push(cleanText(finding.summary, 300));
        continue;
      }
      if (finding.active === false || finding.withdrawn) continue;
      if (finding.applicability !== 'affected' && finding.applicability !== 'unknown') continue;
      const component = finding.component_id ? components.get(finding.component_id) : undefined;
      if (!component) continue;
      report.findings.push(toFinding(finding, component, evidence, target.locations));
    }
  } finally {
    store.close();
  }
  report.findings.sort(compareFindings);
  return report;
}

function toFinding(
  finding: Assessment,
  component: Component,
  evidence: Map<string, Evidence>,
  locations: Map<string, string[]>,
): CheckFinding {
  const records = finding.evidence_ids.map((id) => evidence.get(id)).filter((item) => item !== undefined);
  // A known-exploited entry is cited beside the advisory; the advisory names the problem.
  const primary = records.find((item) => item.kind === 'advisory') ?? records[0];
  const id = primary ? primary.id.replace(/^[a-z_]+:/, '') : finding.event_id;
  // Identifiers keep their own case: OSV answers GHSA-xxxx-xxxx-xxxx, not GHSA-XXXX-XXXX-XXXX.
  const aliases = uniqueIds(records.flatMap((item) => item.aliases ?? [])).filter(
    (alias) => alias.toUpperCase() !== id.toUpperCase(),
  );
  // OSV's MAL- records, and GitHub advisories that say the package itself is malicious (crossenv).
  const malware =
    finding.category === 'malware' ||
    records.some((item) => item.malware) ||
    /\bmalicious (?:package|code|version|release)|\b(?:is|contains|embedded) malware\b/i.test(finding.title);
  const purl = component.purl;
  const files =
    (purl ? locations.get(purl) : undefined) ??
    (component.note?.startsWith('found in ')
      ? component.note
          .slice('found in '.length)
          .replace(/ and others$/, '')
          .split(/,\s*/)
          .filter(Boolean)
      : []);
  return {
    id,
    aliases,
    title: finding.title,
    severity: finding.source_severity,
    priority: malware ? 'critical' : finding.priority,
    applicability: finding.applicability === 'affected' ? 'affected' : 'unknown',
    exploited: finding.exploited,
    malware,
    package: {
      ecosystem: component.ecosystem,
      name: component.name,
      ...(component.version ? { version: component.version } : {}),
    },
    files,
    ...(finding.fix && fixesAbove(finding.fix, component.version)
      ? { fixed: fixesAbove(finding.fix, component.version) }
      : {}),
    ...(primary?.url ? { url: primary.url } : finding.urls[0] ? { url: finding.urls[0] } : {}),
    ...(finding.epss ? { epss: finding.epss } : {}),
    reasons: finding.reasons,
  };
}

/** CVE first (what people search for), then GHSA, then ecosystem IDs; BIT- mirrors last. */
function idOrder(id: string): number {
  return /^CVE-/i.test(id) ? 0 : /^GHSA-/i.test(id) ? 1 : /^BIT-/i.test(id) ? 3 : 2;
}

function uniqueIds(ids: readonly string[]): string[] {
  const seen = new Map<string, string>();
  for (const id of ids) if (!seen.has(id.toUpperCase())) seen.set(id.toUpperCase(), id);
  return [...seen.values()].sort((a, b) => idOrder(a) - idOrder(b) || a.localeCompare(b));
}

/**
 * A git commit ID: 7 to 64 hex digits with at least one letter, or a full 40- or 64-digit ID.
 * Date-style versions (org.json 20230227, pdfminer.six 20251107) are all digits and stay versions.
 */
export function isCommitId(text: string): boolean {
  return (
    /^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(text) || (/^[0-9a-f]{7,64}$/i.test(text) && /[a-f]/i.test(text))
  );
}

/** A version that compares, or undefined: commit IDs and other text never pass for a version. */
export function comparable(version: string): string | undefined {
  const text = version.trim();
  if (!/^v?\d/.test(text) || isCommitId(text)) return undefined;
  return valid(text) ?? coerce(text)?.version ?? undefined;
}

/**
 * The fixed versions worth showing, from an advisory's fix list ("1.2.6; 0.2.4, 1.2.6"): each once,
 * in version order, without commit IDs, and, when the installed version is known, only those above
 * it (an advisory for several release lines lists a fix per line, and "upgrade to 0.2.4" is no
 * advice for 1.2.5). Versions that do not compare are kept as they are.
 */
export function fixesAbove(fix: string, installed: string | undefined): string | undefined {
  const seen = new Set<string>();
  const versions: string[] = [];
  for (const raw of fix.split(/[;,]/)) {
    const version = raw.trim();
    if (!version || isCommitId(version) || seen.has(version)) continue;
    seen.add(version);
    versions.push(version);
  }
  versions.sort((a, b) => {
    const [x, y] = [comparable(a), comparable(b)];
    return x && y ? (gt(x, y) ? 1 : gt(y, x) ? -1 : 0) : x ? -1 : y ? 1 : a.localeCompare(b);
  });
  const current = installed ? comparable(installed) : undefined;
  if (!current) return versions.join('; ') || undefined;
  const kept = versions.filter((version) => {
    const candidate = comparable(version);
    return !candidate || gt(candidate, current);
  });
  return (kept.length ? kept : versions).join('; ') || undefined;
}

function rank(finding: CheckFinding): number {
  return (
    (finding.malware ? 200 : 0) +
    (finding.exploited ? 100 : 0) +
    level(finding) * 10 +
    SEVERITY_ORDER.indexOf(finding.severity)
  );
}

function compareFindings(a: CheckFinding, b: CheckFinding): number {
  return (
    rank(b) - rank(a) ||
    (a.applicability === b.applicability ? 0 : a.applicability === 'affected' ? -1 : 1) ||
    a.package.name.localeCompare(b.package.name) ||
    a.id.localeCompare(b.id)
  );
}

/** Reads a project's dependency files (or an SBOM) and checks every package against OSV. */
export async function checkProject(options: ProjectCheckOptions = {}): Promise<CheckReport> {
  return run(projectTarget(options), options);
}

export interface PackageQuery {
  ecosystem: string;
  name: string;
  /** Exact version. Without one, every advisory for the package is listed as `unknown`. */
  version?: string;
}

/** Checks named packages, such as one an agent is about to add or upgrade to. */
export async function checkPackages(
  packages: readonly PackageQuery[],
  options: CheckOptions = {},
): Promise<CheckReport> {
  if (!packages.length) throw new Error('Name at least one package.');
  if (packages.length > 100) throw new Error('Check at most 100 packages at a time.');
  // A package named twice is one check, not two identical findings.
  const components: Component[] = foldDuplicateComponents(
    packages.map((item, index) => {
      const ecosystem = normalizeEcosystem(item.ecosystem);
      const name = normalizePackageName(ecosystem, item.name);
      if (!name) throw new Error('Package name is empty.');
      const version = item.version?.trim() ? exactLibraryVersion(item.version.trim(), ecosystem) : undefined;
      return {
        id: `package:${index}`,
        ecosystem,
        name,
        ...(version ? { version } : {}),
        provenance: { source: 'check', reference: 'request' },
      } as Component;
    }),
  );
  const target: Target = {
    kind: 'packages',
    label: packages.map((item) => `${item.name}${item.version ? `@${item.version}` : ''}`).join(', '),
    system: blankSystem('packages', components),
    files: [],
    ecosystems: [...new Set(components.map((component) => component.ecosystem))].sort(),
    packages: components.length,
    unversioned: components.filter((component) => !component.version).length,
    unreadable: [],
    notices: [],
    locations: new Map(),
  };
  return run(target, options);
}

export interface ChangeReport {
  /** The ref as given; `REF...` means the point where the working tree's branch left REF. */
  base: string;
  /** The commit the base resolved to. */
  commit: string;
  head: CheckReport;
  /** Findings the change brought in: the advisory did not concern this package at the base. */
  added: CheckFinding[];
  /** Findings at the base that the change removed. */
  resolved: CheckFinding[];
  /** Findings present before and after. */
  unchanged: number;
  packages: { added: string[]; removed: string[]; changed: string[] };
}

function git(root: string, args: string[], maxBuffer = 64 * 1024 * 1024): Buffer {
  // A project's own .git/config can name programs git runs for some commands (core.fsmonitor runs
  // on ls-files): those are switched off, so no project code runs.
  return execFileSync(
    'git',
    ['-C', root, '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', ...args],
    {
      maxBuffer,
      stdio: ['ignore', 'pipe', 'pipe'],
      // The check makes no requests besides its sources: a partial clone must not fetch from its remote.
      env: { ...process.env, GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0' },
    },
  );
}

function gitError(error: unknown): string {
  if ((error as { code?: string }).code === 'ENOENT')
    return 'git is not installed here; the container image has none, so use the npm package for change checks';
  const stderr = (error as { stderr?: Buffer }).stderr?.toString().trim();
  return cleanText(stderr || (error instanceof Error ? error.message : 'git failed'), 300);
}

function isInside(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

interface GitProject {
  /** The project folder as given (real path). */
  root: string;
  /** The repository's top folder. */
  top: string;
  /** The project's path inside the repository, `/`-separated, without a trailing slash. */
  prefix: string;
}

function gitProject(project: string): GitProject {
  const root = realpathSync.native(resolve(project));
  if (!statSync(root).isDirectory()) throw new Error('A change can only be checked for a project folder.');
  try {
    const top = git(root, ['rev-parse', '--show-toplevel']).toString().trim();
    // git's own prefix, so a path typed in another letter case on macOS or Windows still matches.
    const prefix = git(root, ['rev-parse', '--show-prefix']).toString().trim().replace(/\/$/, '');
    return { root, top, prefix };
  } catch (error) {
    throw new Error(`Not a git repository (${gitError(error)}).`);
  }
}

function checkRef(ref: string, shown: string): void {
  if (!ref || ref.startsWith('-') || ref.length > 200 || /[\s\0]/.test(ref))
    throw new Error(`base must be a git ref such as HEAD, main or origin/main (${shown}).`);
}

/**
 * The commit to compare with. `REF...` (three dots, as in `git diff`) is the point where the current
 * branch left REF, so a branch that is behind REF is not blamed for what REF changed since.
 */
function baseCommit(gp: GitProject, base: string): string {
  const branchPoint = base.endsWith('...');
  const ref = branchPoint ? base.slice(0, -3) : base;
  checkRef(ref, base);
  let commit: string;
  try {
    commit = git(gp.root, ['rev-parse', '--verify', '--quiet', '--end-of-options', `${ref}^{commit}`])
      .toString()
      .trim();
  } catch {
    throw new Error(`git does not know ${ref}. Fetch it first, or name a commit that exists here.`);
  }
  if (!branchPoint) return commit;
  try {
    return git(gp.root, ['merge-base', commit, 'HEAD']).toString().trim();
  } catch (error) {
    throw new Error(`${ref} and HEAD have no common commit (${gitError(error)}).`);
  }
}

/** Copies the given files into `folder/<project name>/` at their paths relative to the project. */
function stage(
  gp: GitProject,
  files: Array<{ path: string; size: number; read: () => Buffer }>,
  what: string,
): { folder: string; project: string; skipped: string[]; skippedPaths: string[] } {
  const folder = mkdtempSync(join(tmpdir(), 'security-watch-change-'));
  const project = join(folder, basename(gp.root));
  const skipped: string[] = [];
  const skippedPaths: string[] = [];
  try {
    mkdirSync(project);
    let total = 0;
    for (const file of files) {
      // The same limit and wording as reading the project directly, so the check counts as incomplete.
      if (file.size > MAX_GIT_BYTES) {
        skipped.push(`${file.path}: larger than 20 MiB; skipped.`);
        skippedPaths.push(file.path);
        continue;
      }
      total += file.size;
      if (total > MAX_GIT_TOTAL) throw new Error(`Dependency files in ${what} exceed 200 MiB.`);
      let content: Buffer;
      try {
        content = file.read();
      } catch (error) {
        skipped.push(`${file.path}: could not be read (${gitError(error)}); skipped.`);
        skippedPaths.push(file.path);
        continue;
      }
      const destination = join(project, ...file.path.split('/'));
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, content);
    }
    return { folder, project, skipped, skippedPaths };
  } catch (error) {
    rmSync(folder, { recursive: true, force: true });
    throw error;
  }
}

function relativeToProject(gp: GitProject, path: string): string | undefined {
  if (!gp.prefix) return path;
  return path.startsWith(`${gp.prefix}/`) ? path.slice(gp.prefix.length + 1) : undefined;
}

/**
 * Writes the dependency files of `project` as they were at `base` into a new temporary folder.
 * Only files the project reader would pick up are taken, with `git cat-file`; nothing is checked
 * out and no repository code runs. Submodules are not followed.
 */
export function dependencyFilesAt(
  project: string,
  base: string,
): { folder: string; project: string; commit: string; skipped: string[]; skippedPaths: string[] } {
  const gp = gitProject(project);
  const commit = baseCommit(gp, base);
  const listed = git(gp.top, [
    'ls-tree',
    '-r',
    '-z',
    '-l',
    '--full-tree',
    commit,
    '--',
    ...(gp.prefix ? [gp.prefix] : []),
  ])
    .toString()
    .split('\0')
    .filter(Boolean);
  const files: Array<{ path: string; size: number; read: () => Buffer }> = [];
  for (const line of listed) {
    const tab = line.indexOf('\t');
    const [mode, type, object, size] = line.slice(0, tab).split(/\s+/);
    const path = relativeToProject(gp, line.slice(tab + 1));
    if (type !== 'blob' || mode === '120000' || !object || path === undefined) continue;
    if (!isDependencyFilePath(path, basename(gp.root))) continue;
    files.push({
      path,
      size: Number(size),
      read: () => git(gp.top, ['cat-file', 'blob', object], MAX_GIT_BYTES + 1),
    });
    if (files.length > MAX_GIT_FILES)
      throw new Error(`More than ${MAX_GIT_FILES} dependency files at ${base}; check a smaller folder.`);
  }
  return { ...stage(gp, files, base), commit };
}

/**
 * The dependency files of the working tree that git tracks or would track: tracked files as they
 * are on disk, and untracked files that are not ignored. Submodules, nested repositories and
 * ignored folders are left out, as they are at the base.
 */
export function dependencyFilesInWorkingTree(project: string): {
  folder: string;
  project: string;
  skipped: string[];
  skippedPaths: string[];
} {
  const gp = gitProject(project);
  const listed = git(gp.top, [
    'ls-files',
    '-z',
    '-c',
    '-o',
    '--exclude-standard',
    '--',
    ...(gp.prefix ? [gp.prefix] : []),
  ])
    .toString()
    .split('\0')
    .filter(Boolean);
  const files: Array<{ path: string; size: number; read: () => Buffer }> = [];
  const outside: string[] = [];
  const seen = new Set<string>();
  for (const entry of listed) {
    const path = relativeToProject(gp, entry);
    if (path === undefined || seen.has(path) || !isDependencyFilePath(path, basename(gp.root))) continue;
    seen.add(path);
    const absolute = join(gp.top, ...entry.split('/'));
    let stat;
    try {
      stat = lstatSync(absolute);
    } catch {
      continue; // tracked but deleted in the working tree
    }
    if (!stat.isFile()) continue; // a link, or a submodule's folder
    // A folder on the way can be a link that leads out of the project, as the file itself cannot.
    if (!isInside(realpathSync.native(absolute), gp.root)) {
      outside.push(path);
      continue;
    }
    files.push({ path, size: stat.size, read: () => readFileSync(absolute) });
    if (files.length > MAX_GIT_FILES)
      throw new Error(
        `More than ${MAX_GIT_FILES} dependency files in the working tree; check a smaller folder.`,
      );
  }
  const staged = stage(gp, files, 'the working tree');
  for (const path of outside) {
    staged.skipped.push(`${path}: reached through a link that leads outside the project; skipped.`);
    staged.skippedPaths.push(path);
  }
  return staged;
}

function findingKey(finding: CheckFinding): string {
  return JSON.stringify([finding.id.toUpperCase(), finding.package.ecosystem, finding.package.name]);
}

function packageVersions(target: Target): Map<string, string> {
  const out = new Map<string, string>();
  for (const component of target.system.components) {
    const key = `${component.ecosystem}:${component.name}`;
    const versions = out.get(key);
    out.set(key, versions ? `${versions}, ${component.version ?? '?'}` : (component.version ?? '?'));
  }
  return out;
}

function stagedTarget(
  staged: { project: string; skipped: string[] },
  options: ProjectCheckOptions,
  label: string,
): Target {
  const target = projectTarget({ ...options, project: staged.project });
  target.label = label;
  target.unreadable.push(...staged.skipped);
  return target;
}

/**
 * Compares a project's dependencies at a git ref with the working tree and reports what the change
 * added and fixed. Both sides are the files git knows: the base from its objects, the working tree
 * as it is on disk (tracked, plus untracked files that are not ignored).
 */
export async function checkChange(options: ProjectCheckOptions & { base: string }): Promise<ChangeReport> {
  const project = resolve(options.project ?? '.');
  const before = dependencyFilesAt(project, options.base);
  let after: ReturnType<typeof dependencyFilesInWorkingTree> | undefined;
  try {
    after = dependencyFilesInWorkingTree(project);
    // A file left out on one side is left out on both, or its packages would read as removed (or
    // added) and their advisories as fixed (or brought in).
    for (const path of after.skippedPaths) rmSync(join(before.project, ...path.split('/')), { force: true });
    for (const path of before.skippedPaths) rmSync(join(after.project, ...path.split('/')), { force: true });
    const baseTarget = stagedTarget(before, options, `${options.base} (${before.commit.slice(0, 12)})`);
    const headTarget = stagedTarget(after, options, realpathSync(project));
    const http = options.http ?? cachingHttp();
    const [old, now] = await Promise.all([
      run(baseTarget, { ...options, http }),
      run(headTarget, { ...options, http }),
    ]);
    const beforeKeys = new Map(old.findings.map((finding) => [findingKey(finding), finding]));
    const afterKeys = new Set(now.findings.map(findingKey));
    const added = now.findings.filter((finding) => !beforeKeys.has(findingKey(finding)));
    const resolved = old.findings.filter((finding) => !afterKeys.has(findingKey(finding)));
    const oldPackages = packageVersions(baseTarget);
    const newPackages = packageVersions(headTarget);
    const packages = { added: [] as string[], removed: [] as string[], changed: [] as string[] };
    for (const [key, version] of newPackages) {
      const was = oldPackages.get(key);
      if (was === undefined) packages.added.push(`${key}@${version}`);
      else if (was !== version) packages.changed.push(`${key} ${was} -> ${version}`);
    }
    for (const [key, version] of oldPackages)
      if (!newPackages.has(key)) packages.removed.push(`${key}@${version}`);
    for (const list of Object.values(packages)) list.sort();
    if (old.degraded) {
      now.degraded = true;
      now.errors.push(...old.errors.map((error) => `at ${options.base}: ${error}`));
      now.warnings.push(...old.warnings.map((warning) => `at ${options.base}: ${warning}`));
    }
    return {
      base: options.base,
      commit: before.commit,
      head: now,
      added,
      resolved,
      unchanged: now.findings.length - added.length,
      packages,
    };
  } finally {
    rmSync(before.folder, { recursive: true, force: true });
    if (after) rmSync(after.folder, { recursive: true, force: true });
  }
}

export interface AdvisoryReport {
  id: string;
  /** The record was found in OSV. */
  found: boolean;
  title?: string;
  summary?: string;
  aliases: string[];
  url?: string;
  severity?: Severity;
  /** Packages the advisory names, with their affected ranges and fixes. */
  packages: Array<{ ecosystem: string; name: string; range?: string; fixed?: string }>;
  /** Findings in the project for this advisory (by its ID or an alias). */
  findings: CheckFinding[];
  /** Packages the advisory names that the project has, at versions it does not list as affected. */
  present_not_affected: string[];
  project: CheckReport;
}

async function osvRecordById(
  http: HttpClient,
  id: string,
  now: number,
  signal?: AbortSignal,
): Promise<Evidence | undefined> {
  signal?.throwIfAborted();
  const response = await http(`${OSV}/vulns/${encodeURIComponent(id)}`, { maxBytes: 8_000_000 });
  if (response.status === 404) return undefined;
  if (response.status !== 200) throw new Error(`OSV answered HTTP ${response.status} for ${id}.`);
  const raw = JSON.parse(response.body) as unknown;
  try {
    return osvEvidence(raw, id, now);
  } catch {
    // CVE records converted from NVD can name source-code ranges the monitor's reader refuses; the
    // title, aliases and description still answer the question, and aliases lead to package records.
    const data = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
    const text = (value: unknown) => (typeof value === 'string' ? cleanText(value, 2000) : undefined);
    const aliases = Array.isArray(data.aliases)
      ? data.aliases.filter((alias) => typeof alias === 'string')
      : [];
    const summary = text(data.summary);
    const details = text(data.details);
    return {
      id: `osv:${id}`,
      source: 'osv',
      kind: 'advisory',
      title: summary ?? details?.split(/(?<=\.)\s/)[0]?.slice(0, 200) ?? id,
      url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
      description: details ?? summary ?? '',
      aliases: [id, ...aliases],
      severity: 'unknown',
      modified_at: new Date(now).toISOString(),
      fetched_at: new Date(now).toISOString(),
      packages: [],
    } as Evidence;
  }
}

function advisorySeverity(
  records: readonly Evidence[],
  findings: readonly CheckFinding[],
): Severity | undefined {
  const levels = [
    ...records.map((item) => item.severity ?? 'unknown'),
    ...findings.map((finding) => finding.severity),
  ];
  const top = levels.reduce<Severity>(
    (best, value) => (SEVERITY_ORDER.indexOf(value) > SEVERITY_ORDER.indexOf(best) ? value : best),
    'unknown',
  );
  return top === 'unknown' ? undefined : top;
}

/** CVE and GHSA identifiers in the case OSV uses; anything else as typed. */
export function normalizeAdvisoryId(value: string): string {
  const id = value.trim();
  if (/^ghsa-/i.test(id)) return `GHSA-${id.slice(5).toLowerCase()}`;
  if (/^cve-/i.test(id)) return id.toUpperCase();
  return id;
}

/**
 * Answers "does this advisory concern the project?": looks the identifier up in OSV (CVE, GHSA,
 * PYSEC, RUSTSEC, GO, MAL ...), follows aliases to the records that name packages, and checks
 * the project.
 */
export async function checkAdvisory(
  advisory: string,
  options: ProjectCheckOptions = {},
): Promise<AdvisoryReport> {
  const id = normalizeAdvisoryId(advisory);
  if (!ADVISORY_ID.test(id) || id.length > 100)
    throw new Error('Give an advisory ID such as CVE-2021-44906, GHSA-xvch-5gv4-984h or PYSEC-2024-1.');
  const now = options.now ?? Date.now();
  const http = options.http ?? cachingHttp();
  const target = projectTarget(options);
  const lookup = async () =>
    (await osvRecordById(http, id, now, options.signal)) ??
    // OSV identifiers are case-sensitive (openSUSE-SU-..., GHSA-xxxx): try the upper-case form too.
    (id.toUpperCase() !== id ? await osvRecordById(http, id.toUpperCase(), now, options.signal) : undefined);
  const [project, record] = await Promise.all([run(target, { ...options, http }), lookup()]);
  const records: Evidence[] = record ? [record] : [];
  if (record && !(record.packages ?? []).length)
    for (const alias of (record.aliases ?? []).filter((alias) => alias.toUpperCase() !== id).slice(0, 4))
      try {
        const other = await osvRecordById(http, alias, now, options.signal);
        if (other) records.push(other);
      } catch (error) {
        if (options.signal?.aborted) throw error;
        /* The first record still answers; an alias that fails only loses package detail. */
      }
  const names = new Set(
    [id, ...records.flatMap((item) => [item.id.replace(/^osv:/, ''), ...(item.aliases ?? [])])].map((name) =>
      name.toUpperCase(),
    ),
  );
  const findings = project.findings.filter(
    (finding) =>
      names.has(finding.id.toUpperCase()) || finding.aliases.some((alias) => names.has(alias.toUpperCase())),
  );
  const packages = new Map<string, { ecosystem: string; name: string; range?: string; fixed?: string }>();
  for (const item of records)
    for (const claim of item.packages ?? []) {
      const key = `${claim.ecosystem}\0${claim.name}\0${claim.range ?? ''}`;
      const known = packages.get(key);
      // One package often has an entry per release line (urllib3 1.26.17 and 2.0.6): keep every fix.
      const fixed = fixesAbove([known?.fixed, claim.fixed].filter(Boolean).join('; '), undefined);
      packages.set(key, {
        ecosystem: claim.ecosystem,
        name: claim.name,
        ...(claim.range ? { range: claim.range } : {}),
        ...(fixed ? { fixed } : {}),
      });
    }
  const affectedPackages = new Set(
    findings.map((finding) => `${finding.package.ecosystem}:${finding.package.name}`),
  );
  const present = new Set<string>();
  for (const claim of packages.values())
    for (const component of target.system.components)
      if (
        ECOSYSTEMS.includes(claim.ecosystem as (typeof ECOSYSTEMS)[number]) &&
        component.ecosystem === claim.ecosystem &&
        component.name.toLowerCase() ===
          normalizePackageName(component.ecosystem, claim.name).toLowerCase() &&
        !affectedPackages.has(`${component.ecosystem}:${component.name}`)
      )
        present.add(`${component.ecosystem}:${component.name}@${component.version ?? '?'}`);
  const main = records[0];
  return {
    id,
    found: Boolean(record),
    ...(main?.title ? { title: main.title } : {}),
    ...(main?.description ? { summary: cleanText(main.description, 600) } : {}),
    aliases: uniqueIds(
      records.flatMap((item) => [item.id.replace(/^osv:/, ''), ...(item.aliases ?? [])]),
    ).filter((alias) => alias.toUpperCase() !== id.toUpperCase()),
    ...(main?.url ? { url: main.url } : {}),
    // The highest severity any of its records gives, so the header never reads lower than a finding.
    ...(advisorySeverity(records, findings) ? { severity: advisorySeverity(records, findings)! } : {}),
    packages: [...packages.values()].slice(0, 50),
    findings,
    present_not_affected: [...present].sort(),
    project,
  };
}

// Text for people and agents.

function plural(count: number, word: string): string {
  if (count === 1) return `1 ${word}`;
  return `${count} ${word.endsWith('y') && !/[aeiou]y$/.test(word) ? `${word.slice(0, -1)}ies` : `${word}s`}`;
}

/**
 * The level a finding is filtered and gated at. An advisory without a severity (many GO- and some
 * PYSEC records) is not "low": it counts as medium, so it is shown by default and fails
 * `--fail-on medium`, and the output says how many there are.
 */
function level(finding: CheckFinding): number {
  return finding.priority === 'unknown'
    ? SEVERITY_ORDER.indexOf('medium')
    : SEVERITY_ORDER.indexOf(finding.priority);
}

function atLeast(finding: CheckFinding, min: Severity): boolean {
  return finding.malware || finding.exploited || level(finding) >= SEVERITY_ORDER.indexOf(min);
}

/**
 * Whether a finding fails a check at `failOn`. Malware always does. An installed version that is
 * affected fails when it is known exploited or at or above the level. A package without an exact
 * version ("check by hand") does not: nothing says the version in use is affected.
 */
export function failsAt(finding: CheckFinding, failOn: Severity | 'none'): boolean {
  if (failOn === 'none') return false;
  if (finding.malware) return true;
  if (finding.applicability !== 'affected') return false;
  return finding.exploited || level(finding) >= SEVERITY_ORDER.indexOf(failOn);
}

export function findingLine(finding: CheckFinding, kind: CheckReport['kind'] = 'project'): string {
  const name = `${finding.package.ecosystem} ${finding.package.name}${finding.package.version ? ` ${finding.package.version}` : ''}`;
  const flags = [
    finding.malware ? 'MALWARE' : '',
    finding.exploited ? 'known exploited (CISA KEV)' : '',
    finding.applicability === 'unknown'
      ? kind === 'packages'
        ? 'no version given'
        : 'no exact version: check by hand'
      : '',
    finding.priority === 'unknown' ? 'the advisory gives no severity' : '',
    finding.epss ? `EPSS ${(finding.epss.probability * 100).toFixed(1)}%` : '',
  ].filter(Boolean);
  const ids = [finding.id, ...finding.aliases.slice(0, 3)].join(', ');
  return [
    `- [${finding.priority}] ${name}: ${finding.title} (${ids})${flags.length ? ` [${flags.join('; ')}]` : ''}`,
    `  ${finding.malware ? 'Fix: remove this package and rotate any credentials it could reach.' : finding.fixed ? (finding.applicability === 'affected' ? `Fix: upgrade to ${finding.fixed}.` : `Fixed in ${finding.fixed}: use at least the one on the release line you run.`) : 'Fix: no fixed version listed.'}${finding.files.length ? ` In: ${finding.files.slice(0, 4).join(', ')}${finding.files.length > 4 ? ` and ${finding.files.length - 4} more` : ''}.` : ''}${finding.url ? ` ${finding.url}` : ''}`,
  ].join('\n');
}

/** The release line a version belongs to: major.minor, the unit projects backport fixes to. */
function line(version: string): string {
  return `${major(version)}.${minor(version)}`;
}

/** Whether `candidate` is fixed for an advisory that lists these fixed versions, one per line. */
function fixedBy(candidate: string, fixes: readonly string[]): boolean {
  const same = fixes.filter((fix) => line(fix) === line(candidate));
  if (same.length) return same.some((fix) => !gt(fix, candidate));
  // A line the advisory does not mention is fixed only if it is newer than every fix it lists.
  return fixes.every((fix) => !gt(fix, candidate));
}

/**
 * One line per package with several findings: the lowest listed fixed version that fixes all of
 * them, each judged on its own release line, so that an agent upgrades once instead of once per
 * finding. Nothing is said when no listed version fixes them all.
 */
export function upgradeSummary(findings: readonly CheckFinding[]): string[] {
  const groups = new Map<string, CheckFinding[]>();
  for (const finding of findings) {
    if (finding.malware || finding.applicability !== 'affected' || !finding.package.version) continue;
    const key = `${finding.package.ecosystem} ${finding.package.name} ${finding.package.version}`;
    groups.set(key, [...(groups.get(key) ?? []), finding]);
  }
  const out: string[] = [];
  for (const [key, group] of groups) {
    if (group.length < 2) continue;
    const installed = comparable(group[0]!.package.version!);
    if (!installed) continue;
    // The version as the advisory writes it, for each form that compares (20260719, not 20260719.0.0).
    const written = new Map<string, string>();
    const fixLists = group.map((finding) =>
      (finding.fixed ?? '')
        .split(/[;,]/)
        .map((fix) => {
          const value = comparable(fix);
          if (value && !written.has(value)) written.set(value, fix.trim());
          return value;
        })
        .filter((fix): fix is string => fix !== undefined),
    );
    const open = fixLists.filter((fixes) => !fixes.length).length;
    const lists = fixLists.filter((fixes) => fixes.length);
    if (!lists.length) continue;
    const candidates = [...new Set(lists.flat())]
      .filter((fix) => gt(fix, installed))
      .sort((a, b) => (gt(a, b) ? 1 : -1));
    const target = candidates.find((candidate) => lists.every((fixes) => fixedBy(candidate, fixes)));
    if (!target) continue;
    const shown = written.get(target) ?? target;
    // Release lines exist for dotted versions (5.2.17 is on 5.2); a date version has none.
    const lined = /^v?\d+\.\d+/.test(shown);
    const count = open
      ? `${lists.length} of ${group.length}; ${open} name no fixed version`
      : `all ${group.length}`;
    out.push(
      lined
        ? `- ${key}: upgrading to ${shown} (or a later ${line(target)}.x release) fixes ${count}. A newer release line is not checked here: check it before moving to one.`
        : `- ${key}: upgrading to ${shown} or later fixes ${count}.`,
    );
  }
  return out;
}

/** Said first, so that a reader who stops early knows the answer is partial. */
function incomplete(report: CheckReport): string[] {
  if (!report.degraded && !report.errors.length && !report.warnings.length) return [];
  const out = ['INCOMPLETE: findings may be missing.'];
  for (const warning of report.warnings.slice(0, 10)) out.push(`- not read: ${warning}`);
  if (report.warnings.length > 10) out.push(`- and ${report.warnings.length - 10} more files not read`);
  for (const error of report.errors.slice(0, 10)) out.push(`- source failed: ${error}`);
  return out;
}

function notes(report: CheckReport): string[] {
  if (!report.notices.length) return [];
  return [
    '',
    'Notes:',
    ...report.notices.slice(0, 8).map((notice) => `- ${notice}`),
    ...(report.notices.length > 8 ? [`- and ${report.notices.length - 8} more`] : []),
  ];
}

function sourcesText(report: CheckReport): string {
  return report.sources
    .map((source) => ({ osv: 'OSV', kev: 'CISA KEV', epss: 'EPSS' })[source] ?? source)
    .join(', ');
}

function hiddenText(total: CheckFinding[], shown: CheckFinding[], min: Severity): string {
  return shown.length < total.length ? ` (${total.length - shown.length} below ${min} not shown)` : '';
}

export function formatCheckReport(report: CheckReport, min: Severity = 'low'): string {
  const shown = report.findings.filter((finding) => atLeast(finding, min));
  const files = report.files.filter((file) => file.packages);
  const out = [
    `Checked ${plural(report.packages, 'package')}${report.ecosystems.length ? ` (${report.ecosystems.join(', ')})` : ''}${files.length ? ` from ${plural(files.length, 'file')}` : ''} in ${report.target} against ${sourcesText(report)} at ${report.checked_at}.`,
    ...incomplete(report),
  ];
  if (!report.packages)
    out.push(
      'No dependencies found. Supported files: lockfiles and manifests for npm, Python, Go, Rust, PHP, Ruby, Java, .NET, Dart, Elixir, Swift and Haskell, or a CycloneDX/SPDX SBOM.',
    );
  if (report.unversioned)
    out.push(
      report.kind === 'packages'
        ? `${plural(report.unversioned, 'package')} named without a version: every advisory for ${report.unversioned === 1 ? 'it is' : 'them is'} listed.`
        : `${plural(report.unversioned, 'package')} had no exact version${report.files.length ? ' (a manifest without its lockfile)' : ''} and could only be checked by name.`,
    );
  const affected = report.findings.filter((finding) => finding.applicability === 'affected');
  const byHand = report.findings.length - affected.length;
  const noSeverity = report.findings.filter((finding) => finding.priority === 'unknown').length;
  if (report.packages)
    out.push(
      report.findings.length
        ? `${plural(affected.length, 'known vulnerability')} in ${report.kind === 'packages' ? 'these versions' : 'installed versions'}${byHand ? `, ${byHand} ${report.kind === 'packages' ? 'for packages named without a version' : 'to check by hand (no exact version)'}` : ''}${noSeverity ? `; ${noSeverity} without a severity in the advisory` : ''}${hiddenText(report.findings, shown, min)}:`
        : report.degraded
          ? 'No known vulnerabilities in the packages that could be checked.'
          : 'No known vulnerabilities in these versions.',
    );
  out.push(...shown.map((finding) => findingLine(finding, report.kind)));
  const upgrades = upgradeSummary(shown);
  if (upgrades.length) out.push('', 'Upgrades that fix several at once:', ...upgrades);
  out.push(...notes(report));
  return out.join('\n');
}

export function formatChangeReport(change: ChangeReport, min: Severity = 'low'): string {
  const { packages } = change;
  const out = [
    `Compared dependencies in ${change.head.target} at ${change.base} (${change.commit.slice(0, 12)}) with the working tree: ${plural(packages.added.length, 'package')} added, ${packages.removed.length} removed, ${packages.changed.length} changed.`,
    ...incomplete(change.head),
  ];
  for (const [label, list] of [
    ['Added', packages.added],
    ['Changed', packages.changed],
    ['Removed', packages.removed],
  ] as const)
    if (list.length)
      out.push(
        `${label}: ${list.slice(0, 15).join('; ')}${list.length > 15 ? `; and ${list.length - 15} more` : ''}`,
      );
  const added = change.added.filter((finding) => atLeast(finding, min));
  out.push(
    '',
    change.added.length
      ? `The change brings in ${plural(change.added.length, 'known vulnerability')}${hiddenText(change.added, added, min)}:`
      : 'The change brings in no known vulnerabilities.',
    ...added.map((finding) => findingLine(finding)),
  );
  const upgrades = upgradeSummary(added);
  if (upgrades.length) out.push('', 'Upgrades that fix several at once:', ...upgrades);
  if (change.resolved.length)
    out.push(
      '',
      `It fixes ${change.resolved.length}:`,
      ...change.resolved
        .slice(0, 20)
        .map((finding) => `- ${finding.package.name}: ${finding.id} ${finding.title}`),
      ...(change.resolved.length > 20 ? [`- and ${change.resolved.length - 20} more`] : []),
    );
  if (change.unchanged)
    out.push('', `${plural(change.unchanged, 'known vulnerability')} were there before and still are.`);
  out.push(...notes(change.head));
  return out.join('\n');
}

export function formatAdvisoryReport(report: AdvisoryReport): string {
  const out: string[] = [];
  if (!report.found)
    out.push(
      `OSV has no record under ${report.id}. If it was published in the last hours, OSV may not have it yet; the vendor's advisory or GitHub's advisory database may.`,
    );
  else {
    out.push(
      `${report.id}${report.title ? `: ${report.title}` : ''}${report.severity ? ` [${report.severity}]` : ''}`,
    );
    if (report.aliases.length) out.push(`Also known as: ${report.aliases.slice(0, 8).join(', ')}`);
    if (report.summary && !(report.title && report.summary.startsWith(report.title)))
      out.push(report.summary);
    if (report.packages.length)
      out.push(
        `Packages it concerns: ${report.packages
          .slice(0, 10)
          .map(
            (item) =>
              `${item.ecosystem} ${item.name}${item.range ? ` ${item.range}` : ''}${item.fixed ? ` (fixed in ${item.fixed})` : ''}`,
          )
          .join('; ')}${report.packages.length > 10 ? `; and ${report.packages.length - 10} more` : ''}`,
      );
    else
      out.push(
        'The record names no package ecosystem Security Watch reads (it may concern an operating system, a product or source code).',
      );
    if (report.url) out.push(report.url);
  }
  out.push('', `Project: ${report.project.target}`, ...incomplete(report.project));
  const affected = report.findings.filter((finding) => finding.applicability === 'affected');
  const unknown = report.findings.filter((finding) => finding.applicability !== 'affected');
  if (affected.length)
    out.push('This project IS affected:', ...affected.map((finding) => findingLine(finding)));
  if (unknown.length)
    out.push(
      `This project MAY be affected: it has the package without an exact version (no lockfile), so the version in use cannot be compared. Check the installed version against the ranges above:`,
      ...unknown.map((finding) => findingLine(finding)),
    );
  if (!report.findings.length) {
    if (report.present_not_affected.length)
      out.push(
        `This project has ${report.present_not_affected.join(', ')}, at versions the advisory does not list as affected.`,
      );
    else if (report.project.packages)
      out.push(
        `This project ${report.project.degraded ? 'shows no' : 'is not affected: none of its'} ${plural(report.project.packages, 'package')}${report.project.degraded ? ' that could be read with an affected version' : ' is named with an affected version'}.`,
      );
    else out.push('No dependencies were found in this project, so nothing could be matched.');
  }
  out.push(...notes(report.project));
  return out.join('\n');
}
