import { readFileSync, statSync } from 'node:fs';
import type { Assessment, Evidence, Inventory } from './types.js';
import { timestamp } from './util.js';

/**
 * Runtime mitigation status (a shield, a blocking policy, a firewall rule, a live patch) read from
 * JSON Lines files that the operator writes on a timer: Shirudo's `node_vulns` export, or the generic
 * format any tool can produce. Security Watch never connects to the tool and holds no credential for it.
 *
 * The status is shown only, like EPSS: it never changes applicability, priority, routing or a
 * finding's revision, and a mitigation never closes a finding. It is temporary; the fix is not.
 */

export const MITIGATION_STATES = [
  'mitigated',
  'pending',
  'failed',
  'excluded',
  'withdrawn',
  'expired',
  'unmitigated',
  'unknown',
] as const;
export type MitigationState = (typeof MITIGATION_STATES)[number];
export type MitigationFormat = 'shirudo' | 'generic';

/** Worst first: a host reported in several rows for one finding counts once, by its worst row. */
const WORST_FIRST: MitigationState[] = [
  'unmitigated',
  'expired',
  'withdrawn',
  'excluded',
  'failed',
  'unknown',
  'pending',
  'mitigated',
];
const WORDS: Record<MitigationState, string> = {
  mitigated: 'mitigated',
  pending: 'mitigation waiting to load',
  failed: 'mitigation failed to load',
  excluded: 'mitigation excludes the host',
  withdrawn: 'mitigation withdrawn',
  expired: 'mitigation expired',
  unmitigated: 'not mitigated',
  unknown: 'status unknown',
};
/** Shirudo's `exposure` values in the generic vocabulary. */
const SHIRUDO_STATES: Record<string, MitigationState | 'none'> = {
  shielded: 'mitigated',
  shield_pending: 'pending',
  shield_module_absent: 'failed',
  shield_excludes_node: 'excluded',
  shield_withdrawn: 'withdrawn',
  exposed_no_shield: 'unmitigated',
  unknown: 'unknown',
  none: 'none',
};

/** One host's state for one finding, from either format. */
export interface MitigationRow {
  /** The system key: Shirudo's image ID, or the generic `system_id`; `systems` maps it to a system ID. */
  system: string;
  host: string;
  /** The advisory identifier (CVE, GHSA, ...), upper case; empty for a `none` row. */
  identifier: string;
  package?: string;
  /** A kernel row matches by identifier alone. */
  kernel?: boolean;
  /** `none`: a host with nothing to report, counted among the hosts of its system. */
  state: MitigationState | 'none';
  /** The shield, policy or patch that mitigates it. */
  mitigation?: string;
  /** When a mitigated or pending row stops counting, in milliseconds (generic `expires_at`). */
  expires?: number;
}

export interface MitigationSource {
  /** Shown in alerts. Unique among sources. */
  name: string;
  format: MitigationFormat;
  file: string;
  max_age_minutes: number;
  /** Row system key to Security Watch system ID; an unmapped key is the system ID. */
  systems: Record<string, string>;
}

export interface MitigationExport {
  /** The file's modification time. */
  exported_at: string;
  stale: boolean;
  rows: MitigationRow[];
  /** Lines that could not be read, with the first reason. */
  skipped: number;
  first_problem?: string;
  /** Rows with a status or exposure value this release does not know; read as `unknown`. */
  unknown_values: number;
  /** Shirudo rows of machines bound to no image: they belong to no system and are left out. */
  unbound: number;
}

/** What one source reports for one finding across the hosts running the finding's system. */
export interface MitigationStatus {
  /** The source's `name`. */
  source: string;
  format: MitigationFormat;
  exported_at: string;
  /** The export is older than the source's `max_age_minutes`. */
  stale: boolean;
  /** Hosts of the system in the export. */
  hosts: number;
  /** Hosts per state, each host counted once by its worst row for this finding. */
  states: Partial<Record<MitigationState, number>>;
  /** The source has no row for this finding on those hosts: it does not know about it. */
  not_listed?: boolean;
  /** Mitigations in place or waiting to load. A withdrawn, expired or failed one is not named. */
  mitigations: string[];
  /** The earliest time a mitigation counted here expires; after it, `mitigated` is no longer proven. */
  expires_at?: string;
  /**
   * Why `stale` is true when it was set on reading rather than at the scan: the export is now older than
   * the source's limit, the source is no longer configured, or a mitigation counted here has expired.
   */
  stale_reason?: 'old_export' | 'source_removed' | 'expired';
  /** One line for people. */
  summary: string;
}

export const MAX_EXPORT_BYTES = 64 * 1024 * 1024;
export const MAX_EXPORT_ROWS = 500_000;
const MAX_FIELD = 512;
/** Line and paragraph separators, other C1 controls, zero-width and bidirectional marks. */
const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/;

function field(value: unknown, required: boolean): string | undefined {
  if (value === undefined || value === null || value === '') {
    if (required) throw new Error('missing field');
    return undefined;
  }
  // A number beyond 2^53 has already lost digits: two machine IDs would become one.
  if (typeof value !== 'string' && (typeof value !== 'number' || !Number.isSafeInteger(value)))
    throw new Error('not text');
  const text = String(value).trim();
  if (!text) {
    if (required) throw new Error('missing field');
    return undefined;
  }
  if (text.length > MAX_FIELD || UNSAFE_TEXT.test(text)) throw new Error('invalid text');
  return text;
}
/** A display-only field: an odd value is left out instead of costing the row. */
function optionalField(value: unknown): string | undefined {
  try {
    return field(value, false);
  } catch {
    return undefined;
  }
}
function objectOf(line: string): Record<string, unknown> {
  let data: unknown;
  try {
    data = JSON.parse(line);
  } catch {
    throw new Error('not JSON');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not an object');
  return data as Record<string, unknown>;
}
function withOptional(
  row: MitigationRow,
  extra: { package?: string | undefined; mitigation?: string | undefined; expires?: number | undefined },
): MitigationRow {
  return {
    ...row,
    ...(extra.package ? { package: extra.package } : {}),
    ...(extra.mitigation ? { mitigation: extra.mitigation } : {}),
    ...(extra.expires !== undefined ? { expires: extra.expires } : {}),
  };
}

/** A row and whether one of its values was one this release does not know. */
type Parsed = { row: MitigationRow; unknown_value: boolean } | { unbound: true };

/**
 * One line of a Shirudo `node_vulns` export; throws with a short reason when it is not one. A node
 * that has stopped reporting (`status: stale`) proves nothing about its shields: its rows are
 * `unknown`. A row of a node bound to no image belongs to no system and is set aside.
 */
export function parseShirudoRow(line: string): Parsed {
  const row = objectOf(line);
  if (row.image_id === '' || row.image_id === null || row.image_id === undefined) {
    field(row.node_id, true);
    return { unbound: true };
  }
  const known = typeof row.exposure === 'string' && Object.hasOwn(SHIRUDO_STATES, row.exposure);
  let state = known ? SHIRUDO_STATES[row.exposure as string]! : 'unknown';
  if (state !== 'none' && optionalField(row.status) === 'stale') state = 'unknown';
  // The fields used for matching must be valid, or the row is skipped and counted; the rest are shown
  // only and are left out when odd.
  const identifier = (field(row.vuln_id, state !== 'none') ?? '').toUpperCase();
  return {
    row: withOptional(
      {
        system: field(row.image_id, true)!,
        host: field(row.node_id, true)!,
        identifier,
        ...(optionalField(row.source) === 'kernel' ? { kernel: true } : {}),
        state,
      },
      { package: field(row.package, false), mitigation: optionalField(row.upatch_id) },
    ),
    unknown_value: !known,
  };
}

/** ISO 8601 with a zone, or a plain date (read as UTC midnight); nothing else is a time. */
const ISO_TIME = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2}))?$/;

/**
 * One line of the generic format:
 * `{"system_id", "host", "identifier", "package"?, "kernel"?, "status", "mitigation"?, "expires_at"?}`.
 * A mitigated or pending row whose `expires_at` has passed is `expired`.
 */
export function parseGenericRow(line: string, now: number): Parsed {
  const row = objectOf(line);
  const status = row.status;
  const known =
    status === 'none' ||
    (typeof status === 'string' && (MITIGATION_STATES as readonly string[]).includes(status));
  let state: MitigationState | 'none' = known ? (status as MitigationState | 'none') : 'unknown';
  let expires: number | undefined;
  if (row.expires_at !== undefined && row.expires_at !== null) {
    if (typeof row.expires_at !== 'string' || !ISO_TIME.test(row.expires_at))
      throw new Error('invalid expires_at');
    expires = Date.parse(/T/.test(row.expires_at) ? row.expires_at : `${row.expires_at}T00:00:00Z`);
    if (!Number.isFinite(expires)) throw new Error('invalid expires_at');
    if (expires <= now && (state === 'mitigated' || state === 'pending')) state = 'expired';
  }
  if (row.kernel !== undefined && typeof row.kernel !== 'boolean')
    throw new Error('kernel is not true or false');
  const identifier = (field(row.identifier, state !== 'none') ?? '').toUpperCase();
  return {
    row: withOptional(
      {
        system: field(row.system_id, true)!,
        host: field(row.host, true)!,
        identifier,
        ...(row.kernel === true ? { kernel: true } : {}),
        state,
      },
      {
        package: field(row.package, false),
        mitigation: optionalField(row.mitigation),
        ...(state === 'mitigated' || state === 'pending' ? { expires } : {}),
      },
    ),
    unknown_value: !known,
  };
}

/**
 * Reads an export. Throws when the file is missing, not a regular file, too large, not UTF-8 text or
 * has no readable row at all; individual bad lines are skipped and counted, so one odd row never
 * hides the rest.
 */
export function readMitigationExport(source: MitigationSource, now: number): MitigationExport {
  const stat = statSync(source.file);
  if (!stat.isFile()) throw new Error('not a regular file');
  if (stat.size > MAX_EXPORT_BYTES) throw new Error(`larger than ${MAX_EXPORT_BYTES / 1024 / 1024} MiB`);
  const bytes = readFileSync(source.file);
  if (
    bytes.length >= 2 &&
    ((bytes[0] === 0xff && bytes[1] === 0xfe) || (bytes[0] === 0xfe && bytes[1] === 0xff))
  )
    throw new Error('the file is UTF-16 text; write it as UTF-8 (PowerShell: Out-File -Encoding utf8)');
  // A byte order mark is not part of the first row; Windows line ends are line ends.
  const text = bytes.toString('utf8').replace(/^\ufeff/, '');
  const parse = source.format === 'shirudo' ? parseShirudoRow : (line: string) => parseGenericRow(line, now);
  const rows: MitigationRow[] = [];
  let skipped = 0;
  let unknown = 0;
  let unbound = 0;
  let firstProblem: string | undefined;
  let lineNumber = 0;
  for (const raw of text.split('\n')) {
    lineNumber++;
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (!line.trim()) continue;
    if (rows.length + skipped + unbound >= MAX_EXPORT_ROWS)
      throw new Error(`more than ${MAX_EXPORT_ROWS} rows`);
    try {
      const parsed = parse(line);
      if ('unbound' in parsed) unbound++;
      else {
        rows.push(parsed.row);
        if (parsed.unknown_value) unknown++;
      }
    } catch (error) {
      skipped++;
      firstProblem ??= `line ${lineNumber}: ${(error as Error).message}`;
    }
  }
  if (!rows.length && skipped) throw new Error(`no readable row (${firstProblem})`);
  return {
    exported_at: timestamp(stat.mtimeMs),
    // A modification time ahead of the clock is not fresh either: the file cannot be trusted to be current.
    stale: now - stat.mtimeMs > source.max_age_minutes * 60_000 || stat.mtimeMs - now > 5 * 60_000,
    rows,
    skipped,
    ...(firstProblem ? { first_problem: firstProblem } : {}),
    unknown_values: unknown,
    unbound,
  };
}

/** Problems with an export that should reach monitoring health. */
export function exportProblems(exported: MitigationExport, source: MitigationSource, now: number): string[] {
  const problems: string[] = [];
  const age = Math.round((now - Date.parse(exported.exported_at)) / 60_000);
  if (exported.stale)
    problems.push(
      age < 0
        ? `${source.name}: the export's modification time is ${-age} minutes in the future; check the clock of the machine that writes it.`
        : `${source.name}: the export was written ${age} minutes ago, more than max_age_minutes (${source.max_age_minutes}); its status may be out of date.`,
    );
  if (!exported.rows.length && !exported.skipped)
    problems.push(
      `${source.name}: the export has no row for any system, so no mitigation status is shown. Check the export job: a fleet with hosts has at least one row per host.`,
    );
  if (exported.skipped)
    problems.push(
      `${source.name}: ${exported.skipped} line(s) of the export could not be read and were left out (${exported.first_problem}).`,
    );
  if (exported.unknown_values)
    problems.push(
      `${source.name}: ${exported.unknown_values} row(s) have a status this release does not know and are shown as status unknown; the tool may have added a value.`,
    );
  return problems;
}

/** Whether an export says anything about the inventory's systems: rows that all miss is a mapping mistake. */
export function unmatchedSystems(
  exported: MitigationExport,
  source: MitigationSource,
  systemIds: ReadonlySet<string>,
): string[] {
  const keys = new Set(exported.rows.map((row) => row.system));
  return [...keys].filter(
    (key) => !systemIds.has(Object.hasOwn(source.systems, key) ? source.systems[key]! : key),
  );
}

/** Package names compare as their ecosystem compares them: PyPI folds case and separators, the rest only case. */
function samePackage(row: string, component: { ecosystem: string; name: string }): boolean {
  const fold = (name: string) =>
    component.ecosystem === 'PyPI'
      ? name
          .trim()
          .toLowerCase()
          .replace(/[-_.]+/g, '-')
      : name.trim().toLowerCase();
  return fold(row) === fold(component.name);
}
function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

/** Rows of one system, by identifier, with every host the system has in the export. */
interface SystemRows {
  hosts: Set<string>;
  byIdentifier: Map<string, MitigationRow[]>;
}

/**
 * Finds one source's rows for a finding: rows whose system key belongs to the finding's system, whose
 * identifier is the finding's event or one of its current advisories' aliases, and, for a library
 * finding, whose package is the finding's package. A row without a package says nothing about a
 * library (one CVE can name several packages); a kernel row matches by identifier alone.
 */
export class MitigationIndex {
  readonly #systems = new Map<string, SystemRows>();
  readonly #export: MitigationExport;
  readonly #source: MitigationSource;

  constructor(exported: MitigationExport, source: MitigationSource) {
    this.#export = exported;
    this.#source = source;
    for (const row of exported.rows) {
      const system = Object.hasOwn(source.systems, row.system) ? source.systems[row.system]! : row.system;
      let entry = this.#systems.get(system);
      if (!entry) {
        entry = { hosts: new Set(), byIdentifier: new Map() };
        this.#systems.set(system, entry);
      }
      // A host is named per system key: the same name under two keys is two machines.
      entry.hosts.add(`${row.system}\u0000${row.host}`);
      if (row.state === 'none') continue;
      const list = entry.byIdentifier.get(row.identifier) ?? [];
      list.push(row);
      entry.byIdentifier.set(row.identifier, list);
    }
  }

  status(
    finding: Assessment,
    evidence: Map<string, Evidence>,
    inventory?: Inventory,
  ): MitigationStatus | undefined {
    if (finding.category === 'health' || finding.category === 'malware') return undefined;
    const entry = this.#systems.get(finding.system_id);
    if (!entry) return undefined;
    const identifiers = new Set([finding.event_id.toUpperCase()]);
    for (const id of finding.evidence_ids) {
      const item = evidence.get(id);
      if (item && item.kind !== 'news' && item.kind !== 'health' && !item.withdrawn)
        for (const alias of item.aliases) identifiers.add(alias.toUpperCase());
    }
    const component =
      finding.component_id && inventory
        ? inventory.systems
            .find((system) => system.id === finding.system_id)
            ?.components.find((item) => item.id === finding.component_id)
        : undefined;
    const library = finding.category === 'library';
    const worst = new Map<string, MitigationState>();
    const mitigations = new Set<string>();
    let expires: number | undefined;
    for (const identifier of identifiers)
      for (const row of entry.byIdentifier.get(identifier) ?? []) {
        if (library && !row.kernel) {
          if (!row.package) continue;
          if (component && !samePackage(row.package, component)) continue;
        }
        // Rows of `none` are never indexed by identifier; this keeps the type exact.
        if (row.state === 'none') continue;
        const host = `${row.system}\u0000${row.host}`;
        const known = worst.get(host);
        if (!known || WORST_FIRST.indexOf(row.state) < WORST_FIRST.indexOf(known)) worst.set(host, row.state);
        if (row.state === 'mitigated' || row.state === 'pending') {
          if (row.mitigation) mitigations.add(row.mitigation);
          if (row.expires !== undefined) expires = Math.min(expires ?? row.expires, row.expires);
        }
      }
    const hosts = entry.hosts.size;
    const states: Partial<Record<MitigationState, number>> = {};
    for (const value of worst.values()) states[value] = (states[value] ?? 0) + 1;
    const base = {
      source: this.#source.name,
      format: this.#source.format,
      exported_at: this.#export.exported_at,
      stale: this.#export.stale,
      hosts,
      states,
      mitigations: [...mitigations].sort().slice(0, 20),
      ...(expires !== undefined ? { expires_at: timestamp(expires) } : {}),
    };
    if (!worst.size)
      return {
        ...base,
        not_listed: true,
        summary: `${this.#source.name} lists no such finding on the ${plural(hosts, 'host')} running this system, so no mitigation is linked to it.`,
      };
    // How many hosts are covered comes first, then those that are not, worst first.
    const parts = [
      `mitigated on ${states.mitigated ?? 0} of ${plural(hosts, 'host')}`,
      ...WORST_FIRST.filter((value) => value !== 'mitigated' && states[value]).map(
        (value) => `${states[value]} ${WORDS[value]}`,
      ),
    ];
    const unreported = hosts - worst.size;
    if (unreported) parts.push(`${unreported} not listed for it`);
    return { ...base, summary: `${this.#source.name}: ${parts.join('; ')}.` };
  }
}

/**
 * Whether a status proves that every host it covers is mitigated now: fresh, listed, all hosts
 * mitigated, and no counted mitigation expired since the export.
 */
export function mitigatedEverywhere(status: MitigationStatus, now = Date.now()): boolean {
  const expiry = status.expires_at === undefined ? undefined : Date.parse(status.expires_at);
  return (
    !status.stale &&
    !status.not_listed &&
    status.hosts > 0 &&
    status.states.mitigated === status.hosts &&
    (expiry === undefined || expiry > now)
  );
}

/**
 * A saved status as it stands now. Statuses are saved at each scan; when scans stop, or a mitigation
 * expires between scans, a reader must not show the saved one as current. `maxAgeByName` holds each
 * configured source's `max_age_minutes`; a source that is no longer configured proves nothing.
 */
export function currentStatus(
  status: MitigationStatus,
  maxAgeByName: Readonly<Record<string, number>> | undefined,
  now: number,
): MitigationStatus {
  if (status.stale) return status;
  const exported = Date.parse(status.exported_at);
  const expiry = status.expires_at === undefined ? undefined : Date.parse(status.expires_at);
  let reason: MitigationStatus['stale_reason'];
  if (maxAgeByName && !Object.hasOwn(maxAgeByName, status.source)) reason = 'source_removed';
  else if (
    !Number.isFinite(exported) ||
    (maxAgeByName && now - exported > maxAgeByName[status.source]! * 60_000)
  )
    reason = 'old_export';
  else if (expiry !== undefined && expiry <= now) reason = 'expired';
  return reason ? { ...status, stale: true, stale_reason: reason } : status;
}

/** A finding with its saved statuses as they stand now. */
export function withCurrentMitigations<T extends Assessment>(
  finding: T,
  maxAgeByName: Readonly<Record<string, number>> | undefined,
  now: number,
): T {
  return finding.mitigations?.length
    ? {
        ...finding,
        mitigations: finding.mitigations.map((status) => currentStatus(status, maxAgeByName, now)),
      }
    : finding;
}

/** Each configured source's limit, by name, for `currentStatus`. */
export function maxAges(sources: readonly MitigationSource[] | undefined): Record<string, number> {
  return Object.fromEntries((sources ?? []).map((source) => [source.name, source.max_age_minutes]));
}

/** Attaches the current statuses, or removes earlier ones when there are none now. */
export function attachMitigations(
  finding: Assessment,
  indexes: readonly MitigationIndex[],
  evidence: Map<string, Evidence>,
  inventory?: Inventory,
): Assessment {
  // `runtime_shield` was this field's name in unreleased development builds; it is dropped too.
  const {
    mitigations: _previous,
    runtime_shield: _old,
    ...rest
  } = finding as Assessment & {
    runtime_shield?: unknown;
  };
  const statuses = indexes
    .map((index) => index.status(rest, evidence, inventory))
    .filter((status): status is MitigationStatus => status !== undefined);
  return statuses.length ? { ...rest, mitigations: statuses } : rest;
}
