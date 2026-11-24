import { readFileSync, statSync } from 'node:fs';
import type { Assessment, Evidence, Inventory } from './types.js';
import { timestamp } from './util.js';

/**
 * Runtime shield status from Shirudo (https://shirudo.dev), read from a JSON Lines export of its
 * `shirudo.node_vulns` table that the operator writes on a timer. Security Watch never connects to
 * ClickHouse and holds no Shirudo credential.
 *
 * The status is shown only, like EPSS: it never changes applicability, priority, routing or a
 * finding's revision, and a shield never closes a finding. A shield is a temporary safeguard.
 */

export const SHIRUDO_EXPOSURES = [
  'shielded',
  'shield_pending',
  'shield_module_absent',
  'shield_excludes_node',
  'shield_withdrawn',
  'exposed_no_shield',
  'unknown',
] as const;
export type ShirudoExposure = (typeof SHIRUDO_EXPOSURES)[number];

/** Worst first: a node reported in several rows for one finding counts once, by its worst row. */
const WORST_FIRST: ShirudoExposure[] = [
  'exposed_no_shield',
  'shield_withdrawn',
  'shield_excludes_node',
  'shield_module_absent',
  'unknown',
  'shield_pending',
  'shielded',
];
const WORDS: Record<ShirudoExposure, string> = {
  shielded: 'shielded',
  shield_pending: 'shield waiting to load',
  shield_module_absent: 'shield cannot load (module absent)',
  shield_excludes_node: 'shield excludes the node',
  shield_withdrawn: 'shield withdrawn',
  exposed_no_shield: 'exposed with no shield',
  unknown: 'status unknown',
};

export interface ShirudoRow {
  node_id: string;
  host_name?: string;
  image_id: string;
  image_version?: string;
  /** `sbom`, `kernel` or `none` (a node with no finding). */
  source?: string;
  vuln_id: string;
  package?: string;
  installed?: string;
  fixed?: string;
  exposure: ShirudoExposure | 'none';
  upatch_id?: string;
}

export interface ShirudoExport {
  /** The export file's modification time. */
  exported_at: string;
  stale: boolean;
  rows: ShirudoRow[];
  /** Rows that could not be read, with the first reason. */
  skipped: number;
  first_problem?: string;
}

/** What Shirudo reports for one finding across the nodes running the finding's system. */
export interface RuntimeShieldStatus {
  source: 'shirudo';
  exported_at: string;
  /** The export is older than `shirudo.max_age_minutes`. */
  stale: boolean;
  /** Nodes running the system's image(s) in the export. */
  nodes: number;
  /** Nodes per exposure, each node counted once by its worst row for this finding. */
  exposure: Partial<Record<ShirudoExposure, number>>;
  /** Shirudo has no row for this finding on those nodes: it does not know about it, so no shield is linked. */
  not_in_shirudo?: boolean;
  /** Upatches named in the rows: the shields in place or waiting. */
  upatch_ids: string[];
  /** One line for people. */
  summary: string;
}

export interface ShirudoSettings {
  exposure_file: string;
  max_age_minutes: number;
  image_systems: Record<string, string>;
}

export const MAX_EXPORT_BYTES = 64 * 1024 * 1024;
export const MAX_EXPORT_ROWS = 500_000;
const MAX_FIELD = 512;

function field(value: unknown, required: boolean): string | undefined {
  if (value === undefined || value === null || value === '') {
    if (required) throw new Error('missing field');
    return undefined;
  }
  if (typeof value !== 'string' && typeof value !== 'number') throw new Error('not text');
  const text = String(value).trim();
  if (!text) {
    if (required) throw new Error('missing field');
    return undefined;
  }
  if (text.length > MAX_FIELD || /[\u0000-\u001f\u007f]/.test(text)) throw new Error('invalid text');
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

function exposureOf(value: unknown): ShirudoExposure | 'none' {
  if (value === 'none') return 'none';
  return (SHIRUDO_EXPOSURES as readonly unknown[]).includes(value) ? (value as ShirudoExposure) : 'unknown';
}

/** One export line; throws with a short reason when it is not a node_vulns row. */
export function parseShirudoRow(line: string): ShirudoRow {
  let data: unknown;
  try {
    data = JSON.parse(line);
  } catch {
    throw new Error('not JSON');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not an object');
  const row = data as Record<string, unknown>;
  const exposure = exposureOf(row.exposure);
  // The fields used for matching must be valid, or the row is skipped and counted; the rest are shown
  // only and are left out when odd.
  const vuln = field(row.vuln_id, exposure !== 'none');
  const pkg = field(row.package, false);
  const optional = {
    host_name: optionalField(row.host_name),
    image_version: optionalField(row.image_version),
    source: optionalField(row.source),
    installed: optionalField(row.installed),
    fixed: optionalField(row.fixed),
    upatch_id: optionalField(row.upatch_id),
  };
  return {
    node_id: field(row.node_id, true)!,
    image_id: field(row.image_id, true)!,
    vuln_id: vuln ?? '',
    ...(pkg ? { package: pkg } : {}),
    exposure,
    ...Object.fromEntries(Object.entries(optional).filter(([, value]) => value !== undefined)),
  };
}

/**
 * Reads the export. Throws when the file is missing, too large or has no readable row at all;
 * individual bad lines are skipped and counted, so one odd row never hides the rest.
 */
export function readShirudoExport(settings: ShirudoSettings, now: number): ShirudoExport {
  const stat = statSync(settings.exposure_file);
  if (!stat.isFile()) throw new Error('The Shirudo export is not a regular file.');
  if (stat.size > MAX_EXPORT_BYTES)
    throw new Error(`The Shirudo export is larger than ${MAX_EXPORT_BYTES / 1024 / 1024} MiB.`);
  // A byte order mark is not part of the first row.
  const text = readFileSync(settings.exposure_file, 'utf8').replace(/^\uFEFF/, '');
  const rows: ShirudoRow[] = [];
  let skipped = 0;
  let firstProblem: string | undefined;
  let lineNumber = 0;
  for (const line of text.split('\n')) {
    lineNumber++;
    if (!line.trim()) continue;
    if (rows.length >= MAX_EXPORT_ROWS)
      throw new Error(`The Shirudo export has more than ${MAX_EXPORT_ROWS} rows.`);
    try {
      rows.push(parseShirudoRow(line));
    } catch (error) {
      skipped++;
      firstProblem ??= `line ${lineNumber}: ${(error as Error).message}`;
    }
  }
  if (!rows.length && skipped) throw new Error(`The Shirudo export has no readable row (${firstProblem}).`);
  const modified = stat.mtimeMs;
  return {
    exported_at: timestamp(modified),
    stale: now - modified > settings.max_age_minutes * 60_000,
    rows,
    skipped,
    ...(firstProblem ? { first_problem: firstProblem } : {}),
  };
}

/** Problems with an export that should reach monitoring health. */
export function exportProblems(exported: ShirudoExport, settings: ShirudoSettings, now: number): string[] {
  const problems: string[] = [];
  if (exported.stale)
    problems.push(
      `The Shirudo export was written ${Math.round((now - Date.parse(exported.exported_at)) / 60_000)} minutes ago, more than shirudo.max_age_minutes (${settings.max_age_minutes}); runtime shield status may be out of date.`,
    );
  if (!exported.rows.length && !exported.skipped)
    problems.push(
      'The Shirudo export is empty, so no runtime shield status is shown. Check the export job: a fleet with machines has at least one row per machine.',
    );
  if (exported.skipped)
    problems.push(
      `${exported.skipped} line(s) of the Shirudo export could not be read and were left out (${exported.first_problem}).`,
    );
  return problems;
}

function packageKey(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[-_.]+/g, '-');
}

/**
 * Finds the rows for one finding: rows of images that belong to the finding's system, whose advisory
 * ID is the finding's event or one of its advisories' aliases, and, for a library finding, whose
 * package is the finding's package. A kernel row names no package and matches by identifier alone.
 */
export class ShirudoIndex {
  readonly #byImage = new Map<string, ShirudoRow[]>();
  readonly #systemImages = new Map<string, Set<string>>();
  readonly #export: ShirudoExport;

  constructor(exported: ShirudoExport, settings: ShirudoSettings) {
    this.#export = exported;
    for (const row of exported.rows) {
      const list = this.#byImage.get(row.image_id) ?? [];
      list.push(row);
      this.#byImage.set(row.image_id, list);
      const system = Object.hasOwn(settings.image_systems, row.image_id)
        ? settings.image_systems[row.image_id]!
        : row.image_id;
      const images = this.#systemImages.get(system) ?? new Set<string>();
      images.add(row.image_id);
      this.#systemImages.set(system, images);
    }
  }

  status(
    finding: Assessment,
    evidence: Map<string, Evidence>,
    inventory?: Inventory,
  ): RuntimeShieldStatus | undefined {
    if (finding.category === 'health' || finding.category === 'malware') return undefined;
    const images = this.#systemImages.get(finding.system_id);
    if (!images) return undefined;
    const identifiers = new Set([finding.event_id.toUpperCase()]);
    for (const id of finding.evidence_ids) {
      const item = evidence.get(id);
      if (item && item.kind !== 'news' && item.kind !== 'health')
        for (const alias of item.aliases) identifiers.add(alias.toUpperCase());
    }
    const component =
      finding.component_id && inventory
        ? inventory.systems
            .find((system) => system.id === finding.system_id)
            ?.components.find((item) => item.id === finding.component_id)
        : undefined;
    const wanted = component ? packageKey(component.name) : undefined;
    const nodes = new Set<string>();
    const worst = new Map<string, ShirudoExposure>();
    const upatches = new Set<string>();
    for (const image of images)
      for (const row of this.#byImage.get(image) ?? []) {
        nodes.add(row.node_id);
        if (row.exposure === 'none' || !identifiers.has(row.vuln_id.toUpperCase())) continue;
        if (wanted && row.package && row.source !== 'kernel' && packageKey(row.package) !== wanted) continue;
        const known = worst.get(row.node_id);
        if (!known || WORST_FIRST.indexOf(row.exposure) < WORST_FIRST.indexOf(known))
          worst.set(row.node_id, row.exposure);
        // Only shields in place or waiting to load are named; a withdrawn one protects nothing.
        if (row.upatch_id && (row.exposure === 'shielded' || row.exposure === 'shield_pending'))
          upatches.add(row.upatch_id);
      }
    if (!nodes.size) return undefined;
    const exposure: Partial<Record<ShirudoExposure, number>> = {};
    for (const value of worst.values()) exposure[value] = (exposure[value] ?? 0) + 1;
    const base = {
      source: 'shirudo' as const,
      exported_at: this.#export.exported_at,
      stale: this.#export.stale,
      nodes: nodes.size,
      exposure,
      upatch_ids: [...upatches].sort().slice(0, 20),
    };
    if (!worst.size)
      return {
        ...base,
        not_in_shirudo: true,
        summary: `Shirudo lists no such finding on the ${plural(nodes.size, 'node')} running this system, so no shield is linked to it.`,
      };
    // How many nodes are covered comes first, then the nodes that are not, worst first.
    const parts = [
      `shielded on ${exposure.shielded ?? 0} of ${plural(nodes.size, 'node')}`,
      ...WORST_FIRST.filter((value) => value !== 'shielded' && exposure[value]).map(
        (value) => `${exposure[value]} ${WORDS[value]}`,
      ),
    ];
    const unreported = nodes.size - worst.size;
    if (unreported) parts.push(`${unreported} not listed by Shirudo for it`);
    return { ...base, summary: `Shirudo: ${parts.join('; ')}.` };
  }
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

/** Attaches the status, or removes an earlier one when there is none now. */
export function attachRuntimeShield(
  finding: Assessment,
  index: ShirudoIndex | undefined,
  evidence: Map<string, Evidence>,
  inventory?: Inventory,
): Assessment {
  const { runtime_shield: _previous, ...rest } = finding;
  const status = index?.status(rest, evidence, inventory);
  return status ? { ...rest, runtime_shield: status } : rest;
}
