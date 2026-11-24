import { readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { explain as explainPython, valid as validPython } from '@renovatebot/pep440';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import type { Component, Inventory } from './types.js';
import {
  capitalisedName,
  exactLibraryVersion,
  mergeNotes,
  normalizeEcosystem,
  normalizePackageName,
  packageKey,
  parseLibrary,
} from './ecosystems.js';
import { hash, LINE_BREAKING, singleLine } from './util.js';
import { importSbom, type SbomImport } from './sbom.js';

// Inventory text is shown in notifications, one value per line. A control character or a Unicode
// line separator inside a name, owner or note would let that value start a line of its own.
const shortText = z
  .string()
  .trim()
  .min(1)
  .max(500)
  .refine((value) => !LINE_BREAKING.test(value), 'Control characters are not allowed');
const severity = z.enum(['unknown', 'low', 'medium', 'high', 'critical']);
const evidenceText = shortText;
const referenceText = z
  .string()
  .min(1)
  .max(1000)
  .refine((value) => !LINE_BREAKING.test(value), 'Control characters are not allowed');
const declaredVerification = z.strictObject({
  status: z.enum(['verified', 'failed', 'unknown']),
  reference: evidenceText,
  recorded_at: z.iso.datetime({ offset: true }),
  recorded_by: evidenceText.optional(),
});
const dependencyLinks = z
  .array(z.strictObject({ ref: referenceText, component_id: evidenceText.optional() }))
  .max(1000)
  .refine(
    (links) => new Set(links.map((link) => link.ref)).size === links.length,
    'Duplicate dependency reference',
  );
const dependencyGraph = z
  .array(z.strictObject({ ref: referenceText, depends_on: z.array(referenceText).max(1000) }))
  .max(20_000)
  .refine(
    (entries) => entries.reduce((count, entry) => count + entry.depends_on.length, 0) <= 100_000,
    'At most 100000 dependency edges',
  )
  .refine(
    (entries) =>
      new Set(entries.map((entry) => entry.ref)).size === entries.length &&
      entries.every((entry) => new Set(entry.depends_on).size === entry.depends_on.length),
    'Duplicate dependency reference',
  );
const inventoryEvidence = {
  artifact_kind: z
    .enum([
      'application',
      'library',
      'mcp_server',
      'mcp_client',
      'plugin',
      'skill',
      'model',
      'container',
      'other',
    ])
    .optional(),
  purl: z
    .string()
    .max(1000)
    .regex(/^pkg:[a-z][a-z0-9.+-]*\/[^\s\u0000-\u001f\u007f]+$/u)
    .optional(),
  source_url: z
    .url()
    .max(2048)
    .refine((value) => {
      const url = new URL(value);
      return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash;
    }, 'Source URL must be HTTPS without credentials, query or fragment')
    .optional(),
  source_revision: evidenceText.optional(),
  sbom_ref: referenceText.optional(),
  dependencies: dependencyLinks.optional(),
  signature_verification: declaredVerification.optional(),
  attestation_verification: declaredVerification.optional(),
  remediation_evidence: z
    .array(
      z.strictObject({
        event_id: evidenceText,
        stage: z.enum(['proposed', 'changed', 'deployed']),
        verification: z.enum(['supported', 'failed', 'unknown']),
        reference: evidenceText,
        recorded_at: z.iso.datetime({ offset: true }),
        recorded_by: evidenceText.optional(),
      }),
    )
    .max(100)
    .optional(),
  origin: shortText.optional(),
  digest: z
    .string()
    .regex(/^(?:sha256:[a-f0-9]{64}|sha384:[a-f0-9]{96}|sha512:[a-f0-9]{128})$/)
    .optional(),
  provenance: z
    .strictObject({
      source: shortText,
      reference: shortText.optional(),
      recorded_at: z.iso.datetime({ offset: true }).optional(),
    })
    .optional(),
  observation: z
    .strictObject({
      observed_at: z.iso.datetime({ offset: true }),
      method: shortText,
      reference: shortText.optional(),
    })
    .optional(),
};
const componentSchema = z
  .strictObject({
    ...inventoryEvidence,
    id: shortText,
    ecosystem: shortText,
    name: shortText,
    version: shortText.optional(),
    note: evidenceText.optional(),
  })
  .transform((component) => {
    const ecosystem = normalizeEcosystem(component.ecosystem);
    return {
      ...component,
      ecosystem,
      name: normalizePackageName(ecosystem, component.name),
      ...(component.version === undefined
        ? {}
        : { version: exactLibraryVersion(component.version, ecosystem) }),
    };
  });
const productSchema = z.strictObject({
  name: shortText,
  version: shortText.optional(),
  keywords: z.array(shortText).max(100).default([]),
  note: evidenceText.optional(),
});
const systemSchema = z.strictObject({
  ...inventoryEvidence,
  sbom_dependencies: dependencyGraph.optional(),
  configuration: z
    .record(z.string().min(1).max(100), z.union([shortText, z.boolean(), z.number().finite()]))
    .refine((value) => Object.keys(value).length <= 100, 'At most 100 configuration observations')
    .optional(),
  sbom: z.string().trim().min(1).max(4096).optional(),
  id: shortText,
  name: shortText,
  environment: shortText.default('unknown'),
  owner: shortText.optional(),
  note: evidenceText.optional(),
  exposure: z.enum(['internet', 'internal', 'unknown']).default('unknown'),
  criticality: severity.default('unknown'),
  updated_at: z.iso.datetime({ offset: true }),
  components: z.array(componentSchema).max(20_000).default([]),
  libraries: z
    .union([z.array(z.unknown()).max(20_000), z.record(z.string(), z.array(z.unknown()).max(20_000))])
    .optional(),
  products: z.array(productSchema).max(1000).default([]),
  keywords: z.array(shortText).max(100).default([]),
  lockfile: z.string().trim().min(1).max(4096).optional(),
});
const inventorySchema = z.strictObject({
  sbom_directory: z.string().trim().min(1).max(4096).optional(),
  systems: z.array(systemSchema).max(1000).default([]),
});

/** Already materialized snapshots cannot import files or expand filesystem references. */
export const inventorySnapshotSchema = z
  .strictObject({
    systems: z
      .array(systemSchema.omit({ lockfile: true, libraries: true, sbom: true }))
      .min(1)
      .max(1000),
    import_warnings: z.array(z.string().max(2000)).max(1000).optional(),
    name_notices: z.array(z.string().max(2000)).max(1000).optional(),
  })
  .refine((inventory) => {
    const ids = new Set(inventory.systems.map((system) => system.id));
    return (
      ids.size === inventory.systems.length &&
      inventory.systems.every(
        (system) =>
          new Set(system.components.map((component) => component.id)).size === system.components.length &&
          new Set(system.products.map((product) => product.name.toLowerCase())).size ===
            system.products.length,
      )
    );
  }, 'Duplicate inventory identities');

function readBounded(path: string, maximum: number): string {
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > maximum)
    throw new Error(`Inventory input must be a regular file no larger than ${maximum} bytes: ${path}`);
  const content = readFileSync(path);
  if (content.byteLength > maximum) throw new Error(`Inventory input exceeds ${maximum} bytes: ${path}`);
  return content.toString('utf8');
}

function shortLabel(value: string): string {
  return singleLine(value, 120);
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Imports metadata only. No install scripts or package manager commands are executed. */
function importLockfile(path: string): { components: Component[]; warnings: string[] } {
  const lock: unknown = JSON.parse(readBounded(path, 20 * 1024 * 1024).replace(/^\uFEFF/, ''));
  if (!record(lock) || (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) || !record(lock.packages)) {
    throw new Error(`Expected package-lock v2 or v3 with a packages map: ${path}`);
  }
  const entries = Object.entries(lock.packages);
  if (entries.length > 20_000) throw new Error(`Lockfile exceeds 20000 package entries: ${path}`);
  const components: Component[] = [];
  const warnings: string[] = [];
  for (const [location, value] of entries) {
    if (!location || !record(value) || value.link === true) continue;
    const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(location);
    if (!match) continue;
    // The location becomes the component's identifier, which is shown in notifications.
    if (LINE_BREAKING.test(location) || location.length > 480) {
      warnings.push(
        `Lockfile entry ${shortLabel(location)}: the path contains control characters or is too long; not imported.`,
      );
      continue;
    }
    // One entry this application cannot read must not hide every other dependency in the file.
    let name: string;
    let version: string | undefined;
    try {
      name = normalizePackageName('npm', z.string().parse(value.name ?? match[1]));
      version = value.version === undefined ? undefined : shortText.parse(value.version);
    } catch {
      warnings.push(
        `Lockfile entry ${shortLabel(location)}: unsupported package name or version; not imported.`,
      );
      continue;
    }
    components.push({
      id: `lock:${location}`,
      ecosystem: 'npm',
      name,
      ...(version === undefined ? {} : { version }),
    });
  }
  return { components, warnings };
}

/** Where a component was found, as its note says, or the lockfile path its identifier carries. */
function placeOf(component: Component): string | undefined {
  if (component.note) return component.note;
  return component.id.startsWith('lock:') ? `found in ${component.id.slice('lock:'.length)}` : undefined;
}

const NOTE_LIMIT = 500;
const AND_OTHERS = ' and others';

/**
 * Joins the notes of several listings into one note of at most 500 characters. Every "found in"
 * location goes into one list, written the way the SBOM importer writes it (and `check` reads it
 * back); other notes are kept as written, joined with " | ". Room is always left for the list, so
 * an operator's note cannot push out every place the package was found, nor the other way round.
 */
function joinPlaces(places: readonly string[]): string | undefined {
  const found = new Set<string>();
  let foundLength = 0;
  let more = false;
  // The number of other notes that came before the first "found in" list.
  let foundAt = -1;
  const others: string[] = [];
  for (const place of places)
    for (const part of place.split(' | ')) {
      if (!part.startsWith('found in ')) {
        if (part && !others.includes(part)) others.push(part);
        continue;
      }
      if (foundAt < 0) foundAt = others.length;
      let list = part.slice('found in '.length);
      if (list.endsWith(AND_OTHERS)) {
        more = true;
        list = list.slice(0, -AND_OTHERS.length);
      }
      for (const location of list.split(', ')) {
        if (!location || found.has(location)) continue;
        // Enough to fill any note: the rest is said as "and others", without being collected.
        if (foundLength > NOTE_LIMIT) {
          more = true;
          break;
        }
        found.add(location);
        foundLength += location.length + 2;
      }
    }
  const reserve = found.size
    ? Math.min('found in '.length + foundLength + (more ? AND_OTHERS.length : 0), 160)
    : 0;
  const kept: string[] = [];
  let used = 0;
  let before = 0;
  for (let [index, other] of others.entries()) {
    const separator = kept.length || reserve ? 3 : 0;
    // A long first note is shortened rather than left out.
    if (!kept.length && other.length + separator + reserve > NOTE_LIMIT)
      other = `${other.slice(0, NOTE_LIMIT - separator - reserve - 1)}…`;
    const cost = other.length + separator;
    if (used + cost + reserve > NOTE_LIMIT) continue;
    kept.push(other);
    used += cost;
    if (index < foundAt) before++;
  }
  if (!found.size) return kept.length ? kept.join(' | ') : undefined;
  const budget = NOTE_LIMIT - used;
  const locations = [...found];
  let list = `found in ${locations[0]}`;
  if (list.length > budget) {
    list = `${list.slice(0, budget - 1)}…`;
    more = false;
  } else
    for (const [index, location] of locations.slice(1).entries()) {
      const last = index === locations.length - 2 && !more;
      if (list.length + 2 + location.length + (last ? 0 : AND_OTHERS.length) > budget) {
        more = true;
        break;
      }
      list += `, ${location}`;
    }
  if (more && list.length + AND_OTHERS.length <= budget) list += AND_OTHERS;
  kept.splice(before, 0, list);
  return kept.join(' | ');
}

/**
 * One key for every spelling of one release of one package, as the SBOM importer judges versions:
 * Go tools write v1.8.0 or 1.8.0, and in Python 1.0, 1.0.0 and 1.0.post0 differ only in spelling
 * where the release is the same. A map of keys keeps grouping linear in the number of listings.
 */
function releaseKey(component: Component): string | undefined {
  const key = packageKey(component);
  if (!key) return undefined;
  const version = component.version;
  let release: string | null = version ?? null;
  if (version !== undefined && component.ecosystem === 'Go') release = version.replace(/^v/, '');
  else if (version !== undefined && component.ecosystem === 'PyPI' && validPython(version)) {
    const parts = explainPython(version)!;
    const numbers = [...parts.release];
    while (numbers.length > 1 && numbers.at(-1) === 0) numbers.pop();
    release = JSON.stringify([parts.epoch, numbers, parts.pre, parts.post, parts.dev, parts.local]);
  }
  return JSON.stringify([key, release]);
}

/**
 * Which listing of a package is kept: one the operator declared under `components:` (it is where
 * remediation records, verification results and observations are written), then an SBOM entry (it
 * carries the package URL and digest), a `libraries:` entry, a lockfile entry; the smallest
 * identifier among equals. None of this depends on the order a generator writes its document in.
 */
function listingRank(component: Component): number {
  const source = /^(sbom|library|lock|package):/.exec(component.id)?.[1];
  return source === undefined ? 0 : ['sbom', 'library', 'lock', 'package'].indexOf(source) + 1;
}
const byListing = (a: Component, b: Component): number =>
  listingRank(a) - listingRank(b) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/**
 * Evidence the kept listing takes from the others when it has none of its own. A digest and a
 * deployment observation are left out on purpose: they decide a finding's remediation status, so
 * taking them would make the finding already reported a new revision and send it again. Provenance
 * says where the kept listing itself came from, so it is not taken either.
 */
const FILLED = [
  'purl',
  'sbom_ref',
  'artifact_kind',
  'origin',
  'source_url',
  'source_revision',
  'signature_verification',
  'attestation_verification',
] as const;

/** The components of one system that are one package at one release, in list order. */
function sameReleaseGroups(components: readonly Component[]): Component[][] {
  const groups = new Map<string, Component[]>();
  for (const component of components) {
    const key = releaseKey(component);
    if (!key) continue;
    const group = groups.get(key);
    if (group) group.push(component);
    else groups.set(key, [component]);
  }
  return [...groups.values()];
}

/** Points dependency links at new component identifiers. */
function renameLinks(components: Component[], renamed: ReadonlyMap<string, string>): Component[] {
  if (!renamed.size) return components;
  return components.map((component) =>
    component.dependencies?.some((link) => link.component_id && renamed.has(link.component_id))
      ? {
          ...component,
          dependencies: component.dependencies.map((link) =>
            link.component_id && renamed.has(link.component_id)
              ? { ...link, component_id: renamed.get(link.component_id)! }
              : link,
          ),
        }
      : component,
  );
}

/**
 * One package at one release is one component of a system, however many times it is listed: Syft
 * lists a package once for each path it was found at, and a system can name a library that its
 * SBOM or lockfile lists again. Each listing would otherwise be its own finding and its own alert.
 *
 * One listing is kept (see `listingRank`), so a finding's identifier, which is made from the
 * component's, is one the system already had. It takes over every place the others were found at,
 * their dependency edges, their remediation records and the evidence it lacks. Different releases of
 * one package stay separate components. A list without such repeats is returned as it is.
 */
export function foldDuplicateComponents(components: Component[]): Component[] {
  const keptFor = new Map<Component, Component>();
  const renamed = new Map<string, string>();
  for (const group of sameReleaseGroups(components)) {
    if (group.length < 2) continue;
    const ordered = [...group].sort(byListing);
    const first = ordered[0]!;
    const kept: Component = { ...first };
    const note = joinPlaces(ordered.map(placeOf).filter((place) => place !== undefined));
    if (note) kept.note = note;
    const members = new Set(group.map((member) => member.id));
    const dependencies = new Map<string, NonNullable<Component['dependencies']>[number]>();
    for (const member of ordered)
      for (const link of member.dependencies ?? [])
        // A link from one listing to another of the same package would be a link to itself.
        if (!(link.component_id && members.has(link.component_id)) && !dependencies.has(link.ref))
          if (dependencies.size < 1000) dependencies.set(link.ref, link);
    if (dependencies.size) kept.dependencies = [...dependencies.values()];
    else delete kept.dependencies;
    const records = new Map<string, NonNullable<Component['remediation_evidence']>[number]>();
    for (const member of ordered)
      for (const record of member.remediation_evidence ?? [])
        if (records.size < 100) records.set(JSON.stringify(record), record);
    if (records.size) kept.remediation_evidence = [...records.values()];
    for (const field of FILLED)
      if (kept[field] === undefined) {
        // A package URL names its version: only one written as the kept listing writes it fits.
        const source = ordered.find(
          (member) => member[field] !== undefined && (field !== 'purl' || member.version === kept.version),
        );
        if (source) (kept as unknown as Record<string, unknown>)[field] = source[field];
      }
    for (const member of group) {
      keptFor.set(member, kept);
      if (member !== first) renamed.set(member.id, first.id);
    }
  }
  if (!keptFor.size) return components;
  const result: Component[] = [];
  const placed = new Set<Component>();
  for (const component of components) {
    const kept = keptFor.get(component) ?? component;
    if (placed.has(kept)) continue;
    placed.add(kept);
    result.push(kept);
  }
  return renameLinks(result, renamed);
}

/** Every system of an inventory with its repeated listings folded (see `foldDuplicateComponents`). */
export function foldInventory(inventory: Inventory): Inventory {
  let changed = false;
  const systems = inventory.systems.map((system) => {
    const components = foldDuplicateComponents(system.components);
    if (components === system.components) return system;
    changed = true;
    return { ...system, components };
  });
  return changed ? { ...inventory, systems } : inventory;
}

/**
 * Gives each component the identifier its package release had at the previous scan, when that
 * listing is gone but the release is still in the system: the copy that was kept was removed and
 * another remains, or a generator gave the package a new reference. A finding's identifier is made
 * from the component's, so the finding already reported goes on instead of a new one being sent.
 * The note still says where the package is now. The scan applies this before it assesses, and the
 * commands that read the inventory beside stored findings apply it with the same previous inventory.
 */
export function keepComponentIds(inventory: Inventory, previous: Inventory | undefined): Inventory {
  if (!previous) return inventory;
  const previousSystems = new Map(previous.systems.map((system) => [system.id, system]));
  let changed = false;
  const systems = inventory.systems.map((system) => {
    const before = previousSystems.get(system.id);
    if (!before) return system;
    const earlier = new Map<string, Component[]>();
    for (const component of before.components ?? []) {
      const key = releaseKey(component);
      if (!key) continue;
      const list = earlier.get(key);
      if (list) list.push(component);
      else earlier.set(key, [component]);
    }
    const candidatesOf = (component: Component): string[] => {
      const key = releaseKey(component);
      return [...((key && earlier.get(key)) || [])].sort(byListing).map((item) => item.id);
    };
    // A component takes an earlier identifier no current component uses, or one whose component has
    // itself moved to another; otherwise it keeps its own. No two components end with one identifier.
    const owners = new Map(system.components.map((component) => [component.id, component]));
    const moving = new Map<Component, string[]>();
    const used = new Set<string>();
    for (const component of system.components) {
      const candidates = candidatesOf(component);
      if (candidates.length && !candidates.includes(component.id)) moving.set(component, candidates);
      else used.add(component.id);
    }
    // A component waiting for an identifier its owner still holds is tried again when that owner
    // moves, so a long chain of moves takes one pass, not one pass per link.
    const assigned = new Map<Component, string>();
    const waiting = new Map<Component, Component[]>();
    const queue = [...moving.keys()];
    for (let next = 0; next < queue.length; next++) {
      const component = queue[next]!;
      if (assigned.has(component)) continue;
      let id: string | undefined;
      const blockers: Component[] = [];
      for (const candidate of moving.get(component)!) {
        if (used.has(candidate)) continue;
        const owner = owners.get(candidate);
        if (!owner || assigned.has(owner)) {
          id = candidate;
          break;
        }
        blockers.push(owner);
      }
      if (id === undefined) {
        for (const owner of blockers) {
          const list = waiting.get(owner);
          if (list) list.push(component);
          else waiting.set(owner, [component]);
        }
        continue;
      }
      assigned.set(component, id);
      used.add(id);
      queue.push(...(waiting.get(component) ?? []));
      waiting.delete(component);
    }
    const renamed = new Map<string, string>();
    const components = system.components.map((component) => {
      const id = assigned.get(component);
      if (!id) return component;
      renamed.set(component.id, id);
      const note = placeOf(component);
      return { ...component, id, ...(note ? { note } : {}) };
    });
    if (!renamed.size) return system;
    changed = true;
    return { ...system, components: renameLinks(components, renamed) };
  });
  return changed ? { ...inventory, systems } : inventory;
}

const SBOM_FILES = 1000;
const UNMATCHED_KIND =
  /unsupported package ecosystem (deb|rpm|apk|alpm|opkg|qpkg|bitnami|oci|docker|githubactions|github); not imported/i;
const isoTimestamp = z.iso.datetime({ offset: true });

/**
 * Every `.json` SBOM in a folder becomes one system. Pipelines drop their SBOM there; the next scan
 * picks it up. The SBOM's creation time is the system's `updated_at`, so an SBOM that is no longer
 * refreshed is reported as stale. A file that cannot be imported is reported and left out; it does
 * not stop the other systems from being watched.
 */
/**
 * One system from one SBOM file, described by the SBOM itself, exactly as a scan will read it. The
 * SBOM receiver calls this before it accepts an upload, so an upload it accepts is one a scan uses.
 * Throws when the file cannot be imported or describes the system with values the inventory refuses.
 */
export function systemFromSbom(
  path: string,
  file: string,
  label: string,
  imported: SbomImport = importSbom(path),
): { system: Inventory['systems'][number]; warnings: string[]; notices: string[] } {
  const properties = imported.subject?.properties ?? {};
  const property = (name: string) => properties[`security-watch:${name}`];
  const id =
    property('system-id') ?? basename(file).replace(/(?:\.(?:cdx|spdx|bom|sbom|cyclonedx))?\.json$/i, '');
  const created = imported.subject?.created;
  const enumValue = <T extends string>(value: string | undefined, allowed: readonly T[]): T | undefined =>
    value !== undefined && (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
  const parsed = systemSchema.safeParse({
    id,
    name: imported.subject?.name ?? id,
    updated_at:
      created && isoTimestamp.safeParse(created).success ? created : statSync(path).mtime.toISOString(),
    note: property('note') ?? `SBOM ${label}`,
    ...(property('owner') ? { owner: property('owner') } : {}),
    ...(property('environment') ? { environment: property('environment') } : {}),
    ...(enumValue(property('exposure'), ['internet', 'internal', 'unknown'] as const)
      ? { exposure: property('exposure') }
      : {}),
    ...(enumValue(property('criticality'), ['unknown', 'low', 'medium', 'high', 'critical'] as const)
      ? { criticality: property('criticality') }
      : {}),
    ...(property('source-url') ? { source_url: property('source-url') } : {}),
    ...(property('source-revision') ? { source_revision: property('source-revision') } : {}),
    provenance: { source: `${imported.source.format} SBOM`, reference: imported.source.digest },
  });
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(
      issue ? `${issue.path.join('.') || 'system'}: ${issue.message}` : 'invalid system description',
    );
  }
  const { lockfile: _lockfile, libraries: _libraries, sbom: _sbom, ...system } = parsed.data;
  system.components = foldDuplicateComponents(imported.components);
  if (imported.dependencies.length) system.sbom_dependencies = dependencyGraph.parse(imported.dependencies);
  // A container SBOM always lists the image's operating-system packages, and GitHub's export lists
  // the workflow's actions. Security Watch does not match those (it has no distribution backport
  // data), which is a known limit rather than a fault, so it is said once as a notice instead of
  // degrading every scan, together with the dependency edges that lead to them.
  const warnings: string[] = [];
  const notices: string[] = (imported.notices ?? []).map((notice) => `${id}: ${notice}`);
  const unmatched = new Map<string, number>();
  for (const warning of imported.warnings) {
    const kind = UNMATCHED_KIND.exec(warning)?.[1]?.toLowerCase();
    if (kind) unmatched.set(kind, (unmatched.get(kind) ?? 0) + 1);
    else if (!unmatched.size || !/^Dependency (?:target|source) .*: not an imported package/.test(warning))
      warnings.push(`${id}: ${warning}`);
  }
  if (unmatched.size) {
    const count = [...unmatched.values()].reduce((sum, value) => sum + value, 0);
    notices.push(
      `${id}: ${count} package${count === 1 ? '' : 's'} in ${label} ${count === 1 ? 'is' : 'are'} of a kind Security Watch does not match against advisories (${[...unmatched.keys()].sort().join(', ')}): operating-system packages and CI actions need your image or repository scanner. The other packages are watched.`,
    );
  }
  return { system, warnings, notices };
}

function loadSbomDirectory(
  folder: string,
  base: string,
  taken: Set<string>,
): { systems: Inventory['systems']; warnings: string[]; notices: string[] } {
  if (!statSync(folder).isDirectory()) throw new Error(`sbom_directory is not a folder: ${folder}`);
  const files = readdirSync(folder)
    .filter((name) => !name.startsWith('.') && name.toLowerCase().endsWith('.json'))
    .sort();
  if (files.length > SBOM_FILES) throw new Error(`sbom_directory holds more than ${SBOM_FILES} SBOM files`);
  const systems: Inventory['systems'] = [];
  const warnings: string[] = [];
  const notices: string[] = [];
  for (const file of files) {
    const path = join(folder, file);
    const label = relative(base, path) || file;
    try {
      if (!statSync(path).isFile()) continue;
      const loaded = systemFromSbom(path, file, label);
      const id = loaded.system.id;
      if (taken.has(id)) {
        warnings.push(
          `${label}: system ID ${id} is already used in the inventory; this SBOM is not watched.`,
        );
        continue;
      }
      taken.add(id);
      systems.push(loaded.system);
      warnings.push(...loaded.warnings);
      notices.push(...loaded.notices);
    } catch (error) {
      warnings.push(
        `${label}: ${singleLine(error instanceof Error ? error.message : 'could not be imported', 200)}; this SBOM is not watched.`,
      );
    }
  }
  return { systems, warnings, notices };
}

/** Load a local YAML/JSON inventory, checking its size and schema. */
export function loadInventory(path: string): Inventory {
  const absolute = resolve(path);
  const document = parseDocument(readBounded(absolute, 2 * 1024 * 1024), { uniqueKeys: true });
  if (document.errors.length) throw new Error(`Invalid inventory YAML: ${document.errors[0]!.message}`);
  const parsed = inventorySchema.parse(document.toJS({ maxAliasCount: 0 }));
  const systemIds = new Set<string>();
  const importWarnings: string[] = [];
  const nameNotices: string[] = [];
  // A hostile or broken import can produce a warning per entry. Keep a bounded number of bounded,
  // single-line messages and say how many more there were.
  let omittedWarnings = 0;
  let omittedNotices = 0;
  const warn = (system: string, warnings: string[]): void => {
    for (const warning of warnings) {
      if (importWarnings.length < 200) importWarnings.push(singleLine(`${system}: ${warning}`, 400));
      else omittedWarnings++;
    }
  };
  const systems = parsed.systems.map(({ lockfile, libraries, sbom, ...system }) => {
    if (systemIds.has(system.id)) throw new Error(`Duplicate system ID: ${system.id}`);
    systemIds.add(system.id);
    if (libraries) {
      const groups = Array.isArray(libraries) ? [[undefined, libraries] as const] : Object.entries(libraries);
      const added = new Map(
        system.components.map((component) => [
          JSON.stringify([component.ecosystem, component.name, component.version ?? null]),
          component,
        ]),
      );
      let count = 0;
      for (const [ecosystem, entries] of groups) {
        if (ecosystem !== undefined) normalizeEcosystem(ecosystem);
        for (const entry of entries) {
          if (++count > 20_000) throw new Error(`System ${system.id} exceeds 20000 library entries`);
          const library = parseLibrary(entry, ecosystem);
          const key = JSON.stringify([library.ecosystem, library.name, library.version ?? null]);
          const existing = added.get(key);
          if (existing) {
            // The same library listed twice keeps every place it was said to be used.
            const note = mergeNotes(existing.note, library.note);
            if (note) existing.note = note;
            continue;
          }
          const component = { id: `library:${hash(key).slice(0, 24)}`, ...library };
          added.set(key, component);
          system.components.push(component);
        }
      }
    }
    // Names typed by hand, before anything is imported: a lockfile or SBOM carries the published
    // spelling, a person may have typed `Lodash` for `lodash`. The entry is valid as written (some
    // old packages do have capitals), so this is a notice to read once, not a monitoring fault.
    for (const component of system.components) {
      const notice = capitalisedName(component);
      if (!notice) continue;
      if (nameNotices.length < 200) nameNotices.push(`${system.id}: ${notice}`);
      else omittedNotices++;
    }
    if (sbom) {
      const imported = importSbom(resolve(dirname(absolute), sbom));
      system.components.push(...imported.components);
      if (imported.dependencies.length) {
        system.sbom_dependencies = dependencyGraph.parse([
          ...(system.sbom_dependencies ?? []),
          ...imported.dependencies,
        ]);
      }
      warn(system.id, imported.warnings);
    }
    if (lockfile) {
      const imported = importLockfile(resolve(dirname(absolute), lockfile));
      system.components.push(...imported.components);
      warn(system.id, imported.warnings);
    }
    if (system.components.length > 20_000) throw new Error(`System ${system.id} exceeds 20000 components`);
    const componentIds = new Set<string>();
    for (const component of system.components) {
      if (componentIds.has(component.id))
        throw new Error(`Duplicate component ID in ${system.id}: ${component.id}`);
      componentIds.add(component.id);
    }
    // After the identity check: a repeated identifier is still a mistake in the inventory.
    system.components = foldDuplicateComponents(system.components);
    const productNames = new Set<string>();
    for (const product of system.products) {
      const name = product.name.toLowerCase();
      if (productNames.has(name)) throw new Error(`Duplicate product name in ${system.id}: ${product.name}`);
      productNames.add(name);
    }
    return system;
  });
  if (parsed.sbom_directory) {
    const folder = resolve(dirname(absolute), parsed.sbom_directory);
    const loaded = loadSbomDirectory(folder, dirname(absolute), new Set(systems.map((system) => system.id)));
    systems.push(...loaded.systems);
    for (const warning of loaded.warnings)
      if (importWarnings.length < 200) importWarnings.push(singleLine(warning, 400));
      else omittedWarnings++;
    for (const notice of loaded.notices)
      if (nameNotices.length < 200) nameNotices.push(singleLine(notice, 400));
      else omittedNotices++;
  }
  if (!systems.length && !parsed.sbom_directory)
    throw new Error('No systems: add at least one system, or an sbom_directory with SBOM files.');
  // An empty SBOM folder is how a monitor fed by pipelines starts. Scans report the empty inventory
  // as degraded monitoring until the first SBOM arrives.
  if (!systems.length)
    nameNotices.push(
      `The SBOM folder ${parsed.sbom_directory} has no SBOM that could be imported, so nothing is watched yet. Upload one from CI (security-watch upload) or create one with: security-watch sbom --project PATH --output ${join(parsed.sbom_directory!, 'NAME.cdx.json')}`,
    );
  if (omittedWarnings) importWarnings.push(`${omittedWarnings} more import warning(s) are not shown.`);
  if (omittedNotices) nameNotices.push(`${omittedNotices} more name notice(s) are not shown.`);
  return {
    systems,
    ...(importWarnings.length ? { import_warnings: importWarnings } : {}),
    ...(nameNotices.length ? { name_notices: nameNotices } : {}),
  };
}

/**
 * For a finding retired because its listing was folded into another listing of the same package
 * release: the component that is watched in its place. Nothing when the package was listed once.
 */
export function foldedInto(
  previous: Inventory | undefined,
  current: Inventory,
  systemId: string,
  componentId: string,
): string | undefined {
  const system = current.systems.find((item) => item.id === systemId);
  if (!system || system.components.some((item) => item.id === componentId)) return undefined;
  const before = previous?.systems.find((item) => item.id === systemId)?.components ?? [];
  const listing = before.find((item) => item.id === componentId);
  const key = listing && releaseKey(listing);
  if (!listing || !key) return undefined;
  const release = (item: Component) => releaseKey(item) === key;
  if (before.filter(release).length < 2) return undefined;
  return system.components.find(release)?.id;
}
