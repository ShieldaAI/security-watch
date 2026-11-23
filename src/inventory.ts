import { readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import type { Component, Inventory } from './types.js';
import {
  capitalisedName,
  exactLibraryVersion,
  mergeNotes,
  normalizeEcosystem,
  normalizePackageName,
  parseLibrary,
} from './ecosystems.js';
import { hash, LINE_BREAKING, singleLine } from './util.js';
import { importSbom } from './sbom.js';

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
): { system: Inventory['systems'][number]; warnings: string[]; notices: string[] } {
  const imported = importSbom(path);
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
  system.components = imported.components;
  if (imported.dependencies.length) system.sbom_dependencies = dependencyGraph.parse(imported.dependencies);
  // A container SBOM always lists the image's operating-system packages, and GitHub's export lists
  // the workflow's actions. Security Watch does not match those (it has no distribution backport
  // data), which is a known limit rather than a fault, so it is said once as a notice instead of
  // degrading every scan, together with the dependency edges that lead to them.
  const warnings: string[] = [];
  const notices: string[] = [];
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
