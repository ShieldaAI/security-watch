import { readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
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
import { importCycloneDx } from './sbom.js';

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
const inventorySchema = z.strictObject({ systems: z.array(systemSchema).min(1).max(1000) });

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
  const lock: unknown = JSON.parse(readBounded(path, 20 * 1024 * 1024));
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
      if (warnings.length < 50)
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
      if (warnings.length < 50)
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
      const imported = importCycloneDx(resolve(dirname(absolute), sbom));
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
  if (omittedWarnings) importWarnings.push(`${omittedWarnings} more import warning(s) are not shown.`);
  if (omittedNotices) nameNotices.push(`${omittedNotices} more name notice(s) are not shown.`);
  return {
    systems,
    ...(importWarnings.length ? { import_warnings: importWarnings } : {}),
    ...(nameNotices.length ? { name_notices: nameNotices } : {}),
  };
}
