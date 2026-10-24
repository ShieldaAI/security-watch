import { readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import type { Component, Inventory } from './types.js';
import { exactLibraryVersion, normalizeEcosystem, normalizePackageName, parseLibrary } from './ecosystems.js';
import { hash } from './util.js';

const shortText = z.string().trim().min(1).max(500);
const npmName = z
  .string()
  .max(214)
  .regex(/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/, 'Expected a canonical npm package name');
const severity = z.enum(['unknown', 'low', 'medium', 'high', 'critical']);
const componentSchema = z
  .strictObject({
    id: shortText,
    ecosystem: shortText,
    name: shortText,
    version: shortText.optional(),
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
});
const systemSchema = z.strictObject({
  id: shortText,
  name: shortText,
  environment: shortText.default('unknown'),
  owner: shortText.optional(),
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

function readBounded(path: string, maximum: number): string {
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > maximum)
    throw new Error(`Inventory input must be a regular file no larger than ${maximum} bytes: ${path}`);
  const content = readFileSync(path);
  if (content.byteLength > maximum) throw new Error(`Inventory input exceeds ${maximum} bytes: ${path}`);
  return content.toString('utf8');
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Imports metadata only. No install scripts or package manager commands are executed. */
function importLockfile(path: string): Component[] {
  const lock: unknown = JSON.parse(readBounded(path, 20 * 1024 * 1024));
  if (!record(lock) || (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) || !record(lock.packages)) {
    throw new Error(`Expected package-lock v2 or v3 with a packages map: ${path}`);
  }
  const entries = Object.entries(lock.packages);
  if (entries.length > 20_000) throw new Error(`Lockfile exceeds 20000 package entries: ${path}`);
  const components: Component[] = [];
  for (const [location, value] of entries) {
    if (!location || !record(value) || value.link === true) continue;
    const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(location);
    if (!match) continue;
    const name = npmName.parse(value.name ?? match[1]);
    const version = value.version === undefined ? undefined : shortText.parse(value.version);
    components.push({
      id: `lock:${location}`,
      ecosystem: 'npm',
      name,
      ...(version === undefined ? {} : { version }),
    });
  }
  return components;
}

/** Load a local YAML/JSON inventory, checking its size and schema. */
export function loadInventory(path: string): Inventory {
  const absolute = resolve(path);
  const document = parseDocument(readBounded(absolute, 2 * 1024 * 1024), { uniqueKeys: true });
  if (document.errors.length) throw new Error(`Invalid inventory YAML: ${document.errors[0]!.message}`);
  const parsed = inventorySchema.parse(document.toJS({ maxAliasCount: 0 }));
  const systemIds = new Set<string>();
  const systems = parsed.systems.map(({ lockfile, libraries, ...system }) => {
    if (systemIds.has(system.id)) throw new Error(`Duplicate system ID: ${system.id}`);
    systemIds.add(system.id);
    if (libraries) {
      const groups = Array.isArray(libraries) ? [[undefined, libraries] as const] : Object.entries(libraries);
      const added = new Set(
        system.components.map((component) =>
          JSON.stringify([component.ecosystem, component.name, component.version ?? null]),
        ),
      );
      let count = 0;
      for (const [ecosystem, entries] of groups) {
        if (ecosystem !== undefined) normalizeEcosystem(ecosystem);
        for (const entry of entries) {
          if (++count > 20_000) throw new Error(`System ${system.id} exceeds 20000 library entries`);
          const library = parseLibrary(entry, ecosystem);
          const key = JSON.stringify([library.ecosystem, library.name, library.version ?? null]);
          if (added.has(key)) continue;
          added.add(key);
          system.components.push({ id: `library:${hash(key).slice(0, 24)}`, ...library });
        }
      }
    }
    if (lockfile) system.components.push(...importLockfile(resolve(dirname(absolute), lockfile)));
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
  return { systems };
}
