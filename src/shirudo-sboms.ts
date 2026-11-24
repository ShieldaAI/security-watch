import { createHash, randomUUID } from 'node:crypto';
import {
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, join, sep } from 'node:path';
import { cycloneDxMinor, importCycloneDxValue } from './sbom.js';
import { MAX_EXPORT_BYTES, MAX_EXPORT_ROWS } from './mitigations.js';

/**
 * Copies the SBOMs of Shirudo's images from its SBOM store (`<image_id>/<image_version>/<root>/
 * sbom.cdx.json`, a `file://` store) into Security Watch's SBOM folder, one file per image.
 *
 * The system ID is the image ID, so it stays the same across upgrades and a finding is not reported
 * again for each new version. With a `node_vulns` export, the versions machines run are read; when
 * several run (a rolling upgrade, a canary), their SBOMs are merged so the old version stays watched
 * until it is gone. Without one, the newest version is taken.
 *
 * Only files this command wrote are replaced or removed; it marks them with a property. Nothing is
 * written unless `apply` is set.
 */

export const WRITTEN_BY = 'shirudo-sboms';
const ID = /^[A-Za-z0-9_~+-][A-Za-z0-9._~+-]{0,254}$/;
const ROOT = /^(?:[0-9a-f]{64}|-)$/;
const MAX_SBOM_BYTES = 20 * 1024 * 1024;
const MAX_IMAGES = 1000;
const MAX_VERSIONS = 1000;

export interface ShirudoSyncOptions {
  /** The store's directory (a `file://` store; sync an `s3://` store to a directory first). */
  store: string;
  /** The SBOM folder that the inventory's `sbom_directory` names. */
  output: string;
  /** A JSON Lines export of `shirudo.node_vulns` with `image_id`, `image_version` and `node_id`. */
  exposure?: string;
  apply?: boolean;
  now?: number;
  /** System IDs the inventory describes by hand: an image with one of these IDs is not written. */
  reserved?: readonly string[];
  /** Allow a run to remove more than half of the images it watches. */
  allowRemovals?: boolean;
}

export interface ShirudoSyncImage {
  image_id: string;
  file: string;
  /** The versions in the SBOM, with the hosts running each when an export was given. */
  versions: { version: string; hosts?: number }[];
  action: 'write' | 'unchanged';
}

export interface ShirudoSyncPlan {
  store: string;
  output: string;
  applied: boolean;
  /** Whether the versions came from an export of the machines (`running`) or the newest in the store. */
  selection: 'running' | 'newest';
  images: ShirudoSyncImage[];
  /** Files this command wrote earlier for images that are no longer selected. */
  remove: string[];
  /**
   * What could not be done, in plain words. An image with a problem is left as it is: its earlier
   * file, if any, is kept, never removed.
   */
  problems: string[];
}

function directoryEntries(path: string): string[] {
  return readdirSync(path).sort();
}
/** A real directory, not a link to one: a link could lead the command out of the store. */
function isDirectory(path: string): boolean {
  try {
    return lstatSync(path).isDirectory();
  } catch {
    return false;
  }
}

/** Natural order: 2026.11.10 after 2026.11.9, 1.10 after 1.9; text parts compare as text. */
export function compareVersions(a: string, b: string): number {
  const parts = (value: string) => value.match(/\d+|\D+/g) ?? [];
  const left = parts(a);
  const right = parts(b);
  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    const x = left[index];
    const y = right[index];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const numeric = /^\d/.test(x) && /^\d/.test(y);
    const order = numeric
      ? BigInt(x) < BigInt(y)
        ? -1
        : BigInt(x) > BigInt(y)
          ? 1
          : 0
      : x < y
        ? -1
        : x > y
          ? 1
          : 0;
    if (order) return order;
  }
  return 0;
}

/** The versions machines run, per image, with the hosts on each; and whether the export is whole. */
function runningVersions(
  path: string,
  problems: string[],
): { running: Map<string, Map<string, Set<string>>>; complete: boolean } {
  const stat = statSync(path);
  if (!stat.isFile()) throw new Error('The export is not a regular file');
  if (stat.size > MAX_EXPORT_BYTES) throw new Error('The export is larger than 64 MiB');
  const running = new Map<string, Map<string, Set<string>>>();
  let rows = 0;
  let unusable = 0;
  for (const raw of readFileSync(path, 'utf8')
    .replace(/^\ufeff/, '')
    .split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (++rows > MAX_EXPORT_ROWS) throw new Error(`The export has more than ${MAX_EXPORT_ROWS} rows`);
    let row: unknown;
    try {
      row = JSON.parse(line);
    } catch {
      unusable++;
      continue;
    }
    if (!isObject(row)) {
      unusable++;
      continue;
    }
    const { image_id: image, image_version: version, node_id: node } = row;
    // A machine bound to no image runs nothing to watch; it is not a damaged row.
    if (image === '' || image === null) continue;
    if (
      typeof image !== 'string' ||
      typeof version !== 'string' ||
      (typeof node !== 'string' && !Number.isSafeInteger(node)) ||
      !ID.test(image) ||
      !ID.test(version) ||
      String(node) === ''
    ) {
      unusable++;
      continue;
    }
    const versions = running.get(image) ?? new Map<string, Set<string>>();
    const hosts = versions.get(version) ?? new Set<string>();
    hosts.add(String(node));
    versions.set(version, hosts);
    running.set(image, versions);
  }
  if (unusable)
    problems.push(
      `${unusable} export row(s) without a usable image_id, image_version and node_id were left out; nothing is removed while the export is incomplete.`,
    );
  if (!rows) problems.push('The export is empty: no image is known to run. Nothing is written or removed.');
  return { running, complete: rows > 0 && unusable === 0 };
}

/** The SBOM of one version: the newest of its builds (roots), with a note when there are several. */
function versionSbom(dir: string, image: string, version: string, problems: string[]): string | undefined {
  const roots = directoryEntries(dir).filter((name) => ROOT.test(name) && isDirectory(join(dir, name)));
  const files = roots
    .map((root) => join(dir, root, 'sbom.cdx.json'))
    .filter((file) => {
      try {
        const stat = lstatSync(file);
        return stat.isFile() && stat.size <= MAX_SBOM_BYTES;
      } catch {
        return false;
      }
    })
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs || a.localeCompare(b));
  if (!files.length) {
    problems.push(`${image} ${version}: no readable sbom.cdx.json of at most 20 MiB in the store.`);
    return undefined;
  }
  if (files.length > 1)
    problems.push(
      `${image} ${version}: ${files.length} builds in the store; the most recently stored one is used.`,
    );
  return files[0];
}

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Prefixes every component reference so that the SBOMs of several versions can be merged. */
function prefixComponents(components: unknown[], prefix: string, renamed: Map<string, string>): unknown[] {
  return components.map((entry) => {
    if (!isObject(entry)) return entry;
    const copy: Json = { ...entry };
    if (typeof copy['bom-ref'] === 'string') {
      const ref = `${prefix}${copy['bom-ref']}`;
      renamed.set(copy['bom-ref'], ref);
      copy['bom-ref'] = ref;
    }
    if (Array.isArray(copy.components)) copy.components = prefixComponents(copy.components, prefix, renamed);
    return copy;
  });
}

/**
 * One document from the SBOMs of the running versions. Components with the same package URL are kept
 * once; references are prefixed per version; dependency entries are kept where both ends survive.
 */
export function mergeCycloneDx(documents: Json[]): Json {
  if (documents.length === 1) return structuredClone(documents[0]!);
  const minor = Math.max(...documents.map((doc) => cycloneDxMinor(doc.specVersion) ?? 2));
  const components: unknown[] = [];
  const seen = new Map<string, string | undefined>();
  const kept = new Set<string>();
  const alias = new Map<string, string>();
  const dependencies = new Map<string, Set<string>>();
  documents.forEach((doc, index) => {
    const prefix = `v${index}:`;
    const renamed = new Map<string, string>();
    // Nested components count too: a package that one version lists inside another component and
    // a second version lists at the top level is still one package, and the importer would read it
    // twice. A duplicate with components of its own passes those on in its place.
    const unique = (entries: unknown[]): unknown[] => {
      const result: unknown[] = [];
      for (const entry of entries) {
        if (!isObject(entry)) {
          result.push(entry);
          continue;
        }
        const purl = typeof entry.purl === 'string' ? entry.purl : undefined;
        const ref = typeof entry['bom-ref'] === 'string' ? entry['bom-ref'] : undefined;
        const children = Array.isArray(entry.components) ? entry.components : undefined;
        if (purl && seen.has(purl)) {
          // The same package in an earlier version: its references point at the one kept.
          const first = seen.get(purl);
          if (ref && first) alias.set(ref, first);
          if (children) result.push(...unique(children));
          continue;
        }
        if (purl) seen.set(purl, ref);
        if (!children) result.push(entry);
        else {
          const rest = unique(children);
          const { components: _children, ...copy } = entry;
          result.push(rest.length ? { ...copy, components: rest } : copy);
        }
      }
      return result;
    };
    const own = unique(
      prefixComponents(Array.isArray(doc.components) ? doc.components : [], prefix, renamed),
    );
    components.push(...own);
    const collect = (entries: unknown[]) => {
      for (const entry of entries)
        if (isObject(entry)) {
          if (typeof entry['bom-ref'] === 'string') kept.add(entry['bom-ref']);
          if (Array.isArray(entry.components)) collect(entry.components);
        }
    };
    collect(own);
    for (const dependency of Array.isArray(doc.dependencies) ? doc.dependencies : []) {
      if (!isObject(dependency) || typeof dependency.ref !== 'string') continue;
      const source = renamed.get(dependency.ref);
      if (!source) continue;
      const targets = dependencies.get(source) ?? new Set<string>();
      for (const target of Array.isArray(dependency.dependsOn) ? dependency.dependsOn : [])
        if (typeof target === 'string' && renamed.has(target)) targets.add(renamed.get(target)!);
      dependencies.set(source, targets);
    }
  });
  const resolve = (ref: string) => alias.get(ref) ?? ref;
  const merged = new Map<string, Set<string>>();
  for (const [source, targets] of dependencies) {
    const from = resolve(source);
    if (!kept.has(from) || alias.has(from)) continue;
    const list = merged.get(from) ?? new Set<string>();
    for (const target of targets) {
      const to = resolve(target);
      if (kept.has(to) && !alias.has(to) && to !== from) list.add(to);
    }
    merged.set(from, list);
  }
  const first = documents[0]!;
  return {
    bomFormat: 'CycloneDX',
    specVersion: `1.${minor}`,
    version: 1,
    ...(isObject(first.metadata) ? { metadata: structuredClone(first.metadata) } : {}),
    components,
    dependencies: [...merged].map(([ref, targets]) => ({ ref, dependsOn: [...targets].sort() })),
  };
}

/** Sets the Security Watch properties first (the importer takes the first of each name). */
function described(doc: Json, image: string, note: string, observedAt: string | undefined): Json {
  const metadata: Json = isObject(doc.metadata) ? { ...doc.metadata } : {};
  const others = Array.isArray(metadata.properties)
    ? metadata.properties.filter(
        (property) =>
          !(
            isObject(property) &&
            typeof property.name === 'string' &&
            property.name.startsWith('security-watch:')
          ),
      )
    : [];
  metadata.properties = [
    { name: 'security-watch:system-id', value: image },
    { name: 'security-watch:note', value: note },
    { name: 'security-watch:written-by', value: WRITTEN_BY },
    ...others,
  ];
  // Seen running now: the list is current, whenever the image was built.
  if (observedAt) metadata.timestamp = observedAt;
  return { ...doc, metadata };
}

/** The system ID a file in the SBOM folder describes, as the folder's reader takes it. */
function systemIdOf(name: string, doc: unknown): string {
  const properties = isObject(doc) && isObject(doc.metadata) ? doc.metadata.properties : undefined;
  if (Array.isArray(properties))
    for (const property of properties)
      if (
        isObject(property) &&
        property.name === 'security-watch:system-id' &&
        typeof property.value === 'string'
      )
        return property.value;
  return name.replace(/(?:\.(?:cdx|spdx|bom|sbom|cyclonedx))?\.json$/i, '');
}

/** What each file in the folder is: one this command wrote, and the system each describes. */
function folderContents(folder: string): Map<string, { ours: boolean; system: string }> {
  const files = new Map<string, { ours: boolean; system: string }>();
  for (const name of directoryEntries(folder)) {
    if (!name.toLowerCase().endsWith('.json') || name.startsWith('.')) continue;
    const path = join(folder, name);
    let doc: unknown;
    try {
      const stat = lstatSync(path);
      // Larger files are read by nobody: the folder's reader refuses them too.
      if (stat.isFile() && stat.size <= 64 * 1024 * 1024)
        doc = JSON.parse(readFileSync(path, 'utf8').replace(/^\ufeff/, ''));
    } catch {
      doc = undefined;
    }
    const properties = isObject(doc) && isObject(doc.metadata) ? doc.metadata.properties : undefined;
    const ours =
      Array.isArray(properties) &&
      properties.some(
        (property) =>
          isObject(property) &&
          property.name === 'security-watch:written-by' &&
          property.value === WRITTEN_BY,
      );
    files.set(name, { ours, system: systemIdOf(name, doc) });
  }
  return files;
}

function hostWord(count: number): string {
  return `${count} host${count === 1 ? '' : 's'}`;
}

/** A file name the file system takes: at most 255 bytes. */
const MAX_NAME_BYTES = 255;

export function syncShirudoSboms(options: ShirudoSyncOptions): ShirudoSyncPlan {
  const now = options.now ?? Date.now();
  const problems: string[] = [];
  if (!statSync(options.store).isDirectory()) throw new Error('The store is not a directory');
  if (!statSync(options.output).isDirectory()) throw new Error('The output is not a directory');
  // The SBOM folder inside the store would be read as an image, and the store inside the folder would
  // put store files where the scan reads SBOMs.
  const store = realpathSync(options.store);
  const output = realpathSync(options.output);
  const inside = (child: string, parent: string) =>
    child === parent || child.startsWith(parent.endsWith(sep) ? parent : parent + sep);
  if (inside(output, store) || inside(store, output))
    throw new Error('The SBOM folder and the store must be separate folders, neither inside the other');
  const exported = options.exposure ? runningVersions(options.exposure, problems) : undefined;
  const running = exported?.running;
  const plan: ShirudoSyncPlan = {
    store: options.store,
    output: options.output,
    applied: Boolean(options.apply),
    selection: running ? 'running' : 'newest',
    images: [],
    remove: [],
    problems,
  };
  // An empty export says nothing about what runs: nothing is changed on its word.
  if (exported && !running!.size) return plan;
  // A name that is in the store but not a real directory (a link) is held: its file is kept.
  const unusable = new Set<string>();
  const images = directoryEntries(options.store).filter((name) => {
    if (!ID.test(name)) return false;
    if (!isDirectory(join(options.store, name))) {
      problems.push(`${name}: not a directory (or a link) in the store; left as it was.`);
      unusable.add(name);
      return false;
    }
    return true;
  });
  if (images.length > MAX_IMAGES) throw new Error(`The store holds more than ${MAX_IMAGES} images`);
  // An empty store is an unmounted disk or a copy that failed, not a fleet without images.
  if (!images.length) {
    problems.push(
      'The store holds no image: it may not be mounted or copied. Nothing is written or removed.',
    );
    return plan;
  }
  if (running)
    for (const image of running.keys())
      if (!images.includes(image)) problems.push(`${image}: runs on machines but is not in the store.`);
  const folder = folderContents(options.output);
  // Systems described by files this command did not write, and by hand: an image with one of these
  // IDs would displace that system or be refused by every scan.
  const taken = new Map<string, string>();
  for (const [name, item] of folder) if (!item.ours) taken.set(item.system, name);
  for (const id of options.reserved ?? []) if (!taken.has(id)) taken.set(id, 'the inventory');
  /** Images whose earlier file must stay as it is, because this run could not establish their list. */
  const held = new Set<string>();
  const files = new Map<string, string>();
  // The store and, with an export, the machines confirm the list is current; the scan's staleness
  // check then measures how long ago the sync last ran, not when the image was built.
  const observedAt = new Date(now).toISOString();
  const contents = new Map<string, string>();
  for (const image of images) {
    const hold = (problem: string) => {
      problems.push(problem);
      held.add(image);
    };
    const dir = join(options.store, image);
    const stored = directoryEntries(dir).filter((name) => ID.test(name) && isDirectory(join(dir, name)));
    if (stored.length > MAX_VERSIONS) {
      hold(`${image}: more than ${MAX_VERSIONS} versions in the store; left as it was.`);
      continue;
    }
    let chosen: { version: string; hosts?: number }[];
    const versions = running?.get(image);
    if (running) {
      if (!versions) continue; // In the store but not running: not watched.
      chosen = [...versions]
        .filter(([version]) => {
          if (stored.includes(version)) return true;
          problems.push(
            `${image} ${version}: runs on ${hostWord(versions.get(version)!.size)} but has no SBOM in the store.`,
          );
          return false;
        })
        .map(([version, hosts]) => ({ version, hosts: hosts.size }));
    } else {
      const newest = [...stored].sort(compareVersions).at(-1);
      chosen = newest ? [{ version: newest }] : [];
    }
    chosen.sort((a, b) => compareVersions(b.version, a.version));
    if (!chosen.length) {
      // With an export, each running version without an SBOM was named above.
      if (running) held.add(image);
      else hold(`${image}: no version in the store; left as it was.`);
      continue;
    }
    const documents: Json[] = [];
    const used: { version: string; hosts?: number }[] = [];
    for (const item of chosen) {
      const file = versionSbom(join(dir, item.version), image, item.version, problems);
      if (!file) continue;
      try {
        const doc: unknown = JSON.parse(readFileSync(file, 'utf8').replace(/^\ufeff/, ''));
        if (!isObject(doc) || doc.bomFormat !== 'CycloneDX' || cycloneDxMinor(doc.specVersion) === undefined)
          throw new Error('not CycloneDX JSON 1.2 or later 1.x');
        documents.push(doc);
        used.push(item);
      } catch (error) {
        problems.push(`${image} ${item.version}: the SBOM cannot be read (${(error as Error).message}).`);
      }
    }
    // A running version whose SBOM is missing or unreadable: a new list without it would stop watching
    // that version's packages while hosts still run it, so an earlier list is kept instead. With no
    // earlier list, the versions that can be read are better than nothing.
    // Running versions with no SBOM in the store count too: they were left out of `chosen`.
    const failed = used.length < (versions?.size ?? chosen.length);
    const earlier = [...folder].some(
      ([file, item]) => item.ours && file.toLowerCase() === `${image}.cdx.json`.toLowerCase(),
    );
    if (failed && earlier && documents.length) {
      held.add(image);
      problems.push(`${image}: kept as it was, because not every running version's SBOM could be read.`);
      continue;
    }
    // No version could be read: the earlier list, if any, is kept rather than lost.
    if (!documents.length) {
      held.add(image);
      if (!problems.some((problem) => problem.startsWith(`${image} `) || problem.startsWith(`${image}:`)))
        problems.push(`${image}: no SBOM could be read; left as it was.`);
      continue;
    }
    const name = `${image}.cdx.json`;
    if (Buffer.byteLength(name) > MAX_NAME_BYTES) {
      hold(`${image}: the image ID is too long for a file name; left out.`);
      continue;
    }
    if (taken.has(image)) {
      hold(
        `${image}: the system ID is already used by ${taken.get(image)}; this image is not written. Rename that system, or watch the image under another ID.`,
      );
      continue;
    }
    const note = `Shirudo image ${image}: ${used
      .map((item) =>
        item.hosts === undefined
          ? `version ${item.version} (newest in the store)`
          : `version ${item.version} on ${hostWord(item.hosts)}`,
      )
      .join(', ')}`;
    const doc = described(mergeCycloneDx(documents), image, note.slice(0, 1000), observedAt);
    // Compact: the folder's reader takes at most 20 MiB, and indentation would cost a third more.
    const text = JSON.stringify(doc) + '\n';
    if (Buffer.byteLength(text) > MAX_SBOM_BYTES) {
      hold(`${image}: the SBOM would be larger than 20 MiB, which a scan refuses; left as it was.`);
      continue;
    }
    try {
      // What a scan will read, checked now: a file it would refuse is not written.
      importCycloneDxValue(JSON.parse(text), `sha256:${createHash('sha256').update(text).digest('hex')}`);
    } catch (error) {
      hold(
        `${image}: the SBOM would not be accepted by a scan (${(error as Error).message}); left as it was.`,
      );
      continue;
    }
    // On a case-insensitive file system Fleet-OS and fleet-os are one file.
    const folded = name.toLowerCase();
    if (files.has(folded)) {
      hold(`${image}: its file name differs from ${files.get(folded)}'s only in letter case; left out.`);
      continue;
    }
    files.set(folded, image);
    const target = join(options.output, name);
    // On a case-insensitive file system app.cdx.json is App.cdx.json: look the name up without case.
    const found = [...folder].find(([existing]) => existing.toLowerCase() === folded);
    if (found && found[0] !== name) {
      hold(`${image}: ${found[0]} in the SBOM folder differs from ${name} only in letter case; left out.`);
      continue;
    }
    const present = found?.[1];
    if (present && !present.ours) {
      hold(`${name} exists in the SBOM folder and was not written by this command; it is not replaced.`);
      continue;
    }
    const existing = present ? readFileSync(target, 'utf8') : undefined;
    // An unchanged list is not rewritten, so its time is kept; a confirmed time alone is not a change...
    const comparable = (value: string) => {
      try {
        const parsed = JSON.parse(value) as Json;
        if (isObject(parsed.metadata)) delete parsed.metadata.timestamp;
        return JSON.stringify(parsed);
      } catch {
        return value;
      }
    };
    // ...but it is confirmed at least daily, so a stable image never looks stale.
    const confirmedRecently = (() => {
      if (existing === undefined) return true;
      try {
        const parsed = JSON.parse(existing) as Json;
        const time = isObject(parsed.metadata) ? Date.parse(String(parsed.metadata.timestamp)) : Number.NaN;
        return Number.isFinite(time) && now - time < 86_400_000;
      } catch {
        return false;
      }
    })();
    const unchanged =
      existing !== undefined && confirmedRecently && comparable(existing) === comparable(text);
    plan.images.push({
      image_id: image,
      file: name,
      versions: used,
      action: unchanged ? 'unchanged' : 'write',
    });
    if (!unchanged) contents.set(target, text);
  }
  // A file is removed only when its image is known to be gone: not run by any machine of a complete
  // export, or no longer in the store. A failed read, an incomplete export or any problem with the
  // image keeps the file, so a scan never loses a system because the sync could not see it.
  const removable = !exported || exported.complete;
  const selected = new Set(plan.images.map((item) => item.file));
  let kept = 0;
  for (const [name, item] of folder) {
    if (!item.ours || selected.has(name) || held.has(item.system) || unusable.has(item.system)) continue;
    const gone = running ? !running.has(item.system) : !images.includes(item.system);
    if (!gone) continue;
    if (removable) plan.remove.push(name);
    else kept++;
  }
  if (kept)
    problems.push(`${kept} file(s) for images no longer seen were kept, because the export is incomplete.`);
  // Most of the watched images disappearing at once is more likely a half-copied store or a cut
  // export than a fleet that changed: it is done only when asked for.
  const ours = [...folder.values()].filter((item) => item.ours).length;
  if (plan.remove.length >= 2 && plan.remove.length * 2 > ours && !options.allowRemovals) {
    problems.push(
      `${plan.remove.length} of ${ours} watched images would be removed; nothing is removed. If the fleet really changed, run again with --allow-removals.`,
    );
    plan.remove = [];
  }
  // The SBOM folder holds at most 1,000 files; a sync that would pass that is refused whole.
  const added = plan.images.filter((item) => !folder.has(item.file)).length;
  if (folder.size + added - plan.remove.length > 1000)
    throw new Error('The SBOM folder would hold more than 1,000 SBOM files');
  if (options.apply) {
    for (const [target, text] of contents) {
      // A hidden temporary name: the SBOM folder skips names that start with a dot, so a scan never
      // reads a half-written file, and the rename makes the new file appear whole.
      const temporary = join(options.output, `.${randomUUID()}.tmp`);
      try {
        writeFileSync(temporary, text, { flag: 'wx', mode: 0o600 });
        renameSync(temporary, target);
      } catch (error) {
        problems.push(
          `${basename(target)}: could not be written (${(error as Error).message}); left as it was.`,
        );
        const entry = plan.images.find((item) => join(options.output, item.file) === target);
        if (entry) entry.action = 'unchanged';
      } finally {
        rmSync(temporary, { force: true });
      }
    }
    for (const name of plan.remove) rmSync(join(options.output, name), { force: true });
  }
  return plan;
}
