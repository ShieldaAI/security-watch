import { readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { exactLibraryVersion, normalizeEcosystem, normalizePackageName } from './ecosystems.js';
import { eq as samePythonVersion, valid as validPython } from '@renovatebot/pep440';
import { hash, LINE_BREAKING } from './util.js';
import type { Component, DependencyRelationship } from './types.js';

export interface SbomImport {
  components: Component[];
  warnings: string[];
  dependencies: DependencyRelationship[];
  source: { format: 'CycloneDX' | 'SPDX'; spec_version: string; digest: string };
  /** Things to read once that do not make the import incomplete, such as a newer CycloneDX 1.x. */
  notices?: string[];
  /**
   * What the document says about the system it describes: its name, when it was created, and the
   * `security-watch:*` properties written by `security-watch sbom`. Used by an SBOM folder.
   */
  subject?: { name?: string; created?: string; properties: Record<string, string> };
}
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const text = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= 1000 && !LINE_BREAKING.test(value);

function readSbom(path: string): { document: unknown; digest: string } {
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > 20 * 1024 * 1024)
    throw new Error('SBOM must be a regular JSON file of at most 20 MiB');
  const bytes = readFileSync(path);
  if (bytes.byteLength > 20 * 1024 * 1024) throw new Error('SBOM exceeds 20 MiB');
  let document: unknown;
  try {
    document = JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, ''));
  } catch {
    throw new Error('SBOM is not valid JSON');
  }
  return { document, digest: `sha256:${createHash('sha256').update(bytes).digest('hex')}` };
}

/** Bounded local metadata import: never follows references, runs scripts or fetches packages. */
export function importCycloneDx(path: string): SbomImport {
  const { document, digest } = readSbom(path);
  return importCycloneDxDocument(document, digest);
}

/**
 * Imports a CycloneDX (1.2 to 1.7, and later 1.x) or SPDX (2.2, 2.3) JSON document, whichever the file is. This
 * accepts the output of `security-watch sbom`, Trivy, Syft, cdxgen and GitHub's dependency-graph
 * export ("Export SBOM", or the REST API's `{ "sbom": ... }` response) without conversion.
 */
export function importSbom(path: string): SbomImport {
  const { document, digest } = readSbom(path);
  if (object(document) && document.bomFormat === 'CycloneDX')
    return importCycloneDxDocument(document, digest);
  const spdx = object(document) && object(document.sbom) ? document.sbom : document;
  if (object(spdx) && typeof spdx.spdxVersion === 'string') return importSpdxDocument(spdx, digest);
  throw new Error('Expected a CycloneDX JSON (1.2 or later 1.x) or SPDX JSON (2.2, 2.3) SBOM');
}

const SPDX_RELATIONSHIPS = 100_000;

/** SPDX packages become CycloneDX-shaped components so that both formats pass the same checks. */
function importSpdxDocument(spdx: Record<string, unknown>, digest: string): SbomImport {
  const version = /^SPDX-(2\.[23])$/.exec(String(spdx.spdxVersion));
  if (!version || !Array.isArray(spdx.packages))
    throw new Error('Expected SPDX JSON 2.2 or 2.3 with packages');
  if (spdx.packages.length > 20_000) throw new Error('SBOM exceeds 20000 component entries');
  const relationships = spdx.relationships === undefined ? [] : spdx.relationships;
  if (!Array.isArray(relationships) || relationships.length > SPDX_RELATIONSHIPS)
    throw new Error('Invalid SPDX relationships');
  // The package the document describes is the system itself, not one of its dependencies.
  const described = new Set<string>(
    Array.isArray(spdx.documentDescribes) ? spdx.documentDescribes.filter(text) : [],
  );
  for (const relation of relationships)
    if (object(relation) && relation.relationshipType === 'DESCRIBES' && text(relation.relatedSpdxElement))
      described.add(relation.relatedSpdxElement);
  const warnings: string[] = [];
  const components: Record<string, unknown>[] = [];
  let root: string | undefined;
  for (const [index, entry] of spdx.packages.entries()) {
    if (!object(entry)) throw new Error('Invalid SBOM component');
    const id = entry.SPDXID;
    if (!text(id)) throw new Error('Invalid SBOM component reference');
    const refs = Array.isArray(entry.externalRefs) ? entry.externalRefs : [];
    const purl = refs.find(
      (ref) => object(ref) && ref.referenceType === 'purl' && text(ref.referenceLocator),
    ) as { referenceLocator: string } | undefined;
    if (described.has(id)) {
      root ??= id;
      continue;
    }
    const info = entry.versionInfo;
    const component: Record<string, unknown> = {
      'bom-ref': id,
      ...(purl ? { purl: purl.referenceLocator } : {}),
    };
    // The package URL is authoritative. A version field beside a versionless purl is used only when
    // it is one exact version: GitHub writes manifest ranges (`^4.17.0`) there.
    if (
      purl &&
      !/@[^/]+$/.test(purl.referenceLocator.split(/[?#]/)[0]!) &&
      text(info) &&
      info !== 'NOASSERTION'
    ) {
      if (/^[A-Za-z0-9][A-Za-z0-9.!+_-]*$/.test(info) && !/^(?:latest|\*)$/i.test(info))
        component.version = info;
      else
        warnings.push(
          `Component ${index + 1}: version ${info.slice(0, 40)} is a range; imported by name only.`,
        );
    }
    if (Array.isArray(entry.checksums)) {
      const sha = entry.checksums.find(
        (value) =>
          object(value) &&
          value.algorithm === 'SHA256' &&
          typeof value.checksumValue === 'string' &&
          /^[a-fA-F0-9]{64}$/.test(value.checksumValue),
      );
      if (object(sha)) component.hashes = [{ alg: 'SHA-256', content: sha.checksumValue }];
    }
    components.push(component);
  }
  const edges = new Map<string, string[]>();
  for (const relation of relationships) {
    if (!object(relation)) throw new Error('Invalid SPDX relationships');
    const type = relation.relationshipType;
    if (type !== 'DEPENDS_ON' && type !== 'DEPENDENCY_OF') continue;
    const [from, to] =
      type === 'DEPENDS_ON'
        ? [relation.spdxElementId, relation.relatedSpdxElement]
        : [relation.relatedSpdxElement, relation.spdxElementId];
    if (!text(from) || !text(to)) throw new Error('Invalid SBOM dependency references');
    const targets = edges.get(from) ?? [];
    if (!targets.includes(to)) targets.push(to);
    edges.set(from, targets);
  }
  const creation = object(spdx.creationInfo) ? spdx.creationInfo : {};
  const result = importCycloneDxDocument(
    {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      ...(root ? { metadata: { component: { 'bom-ref': root } } } : {}),
      components,
      ...(edges.size ? { dependencies: [...edges].map(([ref, dependsOn]) => ({ ref, dependsOn })) } : {}),
    },
    digest,
    'SPDX',
  );
  result.source = { format: 'SPDX', spec_version: version[1]!, digest };
  result.warnings.unshift(...warnings);
  const name = text(spdx.name) ? spdx.name : undefined;
  const created = text(creation.created) ? creation.created : undefined;
  result.subject = { ...(name ? { name } : {}), ...(created ? { created } : {}), properties: {} };
  return result;
}

/** The newest CycloneDX version this release was checked against. */
export const CYCLONEDX_KNOWN_MINOR = 7;
/**
 * The CycloneDX 1.x minor version, or nothing. 1.2 is the first with `metadata` and `dependencies`.
 * Minor versions add fields and deprecate, they do not remove what is read here (components, package
 * URLs, references, dependencies, metadata, properties), so a later 1.x is read by the 1.7 rules.
 * A 2.x is a different format and is refused.
 */
export function cycloneDxMinor(specVersion: unknown): number | undefined {
  // Only text or a number: String(['1.6']) is '1.6', and a one-element array is not a version.
  const match =
    typeof specVersion === 'string' || typeof specVersion === 'number'
      ? // No leading zero: no generator writes "1.07", and "1.07" is not "1.7".
        /^1\.(0|[1-9]\d{0,2})$/.exec(String(specVersion))
      : null;
  const minor = match ? Number(match[1]) : undefined;
  return minor !== undefined && minor >= 2 ? minor : undefined;
}

/** @internal Checks a CycloneDX document held in memory, as a scan will read it. */
export function importCycloneDxValue(bom: unknown, digest: string): SbomImport {
  return importCycloneDxDocument(bom, digest);
}

function importCycloneDxDocument(bom: unknown, digest: string, provenance = 'CycloneDX'): SbomImport {
  const minor = object(bom) ? cycloneDxMinor(bom.specVersion) : undefined;
  // `components` is optional in CycloneDX: an image with no packages is a valid, empty list.
  if (
    !object(bom) ||
    bom.bomFormat !== 'CycloneDX' ||
    minor === undefined ||
    (bom.components !== undefined && !Array.isArray(bom.components))
  )
    throw new Error('Expected CycloneDX JSON 1.2 or later 1.x');
  const result: SbomImport = {
    components: [],
    warnings: [],
    dependencies: [],
    source: { format: 'CycloneDX', spec_version: `1.${minor}`, digest },
    ...(minor > CYCLONEDX_KNOWN_MINOR
      ? {
          notices: [
            `CycloneDX 1.${minor} is newer than this release knows (1.${CYCLONEDX_KNOWN_MINOR}); it was read by the 1.${CYCLONEDX_KNOWN_MINOR} rules.`,
          ],
        }
      : {}),
  };
  const ids = new Set<string>();
  const componentIds = new Set<string>();
  const byReference = new Map<string, Component>();
  const metadataRoot =
    object(bom.metadata) && object(bom.metadata.component) ? bom.metadata.component['bom-ref'] : undefined;
  if (metadataRoot !== undefined && !text(metadataRoot))
    throw new Error('Invalid SBOM metadata root reference');
  let count = 0;
  const visit = (entries: unknown[], depth: number) => {
    if (depth > 32) throw new Error('SBOM component nesting exceeds 32');
    for (const entry of entries) {
      if (++count > 20_000) throw new Error('SBOM exceeds 20000 component entries');
      if (!object(entry)) throw new Error('Invalid SBOM component');
      if (entry.components !== undefined) {
        if (!Array.isArray(entry.components)) throw new Error('Invalid nested SBOM components');
        visit(entry.components, depth + 1);
      }
      const ref = entry['bom-ref'];
      if (ref !== undefined && !text(ref)) throw new Error('Invalid SBOM component reference');
      if (ref !== undefined) {
        if (ids.has(ref as string)) throw new Error('Duplicate SBOM component reference');
        ids.add(ref as string);
      }
      if (!text(entry.purl)) {
        result.warnings.push(`Component ${count}: missing package URL; not imported.`);
        continue;
      }
      // The package type is case-insensitive in the purl specification; tools write `pkg:NPM/…` too.
      const match = /^pkg:([A-Za-z][A-Za-z0-9.+-]*)\/([^?#]+)(?:\?[^#]*)?(?:#.*)?$/.exec(entry.purl);
      if (!match) {
        // One component this application cannot read must not block the rest of the document.
        result.warnings.push(`Component ${count}: package URL is not valid; not imported.`);
        continue;
      }
      let ecosystem;
      try {
        ecosystem = normalizeEcosystem(match[1]!.toLowerCase());
      } catch {
        result.warnings.push(
          `Component ${count}: unsupported package ecosystem ${match[1]!.slice(0, 40)}; not imported.`,
        );
        continue;
      }
      // purl versions are separated before percent decoding (npm scopes use %40). A leading @ is
      // an unencoded npm scope, not a version separator.
      const split = match[2]!.lastIndexOf('@');
      // An empty version string means the generator did not know the version.
      const declared = entry.version === '' || entry.version === null ? undefined : entry.version;
      if (declared !== undefined && !text(declared)) {
        result.warnings.push(`Component ${count}: version is not text; not imported.`);
        continue;
      }
      // Go tools write the same version as v1.8.0 or 1.8.0; Python treats 1.0 and 1.0.0 as equal.
      const sameVersion = (first: string, second: string): boolean => {
        if (ecosystem === 'Go') return first.replace(/^v/, '') === second.replace(/^v/, '');
        if (ecosystem === 'PyPI' && validPython(first) && validPython(second))
          return samePythonVersion(first, second);
        return first === second;
      };
      const rawName = split <= 0 ? match[2]! : match[2]!.slice(0, split);
      const rawVersion = split <= 0 ? undefined : match[2]!.slice(split + 1);
      let name: string;
      let version: string | undefined;
      let purlVersion: string | undefined;
      try {
        name = decodeURIComponent(rawName);
        purlVersion = rawVersion === undefined ? undefined : decodeURIComponent(rawVersion);
        if (ecosystem === 'Maven') name = name.replace(/\/(?!.*\/)/, ':');
        name = normalizePackageName(ecosystem, name);
        version = purlVersion ?? declared;
        if (version !== undefined) version = exactLibraryVersion(version, ecosystem);
      } catch (error) {
        // One component this application cannot read must not block the rest of the document.
        result.warnings.push(
          `Component ${count}: ${error instanceof Error ? error.message.slice(0, 160) : 'unsupported package identity'}; not imported.`,
        );
        continue;
      }
      // Two different versions for one component is a contradiction in the document itself.
      if (purlVersion && declared !== undefined && !sameVersion(purlVersion, declared))
        throw new Error('Conflicting SBOM package versions');
      const component: Component = {
        id: `sbom:${hash(ref ?? entry.purl).slice(0, 32)}`,
        ecosystem,
        name,
        purl: entry.purl,
        ...(typeof ref === 'string' ? { sbom_ref: ref } : {}),
        ...(['application', 'library', 'container'].includes(String(entry.type))
          ? { artifact_kind: entry.type as 'application' | 'library' | 'container' }
          : entry.type === 'machine-learning-model'
            ? { artifact_kind: 'model' as const }
            : {}),
        ...(version === undefined ? {} : { version }),
        provenance: { source: provenance, reference: digest },
      };
      // `evidence.occurrences` (CycloneDX 1.5+) says which files the package was found in. That is
      // where a reader of an alert should look, so it becomes the component's note.
      const occurrences =
        object(entry.evidence) && Array.isArray(entry.evidence.occurrences) ? entry.evidence.occurrences : [];
      const locations = [
        ...new Set(
          occurrences
            .slice(0, 100)
            .map((occurrence) => (object(occurrence) ? occurrence.location : undefined))
            .filter((location): location is string => text(location) && location.length <= 300),
        ),
      ];
      if (locations.length) {
        let note = `found in ${locations[0]}`;
        for (const location of locations.slice(1)) {
          if (note.length + location.length + 2 > 480) {
            note += ' and others';
            break;
          }
          note += `, ${location}`;
        }
        component.note = note;
      }
      if (entry.hashes !== undefined) {
        if (!Array.isArray(entry.hashes) || entry.hashes.length > 32) throw new Error('Invalid SBOM hashes');
        const hashes = entry.hashes.filter((value) => object(value) && value.alg === 'SHA-256');
        if (hashes.length) {
          const values = hashes.map((value) => value.content);
          if (
            values.some((value) => typeof value !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value)) ||
            new Set(values.map((value) => String(value).toLowerCase())).size !== 1
          )
            throw new Error('Invalid or conflicting SBOM SHA-256 hashes');
          component.digest = `sha256:${String(values[0]).toLowerCase()}`;
        }
      }
      if (componentIds.has(component.id)) {
        // The same package listed twice without a reference of its own (nested under two parents)
        // is one component. A reference used twice is a contradiction in the document.
        if (typeof ref !== 'string') continue;
        throw new Error('Duplicate SBOM component identity');
      }
      componentIds.add(component.id);
      if (typeof ref === 'string') byReference.set(ref, component);
      result.components.push(component);
    }
  };
  visit((bom.components as unknown[] | undefined) ?? [], 0);
  if (bom.dependencies !== undefined) {
    if (!Array.isArray(bom.dependencies) || bom.dependencies.length > 20_000)
      throw new Error('Invalid SBOM dependencies');
    const sources = new Set<string>();
    let edges = 0;
    for (const dependency of bom.dependencies) {
      // The schema requires only `ref`; generators omit `dependsOn` for a component with no dependencies.
      if (object(dependency) && dependency.dependsOn === undefined) dependency.dependsOn = [];
      if (
        !object(dependency) ||
        !text(dependency.ref) ||
        !Array.isArray(dependency.dependsOn) ||
        dependency.dependsOn.length > 1000 ||
        dependency.dependsOn.some((ref) => !text(ref))
      )
        throw new Error('Invalid SBOM dependency references');
      if (sources.has(dependency.ref) || new Set(dependency.dependsOn).size !== dependency.dependsOn.length)
        throw new Error('Duplicate SBOM dependency reference');
      sources.add(dependency.ref);
      edges += dependency.dependsOn.length;
      if (edges > 100_000) throw new Error('SBOM exceeds 100000 dependency edges');
      const targets = dependency.dependsOn as string[];
      result.dependencies.push({ ref: dependency.ref, depends_on: [...targets] });
      const component = byReference.get(dependency.ref);
      if (!component && dependency.ref !== metadataRoot)
        result.warnings.push(
          `Dependency source ${dependency.ref}: not an imported package; relationship retained as unverified metadata.`,
        );
      if (component)
        component.dependencies = targets.map((ref) => ({
          ref,
          ...(byReference.has(ref) ? { component_id: byReference.get(ref)!.id } : {}),
        }));
      for (const ref of targets)
        if (!byReference.has(ref))
          result.warnings.push(
            `Dependency target ${ref}: not an imported package; reference retained without resolved identity.`,
          );
    }
  }
  const metadata = object(bom.metadata) ? bom.metadata : {};
  const subject = object(metadata.component) ? metadata.component : {};
  const properties: Record<string, string> = {};
  if (Array.isArray(metadata.properties))
    for (const property of metadata.properties.slice(0, 200))
      if (
        object(property) &&
        text(property.name) &&
        property.name.startsWith('security-watch:') &&
        text(property.value) &&
        !Object.hasOwn(properties, property.name)
      )
        properties[property.name] = property.value;
  result.subject = {
    ...(text(subject.name) ? { name: subject.name } : {}),
    ...(text(metadata.timestamp) ? { created: metadata.timestamp } : {}),
    properties,
  };
  return result;
}
