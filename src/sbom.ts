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
  source: { format: 'CycloneDX'; spec_version: string; digest: string };
}
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const text = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= 1000 && !LINE_BREAKING.test(value);

/** Bounded local metadata import: never follows references, runs scripts or fetches packages. */
export function importCycloneDx(path: string): SbomImport {
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > 20 * 1024 * 1024)
    throw new Error('SBOM must be a regular JSON file of at most 20 MiB');
  const bytes = readFileSync(path);
  if (bytes.byteLength > 20 * 1024 * 1024) throw new Error('SBOM exceeds 20 MiB');
  const bom: unknown = JSON.parse(bytes.toString('utf8'));
  if (
    !object(bom) ||
    bom.bomFormat !== 'CycloneDX' ||
    !['1.4', '1.5', '1.6'].includes(String(bom.specVersion)) ||
    !Array.isArray(bom.components)
  )
    throw new Error('Expected CycloneDX JSON 1.4, 1.5 or 1.6 with components');
  const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  const result: SbomImport = {
    components: [],
    warnings: [],
    dependencies: [],
    source: { format: 'CycloneDX', spec_version: String(bom.specVersion), digest },
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
        provenance: { source: 'CycloneDX', reference: digest },
      };
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
  visit(bom.components, 0);
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
  return result;
}
