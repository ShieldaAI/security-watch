import type { Component } from './types.js';
import { hash } from './util.js';
import { valid } from 'semver';

/** Package identities follow the registry named by the OSV ecosystem. */
export const ECOSYSTEMS = [
  'npm',
  'PyPI',
  'Packagist',
  'Go',
  'Maven',
  'crates.io',
  'RubyGems',
  'NuGet',
  'Hex',
  'Pub',
  'Hackage',
  'SwiftURL',
] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

const aliases: Record<string, Ecosystem> = {
  npm: 'npm',
  node: 'npm',
  nodejs: 'npm',
  javascript: 'npm',
  js: 'npm',
  pypi: 'PyPI',
  python: 'PyPI',
  pip: 'PyPI',
  packagist: 'Packagist',
  php: 'Packagist',
  composer: 'Packagist',
  go: 'Go',
  golang: 'Go',
  maven: 'Maven',
  java: 'Maven',
  'crates.io': 'crates.io',
  rust: 'crates.io',
  cargo: 'crates.io',
  rubygems: 'RubyGems',
  ruby: 'RubyGems',
  gem: 'RubyGems',
  nuget: 'NuGet',
  dotnet: 'NuGet',
  '.net': 'NuGet',
  hex: 'Hex',
  erlang: 'Hex',
  elixir: 'Hex',
  pub: 'Pub',
  dart: 'Pub',
  flutter: 'Pub',
  hackage: 'Hackage',
  haskell: 'Hackage',
  swifturl: 'SwiftURL',
  swift: 'SwiftURL',
};

export function normalizeEcosystem(value: string): Ecosystem {
  const ecosystem = Object.hasOwn(aliases, value.trim().toLowerCase())
    ? aliases[value.trim().toLowerCase()]
    : undefined;
  if (!ecosystem) throw new Error(`Unsupported library ecosystem: ${value}`);
  return ecosystem;
}

export function normalizePackageName(ecosystem: Ecosystem, value: string): string {
  const name = value.trim();
  let normalized = name;
  let valid = name.length > 0 && name.length <= 500 && !/[\s\u0000-\u001f\u007f]/u.test(name);
  switch (ecosystem) {
    case 'npm':
      valid &&= name.length <= 214 && /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(name);
      break;
    case 'PyPI':
      valid &&= /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(name);
      normalized = name.toLowerCase().replace(/[-_.]+/g, '-');
      break;
    case 'Packagist':
      valid &&= /^[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?\/[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?$/.test(name);
      break;
    case 'Maven':
      valid &&= /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/.test(name);
      break;
    case 'Go':
      valid &&=
        /^[A-Za-z0-9][A-Za-z0-9._~/-]*$/.test(name) &&
        !name.split('/').some((p) => !p || p === '.' || p === '..');
      break;
    case 'NuGet':
      valid &&= /^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name);
      break;
    case 'crates.io':
      valid &&= /^[A-Za-z][A-Za-z0-9_-]*$/.test(name);
      normalized = name.toLowerCase();
      break;
    case 'SwiftURL':
      try {
        const url = new URL(name.startsWith('https://') ? name : `https://${name}`);
        valid &&=
          url.protocol === 'https:' &&
          !url.username &&
          !url.password &&
          !url.port &&
          !url.search &&
          !url.hash &&
          url.hostname.includes('.') &&
          !/[\\%]/.test(name) &&
          url.pathname !== '/' &&
          !name
            .replace(/^https:\/\//, '')
            .split('/')
            .some((part) => !part || part === '.' || part === '..');
      } catch {
        valid = false;
      }
      break;
    default:
      valid &&= /^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name);
  }
  if (!valid) throw new Error(`Invalid ${ecosystem} package name: ${value}`);
  return normalized;
}

function packageIdentity(ecosystem: Ecosystem, name: string): string {
  const normalized = normalizePackageName(ecosystem, name);
  if (ecosystem === 'NuGet') return normalized.toLowerCase();
  if (ecosystem === 'crates.io') return normalized.replace(/_/g, '-');
  if (ecosystem === 'SwiftURL') {
    const url = new URL(normalized.startsWith('https://') ? normalized : `https://${normalized}`);
    return `${url.hostname}${url.pathname.replace(/\.git$/, '')}`;
  }
  return normalized;
}

/** Keep the published spelling: OSV does not consistently normalize registry aliases. */
export function osvPackageNames(ecosystem: Ecosystem, value: string): string[] {
  const name = normalizePackageName(ecosystem, value);
  if (ecosystem === 'crates.io')
    return [...new Set([name, name.replace(/_/g, '-'), name.replace(/-/g, '_')])];
  if (ecosystem === 'NuGet') return [...new Set([name, name.toLowerCase()])];
  if (ecosystem === 'SwiftURL') {
    const identity = packageIdentity(ecosystem, name);
    return [
      ...new Set([name, identity, `${identity}.git`, `https://${identity}`, `https://${identity}.git`]),
    ];
  }
  return [name];
}

export function samePackage(
  left: { ecosystem: string; name: string },
  right: { ecosystem: string; name: string },
): boolean {
  try {
    const ecosystem = normalizeEcosystem(left.ecosystem);
    return (
      ecosystem === normalizeEcosystem(right.ecosystem) &&
      packageIdentity(ecosystem, left.name) === packageIdentity(ecosystem, right.name)
    );
  } catch {
    return false;
  }
}

/** A declared version, never a dependency constraint or an inferred latest release. */
export function exactLibraryVersion(value: string, ecosystem?: Ecosystem): string {
  const version = value.trim();
  if (
    !version ||
    version.length > 500 ||
    !/^[A-Za-z0-9][A-Za-z0-9.!+_-]*$/.test(version) ||
    /^(?:latest|\*)$/i.test(version)
  )
    throw new Error('Use an exact installed library version, or omit the version');
  if (
    ecosystem &&
    ['npm', 'Go', 'crates.io', 'Hex', 'Pub', 'SwiftURL'].includes(ecosystem) &&
    !valid(version)
  )
    throw new Error(`Use an exact installed ${ecosystem} version, or omit the version`);
  // Validate PEP 440 syntax without ordering versions or rewriting the declared installation.
  if (
    ecosystem === 'PyPI' &&
    !/^v?(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:alpha|beta|preview|pre|rc|a|b|c)[-_.]?\d*)?(?:-\d+|[-_.]?(?:post|rev|r)[-_.]?\d*)?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$/i.test(
      version,
    )
  )
    throw new Error('Use an exact installed Python version in PEP 440 syntax, or omit the version');
  return version;
}

export interface Library {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
}

export function parseLibrary(value: unknown, defaultEcosystem?: string): Library {
  let ecosystem: Ecosystem;
  let name: string;
  let version: string | undefined;
  if (typeof value === 'string') {
    let entry = value.trim();
    if (defaultEcosystem) ecosystem = normalizeEcosystem(defaultEcosystem);
    else {
      const separator = entry.indexOf(':');
      if (separator < 1)
        throw new Error('Library entries require an ecosystem prefix, such as python:requests');
      ecosystem = normalizeEcosystem(entry.slice(0, separator));
      entry = entry.slice(separator + 1).trim();
    }
    const parts = entry.split(/\s+/);
    if (parts.length > 2) throw new Error('Expected a library name and optional exact version');
    if (parts.length === 2) [name, version] = parts as [string, string];
    else if (ecosystem === 'PyPI' && entry.includes('==')) {
      const split = entry.split('==');
      if (split.length !== 2) throw new Error('Expected one exact library version');
      [name, version] = split as [string, string];
    } else {
      const separator = entry.lastIndexOf('@');
      if (separator > 0) [name, version] = [entry.slice(0, separator), entry.slice(separator + 1)];
      else name = entry;
    }
  } else if (value && typeof value === 'object' && !Array.isArray(value)) {
    const input = value as Record<string, unknown>;
    if (
      Object.keys(input).some((key) => !['name', 'version', 'ecosystem'].includes(key)) ||
      typeof input.name !== 'string' ||
      (input.version !== undefined && typeof input.version !== 'string') ||
      (input.ecosystem !== undefined && typeof input.ecosystem !== 'string')
    )
      throw new Error('Library objects accept name, optional version and ecosystem only');
    if (!defaultEcosystem && typeof input.ecosystem !== 'string')
      throw new Error('Library ecosystem is required');
    ecosystem = normalizeEcosystem(defaultEcosystem ?? String(input.ecosystem));
    if (input.ecosystem !== undefined && normalizeEcosystem(input.ecosystem as string) !== ecosystem)
      throw new Error('Library ecosystem does not match its group');
    name = input.name;
    version = input.version as string | undefined;
  } else throw new Error('Expected a library string or object');
  return {
    ecosystem,
    name: normalizePackageName(ecosystem, name),
    ...(version === undefined ? {} : { version: exactLibraryVersion(version, ecosystem) }),
  };
}

/** Parse one entry per line; the ecosystem is explicit or supplied for the whole list. */
export function parseLibraryList(text: string, ecosystem?: string): Component[] {
  if (ecosystem !== undefined) normalizeEcosystem(ecosystem);
  if (Buffer.byteLength(text, 'utf8') > 2 * 1024 * 1024) throw new Error('Library list exceeds 2 MiB');
  const entries = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
  if (entries.length > 20_000) throw new Error('Library list exceeds 20000 entries');
  const unique = new Map<string, Library>();
  for (const entry of entries) {
    const library = parseLibrary(entry, ecosystem);
    unique.set(JSON.stringify(library), library);
  }
  return [...unique.values()].map((library) => ({
    id: `library:${hash(JSON.stringify([library.ecosystem, library.name, library.version ?? null])).slice(0, 24)}`,
    ...library,
  }));
}
