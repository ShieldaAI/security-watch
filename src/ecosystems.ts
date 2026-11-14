import type { Component } from './types.js';
import { hash, LINE_BREAKING } from './util.js';
import { valid } from 'semver';
import { valid as validPython } from '@renovatebot/pep440';

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
  let valid = name.length > 0 && name.length <= 500 && !/\s/u.test(name) && !LINE_BREAKING.test(name);
  switch (ecosystem) {
    case 'npm':
      // Names registered before 2017 may contain capitals (JSONStream) and are case-sensitive.
      valid &&=
        name.length <= 214 && /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9]|[A-Za-z0-9])[A-Za-z0-9._-]*$/.test(name);
      valid &&= !name.startsWith('@') || name === name.toLowerCase();
      break;
    case 'PyPI':
      valid &&= /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(name);
      normalized = name.toLowerCase().replace(/[-_.]+/g, '-');
      break;
    case 'Packagist':
      // Composer treats names as case-insensitive and publishes them in lower case.
      normalized = name.toLowerCase();
      valid &&= /^[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?\/[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?$/.test(normalized);
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

const identityKeys = new Map<string, string | null>();
/** One comparable key per package identity, or undefined when the ecosystem or name is not recognised. */
export function packageKey(value: { ecosystem: string; name: string }): string | undefined {
  const cacheKey = `${value.ecosystem}\u0000${value.name}`;
  let key = identityKeys.get(cacheKey);
  if (key === undefined) {
    try {
      const ecosystem = normalizeEcosystem(value.ecosystem);
      key = `${ecosystem}\u0000${packageIdentity(ecosystem, value.name)}`;
    } catch {
      key = null;
    }
    if (identityKeys.size >= 200_000) identityKeys.clear();
    identityKeys.set(cacheKey, key);
  }
  return key ?? undefined;
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
  // Keep the declared spelling; assessment separately restricts supported ordering.
  if (ecosystem === 'PyPI' && !validPython(version))
    throw new Error('Use an exact installed Python version in PEP 440 syntax, or omit the version');
  return version;
}

/** Packages published before npm required lower-case names. Their capitals are part of the name. */
const LEGACY_NPM_NAMES = new Set(['JSONStream', 'Base64', 'JSONPath', 'JSONSelect']);

/**
 * What to tell the operator about an npm name typed by hand with capital letters. npm names are
 * case-sensitive, and every name registered since 2017 is lower case: `Lodash` is not `lodash`, and
 * an entry spelled that way matches no advisory. A few packages from before that rule keep their
 * capitals, so the name is accepted, and anything but a known legacy name is reported.
 */
export function capitalisedNpmName(component: { ecosystem: Ecosystem; name: string }): string | undefined {
  if (component.ecosystem !== 'npm' || component.name === component.name.toLowerCase()) return undefined;
  if (LEGACY_NPM_NAMES.has(component.name)) return undefined;
  return `npm package name ${component.name} contains capital letters. npm names are case-sensitive and current names are lower case, so this entry matches only advisories published for exactly that spelling. Write ${component.name.toLowerCase()} unless this is a package from before 2017 that kept its capitals; names imported from a lockfile or SBOM are taken as published.`;
}

export interface Library {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
  /** Where this library is used, in the operator's words. */
  note?: string;
}

/** A short, single-line pointer written by the operator, such as a service, repository path or owner. */
export function libraryNote(value: string): string {
  const note = value.trim();
  if (!note || note.length > 500 || LINE_BREAKING.test(note))
    throw new Error('A library note must be 1 to 500 characters on one line');
  return note;
}

/** Keep each distinct note once, in the order given, within the note length limit. */
export function mergeNotes(first: string | undefined, second: string | undefined): string | undefined {
  if (!first || !second) return first ?? second;
  if (first.split(' | ').includes(second)) return first;
  const merged = `${first} | ${second}`;
  return merged.length > 500 ? first : merged;
}

export function parseLibrary(value: unknown, defaultEcosystem?: string): Library {
  let ecosystem: Ecosystem;
  let name: string;
  let version: string | undefined;
  let note: string | undefined;
  if (typeof value === 'string') {
    let entry = value.trim();
    // "npm:lodash@4.17.21  # checkout service, apps/checkout" keeps the text after # as the note.
    const comment = /\s#/.exec(entry);
    if (comment) {
      const text = entry.slice(comment.index + comment[0].length).trim();
      if (text) note = libraryNote(text);
      entry = entry.slice(0, comment.index).trim();
    }
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
      Object.keys(input).some((key) => !['name', 'version', 'ecosystem', 'note'].includes(key)) ||
      typeof input.name !== 'string' ||
      (input.note !== undefined && typeof input.note !== 'string') ||
      (input.version !== undefined && typeof input.version !== 'string') ||
      (input.ecosystem !== undefined && typeof input.ecosystem !== 'string')
    )
      throw new Error('Library objects accept name, optional version, ecosystem and note only');
    if (!defaultEcosystem && typeof input.ecosystem !== 'string')
      throw new Error('Library ecosystem is required');
    ecosystem = normalizeEcosystem(defaultEcosystem ?? String(input.ecosystem));
    if (input.ecosystem !== undefined && normalizeEcosystem(input.ecosystem as string) !== ecosystem)
      throw new Error('Library ecosystem does not match its group');
    name = input.name;
    version = input.version as string | undefined;
    if (input.note !== undefined) note = libraryNote(input.note as string);
  } else throw new Error('Expected a library string or object');
  return {
    ecosystem,
    name: normalizePackageName(ecosystem, name),
    ...(version === undefined ? {} : { version: exactLibraryVersion(version, ecosystem) }),
    ...(note === undefined ? {} : { note }),
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
    const key = JSON.stringify([library.ecosystem, library.name, library.version ?? null]);
    const note = mergeNotes(unique.get(key)?.note, library.note);
    unique.set(key, { ...library, ...(note ? { note } : {}) });
  }
  return [...unique.values()].map((library) => ({
    id: `library:${hash(JSON.stringify([library.ecosystem, library.name, library.version ?? null])).slice(0, 24)}`,
    ...library,
  }));
}
