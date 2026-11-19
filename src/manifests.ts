import { lstatSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { XMLParser } from 'fast-xml-parser';
import { parse as parseYaml, parseAllDocuments } from 'yaml';
import { exactLibraryVersion, normalizePackageName, packageKey, type Ecosystem } from './ecosystems.js';
import { LINE_BREAKING, singleLine } from './util.js';

/**
 * Builds a CycloneDX software bill of materials from the dependency files already in a project:
 * lockfiles first, manifests where no lockfile exists. It reads files only. It never runs a package
 * manager, installs anything, follows a symbolic link or contacts a registry, so it is safe to run on
 * an untrusted checkout and gives the same answer offline.
 */

/** One dependency file that was read. */
export interface DependencyFile {
  /** Path relative to the project, with `/` separators. */
  path: string;
  ecosystem: Ecosystem;
  /** `lockfile` gives exact versions; `manifest` often only version ranges. */
  kind: 'lockfile' | 'manifest';
  packages: number;
}

/** What `generateSbom` describes the project as. Every field is optional. */
export interface SbomOptions {
  /** Project folder, or one dependency file. Default: the current directory. */
  project?: string;
  /** Human-readable system name. Default: the name in package.json, pyproject.toml or the folder name. */
  name?: string;
  /** Stable system ID used by an SBOM folder. Default: derived from the name. */
  systemId?: string;
  owner?: string;
  environment?: string;
  /** Where the system runs and who to ask. Shown in alerts. */
  note?: string;
  exposure?: 'internet' | 'internal' | 'unknown';
  criticality?: 'unknown' | 'low' | 'medium' | 'high' | 'critical';
  /** HTTPS address of the source repository, without credentials. */
  sourceUrl?: string;
  /** Commit or build the SBOM was made from. */
  sourceRevision?: string;
  /** Leave out development-only dependencies where the dependency file says which they are. */
  production?: boolean;
  /** Time written as the SBOM timestamp. Default: now. */
  now?: Date;
  /** Version of the generating tool, written to the SBOM metadata. */
  toolVersion?: string;
}

export interface GeneratedSbom {
  /** A CycloneDX 1.6 JSON document. Write it with `JSON.stringify`. */
  bom: Record<string, unknown>;
  /** The system ID and name written into the document. */
  system: { id: string; name: string };
  files: DependencyFile[];
  ecosystems: Ecosystem[];
  /** Components in the document. */
  packages: number;
  /** Packages recorded without an exact version: they are watched by name only. */
  unversioned: number;
  warnings: string[];
}

interface Found {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
  dev?: boolean;
}
interface Parsed {
  packages: Found[];
  /** Entries this reader recognised but cannot monitor, such as Git or local-path dependencies. */
  skipped: number;
}
type Reader = (text: string, location: string) => Parsed;

const MAX_FILE_BYTES = 20 * 1024 * 1024;
const MAX_DEPTH = 12;
const MAX_ENTRIES = 200_000;
const MAX_FILES = 2_000;
const MAX_COMPONENTS = 20_000;
const MAX_LOCATIONS = 10;

/** Folders that hold installed, generated or vendored copies rather than the project's own declarations. */
const SKIPPED_FOLDERS = new Set([
  'node_modules',
  'bower_components',
  'jspm_packages',
  'vendor',
  'venv',
  'site-packages',
  '__pycache__',
  'target',
  'dist',
  'build',
  'out',
  'coverage',
  'Pods',
  'Carthage',
  'deps',
  '_build',
  'obj',
  'bin',
  // Test data describes other projects, not this one.
  'fixtures',
  '__fixtures__',
  'testdata',
  '__mocks__',
]);

const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const string = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

function found(ecosystem: Ecosystem, name: string, version?: string, dev?: boolean): Found {
  return {
    ecosystem,
    name,
    ...(version ? { version } : {}),
    ...(dev ? { dev: true } : {}),
  };
}

// ---------------------------------------------------------------------------------------------- npm

/** The registry package a dependency specifier points at, or undefined for Git, file and link specifiers. */
function npmSpecifier(name: string, specifier: string): { name: string; range: string } | undefined {
  let spec = specifier.trim();
  if (spec.length > 1000) return undefined;
  if (spec.startsWith('npm:')) {
    const target = spec.slice(4);
    const at = target.lastIndexOf('@');
    return at > 0 ? { name: target.slice(0, at), range: target.slice(at + 1) } : { name: target, range: '' };
  }
  if (/^(?:file|link|workspace|portal|patch|git|git\+[a-z]+|https?|github|gitlab|bitbucket):/i.test(spec))
    return undefined;
  // `user/repo` is a GitHub shorthand, not a registry version.
  if (/^[^@\s][^\s]*\/[^\s]+$/.test(spec) && !/^\d/.test(spec)) return undefined;
  spec = spec.replace(/^=\s*/, '').replace(/^v(?=\d)/, '');
  return { name, range: spec };
}

const npmPackageLock: Reader = (text) => {
  const lock: unknown = JSON.parse(text);
  if (!record(lock)) throw new Error('not a package-lock document');
  const packages: Found[] = [];
  let skipped = 0;
  if (record(lock.packages)) {
    for (const [location, value] of Object.entries(lock.packages)) {
      const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(location);
      if (!match || !record(value)) continue;
      if (value.link === true || (string(value.resolved) && /^(?:file|git|git\+)/.test(value.resolved))) {
        skipped++;
        continue;
      }
      const name = string(value.name) ? value.name : match[1]!;
      packages.push(
        found('npm', name, string(value.version) ? value.version : undefined, value.dev === true),
      );
    }
    return { packages, skipped };
  }
  // lockfileVersion 1: a nested tree of `dependencies`.
  const visit = (dependencies: unknown, depth: number) => {
    if (!record(dependencies) || depth > 64) return;
    for (const [name, value] of Object.entries(dependencies)) {
      if (!record(value)) continue;
      const version = string(value.version) ? value.version : undefined;
      if (version?.startsWith('npm:')) {
        const target = npmSpecifier(name, version)!;
        packages.push(found('npm', target.name, target.range, value.dev === true));
      } else if (version && /^(?:file|link|git|git\+|https?):/.test(version)) skipped++;
      else packages.push(found('npm', name, version, value.dev === true));
      visit(value.dependencies, depth + 1);
    }
  };
  visit(lock.dependencies, 0);
  return { packages, skipped };
};

/** Yarn 1 (`version "1.2.3"`) and Yarn 2+ (`resolution: "name@npm:1.2.3"`) lockfiles. */
const yarnLock: Reader = (text) => {
  const packages: Found[] = [];
  let skipped = 0;
  let header: string | undefined;
  let fields: Record<string, string> = {};
  const flush = () => {
    if (header === undefined || header.startsWith('__metadata')) return;
    const unquote = (value: string) => value.trim().replace(/^"|"$/g, '');
    if (fields.resolution !== undefined) {
      const resolution = unquote(fields.resolution);
      const match = /^((?:@[^@/]+\/)?[^@]+)@npm:(.+)$/.exec(resolution);
      if (match) packages.push(found('npm', match[1]!, match[2]!));
      else skipped++;
      return;
    }
    const first = unquote(header.split(/,\s*/)[0]!);
    // `"string-width-cjs@npm:string-width@^4.2.0"` installs string-width under another name.
    const alias = first.indexOf('@npm:', 1);
    const at = alias > 0 ? alias : first.lastIndexOf('@');
    if (at <= 0) return;
    const target = npmSpecifier(first.slice(0, at), first.slice(at + 1));
    if (!target) {
      skipped++;
      return;
    }
    packages.push(
      found('npm', target.name, fields.version === undefined ? undefined : unquote(fields.version)),
    );
  };
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      flush();
      header = line.replace(/:\s*$/, '');
      fields = {};
      continue;
    }
    const match = /^ {2}([A-Za-z]+):?\s+(.+)$/.exec(line);
    if (match && (match[1] === 'version' || match[1] === 'resolution')) fields[match[1]] = match[2]!;
  }
  flush();
  return { packages, skipped };
};

const pnpmLock: Reader = (text) => {
  // pnpm 10 can write two YAML documents (the package manager's own lockfile first).
  const documents = parseAllDocuments(text);
  const parsed = (Array.isArray(documents) ? documents : [documents])
    .map((document) => document.toJS({ maxAliasCount: 0 }) as unknown)
    .filter(record);
  // The project's lockfile is the document with the most packages; the other one pins pnpm itself.
  const size = (document: Record<string, unknown>) =>
    record(document.packages) ? Object.keys(document.packages).length : record(document.importers) ? 0 : -1;
  const lock = parsed.reduce<Record<string, unknown> | undefined>(
    (best, document) => (size(document) >= 0 && (!best || size(document) > size(best)) ? document : best),
    undefined,
  );
  if (!lock) throw new Error('not a pnpm lockfile');
  const packages: Found[] = [];
  let skipped = 0;
  const legacy = String(lock.lockfileVersion ?? '').startsWith('5');
  for (const [key, value] of Object.entries(record(lock.packages) ? lock.packages : {})) {
    const entry = key.replace(/^\//, '').split('(')[0]!;
    let name: string;
    let version: string;
    if (legacy) {
      const slash = entry.lastIndexOf('/');
      if (slash <= 0) continue;
      name = entry.slice(0, slash);
      version = entry.slice(slash + 1).split('_')[0]!;
    } else {
      const at = entry.lastIndexOf('@');
      if (at <= 0) continue;
      name = entry.slice(0, at);
      version = entry.slice(at + 1);
    }
    if (/[:]/.test(version) || (name.includes('/') && !name.startsWith('@'))) {
      skipped++;
      continue;
    }
    packages.push(found('npm', name, version, record(value) && value.dev === true));
  }
  return { packages, skipped };
};

const packageJson: Reader = (text) => {
  const manifest: unknown = JSON.parse(text);
  if (!record(manifest)) throw new Error('not a package.json document');
  const packages: Found[] = [];
  let skipped = 0;
  for (const [field, dev] of [
    ['dependencies', false],
    ['optionalDependencies', false],
    ['devDependencies', true],
  ] as const) {
    const dependencies = manifest[field];
    if (!record(dependencies)) continue;
    for (const [name, specifier] of Object.entries(dependencies)) {
      const target = typeof specifier === 'string' ? npmSpecifier(name, specifier) : undefined;
      if (!target) {
        skipped++;
        continue;
      }
      packages.push(found('npm', target.name, target.range, dev));
    }
  }
  return { packages, skipped };
};

// --------------------------------------------------------------------------------------------- PyPI

/** One PEP 508 requirement: the name, and the version only when it is pinned with `==` or `===`. */
function pep508(requirement: string): { name: string; version?: string; direct?: boolean } | undefined {
  const text = requirement.split(';')[0]!.trim();
  const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(text);
  if (!match) return undefined;
  const rest = match[2]!.trim();
  if (rest.startsWith('@')) return { name: match[1]!, direct: true };
  const pinned = /^===?\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)$/.exec(rest);
  return { name: match[1]!, ...(pinned && !pinned[1]!.includes('*') ? { version: pinned[1]! } : {}) };
}

const requirementsTxt: Reader = (text) => {
  const packages: Found[] = [];
  let skipped = 0;
  // A trailing backslash continues a requirement (hashes are usually written that way).
  const lines = text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw
      .replace(/(?:^|\s)#.*$/, '')
      .replace(/\s--hash[=\s]\S+/g, '')
      .trim();
    if (!line || line.startsWith('-')) continue;
    if (/^(?:\.|\/|[a-z+]+:\/\/|git\+)/i.test(line)) {
      skipped++;
      continue;
    }
    const requirement = pep508(line);
    if (!requirement || requirement.direct) {
      skipped++;
      continue;
    }
    packages.push(found('PyPI', requirement.name, requirement.version));
  }
  return { packages, skipped };
};

const pipfileLock: Reader = (text) => {
  const lock: unknown = JSON.parse(text);
  if (!record(lock)) throw new Error('not a Pipfile.lock document');
  const packages: Found[] = [];
  let skipped = 0;
  for (const [section, dev] of [
    ['default', false],
    ['develop', true],
  ] as const) {
    const entries = lock[section];
    if (!record(entries)) continue;
    for (const [name, value] of Object.entries(entries)) {
      if (!record(value) || !string(value.version)) {
        skipped++;
        continue;
      }
      packages.push(found('PyPI', name, value.version.replace(/^===?/, ''), dev));
    }
  }
  return { packages, skipped };
};

/** The `[[package]]` tables of a generated TOML lockfile (Cargo, Poetry, uv, PDM), as flat key/value text. */
function tomlPackages(text: string): Record<string, string>[] {
  const tables: Record<string, string>[] = [];
  let current: Record<string, string> | undefined;
  let prefix = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '[[package]]') {
      current = {};
      tables.push(current);
      prefix = '';
      continue;
    }
    const table = /^\[\[?([^\]]+)\]\]?$/.exec(line);
    if (table) {
      if (current && table[1]!.startsWith('package.')) prefix = `${table[1]!.slice(8)}.`;
      else current = undefined;
      continue;
    }
    if (!current) continue;
    const pair = /^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(line);
    if (!pair) continue;
    const quoted = /^"((?:[^"\\]|\\.)*)"/.exec(pair[2]!);
    current[prefix + pair[1]!] = quoted ? quoted[1]!.replace(/\\(.)/g, '$1') : pair[2]!;
  }
  return tables;
}

const poetryLock: Reader = (text) => {
  const packages: Found[] = [];
  let skipped = 0;
  for (const table of tomlPackages(text)) {
    if (!string(table.name)) continue;
    const source = table['source.type'];
    if (source && source !== 'legacy') {
      skipped++;
      continue;
    }
    packages.push(found('PyPI', table.name, table.version, table.category === 'dev'));
  }
  return { packages, skipped };
};

const uvLock: Reader = (text) => {
  const packages: Found[] = [];
  let skipped = 0;
  for (const table of tomlPackages(text)) {
    if (!string(table.name)) continue;
    const source = table.source;
    if (source !== undefined && !/\bregistry\s*=/.test(source)) {
      skipped++;
      continue;
    }
    packages.push(found('PyPI', table.name, table.version));
  }
  return { packages, skipped };
};

/** Dependencies named in pyproject.toml: PEP 621, PEP 735 dependency groups and Poetry tables. */
const pyprojectToml: Reader = (text) => {
  const packages: Found[] = [];
  let skipped = 0;
  let table = '';
  let collecting: { dev: boolean; text: string; depth: number } | undefined;
  const add = (requirement: string, dev: boolean) => {
    const parsed = pep508(requirement);
    if (!parsed || parsed.direct) skipped++;
    else packages.push(found('PyPI', parsed.name, parsed.version, dev));
  };
  const finish = (value: string, dev: boolean) => {
    for (const match of value.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)) add(match[1] ?? match[2]!, dev);
  };
  const poetryDev = (name: string) =>
    name === 'tool.poetry.dev-dependencies' || /^tool\.poetry\.group\.[^.]+\.dependencies$/.test(name);
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s#.*$/, '').trim();
    if (collecting) {
      collecting.text += ` ${line}`;
      collecting.depth += (line.match(/\[/g) ?? []).length - (line.match(/\]/g) ?? []).length;
      if (collecting.depth <= 0) {
        finish(collecting.text, collecting.dev);
        collecting = undefined;
      }
      continue;
    }
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      table = header[1]!.trim();
      continue;
    }
    const pair = /^("?[A-Za-z0-9_.-]+"?)\s*=\s*(.*)$/.exec(line);
    if (!pair) continue;
    const key = pair[1]!.replace(/"/g, '');
    const value = pair[2]!;
    const pep621 =
      (table === 'project' && key === 'dependencies') ||
      table === 'project.optional-dependencies' ||
      table === 'dependency-groups';
    if (pep621 && value.startsWith('[')) {
      const dev = table === 'dependency-groups';
      const depth = (value.match(/\[/g) ?? []).length - (value.match(/\]/g) ?? []).length;
      if (depth <= 0) finish(value, dev);
      else collecting = { dev, text: value, depth };
      continue;
    }
    if (table === 'tool.poetry.dependencies' || poetryDev(table)) {
      if (key.toLowerCase() === 'python') continue;
      const constraint = /^"([^"]*)"/.exec(value)?.[1] ?? /\bversion\s*=\s*"([^"]*)"/.exec(value)?.[1];
      if (/\b(?:git|path|url)\s*=/.test(value)) {
        skipped++;
        continue;
      }
      // Poetry reads a bare version ("2.31.0") as an exact pin.
      const exact = constraint && /^(?:==)?\s*\d[A-Za-z0-9.!+_-]*$/.test(constraint.trim());
      packages.push(
        found('PyPI', key, exact ? constraint!.trim().replace(/^==\s*/, '') : undefined, poetryDev(table)),
      );
    }
  }
  return { packages, skipped };
};

// ------------------------------------------------------------------------------------- Go and Rust

const goMod: Reader = (text) => {
  const required: Array<{ name: string; version: string }> = [];
  const replaced = new Map<string, { name: string; version: string } | null>();
  let block: 'require' | 'replace' | undefined;
  const replace = (line: string) => {
    const match = /^(\S+)(?:\s+\S+)?\s*=>\s*(\S+)(?:\s+(\S+))?$/.exec(line);
    if (!match) return;
    replaced.set(
      match[1]!,
      /^(?:\.|\/)/.test(match[2]!) || !match[3] ? null : { name: match[2]!, version: match[3] },
    );
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (!line) continue;
    if (block) {
      if (line === ')') block = undefined;
      else if (block === 'require') {
        const [name, version] = line.split(/\s+/);
        if (name && version) required.push({ name, version });
      } else replace(line);
      continue;
    }
    const directive = /^(require|replace)\s*(\(|.+)$/.exec(line);
    if (!directive) continue;
    if (directive[2] === '(') block = directive[1] as 'require' | 'replace';
    else if (directive[1] === 'require') {
      const [name, version] = directive[2]!.trim().split(/\s+/);
      if (name && version) required.push({ name, version });
    } else replace(directive[2]!.trim());
  }
  const packages: Found[] = [];
  let skipped = 0;
  for (const module of required) {
    const replacement = replaced.get(module.name);
    if (replacement === null) skipped++;
    else packages.push(found('Go', (replacement ?? module).name, (replacement ?? module).version));
  }
  return { packages, skipped };
};

const cargoLock: Reader = (text) => {
  const packages: Found[] = [];
  let skipped = 0;
  for (const table of tomlPackages(text)) {
    if (!string(table.name)) continue;
    // Workspace members have no source; Git and path dependencies are not on crates.io.
    if (!table.source || !/^"?(?:registry|sparse)\+/.test(table.source)) {
      if (table.source) skipped++;
      continue;
    }
    packages.push(found('crates.io', table.name, table.version));
  }
  return { packages, skipped };
};

// ------------------------------------------------------------------------------------- PHP and Ruby

/** Composer writes tags as `v6.4.0` and branches as `dev-main` or `2.x-dev`; only a tag is a release. */
function composerVersion(value: unknown): string | undefined {
  if (!string(value) || /^dev-|-dev$/.test(value)) return undefined;
  return value.replace(/^v(?=\d)/, '');
}
// Platform requirements (php, ext-json, lib-icu, composer-plugin-api) have no vendor; every real
// package does, including vendors whose name starts with "php" (phpmailer/phpmailer, phpunit/phpunit).
const composerPlatform = (name: string) => !name.includes('/');

const composerLock: Reader = (text) => {
  const lock: unknown = JSON.parse(text);
  if (!record(lock)) throw new Error('not a composer.lock document');
  const packages: Found[] = [];
  for (const [field, dev] of [
    ['packages', false],
    ['packages-dev', true],
  ] as const) {
    const entries = lock[field];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries)
      if (record(entry) && string(entry.name) && !composerPlatform(entry.name))
        packages.push(found('Packagist', entry.name, composerVersion(entry.version), dev));
  }
  return { packages, skipped: 0 };
};

const composerJson: Reader = (text) => {
  const manifest: unknown = JSON.parse(text);
  if (!record(manifest)) throw new Error('not a composer.json document');
  const packages: Found[] = [];
  for (const [field, dev] of [
    ['require', false],
    ['require-dev', true],
  ] as const) {
    const entries = manifest[field];
    if (!record(entries)) continue;
    for (const [name, constraint] of Object.entries(entries)) {
      if (composerPlatform(name)) continue;
      const exact = typeof constraint === 'string' && /^v?\d+(?:\.\d+)*$/.test(constraint.trim());
      packages.push(found('Packagist', name, exact ? composerVersion(constraint.trim()) : undefined, dev));
    }
  }
  return { packages, skipped: 0 };
};

const gemfileLock: Reader = (text) => {
  const packages: Found[] = [];
  let section = '';
  let specs = false;
  let skipped = 0;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      section = line.trim();
      specs = false;
      continue;
    }
    if (/^ {2}specs:\s*$/.test(line)) {
      specs = true;
      continue;
    }
    const spec = /^ {4}([^\s(]+) \(([^)]+)\)\s*$/.exec(line);
    if (!specs || !spec) continue;
    if (section !== 'GEM') {
      skipped++;
      continue;
    }
    // `nokogiri (1.16.5-x86_64-linux)`: the platform follows the version after a hyphen.
    packages.push(found('RubyGems', spec[1]!, spec[2]!.split('-')[0]));
  }
  return { packages, skipped };
};

const gemfile: Reader = (text) => {
  const packages: Found[] = [];
  let skipped = 0;
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*gem\s+["']([^"']+)["']\s*(?:,\s*["']([^"']+)["'])?(.*)$/.exec(line);
    if (!match) continue;
    if (/\b(?:git|github|path):/.test(match[3]!)) {
      skipped++;
      continue;
    }
    const exact = match[2] && /^(?:=\s*)?\d[\w.]*$/.test(match[2].trim());
    packages.push(found('RubyGems', match[1]!, exact ? match[2]!.replace(/^=\s*/, '').trim() : undefined));
  }
  return { packages, skipped };
};

// ----------------------------------------------------------------------------------- Java and .NET

const xml = (attributes: boolean) =>
  new XMLParser({
    ignoreAttributes: !attributes,
    attributeNamePrefix: '',
    processEntities: false,
    parseTagValue: false,
    trimValues: true,
  });
const list = (value: unknown): unknown[] =>
  Array.isArray(value) ? value : value === undefined ? [] : [value];

const pomXml: Reader = (text) => {
  const document: unknown = xml(false).parse(text);
  const project = record(document) && record(document.project) ? document.project : undefined;
  if (!project) throw new Error('not a Maven project file');
  const properties = new Map<string, string>();
  if (record(project.properties))
    for (const [key, value] of Object.entries(project.properties))
      if (typeof value === 'string' || typeof value === 'number') properties.set(key, String(value));
  const parent = record(project.parent) ? project.parent : {};
  const projectVersion = project.version ?? parent.version;
  if (string(projectVersion)) properties.set('project.version', projectVersion);
  const resolveValue = (value: unknown): string | undefined => {
    if (typeof value !== 'string' && typeof value !== 'number') return undefined;
    let text = String(value);
    for (let round = 0; round < 5 && text.includes('${'); round++)
      text = text.replace(/\$\{([^}]+)\}/g, (whole, key: string) => properties.get(key) ?? whole);
    return text.includes('${') ? undefined : text;
  };
  const dependencies = (container: unknown) =>
    record(container) && record(container.dependencies) ? list(container.dependencies.dependency) : [];
  const managed = new Map<string, string>();
  for (const entry of dependencies(project.dependencyManagement)) {
    if (!record(entry)) continue;
    const version = resolveValue(entry.version);
    if (version) managed.set(`${String(entry.groupId)}:${String(entry.artifactId)}`, version);
  }
  const packages: Found[] = [];
  let skipped = 0;
  for (const entry of [...dependencies(project), ...dependencies(project.dependencyManagement)]) {
    if (!record(entry)) continue;
    const group = resolveValue(entry.groupId);
    const artifact = resolveValue(entry.artifactId);
    if (!group || !artifact || entry.scope === 'import') {
      skipped++;
      continue;
    }
    const version = resolveValue(entry.version) ?? managed.get(`${group}:${artifact}`);
    const exact = version && !/[[\](),]/.test(version) ? version : undefined;
    packages.push(found('Maven', `${group}:${artifact}`, exact, entry.scope === 'test'));
  }
  return { packages, skipped };
};

const gradleLockfile: Reader = (text) => {
  const packages: Found[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^([^:#\s]+):([^:\s]+):([^=\s]+)=(.*)$/.exec(line.trim());
    if (!match) continue;
    const configurations = match[4]!.split(',').filter(Boolean);
    const dev = configurations.length > 0 && configurations.every((name) => /^test/i.test(name));
    packages.push(found('Maven', `${match[1]}:${match[2]}`, match[3], dev));
  }
  return { packages, skipped: 0 };
};

const nugetLock: Reader = (text) => {
  const lock: unknown = JSON.parse(text);
  if (!record(lock) || !record(lock.dependencies)) throw new Error('not a NuGet packages.lock.json');
  const packages: Found[] = [];
  let skipped = 0;
  for (const framework of Object.values(lock.dependencies)) {
    if (!record(framework)) continue;
    for (const [name, value] of Object.entries(framework)) {
      if (!record(value) || value.type === 'Project') {
        skipped++;
        continue;
      }
      packages.push(found('NuGet', name, string(value.resolved) ? value.resolved : undefined));
    }
  }
  return { packages, skipped };
};

/** `1.2.3` and `[1.2.3]` name one version; anything else in NuGet range syntax does not. */
function nugetVersion(value: unknown): string | undefined {
  if (!string(value)) return undefined;
  const match = /^\[?\s*(\d[A-Za-z0-9.+-]*)\s*\]?$/.exec(value.trim());
  return match && value.trim().startsWith('[') === value.trim().endsWith(']') ? match[1] : undefined;
}

/** PackageReference (project files) and PackageVersion (central package management) entries. */
const msbuildProject: Reader = (text) => {
  const document: unknown = xml(true).parse(text);
  const packages: Found[] = [];
  const visit = (node: unknown, depth: number) => {
    if (depth > 16) return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item, depth + 1);
      return;
    }
    if (!record(node)) return;
    for (const [key, value] of Object.entries(node)) {
      if (key === 'PackageReference' || key === 'PackageVersion') {
        for (const entry of list(value)) {
          if (!record(entry)) continue;
          const name = entry.Include ?? entry.Update;
          if (string(name))
            packages.push(found('NuGet', name, nugetVersion(entry.Version ?? entry.VersionOverride)));
        }
      } else visit(value, depth + 1);
    }
  };
  visit(document, 0);
  return { packages, skipped: 0 };
};

// ------------------------------------------------------------------------- Dart, Elixir, Swift, Haskell

const pubspecLock: Reader = (text) => {
  const lock: unknown = parseYaml(text, { maxAliasCount: 0 });
  if (!record(lock) || !record(lock.packages)) throw new Error('not a pubspec.lock document');
  const packages: Found[] = [];
  let skipped = 0;
  for (const [name, value] of Object.entries(lock.packages)) {
    if (!record(value) || value.source !== 'hosted') {
      if (!record(value) || value.source !== 'sdk') skipped++;
      continue;
    }
    packages.push(
      found(
        'Pub',
        name,
        string(value.version) ? value.version : undefined,
        value.dependency === 'direct dev',
      ),
    );
  }
  return { packages, skipped };
};

const pubspecYaml: Reader = (text) => {
  const manifest: unknown = parseYaml(text, { maxAliasCount: 0 });
  if (!record(manifest)) throw new Error('not a pubspec.yaml document');
  const packages: Found[] = [];
  let skipped = 0;
  for (const [field, dev] of [
    ['dependencies', false],
    ['dev_dependencies', true],
  ] as const) {
    const entries = manifest[field];
    if (!record(entries)) continue;
    for (const [name, value] of Object.entries(entries)) {
      const constraint = typeof value === 'string' ? value : record(value) ? value.version : undefined;
      if (record(value) && (value.sdk !== undefined || value.path !== undefined || value.git !== undefined)) {
        if (value.sdk === undefined) skipped++;
        continue;
      }
      const exact = typeof constraint === 'string' && /^\d[\w.+-]*$/.test(constraint.trim());
      packages.push(found('Pub', name, exact ? constraint.trim() : undefined, dev));
    }
  }
  return { packages, skipped };
};

/** `.package(url: "https://github.com/vapor/vapor.git", from: "4.0.0")` and its variants. */
const packageSwift: Reader = (text) => {
  const packages: Found[] = [];
  for (const match of text.matchAll(/\.package\s*\(([^)]{0,2000})\)/g)) {
    const url = /url:\s*"([^"]+)"/.exec(match[1]!)?.[1];
    const name = swiftIdentity(url);
    if (!name) continue;
    const exact = /\bexact:\s*"([^"]+)"/.exec(match[1]!)?.[1] ?? /\.exact\(\s*"([^"]+)"/.exec(match[1]!)?.[1];
    packages.push(found('SwiftURL', name, exact));
  }
  return { packages, skipped: 0 };
};

const mixLock: Reader = (text) => {
  const packages: Found[] = [];
  let skipped = 0;
  for (const line of text.split(/\r?\n/)) {
    const hex = /^\s*"[^"]+":\s*\{:hex,\s*:"?([A-Za-z0-9_]+)"?,\s*"([^"]+)"/.exec(line);
    if (hex) packages.push(found('Hex', hex[1]!, hex[2]!));
    else if (/^\s*"[^"]+":\s*\{:(?:git|path)/.test(line)) skipped++;
  }
  return { packages, skipped };
};

/** `https://github.com/apple/swift-nio.git` → `github.com/apple/swift-nio`. */
function swiftIdentity(location: unknown): string | undefined {
  if (!string(location)) return undefined;
  const scp = /^git@([^:]+):(.+)$/.exec(location);
  const text = scp ? `https://${scp[1]}/${scp[2]}` : location;
  try {
    const url = new URL(text);
    if (url.protocol !== 'https:' && url.protocol !== 'ssh:') return undefined;
    return `${url.hostname}${url.pathname.replace(/\.git$/, '').replace(/\/$/, '')}`;
  } catch {
    return undefined;
  }
}

const packageResolved: Reader = (text) => {
  const document: unknown = JSON.parse(text);
  if (!record(document)) throw new Error('not a Package.resolved document');
  const pins = Array.isArray(document.pins)
    ? document.pins
    : record(document.object) && Array.isArray(document.object.pins)
      ? document.object.pins
      : [];
  const packages: Found[] = [];
  let skipped = 0;
  for (const pin of pins) {
    if (!record(pin)) continue;
    const name = swiftIdentity(pin.location ?? pin.repositoryURL);
    if (!name) {
      skipped++;
      continue;
    }
    const state = record(pin.state) ? pin.state : {};
    packages.push(found('SwiftURL', name, string(state.version) ? state.version : undefined));
  }
  return { packages, skipped };
};

const cabalFreeze: Reader = (text) => {
  const packages: Found[] = [];
  for (const match of text.matchAll(/\bany\.([A-Za-z0-9][A-Za-z0-9-]*)\s*==\s*([0-9][0-9.]*)/g))
    packages.push(found('Hackage', match[1]!, match[2]!.replace(/\.$/, '')));
  return { packages, skipped: 0 };
};

// ------------------------------------------------------------------------------------- File table

interface Kind {
  ecosystem: Ecosystem;
  kind: 'lockfile' | 'manifest';
  read: Reader;
}

/** Which reader handles a file, by its name and the name of its folder. */
function classify(name: string, folder: string): Kind | undefined {
  const lock = (ecosystem: Ecosystem, read: Reader): Kind => ({ ecosystem, kind: 'lockfile', read });
  const manifest = (ecosystem: Ecosystem, read: Reader): Kind => ({ ecosystem, kind: 'manifest', read });
  switch (name) {
    case 'package-lock.json':
    case 'npm-shrinkwrap.json':
      return lock('npm', npmPackageLock);
    case 'yarn.lock':
      return lock('npm', yarnLock);
    case 'pnpm-lock.yaml':
      return lock('npm', pnpmLock);
    case 'package.json':
      return manifest('npm', packageJson);
    case 'Pipfile.lock':
      return lock('PyPI', pipfileLock);
    case 'poetry.lock':
    case 'pdm.lock':
      return lock('PyPI', poetryLock);
    case 'uv.lock':
      return lock('PyPI', uvLock);
    case 'pyproject.toml':
      return manifest('PyPI', pyprojectToml);
    case 'go.mod':
      return lock('Go', goMod);
    case 'Cargo.lock':
      return lock('crates.io', cargoLock);
    case 'composer.lock':
      return lock('Packagist', composerLock);
    case 'composer.json':
      return manifest('Packagist', composerJson);
    case 'Gemfile.lock':
    case 'gems.locked':
      return lock('RubyGems', gemfileLock);
    case 'Gemfile':
    case 'gems.rb':
      return manifest('RubyGems', gemfile);
    case 'pom.xml':
      return lock('Maven', pomXml);
    case 'gradle.lockfile':
    case 'buildscript-gradle.lockfile':
      return lock('Maven', gradleLockfile);
    case 'packages.lock.json':
      return lock('NuGet', nugetLock);
    case 'Directory.Packages.props':
      return manifest('NuGet', msbuildProject);
    case 'pubspec.lock':
      return lock('Pub', pubspecLock);
    case 'pubspec.yaml':
      return manifest('Pub', pubspecYaml);
    case 'Package.swift':
      return manifest('SwiftURL', packageSwift);
    case 'mix.lock':
      return lock('Hex', mixLock);
    case 'Package.resolved':
      return lock('SwiftURL', packageResolved);
    case 'cabal.project.freeze':
      return lock('Hackage', cabalFreeze);
  }
  if (/^requirements.*\.txt$/i.test(name) || (folder === 'requirements' && name.endsWith('.txt')))
    return lock('PyPI', requirementsTxt);
  if (/\.(?:cs|fs|vb)proj$/.test(name)) return manifest('NuGet', msbuildProject);
  if (folder === 'dependency-locks' && name.endsWith('.lockfile')) return lock('Maven', gradleLockfile);
  return undefined;
}

/** Names of the dependency files `generateSbom` reads, for help text and documentation. */
export const DEPENDENCY_FILES: Readonly<Record<Ecosystem, readonly string[]>> = {
  npm: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'package.json'],
  PyPI: ['requirements*.txt', 'poetry.lock', 'uv.lock', 'Pipfile.lock', 'pdm.lock', 'pyproject.toml'],
  Go: ['go.mod'],
  'crates.io': ['Cargo.lock'],
  Packagist: ['composer.lock', 'composer.json'],
  RubyGems: ['Gemfile.lock', 'Gemfile'],
  Maven: ['pom.xml', 'gradle.lockfile'],
  NuGet: ['packages.lock.json', '*.csproj', 'Directory.Packages.props'],
  Pub: ['pubspec.lock', 'pubspec.yaml'],
  Hex: ['mix.lock'],
  SwiftURL: ['Package.resolved', 'Package.swift'],
  Hackage: ['cabal.project.freeze'],
};

interface Candidate extends Kind {
  absolute: string;
  path: string;
  /** A manifest inside a folder whose lockfile already resolves it. */
  workspace?: boolean;
}

/** Walks a project for dependency files without following links or entering installed-package folders. */
function discover(root: string, warnings: string[]): Candidate[] {
  const stat = statSync(root);
  // A link named like a dependency file can point at any file on the machine. The folder given as
  // the project may be a link (the user chose it); a file must be the file itself.
  if (stat.isFile() && lstatSync(root).isSymbolicLink())
    throw new Error(`${basename(root)} is a symbolic link; give the dependency file itself.`);
  if (stat.isFile()) {
    const kind = classify(basename(root), basename(dirname(root)));
    if (!kind) throw new Error(`${basename(root)} is not a supported dependency file.`);
    return [{ ...kind, absolute: root, path: basename(root) }];
  }
  if (!stat.isDirectory()) throw new Error('The project must be a folder or a dependency file.');
  const candidates: Candidate[] = [];
  const queue: Array<{ folder: string; depth: number }> = [{ folder: root, depth: 0 }];
  let entries = 0;
  while (queue.length) {
    const { folder, depth } = queue.shift()!;
    let names;
    try {
      names = readdirSync(folder, { withFileTypes: true });
    } catch {
      warnings.push(`${relative(root, folder) || '.'}: folder could not be read; skipped.`);
      continue;
    }
    names.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of names) {
      if (++entries > MAX_ENTRIES)
        throw new Error(`More than ${MAX_ENTRIES} files and folders; point --project at a smaller folder.`);
      if (entry.isSymbolicLink()) continue;
      const absolute = join(folder, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.startsWith('.') || SKIPPED_FOLDERS.has(entry.name)) continue;
        if (depth + 1 > MAX_DEPTH) continue;
        queue.push({ folder: absolute, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) continue;
      const kind = classify(entry.name, basename(folder));
      if (!kind) continue;
      if (candidates.length >= MAX_FILES)
        throw new Error(`More than ${MAX_FILES} dependency files; point --project at a smaller folder.`);
      candidates.push({ ...kind, absolute, path: relative(root, absolute).split(sep).join('/') });
    }
  }
  // A manifest only adds information where no lockfile of the same ecosystem sits beside it. One
  // below a folder with a lockfile is usually a workspace member that the lockfile already resolves:
  // it is read for anything the lockfile lacks, without warning about its version ranges.
  const locked = new Set(
    candidates
      .filter((file) => file.kind === 'lockfile')
      .map((file) => `${dirname(file.absolute)}\0${file.ecosystem}`),
  );
  const coveredBy = (file: Candidate) => {
    for (
      let folder = dirname(dirname(file.absolute));
      folder.length >= root.length;
      folder = dirname(folder)
    ) {
      if (locked.has(`${folder}\0${file.ecosystem}`)) return true;
      if (folder === dirname(folder)) break;
    }
    return false;
  };
  return candidates
    .filter((file) => file.kind === 'lockfile' || !locked.has(`${dirname(file.absolute)}\0${file.ecosystem}`))
    .map((file) => (file.kind === 'manifest' && coveredBy(file) ? { ...file, workspace: true } : file))
    .sort((a, b) => Number(a.kind === 'manifest') - Number(b.kind === 'manifest'));
}

// ---------------------------------------------------------------------------------------- Package URLs

const PURL_TYPES: Record<Ecosystem, string> = {
  npm: 'npm',
  PyPI: 'pypi',
  Packagist: 'composer',
  Go: 'golang',
  Maven: 'maven',
  'crates.io': 'cargo',
  RubyGems: 'gem',
  NuGet: 'nuget',
  Hex: 'hex',
  Pub: 'pub',
  Hackage: 'hackage',
  SwiftURL: 'swift',
};

/** A package URL (https://github.com/package-url/purl-spec) for a normalised package identity. */
export function packageUrl(ecosystem: Ecosystem, name: string, version?: string): string {
  const path = ecosystem === 'Maven' ? name.replace(':', '/') : name;
  const encoded = path.split('/').map(encodeURIComponent).join('/');
  return `pkg:${PURL_TYPES[ecosystem]}/${encoded}${version ? `@${encodeURIComponent(version)}` : ''}`;
}

// -------------------------------------------------------------------------------------------- Output

function slug(value: string): string {
  const text = value
    .toLowerCase()
    .replace(/^@/, '')
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 100);
  return text || 'application';
}

/** The name a project gives itself in package.json or pyproject.toml, or its folder name. */
function projectName(root: string, isFile: boolean): string {
  const folder = isFile ? dirname(root) : root;
  const read = (file: string): string | undefined => {
    try {
      const path = join(folder, file);
      if (!lstatSync(path).isFile() || statSync(path).size > 1024 * 1024) return undefined;
      return readFileSync(path, 'utf8');
    } catch {
      return undefined;
    }
  };
  try {
    const manifest: unknown = JSON.parse(read('package.json') ?? 'null');
    if (record(manifest) && string(manifest.name)) return manifest.name;
  } catch {
    // Fall through to the next source of a name.
  }
  const pyproject = read('pyproject.toml');
  const name = pyproject && /^\[(?:project|tool\.poetry)\][^[]*?^name\s*=\s*"([^"]+)"/ms.exec(pyproject);
  if (name) return name[1]!;
  return basename(folder) || 'application';
}

function text(value: string | undefined, field: string): string | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed.length > 500 || LINE_BREAKING.test(trimmed))
    throw new Error(`${field} must be one line of at most 500 characters.`);
  return trimmed;
}

/**
 * Reads every supported dependency file in a project and returns a CycloneDX 1.6 SBOM with one
 * component per package and version. Each component records the files it was found in
 * (`evidence.occurrences`), which Security Watch shows in alerts as the place to look.
 */
export function generateSbom(options: SbomOptions = {}): GeneratedSbom {
  const root = resolve(options.project ?? '.');
  const warnings: string[] = [];
  const isFile = statSync(root).isFile();
  const candidates = discover(root, warnings);
  const files: DependencyFile[] = [];
  const versioned = new Map<string, Found & { locations: Set<string>; dev: boolean }>();
  const unversioned = new Map<string, Found & { locations: Set<string>; dev: boolean }>();
  for (const file of candidates) {
    let parsed: Parsed;
    try {
      const size = statSync(file.absolute).size;
      if (size > MAX_FILE_BYTES) {
        warnings.push(`${file.path}: larger than 20 MiB; skipped.`);
        continue;
      }
      parsed = file.read(readFileSync(file.absolute, 'utf8').replace(/^﻿/, ''), file.path);
    } catch (error) {
      warnings.push(
        `${file.path}: could not be read (${singleLine(error instanceof Error ? error.message : 'unknown error', 160)}); skipped.`,
      );
      continue;
    }
    let invalid = 0;
    let ranges = 0;
    let accepted = 0;
    for (const entry of parsed.packages) {
      if (options.production && entry.dev) continue;
      let name: string;
      try {
        name = normalizePackageName(entry.ecosystem, entry.name);
      } catch {
        invalid++;
        continue;
      }
      let version: string | undefined;
      if (entry.version !== undefined) {
        try {
          version = exactLibraryVersion(entry.version, entry.ecosystem);
        } catch {
          version = undefined;
        }
      }
      if (version === undefined) ranges++;
      accepted++;
      const target = version === undefined ? unversioned : versioned;
      const key =
        version === undefined
          ? (packageKey({ ecosystem: entry.ecosystem, name }) ?? `${entry.ecosystem}\0${name}`)
          : packageUrl(entry.ecosystem, name, version);
      const existing = target.get(key);
      if (existing) {
        if (existing.locations.size < MAX_LOCATIONS) existing.locations.add(file.path);
        existing.dev &&= entry.dev === true;
      } else
        target.set(key, {
          ecosystem: entry.ecosystem,
          name,
          ...(version === undefined ? {} : { version }),
          dev: entry.dev === true,
          locations: new Set([file.path]),
        });
    }
    files.push({ path: file.path, ecosystem: file.ecosystem, kind: file.kind, packages: accepted });
    if (file.workspace) continue;
    if (invalid)
      warnings.push(
        `${file.path}: ${invalid} entr${invalid === 1 ? 'y has' : 'ies have'} a name that is not a valid ${file.ecosystem} package name; skipped.`,
      );
    if (parsed.skipped)
      warnings.push(
        `${file.path}: ${parsed.skipped} entr${parsed.skipped === 1 ? 'y comes' : 'ies come'} from Git, a local path or another source that is not a package registry; not monitored.`,
      );
    if (ranges && file.kind === 'manifest')
      warnings.push(
        `${file.path}: ${ranges} of ${accepted} dependencies have a version range, not an exact version; they are watched by name only. Commit a lockfile for exact versions.`,
      );
    else if (ranges)
      warnings.push(
        `${file.path}: ${ranges} of ${accepted} dependencies have no exact version; they are watched by name only.${
          file.ecosystem === 'Maven'
            ? ' Versions inherited from a parent POM or BOM are not resolved here: use Gradle dependency locking, the CycloneDX Maven plugin or Trivy for exact versions (docs/sbom.md).'
            : ''
        }`,
      );
  }
  // A name-only entry adds nothing where an exact version of the same package is already known.
  const known = new Set(
    [...versioned.values()].map((entry) => packageKey(entry) ?? `${entry.ecosystem}\0${entry.name}`),
  );
  const entries = [
    ...versioned.values(),
    ...[...unversioned.entries()].filter(([key]) => !known.has(key)).map(([, entry]) => entry),
  ];
  if (entries.length > MAX_COMPONENTS)
    throw new Error(
      `The project has ${entries.length} packages; at most ${MAX_COMPONENTS} fit one system. Generate one SBOM per service with --project.`,
    );
  const components = entries
    .map((entry) => {
      const purl = packageUrl(entry.ecosystem, entry.name, entry.version);
      return {
        type: 'library',
        'bom-ref': purl,
        name: entry.name,
        ...(entry.version ? { version: entry.version } : {}),
        purl,
        ...(entry.dev ? { scope: 'optional' } : {}),
        evidence: { occurrences: [...entry.locations].sort().map((location) => ({ location })) },
      };
    })
    .sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0));

  const name = text(options.name, 'Name') ?? singleLine(projectName(root, isFile), 200);
  const id = slug(text(options.systemId, 'System ID') ?? name);
  if (options.sourceUrl !== undefined) {
    const url = new URL(options.sourceUrl);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash)
      throw new Error('The source URL must be an HTTPS address without credentials, query or fragment.');
  }
  const properties = (
    [
      ['security-watch:system-id', id],
      ['security-watch:owner', text(options.owner, 'Owner')],
      ['security-watch:environment', text(options.environment, 'Environment')],
      ['security-watch:note', text(options.note, 'Note')],
      ['security-watch:exposure', options.exposure],
      ['security-watch:criticality', options.criticality],
      ['security-watch:source-url', options.sourceUrl],
      ['security-watch:source-revision', text(options.sourceRevision, 'Source revision')],
    ] as const
  )
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => ({ name: key, value: value! }));
  const ecosystems = [...new Set(entries.map((entry) => entry.ecosystem))];
  const bom = {
    $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: (options.now ?? new Date()).toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            group: '@shieldaai',
            name: 'security-watch',
            ...(options.toolVersion ? { version: options.toolVersion } : {}),
          },
        ],
      },
      component: { type: 'application', 'bom-ref': `security-watch:system:${id}`, name },
      properties,
    },
    components,
  };
  return {
    bom,
    system: { id, name },
    files,
    ecosystems: ecosystems.sort(),
    packages: components.length,
    unversioned: components.filter((component) => component.version === undefined).length,
    warnings,
  };
}
