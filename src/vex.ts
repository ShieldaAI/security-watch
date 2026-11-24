import { createHash } from 'node:crypto';
import type { Ecosystem } from './ecosystems.js';
import type { Assessment, Component, Evidence, Inventory } from './types.js';
import { timestamp } from './util.js';

/**
 * An OpenVEX v0.2.0 document for the findings Security Watch holds about installed libraries.
 *
 * A VEX statement says whether a product is affected by a vulnerability, so only findings that name
 * one exact package version can be written. News, product and health findings have no package to
 * point at and are counted as skipped, not guessed at.
 */
export interface VexInput {
  findings: Assessment[];
  evidence: (ids: readonly string[]) => Evidence[];
  inventory: Inventory;
  /** Only this system's findings. */
  systemId?: string;
  /** Also write `not_affected` statements. Default false: they are a claim consumers rely on. */
  includeNotAffected?: boolean;
  /** Default `Security Watch`. */
  author?: string;
  now?: number;
  /** One line about runtime mitigations for a finding, from elsewhere. Appended to action statements. */
  mitigationNote?: (finding: Assessment) => string | undefined;
}

export interface VexStatement {
  vulnerability: { name: string; aliases?: string[] };
  products: { '@id': string }[];
  status: 'affected' | 'not_affected' | 'under_investigation';
  /** Required by OpenVEX for `affected`. */
  action_statement?: string;
  /** OpenVEX requires a justification or an impact statement for `not_affected`. */
  justification?: 'vulnerable_code_not_present';
  impact_statement?: string;
}

export interface VexDocument {
  '@context': 'https://openvex.dev/ns/v0.2.0';
  '@id': string;
  author: string;
  timestamp: string;
  version: 1;
  tooling: 'Security Watch';
  statements: VexStatement[];
}

/** The package URL type for each ecosystem. This inverts the mapping the SBOM import reads. */
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

/** The package URL specification encodes everything but unreserved characters; a colon stays as is. */
function encode(segment: string): string {
  return encodeURIComponent(segment)
    .replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%3A/gi, ':');
}

/** Undefined when the ecosystem has no package URL type or the name has no usable parts. */
export function buildPurl(component: Pick<Component, 'ecosystem' | 'name' | 'version'>): string | undefined {
  const type = PURL_TYPES[component.ecosystem];
  if (!type || !component.version) return undefined;
  let name = component.name;
  // Maven names are group:artifact; the group is the namespace. Anything else is not a Maven name.
  if (component.ecosystem === 'Maven') {
    if (name.split(':').length !== 2) return undefined;
    name = name.replace(':', '/');
  }
  // The specification lowercases PyPI names and writes underscores as dashes, and lowercases the
  // case-insensitive Composer, Hex and Pub names.
  if (component.ecosystem === 'PyPI') name = name.toLowerCase().replace(/_/g, '-');
  if (component.ecosystem === 'Packagist' || component.ecosystem === 'Hex' || component.ecosystem === 'Pub')
    name = name.toLowerCase();
  const parts = name.split('/').filter((part) => part.length > 0);
  if (parts.length === 0) return undefined;
  try {
    return `pkg:${type}/${parts.map(encode).join('/')}@${encode(component.version)}`;
  } catch {
    // A lone surrogate cannot be encoded: the component is skipped, not the document.
    return undefined;
  }
}

/** The CVE, GHSA and other identifiers the finding's advisories publish, without the event itself. */
function aliasesOf(finding: Assessment, evidence: Evidence[]): string[] {
  const ids = new Set<string>();
  for (const item of evidence) {
    // News only mentions identifiers; an advisory or the exploited-vulnerability catalog states them.
    if (item.withdrawn || (item.kind !== 'advisory' && item.kind !== 'kev')) continue;
    for (const alias of item.aliases) if (alias.trim()) ids.add(alias.trim());
  }
  ids.delete(finding.event_id);
  return [...ids].sort();
}

function actionStatement(finding: Assessment, name: string, note: string | undefined): string {
  const base =
    finding.category === 'malware'
      ? `Remove ${name}: it is reported as a malicious package.`
      : finding.fix
        ? `Update ${name} to ${finding.fix}.`
        : 'No fixed version is published; follow the advisory.';
  const extra = note?.trim();
  return extra ? `${base} ${extra}` : base;
}

/** The same statements give the same identifier, so an unchanged state is the same document. */
function documentId(author: string, statements: VexStatement[]): string {
  const hex = createHash('sha256').update(JSON.stringify({ author, statements })).digest('hex');
  // Shaped as a version 4 UUID: version nibble 4, variant bits 10.
  const variant = ((parseInt(hex[16]!, 16) & 0x3) | 0x8).toString(16);
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Qualifiers that describe the package itself and are kept. Others (`repository_url`, `download_url`,
 * `vcs_url`, a vendor's `registry=`) can name a private registry, and a VEX document is read outside.
 */
const PUBLIC_QUALIFIERS = new Set(['classifier', 'type', 'arch', 'distro', 'os', 'epoch']);
/**
 * The inventory's package URL, made fit to publish: the type in lower case, only descriptive
 * qualifiers, no subpath, a scoped npm `@` written as `%40`, and the component's version added when
 * the URL has none. `mismatch` when its version is not the component's: the statement would be about
 * another version. Nothing when it cannot be read; the caller builds one instead.
 */
export function publishablePurl(purl: string, version: string): { purl?: string; mismatch?: boolean } {
  const text = purl.trim().split('#')[0]!;
  const [head, query] = text.split('?', 2) as [string, string | undefined];
  const match = /^pkg:([A-Za-z][A-Za-z0-9.+-]*)\/(.+)$/.exec(head);
  if (!match) return {};
  const [, type, rest] = match;
  // The version follows the last @ after the last slash; an @ that starts a namespace is part of it.
  const slash = rest!.lastIndexOf('/');
  const at = rest!.lastIndexOf('@');
  const path = at > slash && at > 0 ? rest!.slice(0, at) : rest!;
  const given = at > slash && at > 0 ? rest!.slice(at + 1) : undefined;
  if (!path || path.split('/').some((part) => !part)) return {};
  let decoded: string | undefined;
  try {
    decoded = given === undefined ? undefined : decodeURIComponent(given);
  } catch {
    return {};
  }
  if (decoded !== undefined && decoded !== version) return { mismatch: true };
  const qualifiers = (query ?? '')
    .split('&')
    .filter((pair) => PUBLIC_QUALIFIERS.has(pair.split('=')[0]!.toLowerCase()) && pair.includes('='))
    .sort();
  try {
    const namespace = path.replace(/^@/, '%40');
    return {
      purl: `pkg:${type!.toLowerCase()}/${namespace}@${given ?? encode(version)}${qualifiers.length ? `?${qualifiers.join('&')}` : ''}`,
    };
  } catch {
    return {};
  }
}

const STATUS_ORDER: Record<VexStatement['status'], number> = {
  affected: 0,
  under_investigation: 1,
  not_affected: 2,
};

function compare(first: string, second: string): number {
  return first < second ? -1 : first > second ? 1 : 0;
}

export function openVex(input: VexInput): { document: VexDocument; skipped: Record<string, number> } {
  const skipped: Record<string, number> = {};
  const skip = (reason: string): void => {
    skipped[reason] = (skipped[reason] ?? 0) + 1;
  };
  const components = new Map(
    input.inventory.systems.map((system) => [
      system.id,
      new Map(system.components.map((item) => [item.id, item])),
    ]),
  );
  const statements: VexStatement[] = [];

  for (const finding of input.findings) {
    if (input.systemId !== undefined && finding.system_id !== input.systemId) continue;
    if (finding.active === false || finding.withdrawn) {
      skip('inactive');
      continue;
    }
    if (finding.category !== 'library' && finding.category !== 'malware') {
      skip('not_library');
      continue;
    }
    const component = finding.component_id
      ? components.get(finding.system_id)?.get(finding.component_id)
      : undefined;
    if (!component) {
      skip('no_component');
      continue;
    }
    if (!component.version) {
      skip('no_version');
      continue;
    }
    // The inventory's own package URL is what other tools match on, so it is kept, made fit to publish.
    // The inventory's own package URL when it can be published, else one built from the component.
    const published = component.purl?.trim() ? publishablePurl(component.purl, component.version) : {};
    if (published.mismatch) {
      skip('purl_version_mismatch');
      continue;
    }
    const purl = published.purl ?? buildPurl(component);
    if (!purl) {
      skip('no_purl_type');
      continue;
    }
    const vulnerability: VexStatement['vulnerability'] = { name: finding.event_id };
    const aliases = aliasesOf(finding, input.evidence(finding.evidence_ids));
    if (aliases.length > 0) vulnerability.aliases = aliases;
    // Statements carry no time of their own (they inherit the document's), so an unchanged state
    // gives the same statements and the same document identifier on every run.
    const base = { vulnerability, products: [{ '@id': purl }] };

    if (finding.applicability === 'affected') {
      statements.push({
        ...base,
        status: 'affected',
        action_statement: actionStatement(finding, component.name, input.mitigationNote?.(finding)),
      });
    } else if (finding.applicability === 'unknown' || finding.applicability === 'conflicting') {
      statements.push({ ...base, status: 'under_investigation' });
    } else if (finding.applicability === 'not_affected') {
      if (!input.includeNotAffected) {
        skip('not_affected_omitted');
        continue;
      }
      statements.push({
        ...base,
        status: 'not_affected',
        justification: 'vulnerable_code_not_present',
        impact_statement: 'The installed version is outside the affected versions the advisories publish.',
      });
    } else {
      skip('applicability_not_reportable');
    }
  }

  // The same package version in several systems is one statement. When systems disagree, the most
  // severe status stands (affected, then under investigation, then not affected): a consumer must
  // never hide a vulnerability that one of the systems is affected by.
  const byProduct = new Map<string, VexStatement>();
  for (const statement of statements) {
    const key = `${statement.vulnerability.name}\u0000${statement.products[0]!['@id']}`;
    const known = byProduct.get(key);
    if (
      !known ||
      STATUS_ORDER[statement.status] < STATUS_ORDER[known.status] ||
      (statement.status === known.status &&
        compare(statement.action_statement ?? '', known.action_statement ?? '') < 0)
    )
      byProduct.set(key, statement);
  }
  statements.length = 0;
  statements.push(...byProduct.values());
  statements.sort(
    (a, b) =>
      compare(a.vulnerability.name, b.vulnerability.name) ||
      compare(a.products[0]!['@id'], b.products[0]!['@id']),
  );
  const author = input.author ?? 'Security Watch';
  return {
    document: {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': documentId(author, statements),
      author,
      timestamp: timestamp(input.now),
      version: 1,
      tooling: 'Security Watch',
      statements,
    },
    skipped,
  };
}
