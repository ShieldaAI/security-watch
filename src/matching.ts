import { packageKey } from './ecosystems.js';
import type { Ecosystem } from './ecosystems.js';
import type { Inventory } from './types.js';

const escape = (value: string) => value.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** Word/identifier boundaries prevent "express" matching "expressions" or another npm scope. */
const bounded = (pattern: string) =>
  new RegExp(`(?<![\\p{L}\\p{N}_@/\\-])(?:${pattern})(?![\\p{L}\\p{N}_@/\\-])`, 'iu');

export function mentions(text: string, needle: string): boolean {
  if (needle.trim().length < 3) return false;
  return bounded(escape(needle)).test(text);
}

/** Words that show a text is talking about software packages, not using an everyday word. */
const PACKAGE_CONTEXT: Record<Ecosystem, string> = {
  npm: 'npm|node\\.js|nodejs|javascript|typescript',
  PyPI: 'pypi|pip|python',
  Packagist: 'packagist|composer|php',
  Go: 'golang|go module',
  Maven: 'maven|gradle|java',
  'crates.io': 'crates\\.io|cargo|crate|rust',
  RubyGems: 'rubygems|gem|ruby',
  NuGet: 'nuget|\\.net|dotnet',
  Hex: 'hex\\.pm|elixir|erlang',
  Pub: 'pub\\.dev|dart|flutter',
  Hackage: 'hackage|haskell|cabal',
  SwiftURL: 'swift package|swiftpm|swift',
};
const contextPatterns = new Map<string, RegExp>();
function packageContext(text: string, ecosystem: Ecosystem): boolean {
  let pattern = contextPatterns.get(ecosystem);
  if (!pattern) {
    pattern = bounded(`packages?|librar(?:y|ies)|modules?|dependenc(?:y|ies)|${PACKAGE_CONTEXT[ecosystem]}`);
    contextPatterns.set(ecosystem, pattern);
  }
  return pattern.test(text);
}

/** A name made only of letters ("send", "buffer", "request") is also an everyday word. */
function plainWord(name: string): boolean {
  return /^\p{L}+$/u.test(name.trim());
}

/**
 * Whether prose names this package. A distinctive name (with a digit, hyphen, dot, scope or path)
 * counts wherever it appears. A plain word counts only when the text is about packages, so
 * "buffer overflow in a router" does not match the npm package `buffer`.
 */
export function packageMentioned(text: string, component: { ecosystem: Ecosystem; name: string }): boolean {
  if (!mentions(text, component.name)) return false;
  return !plainWord(component.name) || packageContext(text, component.ecosystem);
}

export interface InventoryMatcher {
  /** Identity keys of every inventory component. */
  packages: Set<string>;
  /** Product names, product keywords and system keywords: terms the operator chose on purpose. */
  declared(text: string): boolean;
  /** Any inventory package named in prose, under the plain-word rule above. */
  packageNamed(text: string): boolean;
}

const matchers = new WeakMap<Inventory, InventoryMatcher>();
function anyOf(terms: Iterable<string>): (text: string) => boolean {
  const unique = [...new Set([...terms].map((term) => term.trim()).filter((term) => term.length >= 3))];
  // One alternation per chunk keeps each expression small while testing every name in one pass.
  const patterns: RegExp[] = [];
  for (let offset = 0; offset < unique.length; offset += 400)
    patterns.push(
      bounded(
        unique
          .slice(offset, offset + 400)
          .map(escape)
          .join('|'),
      ),
    );
  return (text) => patterns.some((pattern) => pattern.test(text));
}

/** Built once per loaded inventory; a scan compares thousands of records against the same names. */
export function inventoryMatcher(inventory: Inventory): InventoryMatcher {
  let matcher = matchers.get(inventory);
  if (matcher) return matcher;
  const packages = new Set<string>();
  const declared: string[] = [];
  const distinctive: string[] = [];
  const plain = new Map<Ecosystem, string[]>();
  for (const system of inventory.systems) {
    for (const component of system.components) {
      const key = packageKey(component);
      if (key) packages.add(key);
      if (plainWord(component.name)) {
        if (!plain.has(component.ecosystem)) plain.set(component.ecosystem, []);
        plain.get(component.ecosystem)!.push(component.name);
      } else distinctive.push(component.name);
    }
    for (const product of system.products ?? []) declared.push(product.name, ...product.keywords);
    declared.push(...(system.keywords ?? []));
  }
  const declaredTest = anyOf(declared);
  const distinctiveTest = anyOf(distinctive);
  const plainTests = [...plain].map(([ecosystem, names]) => ({ ecosystem, test: anyOf(names) }));
  matcher = {
    packages,
    declared: declaredTest,
    packageNamed: (text) =>
      distinctiveTest(text) ||
      plainTests.some(({ ecosystem, test }) => packageContext(text, ecosystem) && test(text)),
  };
  matchers.set(inventory, matcher);
  return matcher;
}
