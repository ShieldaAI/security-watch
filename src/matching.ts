import { packageKey } from './ecosystems.js';
import { everydayWord, properName } from './everyday-words.js';
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

/**
 * A name made only of letters that is also an everyday word ("send", "buffer", "request", "next").
 * Prose uses such a word in its ordinary sense far more often than as a package name.
 */
function plainWord(name: string): boolean {
  return /^\p{L}+$/u.test(name.trim()) && everydayWord(name);
}

/**
 * After a name: something only a release is written with. That is "@1.2", "v1.2", a three-part
 * version ("Requests 2.32.0") or, for npm, the ".js" suffix. A bare decimal is not enough: "send
 * 1.5 million requests" and "the next 5.5 years" are quantities.
 */
function releaseSuffix(ecosystem: Ecosystem): string {
  return `(?:${ecosystem === 'npm' ? '\\.js(?:[ @]v?\\d+(?:\\.\\d+)?)?|' : ''}@v?\\d+\\.\\d+| v\\d+\\.\\d+| \\d+\\.\\d+\\.\\d+)`;
}

/**
 * Whether prose names this package. A name counts wherever it appears unless it is also an everyday
 * word. An everyday word counts only when the text is about packages or names a release of it, so
 * "buffer overflow in a router" does not match the npm package `buffer`, while "Next.js" does match
 * `next`. A name written with a version, such as `send@0.19.0`, always counts.
 */
export function packageMentioned(text: string, component: { ecosystem: Ecosystem; name: string }): boolean {
  const name = component.name.trim();
  if (name.length < 3) return false;
  if (bounded(`${escape(name)}${releaseSuffix(component.ecosystem)}`).test(text)) return true;
  if (!mentions(text, name)) return false;
  if (!plainWord(name)) return true;
  return packageContext(text, component.ecosystem) || (properName(name) && namedInSentence(text, name));
}

const namePatterns = new Map<string, RegExp>();
/**
 * Whether the word is written as a name: with a capital straight after a word that has none ("a
 * flaw in Express"), or opening a sentence that goes on in lower case ("Rails releases patches").
 * A capital inside a headline in title case shows nothing.
 */
function namedInSentence(text: string, name: string): boolean {
  const word = name.trim();
  const known = namePatterns.get(word);
  if (known) return known.test(text);
  const capitalised = escape(word[0]!.toUpperCase() + word.slice(1).toLowerCase());
  const end = '(?![\\p{L}\\p{N}_@/\\-])';
  const pattern = new RegExp(
    `(?<=(?:^|[^\\p{L}\\p{N}])\\p{Ll}[\\p{L}\\p{N}'’-]*[,:]? )${capitalised}${end}` +
      `|(?<=^|[.!?]\\s+|\\n)${capitalised}${end}(?= \\p{Ll})`,
    'u',
  );
  namePatterns.set(word, pattern);
  return pattern.test(text);
}

export interface InventoryMatcher {
  /** Identity keys of every inventory component. */
  packages: Set<string>;
  /** Product names, product keywords and system keywords: terms the operator chose on purpose. */
  declared(text: string): boolean;
  /** Any inventory package named in prose, under the everyday-word rule above. */
  packageNamed(text: string): boolean;
}

const matchers = new WeakMap<Inventory, { shape: string; matcher: InventoryMatcher }>();
/**
 * A cheap description of what the matcher was built from. It changes when a system, component,
 * product or keyword is added, removed or replaced, so a caller that edits the same inventory object
 * between scans does not keep matching against the old names.
 */
function shape(inventory: Inventory): string {
  return inventory.systems
    .map((system) =>
      [
        system.id,
        system.components.length,
        system.components.at(-1)?.name ?? '',
        (system.products ?? []).map((product) => `${product.name}:${product.keywords.join(',')}`).join(';'),
        (system.keywords ?? []).join(','),
      ].join('|'),
    )
    .join('\n');
}
function anyOf(terms: Iterable<string>, suffix = ''): (text: string) => boolean {
  const unique = [...new Set([...terms].map((term) => term.trim()).filter((term) => term.length >= 3))];
  // One alternation per chunk keeps each expression small while testing every name in one pass.
  const patterns: RegExp[] = [];
  for (let offset = 0; offset < unique.length; offset += 400)
    patterns.push(
      bounded(
        `(?:${unique
          .slice(offset, offset + 400)
          .map(escape)
          .join('|')})${suffix}`,
      ),
    );
  return (text) => patterns.some((pattern) => pattern.test(text));
}

/**
 * Built once per loaded inventory; a scan compares thousands of records against the same names.
 * Adding or removing entries on the same object rebuilds it. Renaming a component in place (other
 * than the last one of a system) is not noticed: pass a new inventory object after such an edit.
 */
export function inventoryMatcher(inventory: Inventory): InventoryMatcher {
  const current = shape(inventory);
  const cached = matchers.get(inventory);
  if (cached && cached.shape === current) return cached.matcher;
  const packages = new Set<string>();
  const declared: string[] = [];
  const distinctive: string[] = [];
  const proper = new Set<string>();
  const byEcosystem = new Map<Ecosystem, { plain: string[]; all: string[] }>();
  for (const system of inventory.systems) {
    for (const component of system.components) {
      const key = packageKey(component);
      if (key) packages.add(key);
      if (!byEcosystem.has(component.ecosystem)) byEcosystem.set(component.ecosystem, { plain: [], all: [] });
      const names = byEcosystem.get(component.ecosystem)!;
      names.all.push(component.name);
      if (plainWord(component.name)) {
        names.plain.push(component.name);
        if (properName(component.name)) proper.add(component.name);
      } else distinctive.push(component.name);
    }
    for (const product of system.products ?? []) declared.push(product.name, ...product.keywords);
    declared.push(...(system.keywords ?? []));
  }
  const declaredTest = anyOf(declared);
  const distinctiveTest = anyOf(distinctive);
  const ecosystemTests = [...byEcosystem].map(([ecosystem, names]) => ({
    ecosystem,
    plain: anyOf(names.plain),
    release: anyOf(names.all, releaseSuffix(ecosystem)),
  }));
  const matcher: InventoryMatcher = {
    packages,
    declared: declaredTest,
    packageNamed: (text) =>
      distinctiveTest(text) ||
      [...proper].some((name) => namedInSentence(text, name)) ||
      ecosystemTests.some(
        ({ ecosystem, plain, release }) => release(text) || (packageContext(text, ecosystem) && plain(text)),
      ),
  };
  matchers.set(inventory, { shape: current, matcher });
  return matcher;
}
