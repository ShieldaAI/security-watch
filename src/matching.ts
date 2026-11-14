import { packageKey } from './ecosystems.js';
import { dictionaryName, everydayWord, properName } from './everyday-words.js';
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

/**
 * Words that show a text is talking about software packages. The registry and its tools say so
 * plainly. The language alone says less: "the Python backdoor sends requests" is not about the
 * `requests` package, so a language name is enough only for a word that is not among the commonest.
 */
const REGISTRY_CONTEXT: Record<Ecosystem, string> = {
  npm: 'npm|yarn|pnpm',
  PyPI: 'pypi|pip',
  Packagist: 'packagist|composer',
  Go: 'go module|go modules',
  Maven: 'maven|gradle',
  'crates.io': 'crates\\.io|cargo|crate|crates',
  RubyGems: 'rubygems|gem|gems',
  NuGet: 'nuget',
  Hex: 'hex\\.pm',
  Pub: 'pub\\.dev',
  Hackage: 'hackage|cabal',
  SwiftURL: 'swift package|swiftpm',
};
const LANGUAGE_CONTEXT: Record<Ecosystem, string> = {
  npm: 'node\\.js|nodejs|javascript|typescript',
  PyPI: 'python',
  Packagist: 'php',
  Go: 'golang',
  Maven: 'java',
  'crates.io': 'rust',
  RubyGems: 'ruby',
  NuGet: '\\.net|dotnet',
  Hex: 'elixir|erlang',
  Pub: 'dart|flutter',
  Hackage: 'haskell',
  SwiftURL: 'swift',
};
const contextPatterns = new Map<string, RegExp>();
/** `language`: whether naming the ecosystem's language is enough, without a registry or "package". */
function packageContext(text: string, ecosystem: Ecosystem, language: boolean): boolean {
  const key = `${ecosystem}:${language}`;
  let pattern = contextPatterns.get(key);
  if (!pattern) {
    // "module" is left out: kernel modules, PAM modules and web-server modules are not packages.
    pattern = bounded(
      `packages?|librar(?:y|ies)|dependenc(?:y|ies)|${REGISTRY_CONTEXT[ecosystem]}${
        language ? `|${LANGUAGE_CONTEXT[ecosystem]}` : ''
      }`,
    );
    contextPatterns.set(key, pattern);
  }
  return pattern.test(text);
}

/**
 * How much a mention of a name shows by itself:
 * - `distinctive`: not an English word ("axios", "lodash", "left-pad2"). It is the package wherever
 *   it appears.
 * - `common`: one of the commonest words of security prose ("send", "buffer", "request", "next").
 *   It counts only in text about packages, or with a release.
 * - `dictionary`: any other English word or compound of English words ("entities", "scheduler",
 *   "express", "side-channel"). As `common`, and a single word also counts when it is written as
 *   a name.
 */
type NameKind = 'distinctive' | 'common' | 'dictionary';
function nameKind(name: string): NameKind {
  if (!dictionaryName(name)) return 'distinctive';
  return everydayWord(name) ? 'common' : 'dictionary';
}

/**
 * After a name: something only a release is written with. That is "@1.2", "v1.2" or a three-part
 * version ("Requests 2.32.0"). A bare decimal is not enough: "send 1.5 million requests" and "the
 * next 5.5 years" are quantities. Nor is an address: "IP address 203.0.113.7" has four parts.
 */
const RELEASE_SUFFIX = '(?:@v?\\d+\\.\\d+| v\\d+\\.\\d+| \\d+\\.\\d+\\.\\d+(?!\\.\\d))';
const QUANTITY =
  '(?i:%|percent|thousand|million|billion|trillion|times|x|[kmgt]b|bytes|seconds?|minutes?|hours?|days?|weeks?|months?|years?|cvss|severity|score|rated|rating|out of|bn|usd|eur|dollars?)(?![\\p{L}\\p{N}])';
const boundary = { before: '(?<![\\p{L}\\p{N}_@/\\-])', after: '(?![\\p{L}\\p{N}_@/\\-])' };
/** A name with its first letter in upper case and the rest in either case. */
const capitalised = (name: string) =>
  [...name.trim()]
    .map((letter, index) =>
      index === 0
        ? escape(letter.toUpperCase())
        : `[${escape(letter.toLowerCase())}${escape(letter.toUpperCase())}]`,
    )
    .join('');
/**
 * A test for names written as a release. For npm that includes the way JavaScript libraries are
 * called: "Next.js", "Express.js", "ExpressJS", with a capital. In lower case, "config.js" and
 * "server.js" are file names.
 */
function releaseTest(names: Iterable<string>, ecosystem: Ecosystem): (text: string) => boolean {
  const unique = [...new Set([...names].map((name) => name.trim()).filter((name) => name.length >= 3))];
  const patterns: RegExp[] = [];
  // "Rails 7.2", "Flask 3.1": a two-part version after the name written with a capital, unless a
  // unit or a rating follows ("the Next 2.5 years", "Address 9.8 CVSS bug"). The commonest words
  // are left out even so.
  const named = unique.filter((name) => /^\p{L}+$/u.test(name) && nameKind(name) === 'dictionary');
  for (let offset = 0; offset < named.length; offset += 400)
    patterns.push(
      new RegExp(
        `${boundary.before}(?:${named
          .slice(offset, offset + 400)
          .map(capitalised)
          .join('|')}) \\d+\\.\\d+(?![\\p{L}\\p{N}_@/%\\-]|\\.\\d| ?${QUANTITY})`,
        'u',
      ),
    );
  for (let offset = 0; offset < unique.length; offset += 400) {
    const chunk = unique.slice(offset, offset + 400);
    patterns.push(bounded(`(?:${chunk.map(escape).join('|')})${RELEASE_SUFFIX}`));
    if (ecosystem === 'npm')
      patterns.push(
        new RegExp(
          `${boundary.before}(?:${chunk.map(capitalised).join('|')})(?:\\.js|JS)${boundary.after}`,
          'u',
        ),
      );
  }
  return (text) => patterns.some((pattern) => pattern.test(text));
}

/**
 * Whether prose names this package. A name that is not an English word counts wherever it appears.
 * An English word counts only when the text is about packages, names a release of it, or (for a
 * word that is not among the commonest) writes it as a name. So "buffer overflow in a router" does
 * not match the npm package `buffer`, "federal entities" does not match `entities`, "Next.js" does
 * match `next`, and "a flaw in Express" does match `express`. A name written with a version, such
 * as `send@0.19.0`, always counts.
 */
export function packageMentioned(text: string, component: { ecosystem: Ecosystem; name: string }): boolean {
  const name = component.name.trim();
  if (name.length < 3) return false;
  // One story is compared with every component, and a story that cites many advisories is
  // compared again for each of them: remember the answers for the texts seen last.
  let answers = recent.get(text);
  if (!answers) {
    if (recent.size >= 32) recent.clear();
    answers = new Map();
    recent.set(text, answers);
  }
  const key = `${component.ecosystem}\n${name}`;
  let answer = answers.get(key);
  if (answer === undefined) {
    answer = nameTests(component.ecosystem, name)(text);
    answers.set(key, answer);
  }
  return answer;
}
const recent = new Map<string, Map<string, boolean>>();
const compiled = new Map<string, (text: string) => boolean>();
/** The compiled test for one name; building its expressions once matters for large inventories. */
function nameTests(ecosystem: Ecosystem, name: string): (text: string) => boolean {
  const key = `${ecosystem}\n${name}`;
  let test = compiled.get(key);
  if (!test) {
    const release = releaseTest([name], ecosystem);
    const mention = bounded(escape(name));
    const kind = nameKind(name);
    const named = kind === 'dictionary' ? writtenAsName([name]) : () => false;
    const lower = name.toLowerCase();
    test = (text) => {
      // Most components are not in most texts: a plain search settles that before any expression.
      if (!text.toLowerCase().includes(lower)) return false;
      if (release(text)) return true;
      if (!mention.test(text)) return false;
      if (kind === 'distinctive' || packageContext(text, ecosystem, kind === 'dictionary')) return true;
      return named(text);
    };
    if (compiled.size >= 50_000) compiled.clear();
    compiled.set(key, test);
  }
  return test;
}

/** A line set in title case: most of its longer words are capitalised, so a capital shows nothing. */
function titleCase(line: string): boolean {
  const words = line.match(/\p{L}{4,}/gu) ?? [];
  if (words.length < 5) return false;
  return words.filter((word) => /^\p{Lu}/u.test(word)).length / words.length >= 0.6;
}

/**
 * A test for English words written as names. Any of them counts when it has a capital straight
 * after a word that has none and is not followed by another capitalised word ("a flaw in Express
 * lets", "the Scheduler package"); "group Salt Typhoon" and "Windows Task Scheduler" are other
 * names. A well-known library name also counts with a following capital ("in React Server
 * Components") and when it opens a sentence that goes on in lower case ("Rails releases patches").
 * Lines in title case are not considered.
 */
function writtenAsName(names: string[]): (text: string) => boolean {
  const single = names.map((name) => name.trim()).filter((name) => /^\p{L}{3,}$/u.test(name));
  const form = capitalised;
  const end = '(?![\\p{L}\\p{N}_@/\\-])';
  const after = "(?<=(?:^|[^\\p{L}\\p{N}])\\p{Ll}[\\p{L}\\p{N}'’-]*[,:]? )";
  const patterns: RegExp[] = [];
  const add = (group: string[], build: (alternatives: string) => string) => {
    for (let offset = 0; offset < group.length; offset += 400)
      patterns.push(
        new RegExp(
          build(
            `(?:${group
              .slice(offset, offset + 400)
              .map(form)
              .join('|')})`,
          ),
          'u',
        ),
      );
  };
  add(
    single.filter((name) => !properName(name)),
    (alternatives) => `${after}${alternatives}${end}(?! \\p{Lu})`,
  );
  add(
    single.filter((name) => properName(name)),
    (alternatives) =>
      `${after}${alternatives}${end}|(?<=^|[.!?]\\s+)${alternatives}(?:['’]s)?${end}(?= \\p{Ll})`,
  );
  if (!patterns.length) return () => false;
  return (text) =>
    text.split('\n').some((line) => !titleCase(line) && patterns.some((pattern) => pattern.test(line)));
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
  const named: string[] = [];
  const byEcosystem = new Map<Ecosystem, { common: string[]; dictionary: string[]; all: string[] }>();
  for (const system of inventory.systems) {
    for (const component of system.components) {
      const key = packageKey(component);
      if (key) packages.add(key);
      if (!byEcosystem.has(component.ecosystem))
        byEcosystem.set(component.ecosystem, { common: [], dictionary: [], all: [] });
      const names = byEcosystem.get(component.ecosystem)!;
      names.all.push(component.name);
      const kind = nameKind(component.name);
      if (kind === 'distinctive') distinctive.push(component.name);
      else names[kind].push(component.name);
      if (kind === 'dictionary') named.push(component.name);
    }
    for (const product of system.products ?? []) declared.push(product.name, ...product.keywords);
    declared.push(...(system.keywords ?? []));
  }
  const declaredTest = anyOf(declared);
  const distinctiveTest = anyOf(distinctive);
  const namedTest = writtenAsName([...new Set(named)]);
  const ecosystemTests = [...byEcosystem].map(([ecosystem, names]) => ({
    ecosystem,
    common: anyOf(names.common),
    dictionary: anyOf(names.dictionary),
    release: releaseTest(names.all, ecosystem),
  }));
  const matcher: InventoryMatcher = {
    packages,
    declared: declaredTest,
    packageNamed: (text) =>
      distinctiveTest(text) ||
      namedTest(text) ||
      ecosystemTests.some(
        ({ ecosystem, common, dictionary, release }) =>
          release(text) ||
          (packageContext(text, ecosystem, true) &&
            (dictionary(text) || (packageContext(text, ecosystem, false) && common(text)))),
      ),
  };
  matchers.set(inventory, { shape: current, matcher });
  return matcher;
}
