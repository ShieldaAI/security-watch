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
 * The registry of each ecosystem and its tools, as prose names them. A language name is not in
 * this list: "the Python backdoor sends requests" is not about the `requests` package.
 */
/** The install command of each ecosystem, as written in advisories and articles. */
const INSTALL: Record<Ecosystem, string> = {
  npm: '(?:npm (?:install|i|add)|yarn add|pnpm (?:add|install))',
  PyPI: '(?:pip3? install|pipx install|uv (?:add|pip install)|poetry add)',
  Packagist: 'composer require',
  Go: 'go (?:get|install)',
  Maven: '(?!)',
  'crates.io': 'cargo (?:add|install)',
  RubyGems: '(?:gem install|bundle add)',
  NuGet: '(?:dotnet add package|nuget install|Install-Package)',
  Hex: 'mix (?:deps\\.get|archive\\.install)',
  Pub: '(?:dart|flutter) pub add',
  Hackage: 'cabal install',
  SwiftURL: '(?!)',
};
const LANGUAGE_CONTEXT: Record<Ecosystem, string> = {
  npm: 'node\\.js|nodejs|javascript|typescript',
  PyPI: 'python',
  Packagist: 'php',
  Go: 'golang|go',
  Maven: 'java',
  'crates.io': 'rust',
  RubyGems: 'ruby',
  NuGet: '\\.net|dotnet',
  Hex: 'elixir|erlang',
  Pub: 'dart|flutter',
  Hackage: 'haskell',
  SwiftURL: 'swift',
};
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
/**
 * A test for English-word names that the text itself calls a package. The word "package" somewhere
 * near is not enough: "the packages, which deliver a loader", "found three packages" and "a buffer
 * overflow in the C library" are about other things. The name has to be named as one:
 * - "the request package", "the requests library", "the entities npm package": the name, then
 *   "package", "library", "module", "dependency", "gem", "crate" or "plugin", in the singular;
 * - "the npm package next", "PyPI package requests": a registry, the kind, then the name;
 * - "a package called send", "a dependency named once": the kind, "called" or "named", the name;
 * - "npm install send", "pip install requests", "npm:send": an install command or registry prefix;
 * - "the npm packages chalk and debug": a registry, the kind in the plural, and a short list;
 * - "the Python framework Tornado": the language, what the software is, the name with a capital.
 */
function namedAsPackage(
  names: Iterable<string>,
  ecosystem: Ecosystem,
  common: boolean,
): (text: string) => boolean {
  const unique = [...new Set([...names].map((name) => name.trim()).filter((name) => name.length >= 3))];
  const registry = `(?:${REGISTRY_CONTEXT[ecosystem]})`;
  // "module" is left out: kernel, PAM and web-server modules are not packages.
  const kind = '(?:package|library|dependency|gem|crate|plugin)';
  const kinds = '(?:packages|libraries|dependencies|gems|crates|plugins)';
  const install = INSTALL[ecosystem];
  // One entry of a list of package names. Words that join a sentence are never one: "npm packages
  // that send", "PyPI packages which steal".
  const joining =
    'that|which|who|whose|to|are|were|was|is|be|been|being|have|has|had|and|or|but|with|from|for|in|on|of|the|a|an|this|these|those|not|no|it|its|they|their|as|by|at|into|than|then|so|such|also|now|designed|found|used|named|called|published|uploaded|removed';
  const item = `(?!(?:${joining})(?![\\p{L}\\p{N}]))[\\p{L}\\p{N}@/._-]+`;
  // A package named like one of those words is not taken from a list either, unless quoted.
  const joiningWord = new RegExp(`^(?:${joining})$`, 'iu');
  const quote = '["\'`‘’“”]?';
  const { before, after } = boundary;
  const patterns: RegExp[] = [];
  for (let offset = 0; offset < unique.length; offset += 400) {
    const chunk = unique.slice(offset, offset + 400);
    const name = `(?:${chunk.map(escape).join('|')})`;
    const listed = chunk.filter((value) => !joiningWord.test(value));
    // In a list a name must be quoted when it is one of the joining words.
    const listName = listed.length
      ? `(?:${quote}(?:${listed.map(escape).join('|')})${quote}|["'\`‘’“”]${name}["'\`‘’“”])`
      : `(?:["'\`‘’“”]${name}["'\`‘’“”])`;
    patterns.push(
      new RegExp(
        [
          // "the request package", "the requests library". For the commonest words ("which package
          // was affected", "the standard library", "the next package update") the name has to be
          // quoted or followed by the registry: "the 'request' package", "the request npm package".
          common
            ? `${before}(?:["'\`‘’“”]${name}["'\`‘’“”] (?:${registry} )?|${name} ${registry} )${kind}${after}`
            : `${before}${quote}${name}${quote} (?:${registry} )?${kind}${after}`,
          `${before}${registry} ${kind} ${quote}${name}${after}`,
          `${before}${kind} (?:called|named) ${quote}${name}${after}`,
          // The ecosystem's own install command: "pip install express" is not about npm.
          `${before}${install} (?:-\\S+ )*${quote}${name}(?![\\p{L}\\p{N}_/\\-])`,
          `${before}${registry}:${name}${after}`,
          // A real list of names next to a registry and the kind in the plural, with a comma or "and"
          // between the entries: "the npm packages chalk, colors and debug", "the npm libraries
          // colors and faker", "Chalk and Debug npm Packages". One word after or before the plural
          // is not a list: "npm packages that send", "six npm packages".
          `${before}${registry} ${kinds} (?:${item}, ){0,4}${listName}(?:, ${item}){0,4},? and ${item}${after}`,
          `${before}${registry} ${kinds} (?:${item}, ){0,4}${item},? and ${listName}${after}`,
          `${before}(?:${item}, ){0,4}${listName}(?:, ${item}){0,4},? and ${item} ${registry} ${kinds}${after}`,
          `${before}(?:${item}, ){0,4}${item},? and ${listName} ${registry} ${kinds}${after}`,
        ].join('|'),
        'iu',
      ),
    );
    // The ecosystem's language, what the software is, then the name with a capital: "the Python
    // framework Tornado", "the Python formatter Black".
    patterns.push(
      new RegExp(
        `${before}(?i:${LANGUAGE_CONTEXT[ecosystem]}) (?:[\\p{Ll}-]+ )?(?:framework|library|package|module|formatter|linter|tool|client|server|parser|compiler|bundler|runtime) (?:${unique
          .slice(offset, offset + 400)
          .map(capitalised)
          .join('|')})${after}`,
        'u',
      ),
    );
  }
  return (text) => patterns.some((pattern) => pattern.test(text));
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
/** Only the forms no prose writes: "through@1.2", "through v1.2". */
const STRICT_RELEASE_SUFFIX = '(?:@v?\\d+\\.\\d+| v\\d+\\.\\d+)';
/**
 * Words that stand before a version in prose about version ranges: "7.0.0 through 7.0.16", "from
 * 16.1.0", "versions up to 4.1.2". Packages with these names exist; a version after the word is
 * not a release of them unless it is written "name@1.2" or "name v1.2".
 */
const CONNECTORS = new Set(
  `through thru from after before until till to since between and or below above under over prior
including include includes inclusive exclusive version versions release releases build builds patch
patched update updated upgrade upgraded fixed fix fixes affected affects up down at in on of is are
was were be all any each every than then latest earliest older newer later earlier`.split(/\s+/),
);
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
  const all = [...new Set([...names].map((name) => name.trim()))];
  const unique = all.filter((name) => name.length >= 3);
  const patterns: RegExp[] = [];
  // A name of two characters ("ws", "qs", "ip") is too short to be told from anything else in
  // prose. It counts only as `name@version`.
  const short = all.filter((name) => name.length === 2);
  for (let offset = 0; offset < short.length; offset += 400)
    patterns.push(
      bounded(
        `(?:${short
          .slice(offset, offset + 400)
          .map(escape)
          .join('|')})@v?\\d+\\.\\d+`,
      ),
    );
  // Or, in exactly its own spelling, right next to the word "package", "library" or "module":
  // "the ws library", "the npm package qs". "IP address" is not the package `ip`.
  for (let offset = 0; offset < short.length; offset += 400) {
    const alternatives = `(?:${short
      .slice(offset, offset + 400)
      .map(escape)
      .join('|')})`;
    const word = '(?:packages?|librar(?:y|ies))';
    patterns.push(
      new RegExp(
        `${boundary.before}${alternatives} (?:[\\p{L}\\p{N}]+ )?${word}${boundary.after}|${boundary.before}${word} ${alternatives}${boundary.after}`,
        'u',
      ),
    );
  }
  // "Rails 7.2", "Salt 3007.1": a two-part version after an English word written with a capital,
  // unless a unit or a rating follows ("the Next 2.5 years", "Address 9.8 CVSS bug").
  const named = unique.filter(
    (name) =>
      /^\p{L}+$/u.test(name) && nameKind(name) !== 'distinctive' && !CONNECTORS.has(name.toLowerCase()),
  );
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
    const loose = chunk.filter((name) => !CONNECTORS.has(name.toLowerCase()));
    const strict = chunk.filter((name) => CONNECTORS.has(name.toLowerCase()));
    if (loose.length) patterns.push(bounded(`(?:${loose.map(escape).join('|')})${RELEASE_SUFFIX}`));
    if (strict.length) patterns.push(bounded(`(?:${strict.map(escape).join('|')})${STRICT_RELEASE_SUFFIX}`));
    // How a library is often called after its ecosystem: "node-tar", "Python-Markdown".
    const prefix = ecosystem === 'npm' ? 'node-' : ecosystem === 'PyPI' ? 'python-' : undefined;
    if (prefix)
      patterns.push(
        new RegExp(`${boundary.before}${prefix}(?:${chunk.map(escape).join('|')})${boundary.after}`, 'iu'),
      );
    if (ecosystem === 'npm') {
      // In lower case too, unless the word is one of the commonest: "validator.js" is the library,
      // "config.js" and "server.js" are files.
      const uncommon = chunk.filter((name) => nameKind(name) !== 'common');
      if (uncommon.length) patterns.push(bounded(`(?:${uncommon.map(escape).join('|')})\\.js`));
      patterns.push(
        new RegExp(
          `${boundary.before}(?:${chunk.map(capitalised).join('|')})(?:\\.js|JS)${boundary.after}`,
          'u',
        ),
      );
    }
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
  if (name.length < 2) return false;
  // One story is compared with every component, and a story that cites many advisories is
  // compared again for each of them: remember the answers for the texts seen last.
  let seen = recent.get(text);
  if (!seen) {
    if (recent.size >= RECENT_TEXTS) recent.clear();
    const lower = text.toLowerCase();
    seen = { lower, words: new Set(lower.match(/[a-z0-9]+/g) ?? []), answers: new Map() };
    recent.set(text, seen);
  }
  const key = `${component.ecosystem}\n${name}`;
  let answer = seen.answers.get(key);
  if (answer === undefined) {
    // Most components are not in most texts: a plain search settles that before any expression
    // is built for the name.
    // A name of plain letters and digits is looked up among the words of the text ("express", or
    // "expressjs"); searching the whole text for every component costs too much for a lockfile of
    // thousands. Any other name is searched for as it is.
    const wanted = name.toLowerCase();
    const present = /^[a-z0-9]+$/.test(wanted)
      ? seen.words.has(wanted) || seen.words.has(`${wanted}js`)
      : seen.lower.includes(wanted);
    answer = present && nameTests(component.ecosystem, name)(text);
    seen.answers.set(key, answer);
  }
  return answer;
}
/** How many texts, and how many compiled names, are remembered before starting over. */
const RECENT_TEXTS = 32;
const COMPILED_NAMES = 50_000;
const recent = new Map<string, { lower: string; words: Set<string>; answers: Map<string, boolean> }>();
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
    const near = kind === 'distinctive' ? undefined : namedAsPackage([name], ecosystem, kind === 'common');
    test = (text) => {
      if (release(text)) return true;
      if (name.length < 3) return false;
      // Named as a package, which may be written with a version ("npm install send@latest").
      if (near?.(text)) return true;
      if (!mention.test(text)) return false;
      return !near || named(text);
    };
    if (compiled.size >= COMPILED_NAMES) compiled.clear();
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
 * Technology named as what something is built with, not as the subject: "pages built with React",
 * "written in Python or TypeScript", "Electron apps", "a TypeScript loader". These are written in
 * lower case before the written-as-name test, so a capital there shows nothing.
 */
const USED_WITH =
  /\b(?:built|written|developed|made|coded|implemented|based|powered|programmed|created)(?: (?:with|in|on|using|by))? \p{L}[\p{L}.+#-]*(?:(?:,| or| and|, and|, or) \p{L}[\p{L}.+#-]*)*/gu;
const USED_AS =
  /\p{Lu}[\p{L}.+#-]* (?:apps?|applications?|loaders?|sites?|websites?|pages?|projects?|developers?|stealers?|malware|scripts?|payloads?|backdoors?|droppers?)(?![\p{L}\p{N}])/gu;
function technologyInLowerCase(line: string): string {
  return line.replace(USED_WITH, (span) => span.toLowerCase()).replace(USED_AS, (span) => span.toLowerCase());
}

/**
 * A test for English words written as names. Any of them counts when it has a capital straight
 * after a word that has none and is not followed by another capitalised word ("a flaw in Express
 * lets", "the Scheduler package"); "group Salt Typhoon" and "Windows Task Scheduler" are other
 * names. A well-known library name also counts with a following capital ("in React Server
 * Components"), when it opens a sentence that goes on in lower case ("Rails releases patches"),
 * and as the second word of a sentence ("Critical Rails flaw", "The React team").
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
      `${after}${alternatives}${end}` +
      // Opening a sentence that goes on in lower case: "Rails releases patches".
      `|(?<=^|[.!?]\\s+)${alternatives}(?:['’]s)?${end}(?= \\p{Ll})` +
      // Second word of a sentence that goes on in lower case: "Critical Rails flaw", "The React
      // team", "New Express vulnerability".
      `|(?<=(?:^|[.!?]\\s+)\\p{Lu}[\\p{L}'’-]* )${alternatives}(?:['’]s)?${end}(?= \\p{Ll})`,
  );
  if (!patterns.length) return () => false;
  return (text) =>
    text
      .split('\n')
      .some(
        (line) => !titleCase(line) && patterns.some((pattern) => pattern.test(technologyInLowerCase(line))),
      );
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
    // The same rules as `packageMentioned`, for every name of the ecosystem at once.
    common: namedAsPackage(names.common, ecosystem, true),
    dictionary: namedAsPackage(names.dictionary, ecosystem, false),
    release: releaseTest(names.all, ecosystem),
  }));
  const matcher: InventoryMatcher = {
    packages,
    declared: declaredTest,
    packageNamed: (text) =>
      distinctiveTest(text) ||
      namedTest(text) ||
      ecosystemTests.some(
        ({ common, dictionary, release }) => release(text) || dictionary(text) || common(text),
      ),
  };
  matchers.set(inventory, { shape: current, matcher });
  return matcher;
}
