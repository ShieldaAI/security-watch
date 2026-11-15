// Which news stories count as naming an inventory package.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assess } from '../dist/assessment.js';
import { evidenceRelevant } from '../dist/cve-now.js';
import { inventoryMatcher, packageMentioned } from '../dist/matching.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const at = new Date(NOW).toISOString();
const config = { news_lookback_minutes: 40, poll_interval_minutes: 30, inventory_stale_days: 30, policy: {} };
const component = (ecosystem, name) => ({ id: `c:${name}`, ecosystem, name, version: '1.0.0' });
const inventory = (components) => ({
  systems: [{ id: 'prod', name: 'prod', updated_at: at, products: [], keywords: [], components }],
});
const story = (title, description = title) => ({
  id: `hacker_news:entry:${title.length}-${title.charCodeAt(0)}`,
  source: 'hacker_news',
  kind: 'news',
  title,
  url: 'https://example.com/a',
  description,
  aliases: [title.match(/CVE-\d+-\d+/)?.[0] ?? 'CVE-2026-1'],
  severity: 'unknown',
  modified_at: at,
  fetched_at: at,
  packages: [],
  content_status: 'full',
});
const found = (inv, item) => assess(inv, [item], config, NOW).map((finding) => finding.component_id);

test('a headline about a well-known package matches it without the word "package"', () => {
  const inv = inventory([
    component('npm', 'axios'),
    component('npm', 'express'),
    component('npm', 'lodash'),
    component('npm', 'next'),
    component('npm', 'vite'),
    component('npm', 'webpack'),
    component('PyPI', 'django'),
    component('PyPI', 'pillow'),
    component('PyPI', 'langchain'),
    component('RubyGems', 'rails'),
  ]);
  for (const [name, title] of [
    ['axios', 'Axios 1.8.2 fixes SSRF and credential leak tracked as CVE-2026-27152'],
    ['next', 'Critical Next.js middleware bypass CVE-2026-29927 under active exploitation'],
    ['django', 'Django security releases issued: 5.1.7, 5.0.13 and 4.2.20 fix CVE-2026-26699'],
    ['vite', 'Vite dev server arbitrary file read (CVE-2026-30208) exploited in the wild'],
    ['langchain', 'Critical RCE in LangChain (CVE-2026-68664) lets attackers steal secrets from AI agents'],
    ['rails', 'Rails releases patches for Active Storage flaw CVE-2026-24293'],
    ['express', 'Express fixes open redirect CVE-2026-29041 in res.location'],
    ['pillow', 'Researchers disclose Pillow heap overflow CVE-2026-50447'],
    ['webpack', 'Webpack flaw CVE-2026-43788 enables DOM clobbering XSS'],
    ['lodash', 'Lodash prototype pollution CVE-2026-2950 affects millions of projects'],
    ['lodash', 'a flaw in lodash lets attackers pollute prototypes (CVE-2026-2951)'],
  ]) {
    const item = story(title);
    assert.deepEqual(found(inv, item), [`c:${name}`], title);
    assert.equal(evidenceRelevant(item, inv), true, title);
  }
});

test('a package whose name is an everyday word needs a story about packages or a named release', () => {
  const inv = inventory(
    ['send', 'buffer', 'request', 'events', 'process', 'open', 'next', 'router', 'cookie', 'moment'].map(
      (name) => component('npm', name),
    ),
  );
  for (const title of [
    // Title case and a sentence start capitalise ordinary words too.
    'Critical Buffer Overflow in Acme Router Firmware Under Attack (CVE-2026-1000)',
    'Request smuggling flaw CVE-2026-1001 lets attackers send forged headers',
    'Open redirect in ExampleCMS: patch expected next week (CVE-2026-1002)',
    'Session Cookie Theft Campaign Targets Events Industry at the Moment (CVE-2026-1003)',
    'Attackers send 1,5 million requests per process, CVE-2026-1004',
  ]) {
    const item = story(title);
    assert.deepEqual(found(inv, item), [], title);
    assert.equal(evidenceRelevant(item, inv), false, title);
  }
  for (const [name, title] of [
    ['send', 'Malicious release of the send npm package steals tokens (CVE-2026-1005)'],
    ['next', 'Next.js 15.2.3 fixes middleware bypass CVE-2026-1006'],
    ['moment', 'Moment.js path traversal CVE-2026-1007'],
    ['send', 'Upgrade to send@0.19.0 to fix template injection CVE-2026-1008'],
    ['cookie', 'Cookie 0.7.0 fixes out-of-bounds characters, CVE-2026-1009'],
  ]) {
    const item = story(title);
    assert.deepEqual(found(inv, item), [`c:${name}`], title);
    assert.equal(evidenceRelevant(item, inv), true, title);
  }
  // The suffix that names an npm project does not carry over to another ecosystem.
  assert.equal(packageMentioned('Next.js middleware bypass', { ecosystem: 'PyPI', name: 'next' }), false);
  assert.equal(
    packageMentioned('Requests 2.32.0 fixes a leak', { ecosystem: 'PyPI', name: 'requests' }),
    true,
  );
  assert.equal(packageMentioned('sends many requests', { ecosystem: 'PyPI', name: 'requests' }), false);
});

test('the matcher follows entries added to or removed from the same inventory object', () => {
  const inv = inventory([component('npm', 'qrlib-pad')]);
  const record = {
    ...story('unrelated CVE-2026-2000'),
    id: 'cve_now:CVE-2026-2000',
    source: 'cve_now',
    kind: 'advisory',
    packages: [{ ecosystem: 'npm', name: 'is-odd' }],
  };
  assert.equal(evidenceRelevant(record, inv), false);
  const before = inventoryMatcher(inv);
  assert.equal(inventoryMatcher(inv), before, 'an unchanged inventory reuses its matcher');
  inv.systems[0].components.push(component('npm', 'is-odd'));
  assert.equal(evidenceRelevant(record, inv), true);
  inv.systems[0].keywords.push('Acme router');
  assert.equal(evidenceRelevant(story('Acme router flaw CVE-2026-2001'), inv), true);
  inv.systems[0].components.pop();
  assert.equal(evidenceRelevant(record, inv), false);
});

test('a library named second in a sentence counts only after an article or a word of severity or novelty', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  for (const text of [
    'American Express customers were targeted by a phishing wave.',
    'Federal Express drivers were told to update the app.',
  ])
    assert.equal(packageMentioned(text, component('express')), false, text);
  for (const text of [
    'New Express vulnerability lets attackers bypass routing.',
    'Critical Express flaw lets attackers bypass routing.',
    'The Express maintainers released a fix.',
  ])
    assert.equal(packageMentioned(text, component('express')), true, text);
  const flask = { id: 'c', ecosystem: 'PyPI', name: 'flask', version: '1.0.0' };
  assert.equal(packageMentioned('A Flask extension leaks session cookies to other sites.', flask), true);
});

test('a library named second in a sentence before a word that is not about software is not taken for it', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  for (const [name, text] of [
    ['puma', 'The Puma sportswear brand reported a breach of customer data.'],
    ['express', 'The Express reported that attackers stole the data.'],
    ['mongoose', 'The Mongoose ransomware group claimed the attack.'],
    ['meteor', 'The Meteor wiper destroyed the railway systems.'],
    ['cypress', 'The Cypress semiconductor unit was hit by attackers.'],
  ])
    assert.equal(packageMentioned(text, component(name)), false, text);
});

test('a library named second in a sentence: kinds of software and flaws after it, brand and malware words not', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  for (const [name, text] of [
    ['mocha', 'The Mocha test runner fails on Windows.'],
    ['struts', 'Critical Struts remote code execution flaw disclosed.'],
    ['electron', 'New Electron sandbox escape lets pages run code.'],
    ['puma', 'The Puma web server fixes request smuggling.'],
  ])
    assert.equal(packageMentioned(text, component(name)), true, text);
  for (const [name, text] of [
    ['puma', 'The Puma users were told to reset passwords.'],
    ['bootstrap', 'The Bootstrap code was stolen.'],
    ['meteor', 'The Meteor exploit kit spread.'],
    ['meteor', 'The Meteor servers went down.'],
    ['express', 'The Express security breach exposed passengers.'],
    ['thor', 'The Thor code was leaked online.'],
    ['puma', 'The Puma apparel line sold out.'],
    ['puma', 'The Puma releasers met.'],
  ])
    assert.equal(packageMentioned(text, component(name)), false, text);
});

test('second-word rule: software words, capitalised kinds, up to three words naming the kind of flaw', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  for (const [name, text] of [
    ['puma', 'The Puma HTTP server fixes request smuggling.'],
    ['express', 'The Express JavaScript framework fixed it.'],
    ['rails', 'The Rails core team released a fix.'],
    ['react', 'The React community reacted to the bug in the library.'],
    ['express', 'The Express security team responded for 4.21.2.'],
    ['express', 'The Express advisory lists two flaws.'],
    ['react', 'Critical React issue lets pages run code, the maintainers said.'],
    ['react', 'The React devs shipped a patch to npm.'],
    ['struts', 'Critical Struts remote code execution flaw disclosed.'],
  ])
    assert.equal(packageMentioned(text, component(name)), true, text);
  for (const [name, text] of [
    ['struts', 'Critical Struts remote code execution sandbox flaw disclosed.'],
    ['thor', 'The Thor ransomware decryptor bug was found.'],
    ['express', 'The Express mobile banking app flaw leaked data.'],
    ['express', 'The Express rewards portal injection worried users.'],
    ['meteor', 'The Meteor botnet command injection flaw spread.'],
    ['meteor', 'The Meteor shower bug was annoying.'],
    ['puma', 'The Puma store had a bug.'],
    ['mongoose', 'The Mongoose ransomware exploits a flaw.'],
    ['express', 'The Express Remote code flaw was found.'],
  ])
    assert.equal(packageMentioned(text, component(name)), false, text);
});

test('second-word rule: acronyms of flaw kinds as written, and each group of software words', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  for (const [name, text] of [
    ['express', 'The Express SQL injection flaw lets attackers read data.'],
    ['express', 'The Express XSS bug lets pages run scripts.'],
    ['express', 'New Express SSRF flaw reaches internal hosts.'],
    ['react', 'Critical React XSS flaw disclosed.'],
    ['express', 'The Express denial of service flaw stops servers.'],
    ['jackson', 'The Jackson deserialization flaw lets attackers run code.'],
    ['express', 'The Express path traversal vulnerability exposes files.'],
    ['react', 'The React components leak state across requests in the npm package.'],
    ['rails', 'Critical Rails security update released for version 7.1.'],
    ['rails', 'The Rails security advisory lists two flaws in the framework.'],
    ['express', 'The Express web applications were exposed.'],
    ['express', 'The Express web app leaks sessions.'],
  ])
    assert.equal(packageMentioned(text, component(name)), true, text);
  assert.equal(packageMentioned('The Express applications were exposed.', component('express')), false);
  assert.equal(packageMentioned('The Express app leaks sessions.', component('express')), false);
});

test('shared words after a library named second in a sentence count only when the text speaks of a library', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  for (const [name, text] of [
    ['nest', 'The Nest security team confirmed the issue.'],
    ['nest', 'New Nest security update fixes cameras.'],
    ['cypress', 'The Cypress security advisory covers CVE-2026-1111.'],
    ['puma', 'The Puma security team confirmed customer data was taken.'],
    ['mongoose', 'The Mongoose components of the ransomware encrypt files.'],
    ['react', 'The React community reacted to the bug.'],
    ['react', 'The React devs shipped a patch.'],
    ['nest', 'The Nest thermostat bug locked users out.'],
    ['cypress', 'Critical Cypress chip flaw affects billions of devices.'],
  ])
    assert.equal(packageMentioned(text, component(name)), false, text);
  for (const [name, text] of [
    ['express', 'The Express SDK leaks keys.'],
    ['express', 'The Express API router leaks keys.'],
    ['express', 'The Express authentication bypass flaw lets anyone in.'],
  ])
    assert.equal(packageMentioned(text, component(name)), true, text);
});

test('the library cue is read in the same sentence, from registries, kinds of package and written versions', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  const nest = 'The Nest security team confirmed the issue.';
  for (const second of [
    'The flaw has a CVSS score of 9.8.',
    'Stolen data later appeared on GitHub.',
    'About 1.5 million customers were affected.',
    'Devices on iOS 17.4 are safe.',
    'The library of stolen files grew.',
  ])
    assert.equal(packageMentioned(`${nest} ${second}`, component('nest')), false, second);
  for (const cue of [
    'in the npm package',
    'in the library',
    'for the framework',
    'in its modules',
    'in its plugins',
    'in its gems',
    'in its crates',
    'on PyPI',
    'after pip install nest',
    'for v4.2',
    'for version 4.2',
    'in nest@4.2',
    'for 4.21.2',
    'the open-source maintainers said',
  ])
    assert.equal(
      packageMentioned(`The Nest security team fixed the issue ${cue}.`, component('nest')),
      true,
      cue,
    );
  assert.equal(
    packageMentioned('The Nest security team fixed the pipeline issue.', component('nest')),
    false,
  );
  assert.equal(packageMentioned('The Nest security team fixed it for 4.2.', component('nest')), false);
  assert.equal(
    packageMentioned('The Nest security team fixed the subframework issue.', component('nest')),
    false,
  );
  assert.equal(
    packageMentioned('The Svelte UI components leak state in the library.', component('svelte')),
    true,
  );
  assert.equal(packageMentioned('The Nest of bugs in the thermostat firmware.', component('nest')), false);
});

test('word lists of the second-word rule, entry by entry', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  const yes = (text, name = 'express') => assert.equal(packageMentioned(text, component(name)), true, text);
  const no = (text, name = 'express') => assert.equal(packageMentioned(text, component(name)), false, text);
  // Words about software that count on their own.
  for (const word of [
    'team',
    'core team',
    'maintainers',
    'codebase',
    'repository',
    'ecosystem',
    'library',
    'framework',
    'package',
    'modules',
    'plugins',
    'extensions',
    'middleware',
    'router',
    'dependency',
    'gems',
    'crates',
    'runtime',
    'runner',
    'installer',
    'CLI',
    'SDK',
    'API',
    'versions',
    'releases',
    'patch',
    'fix',
    'advisory',
  ])
    yes(`The Express ${word} came under scrutiny this week.`);
  // Words shared with companies: only with a library cue in the sentence or a strong one in the next.
  for (const word of [
    'community',
    'components',
    'devs',
    'issues',
    'security team',
    'security update',
    'security fix',
    'security patch',
    'security release',
    'security advisory',
  ]) {
    no(`The Express ${word} came under scrutiny this week.`);
    yes(`The Express ${word} came under scrutiny in the npm package.`);
    yes(`The Express ${word} came under scrutiny this week. Install it with npm install express.`);
    no(`The Express ${word} came under scrutiny this week. A courier package was lost.`);
  }
  // Cue words and forms in the same sentence.
  for (const cue of [
    'on npm',
    'on PyPI',
    'on RubyGems',
    'on crates.io',
    'on Maven',
    'on NuGet',
    'after gem install',
    'after cargo install',
    'in the package',
    'as open source',
    'by its maintainers',
    'in v4.2',
    'in version 4.2',
    'in core@4.2',
    'in 4.21.2',
  ])
    yes(`The Express community fixed it ${cue}.`);
  for (const notCue of [
    'on GitHub',
    'in the packaging',
    'for v3',
    'rated CVSS v3.1',
    'from 192.168.1.10',
    'on 15.11.2026',
    'for 4.2',
    'for 1.5 million users',
  ])
    no(`The Express community fixed it ${notCue}.`);
  // A sentence does not end at an abbreviation.
  yes('The Express devs fixed it, e.g. in the npm package.');
  yes('The Express devs fixed it, i.e. version 4.2 of it.');
  // Kinds of a flaw, including acronyms as written.
  for (const kind of [
    'SQL injection',
    'XSS',
    'SSRF',
    'CSRF',
    'XXE',
    'RCE',
    'DoS',
    'ReDoS',
    'TLS',
    'SSL',
    'denial of service',
    'path traversal',
    'deserialization',
  ])
    yes(`The Express ${kind} flaw lets attackers in.`);
  // Kinds before a server, app or client.
  for (const kind of ['web', 'HTTP', 'JavaScript', 'open-source'])
    yes(`The Express ${kind} server leaks data.`);
  yes('The Express web clients leak data.');
  no('The Express clients leak data.');
  // Words before the name.
  for (const before of ['The', 'A', 'New', 'Critical', 'Severe', 'Latest', 'Its'])
    yes(`${before} Express flaw lets attackers in.`);
});

test('library cue: versions as written, CVSS forms and dates, sentence ends, strong cues and singular forms', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  const yes = (text) => assert.equal(packageMentioned(text, component('nest')), true, text);
  const no = (text) => assert.equal(packageMentioned(text, component('nest')), false, text);
  const n = 'The Nest security team fixed it';
  for (const v of [
    'in v1.2.3',
    'in V10.0.4',
    'in v1.2.3-beta',
    '(v1.2.3)',
    'for v4.2',
    'in version 4.2',
    'in version 4.2.1',
    'in core@4.2.1',
    'in 4.21.2',
  ])
    yes(`${n} ${v}.`);
  // A version in the next sentence does not count: device and firmware news write them the same way.
  no(`${n}. Upgrade to v5.4.1 now.`);
  no(`${n}. Firmware 4.21.3 fixes it.`);
  for (const v of [
    'for v3',
    'in version 4',
    'rated CVSS v3.1',
    'rated CVSS: v3.1',
    'rated CVSS version 3.1',
    'on 15.11.2026',
    'on 2026.11.15',
    'from 192.168.1.10',
    'from 10.0.0.1:8080',
  ])
    no(`${n} ${v}.`);
  // Strong cues from the next sentence; never from the previous one.
  for (const strong of [
    'It is on RubyGems.',
    'Run gem install nest.',
    'Run cargo install nest.',
    'Run pip install nest.',
    'It is on Maven.',
    'It is on NuGet.',
  ])
    yes(`${n}. ${strong}`);
  no(`It is on PyPI. ${n}.`);
  // After initials a sentence ends, so a weak cue there does not count.
  no('The Nest security team flagged a phishing wave across the U.S. Package delivery scams rose sharply.');
  no('The Nest components, e.g. the loader and the npm-themed lure, were analysed.');
  no(`${n}. The library of stolen files grew.`);
  // A sentence ends before a capital or a digit, not after an abbreviation or a single letter.
  for (const abbreviation of [
    'e.g.',
    'i.e.',
    'incl.',
    'vs.',
    'approx.',
    'cf.',
    'al.',
    'ca.',
    'no.',
    'nr.',
    'ver.',
    'v.',
  ])
    yes(`${n}, ${abbreviation} Version 4.2 of it.`);
  no(
    `${n}. Version 4.2 of the doorbell. Ours too.`.replace(
      'Version 4.2 of the doorbell. ',
      'Ours. Version 4.2. ',
    ),
  );
  // Singular forms of the shared words and the cue words.
  yes('The Nest component leaks state in the library.');
  yes('The Nest issue lets pages run code in the npm package.');
  yes('The Nest community fixed it in its libraries.');
});

test('library cue edges: CVSS forms, separators, named hyphen suffixes, "etc." and digits starting a sentence', () => {
  const component = (name) => ({ id: 'c', ecosystem: 'npm', name, version: '1.0.0' });
  const yes = (text, name = 'nest') => assert.equal(packageMentioned(text, component(name)), true, text);
  const no = (text, name = 'nest') => assert.equal(packageMentioned(text, component(name)), false, text);
  const n = 'The Nest security team fixed it';
  for (const v of [
    'rated CVSS (v3.1) 8.1',
    'rated CVSS v3.1/v4.0 8.1',
    'under CVSS-version 3.1',
    'for TLSv1.2',
    'in subversion 1.2',
  ])
    no(`${n} ${v}.`);
  no(`${n}, rated 9.8 (v3.1) on the CVSS scale.`);
  yes(`${n} in the plugin-based loader.`);
  yes(`${n} in the npm-published release.`);
  no(`${n} in the npm-themed lure.`);
  no(`${n}. Run npm-themed lures.`);
  yes(`${n}. Run npm-based installs.`.replace('npm-based installs', 'npm install nest'));
  // "etc." before a capital ends a sentence; a lower-case single letter does not.
  no('The Puma security team warned of smishing, vishing, etc. Package notices were common.', 'puma');
  yes(`${n}, a. Version 4.2 of it.`);
  // A sentence may start with a digit.
  no(`${n}. 4.2.1 was released.`);
  // After initials a sentence ends: an ambiguous case, kept that way ("led by J. Doe").
  no('The Express security team, led by J. Doe, released 5.0.1.', 'express');
});

test('sentence ends, next-sentence registries and remaining list entries', () => {
  const component = (name, ecosystem = 'npm') => ({ id: 'c', ecosystem, name, version: '1.0.0' });
  const yes = (text, name = 'nest') => assert.equal(packageMentioned(text, component(name)), true, text);
  const no = (text, name = 'nest') => assert.equal(packageMentioned(text, component(name)), false, text);
  const n = 'The Nest security team fixed it';
  // "!" and "?" end a sentence; a lower-case start does not; a single lower-case letter does not.
  no(`${n}! The library of stolen files grew.`.replace('library of stolen files', 'archive'));
  no(`${n}? It is on 4.2 now.`);
  yes(`${n}. it is in the npm package.`);
  yes(`${n} with plan b. Version 4.2 of it.`);
  // Registries that count from the next sentence; the one after does not.
  for (const strong of ['It is on PyPI.', 'It is on crates.io.', 'It is on npm.', 'Run npm install nest.'])
    yes(`${n}. ${strong}`);
  no(`${n}. Npm-themed lures spread.`);
  no(`${n}. Nothing more. It is on PyPI.`);
  no(`${n}. It has gems.`);
  // The cue words in full: "open-source".
  yes(`${n} in the open-source library.`.replace('library', 'project'));
  // A separator before "v": "TLSv1.3" is not a version.
  no(`${n} for TLSv1.3.`);
  // Flaw kinds and words before the name not tested elsewhere.
  yes('The Express use-after-free bug lets attackers in.', 'express');
  yes('The Express zero-day flaw lets attackers in.', 'express');
  yes('Three Express flaws let attackers in.', 'express');
  yes('The Express PyPI package was cloned.', 'express');
  yes('The Express libraries leak data.', 'express');
});
