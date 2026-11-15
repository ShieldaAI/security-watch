// Regressions from the sixth review of delivery and guards: the fix line, when a message counts as
// shortened, invisible characters, version citations, and guards that had no test of their own.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { notificationText } from '../dist/delivery.js';
import { loadInventory } from '../dist/inventory.js';
import { validateAnalysis } from '../dist/models.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const character = String.fromCharCode;
const LF = character(10);
const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const assessment = (extra = {}) => ({
  id: 'F1',
  event_id: 'CVE-2026-50001',
  system_id: 'prod',
  component_id: 'alpha',
  category: 'library',
  applicability: 'affected',
  source_severity: 'critical',
  priority: 'critical',
  title: 'alpha remote code execution',
  summary: 'alpha in prod: affected.',
  reasons: [],
  evidence_ids: [],
  urls: ['https://example.com/advisory'],
  exploited: false,
  updated_at: iso(NOW),
  ...extra,
});
const message = (finding, reason = 'Critical library policy.') =>
  notificationText({ id: 'job-1', payload: JSON.stringify({ assessment: finding, reason }) });
const linesOf = (text) => text.split(LF);
const workspace = (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'sw-sixth-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
};

// ---- The fix line ----------------------------------------------------------------------------------

test('every fixed version shown is whole, and the line says how many more there are', () => {
  const branches = Array.from({ length: 21 }, (_, index) => `${index + 1}.4.${10 + index}`).join('; ');
  const pseudo = Array.from(
    { length: 12 },
    (_, index) => `0.0.0-2025010619115${index}-abcdef12345${index}`,
  ).join('; ');
  for (const fix of [branches, pseudo]) {
    const versions = fix.split('; ');
    const line = linesOf(message(assessment({ fix })).text).find((item) => item.startsWith('Fix: '));
    const shown = line
      .slice('Fix: '.length)
      .replace(/; and \d+ more \(run explain for all\)$/, '')
      .split('; ');
    for (const version of shown) assert.ok(versions.includes(version), `"${version}" is a whole version`);
    if (shown.length < versions.length)
      assert.match(line, new RegExp(`and ${versions.length - shown.length} more \\(run explain for all\\)$`));
    assert.ok(line.length <= 'Fix: '.length + 340);
  }
  // A short list is shown as it is.
  const short = linesOf(message(assessment({ fix: '4.17.21; 3.10.2' })).text);
  assert.ok(short.includes('Fix: 4.17.21; 3.10.2'));
});

// ---- Shortening ------------------------------------------------------------------------------------

test('a message is marked as shortened only when something was left out', () => {
  // Build bodies of every length near the limit, and compare with what fits.
  const links = ['https://example.com/a', 'https://example.com/b'];
  let marked = 0;
  for (let length = 300; length <= 750; length++) {
    const finding = assessment({
      summary: 's'.repeat(length),
      reasons: ['a', 'b', 'c', 'd'].map((letter) => letter.repeat(170)),
      urls: links,
      location: {
        system: 'Checkout',
        system_note: 'n'.repeat(290),
        component: 'alpha',
        component_note: 'n'.repeat(290),
      },
      news_analysis: {
        classification: 'new_vulnerability',
        impact: 'affected',
        affected_products: ['p'.repeat(170)],
        affected_versions: ['1.0.0'],
        prerequisites: ['q'.repeat(230)],
        rationale: 'w'.repeat(390),
        quotes: [],
      },
    });
    const { text } = message(finding);
    assert.ok(text.length <= 2900);
    const note = text.includes('(Message shortened');
    // Every line of the full message that is not in the text means something was left out.
    const all = linesOf(message({ ...finding, reasons: finding.reasons }).text);
    const leftOut =
      finding.reasons.some((reason) => !text.includes(`• ${reason}`)) ||
      !text.includes(`Summary: ${'s'.repeat(length)}`);
    assert.equal(note, leftOut, `summary of ${length}`);
    if (note) marked++;
    assert.ok(all.length > 0);
  }
  assert.ok(marked > 0 && marked < 451, 'both cases occur');
});

// ---- Invisible characters --------------------------------------------------------------------------

test('no invisible character can keep a run of spaces apart', () => {
  const invisible = [0x34f, 0x17b4, 0x17b5, 0x180b, 0x180f, 0xfe0f, 0xfff9, 0xfffb, 0xfffc, 0x206a, 0x2063];
  const astral = ['\u{E0020}', '\u{E0041}', '\u{1BCA0}', '\u{1D173}'];
  for (const mark of [...invisible.map((code) => character(code)), ...astral]) {
    const forged = `Routine update.${` ${mark}`.repeat(150)}Rule: no action needed`;
    const { text } = message(assessment({ summary: forged }));
    const summary = linesOf(text).find((line) => line.startsWith('Summary: '));
    assert.equal(
      summary,
      'Summary: Routine update. Rule: no action needed',
      mark.codePointAt(0).toString(16),
    );
  }
});

// ---- Version citations -----------------------------------------------------------------------------

const cites = (quote, version) => {
  const story = {
    id: 'feed:x:entry:9',
    source: 'feed:x',
    kind: 'news',
    title: 'Example Database remote code execution',
    url: 'https://example.com/s',
    description: quote,
    aliases: [],
    severity: 'unknown',
    modified_at: iso(NOW),
    fetched_at: iso(NOW),
    packages: [],
    content_status: 'full',
  };
  try {
    validateAnalysis(
      {
        relevance: 'irrelevant',
        priority: 'low',
        summary: 'The installed version is outside the affected range.',
        evidence_ids: [story.id],
        quotes: [{ evidence_id: story.id, quote }],
        news_analysis: {
          classification: 'new_vulnerability',
          impact: 'not_affected',
          affected_products: ['Example Database'],
          affected_versions: [version],
          prerequisites: [],
          rationale: 'Version 9.9 is later than the fixed release.',
          quotes: [{ evidence_id: story.id, quote }],
        },
      },
      [story],
    );
    return true;
  } catch (error) {
    assert.match(String(error.message ?? error), /MODEL_UNSUPPORTED_NEWS_CLAIM/);
    return false;
  }
};

test('amounts, ports, qualifiers and dashes of every kind are read as they are written', () => {
  const hyphen = character(0x2011);
  const enDash = character(0x2013);
  const minus = character(0x2212);
  for (const [text, version] of [
    ['the fix costs 5€ per host', '5'],
    ['the fix costs 45 € per host', '45'],
    ['it exposes 443/tcp and 53/udp', '443'],
    ['it exposes 443/tcp and 53/udp', '53'],
    [`it is tracked as CVE${hyphen}2026${hyphen}40001`, '2026'],
    [`it is tracked as CVE${hyphen}2026${hyphen}40001`, '40001'],
    [`patched on 2026${enDash}11${enDash}14`, '11'],
    [`a change of ${minus}5`, '5'],
    ['Spring 5.3.20.RELEASE is affected', '5.3.20'],
    ['Hibernate 6.2.0.Final is affected', '6.2.0'],
    ['the service listens on example.com:443', '443'],
    ['the vector is CVSS:3.1/AV:N', '3.1'],
    ['it binds to ::1 only', '1'],
    ['about 4’200 hosts', '4'],
  ])
    assert.equal(cites(`Example Database: ${text}.`, version), false, `${version} in ${text}`);
  for (const [text, version] of [
    ['the bundle log4j-2.17.1.jar is affected', '2.17.1'],
    ['download foo-1.2.3.tar.gz', '1.2.3'],
    [`versions 2.0${enDash}2.4 are affected`, '2.4'],
    [`version 2.4.1${character(0x2014)}update now`, '2.4.1'],
    ["the fixed release is '2.4.1'", '2.4.1'],
    ['Spring 5.3.20.RELEASE is affected', '5.3.20.RELEASE'],
  ])
    assert.equal(cites(`Example Database: ${text}.`, version), true, `${version} in ${text}`);
});

// ---- Links -----------------------------------------------------------------------------------------

test('a link with a blank inside is left out, and at most three links are shown', () => {
  const { text } = message(
    assessment({
      urls: [
        'https://example.com/a b',
        'https://example.com/one',
        'https://example.com/two',
        'https://example.com/three',
        'https://example.com/four',
      ],
    }),
  );
  const lines = linesOf(text);
  assert.ok(!lines.some((line) => line.includes('example.com/a')));
  assert.deepEqual(lines.slice(-3), [
    'https://example.com/one',
    'https://example.com/two',
    'https://example.com/three',
  ]);
});

// ---- doctor ----------------------------------------------------------------------------------------

test('doctor reports a Slack webhook that delivery would refuse, without repeating it', (t) => {
  const directory = workspace(t);
  writeFileSync(
    join(directory, 'systems.json'),
    JSON.stringify({ systems: [{ id: 'api', name: 'API', updated_at: iso(NOW) }] }),
  );
  writeFileSync(
    join(directory, 'security-watch.yaml'),
    [
      'version: 1',
      'inventory: ./systems.json',
      'sources: { cve_now: false, hacker_news: false }',
      'policy: { health_channels: [slack] }',
      'notifications: { slack: { webhook_url_env: SIXTH_SLACK } }',
    ].join('\n'),
  );
  const doctor = (address) =>
    spawnSync(process.execPath, [cli, 'doctor', '--config', 'security-watch.yaml'], {
      cwd: directory,
      encoding: 'utf8',
      timeout: 15_000,
      env: { ...process.env, SIXTH_SLACK: address },
    });
  for (const address of [
    'http://example.com/hook-secret-value',
    'not a url',
    'https://hooks.slack.com/other',
  ]) {
    const result = doctor(address);
    const report = JSON.parse(result.stdout);
    assert.equal(report.ok, false, address);
    assert.match(report.problems.join(' '), /SIXTH_SLACK: Slack webhook/, address);
    assert.ok(!result.stdout.includes(address), 'the address is not printed');
    assert.equal(result.status, 2, address);
  }
  const usable = doctor('https://hooks.slack.com/services/T000/B000/synthetic');
  assert.equal(JSON.parse(usable.stdout).ok, true);
  assert.equal(usable.status, 0);
});

// ---- Import --------------------------------------------------------------------------------------

test('names imported from an SBOM are taken as published, and the import limits hold', (t) => {
  const directory = workspace(t);
  const write = (name, value) => writeFileSync(join(directory, name), JSON.stringify(value));
  const system = (extra) => ({ systems: [{ id: 'api', name: 'API', updated_at: iso(NOW), ...extra }] });
  write('bom.json', {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    components: [{ type: 'library', name: 'MD5', purl: 'pkg:npm/MD5@1.3.0' }],
  });
  write('systems.json', system({ sbom: './bom.json' }));
  const imported = loadInventory(join(directory, 'systems.json'));
  assert.equal(imported.systems[0].components[0].name, 'MD5');
  assert.equal(imported.name_notices, undefined);
  // 20,000 SBOM components are accepted; one more is refused.
  const components = (count) =>
    Array.from({ length: count }, (_, index) => ({
      type: 'library',
      name: `p${index}`,
      purl: `pkg:npm/p${index}@1.0.0`,
    }));
  write('bom.json', { bomFormat: 'CycloneDX', specVersion: '1.5', components: components(20_001) });
  assert.throws(() => loadInventory(join(directory, 'systems.json')), /SBOM exceeds 20000 component entries/);
  // A lockfile with more than 20,000 entries is refused.
  const packages = { '': {} };
  for (let index = 0; index <= 20_000; index++) packages[`node_modules/p${index}`] = { version: '1.0.0' };
  write('package-lock.json', { lockfileVersion: 3, packages });
  write('systems.json', system({ lockfile: './package-lock.json' }));
  assert.throws(
    () => loadInventory(join(directory, 'systems.json')),
    /Lockfile exceeds 20000 package entries/,
  );
});
