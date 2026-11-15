// Regressions from the ninth review of delivery: the mention guard, a service on the SMTP port that
// is not SMTP, the fix line, SBOM entries listed twice, the heartbeat address in doctor, and
// version citations in name/version and "and later" notation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { notificationText, smtpTranscript } from '../dist/delivery.js';
import { loadInventory } from '../dist/inventory.js';
import { validateAnalysis } from '../dist/models.js';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const ZWSP = String.fromCharCode(0x200b);
const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const workspace = (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'sw-ninth-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
};
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
  urls: [],
  exploited: false,
  updated_at: iso(NOW),
  ...extra,
});
const message = (finding) =>
  notificationText({ id: 'job-1', payload: JSON.stringify({ assessment: finding, reason: 'Policy.' }) }).text;

test('package names and addresses keep their @; only group mentions are broken', () => {
  const text = message(
    assessment({
      summary:
        'express@4.21.2 in Web shop: affected. Mail ops@example.org; npm @angular/core. Ping @channel @here @everyone.',
    }),
  );
  assert.ok(text.includes('express@4.21.2'));
  assert.ok(text.includes('ops@example.org'));
  assert.ok(text.includes('@angular/core'));
  for (const word of ['channel', 'here', 'everyone']) {
    assert.ok(text.includes(`@${ZWSP}${word}`), word);
    assert.ok(!text.includes(`@${word}`), word);
  }
});

test('a service on the SMTP port that is not SMTP received nothing', () => {
  for (const greeting of [
    '* OK [CAPABILITY IMAP4rev1] Dovecot ready.',
    '+OK POP3 ready',
    'SSH-2.0-OpenSSH_9.6',
  ]) {
    const transcript = smtpTranscript();
    transcript.observe({ tnx: 'server' }, greeting);
    assert.equal(transcript.nothingHandedOver(), true, greeting);
  }
  // An SMTP greeting followed by nothing from the client still proves nothing about the client.
  const smtp = smtpTranscript();
  smtp.observe({ tnx: 'server' }, '220 mail.example ESMTP');
  smtp.observe({ tnx: 'server' }, '250 ok');
  assert.equal(smtp.nothingHandedOver(), false);
});

test('a fix line whose versions are all too long says so instead of showing nothing', () => {
  const long = `1.0.0-${'x'.repeat(130)}`;
  const line = message(assessment({ fix: `${long}; 2.0.0-${'y'.repeat(130)}` }))
    .split(String.fromCharCode(10))
    .find((item) => item.startsWith('Fix:'));
  assert.equal(line, 'Fix: 2 version(s) too long to show (run explain for all)');
});

test('a package listed twice without a reference of its own is one component', (t) => {
  const directory = workspace(t);
  writeFileSync(
    join(directory, 'bom.json'),
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        {
          type: 'library',
          name: 'a',
          purl: 'pkg:npm/a@1.0.0',
          components: [{ type: 'library', name: 'ms', purl: 'pkg:npm/ms@2.1.3' }],
        },
        {
          type: 'library',
          name: 'b',
          purl: 'pkg:npm/b@1.0.0',
          components: [{ type: 'library', name: 'ms', purl: 'pkg:npm/ms@2.1.3' }],
        },
      ],
    }),
  );
  writeFileSync(
    join(directory, 'systems.json'),
    JSON.stringify({ systems: [{ id: 'api', name: 'API', updated_at: iso(NOW), sbom: './bom.json' }] }),
  );
  const inventory = loadInventory(join(directory, 'systems.json'));
  assert.deepEqual(inventory.systems[0].components.map((component) => component.name).sort(), [
    'a',
    'b',
    'ms',
  ]);
  // A reference used twice is still a contradiction.
  writeFileSync(
    join(directory, 'bom.json'),
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        { type: 'library', name: 'ms', 'bom-ref': 'r1', purl: 'pkg:npm/ms@2.1.3' },
        { type: 'library', name: 'ms', 'bom-ref': 'r1', purl: 'pkg:npm/ms@2.1.3' },
      ],
    }),
  );
  assert.throws(() => loadInventory(join(directory, 'systems.json')), /Duplicate SBOM/);
});

test('doctor reports a heartbeat address the heartbeat would refuse', (t) => {
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
      'monitoring: { heartbeat_url_env: NINTH_HEARTBEAT }',
    ].join('\n'),
  );
  const doctor = (address) =>
    spawnSync(process.execPath, [cli, 'doctor', '--config', 'security-watch.yaml'], {
      cwd: directory,
      encoding: 'utf8',
      timeout: 15_000,
      env: { ...process.env, NINTH_HEARTBEAT: address },
    });
  for (const address of [
    'notaurl',
    'https://user:pw@hc-ping.example.com/abc',
    'http://hc-ping.example.com/abc',
  ]) {
    const result = doctor(address);
    const report = JSON.parse(result.stdout);
    assert.equal(report.ok, false, address);
    assert.match(report.problems.join(' '), /NINTH_HEARTBEAT: the external heartbeat address cannot be used/);
    assert.ok(!result.stdout.includes('user:pw'), 'the address is not printed');
    assert.equal(result.status, 2, address);
  }
  const usable = doctor('https://hc-ping.example.com/abc');
  assert.equal(JSON.parse(usable.stdout).ok, true);
});

const cites = (quote, version) => {
  const story = {
    id: 'feed:x:entry:9',
    source: 'feed:x',
    kind: 'news',
    title: 'Example server remote code execution',
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
          affected_products: ['Example server'],
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

test('name/version, "and later", abbreviations and letter releases are citations; more qualifiers are not', () => {
  for (const [text, version] of [
    ['Example server Apache/2.4.58 is affected.', '2.4.58'],
    ['Example server OpenSSL/3.0.7 is affected.', '3.0.7'],
    ['Example server 3.0+ are affected.', '3.0'],
    ['Example server v.2.4.1 is affected.', '2.4.1'],
    ['Example server ver.2.4.1 is affected.', '2.4.1'],
    ['Example server openssl-1.1.1w is affected.', '1.1.1w'],
  ])
    assert.equal(cites(text, version), true, `${version} in ${text}`);
  for (const [text, version] of [
    ['Example server HTTP/2 is affected.', '2'],
    ['Example server TLS/1.3 is affected.', '1.3'],
    ['Example server 2.4.1+build.5 is affected.', '2.4.1'],
    ['Example server 9.4.51.v20230217 is affected.', '9.4.51'],
    ['Example server 1.2.3.post1 is affected.', '1.2.3'],
    ['Example server 1.2.3.dev0 is affected.', '1.2.3'],
    ['Example server 2.4.1.preview is affected.', '2.4.1'],
  ])
    assert.equal(cites(text, version), false, `${version} in ${text}`);
});
