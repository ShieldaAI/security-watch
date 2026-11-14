// Follow-ups from the third review: exclusions under a partly read source, cited identifiers the
// service does not have, the request-time plain-HTTP check, the release options, bounded import
// warnings, the mail transcript, version ranges in citations and the published type names.
import test from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns';
import http from 'node:http';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig } from '../dist/config.js';
import { smtpTranscript } from '../dist/delivery.js';
import { runScan } from '../dist/engine.js';
import { safeHttp } from '../dist/http.js';
import { loadInventory } from '../dist/inventory.js';
import { validateAnalysis } from '../dist/models.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';
import { releaseEnvironment, releaseOptions, untrackedPackedFiles } from '../scripts/release-tag.mjs';

const HOUR = 3_600_000;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });

// ---- Exclusions while cve.now is incomplete ------------------------------------------------------

process.env.FOLLOWUP_HOOK = 'https://hooks.slack.com/services/T/B/x';
const scanConfig = parseConfig({
  version: 1,
  poll_interval_minutes: 30,
  sources: { cve_now: true, hacker_news: false, osv: false, github: false, kev: false },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'FOLLOWUP_HOOK' } },
});
const lodashInventory = (time) => ({
  systems: [
    {
      id: 'prod',
      name: 'Production',
      environment: 'production',
      exposure: 'internet',
      criticality: 'critical',
      updated_at: iso(time),
      products: [],
      keywords: [],
      components: [{ id: 'lodash', ecosystem: 'npm', name: 'lodash', version: '4.17.21' }],
    },
  ],
});
const lodashRecord = (id) =>
  json({
    id,
    status: 'published',
    title: 'lodash prototype pollution',
    originalDescription: 'Prototype pollution in lodash before 4.17.20.',
    severity: { cvss: 9.8 },
    affected: [{ ecosystem: 'npm', package: 'lodash', ranges: [{ introduced: '0', fixed: '4.17.20' }] }],
    publishedAt: iso(NOW - 2 * HOUR),
    modifiedAt: iso(NOW - 2 * HOUR),
  });
const cveNow = (listing, detail) => async (url) => {
  const { pathname } = new URL(url);
  if (pathname === '/stack') return json({ packages: 1, entries: [] });
  if (pathname === '/api/v1/entries') return json({ entries: listing });
  return detail(decodeURIComponent(pathname.split('/').pop()));
};
const lodashFinding = (store) => store.findings().find((finding) => finding.category !== 'health');
const first = [{ id: 'CVE-2026-50001', publishedAt: iso(NOW - 2 * HOUR), firstSeenAt: iso(NOW - 2 * HOUR) }];

test('an exclusion holds when cve.now is incomplete only because of an unrelated new record', async () => {
  const store = new Store(':memory:');
  await runScan({
    config: scanConfig,
    inventory: lodashInventory(NOW),
    store,
    now: NOW,
    http: cveNow(first, lodashRecord),
  });
  assert.equal(lodashFinding(store).applicability, 'not_affected');
  // A new record that has nothing to do with lodash is listed and cannot be used.
  const later = NOW + 30 * 60_000;
  const odd = [
    { id: 'CVE-2026-60001', publishedAt: iso(later - 600_000), firstSeenAt: iso(later - 300_000) },
  ];
  const report = await runScan({
    config: scanConfig,
    inventory: lodashInventory(later),
    store,
    now: later,
    http: cveNow(odd, (id) =>
      id === 'CVE-2026-60001' ? json({ id, status: 'reserved', title: id }) : lodashRecord(id),
    ),
  });
  const receipt = report.coverage.find((item) => item.source === 'cve_now');
  assert.equal(receipt.status, 'partial');
  assert.equal(receipt.package_results, 'complete');
  // The gap is still reported as a monitoring problem.
  assert.equal(report.degraded, true);
  assert.match(report.errors[0].message, /1 advisory detail request\(s\) failed/);
  // The lodash record itself was read again, so its ranges are current: no change, no alert.
  const finding = lodashFinding(store);
  assert.equal(finding.applicability, 'not_affected');
  assert.equal(store.history(finding.id).length, 1);
  assert.deepEqual(
    store.jobs().filter((job) => job.finding_id === finding.id),
    [],
  );
});

test('an exclusion does not hold when the record it rests on could not be read', async () => {
  const store = new Store(':memory:');
  await runScan({
    config: scanConfig,
    inventory: lodashInventory(NOW),
    store,
    now: NOW,
    http: cveNow(first, lodashRecord),
  });
  const later = NOW + 30 * 60_000;
  // An unrelated record keeps the source partial with evidence; the lodash record answers 503.
  const other = [
    { id: 'CVE-2026-60002', publishedAt: iso(later - 600_000), firstSeenAt: iso(later - 300_000) },
  ];
  const report = await runScan({
    config: scanConfig,
    inventory: lodashInventory(later),
    store,
    now: later,
    http: cveNow(other, (id) =>
      id === 'CVE-2026-50001'
        ? { status: 503, headers: {}, body: '' }
        : json({
            id,
            status: 'published',
            title: id,
            originalDescription: 'unrelated',
            publishedAt: iso(later - 600_000),
            modifiedAt: iso(later - 600_000),
          }),
    ),
  });
  const receipt = report.coverage.find((item) => item.source === 'cve_now');
  assert.notEqual(receipt.status, 'complete');
  assert.equal(receipt.package_results, undefined);
  assert.equal(lodashFinding(store).applicability, 'unknown');
});

// ---- Cited identifiers the service does not have ------------------------------------------------

test('a cited CVE that cve.now does not have is asked for once a day, not on every poll', async () => {
  const sources = {
    news_lookback_minutes: 40,
    poll_interval_minutes: 30,
    inventory_stale_days: 30,
    policy: {},
    sources: {
      cve_now: true,
      hacker_news: false,
      osv: false,
      github: false,
      github_token_env: 'FOLLOWUP_UNUSED',
      kev: false,
      feeds: [],
    },
  };
  const inventory = {
    systems: [
      {
        id: 'prod',
        name: 'prod',
        updated_at: iso(NOW),
        products: [],
        keywords: ['Acme router'],
        components: [],
      },
    ],
  };
  const stories = Array.from({ length: 30 }, (_, index) => ({
    id: `hacker_news:entry:${index}`,
    source: 'hacker_news',
    kind: 'news',
    title: `Acme router flaw ${index}`,
    url: 'https://example.com/x',
    description: `Acme router bug CVE-2025-${20000 + index}`,
    aliases: [`CVE-2025-${20000 + index}`],
    severity: 'unknown',
    modified_at: iso(NOW - 90 * 24 * HOUR),
    fetched_at: iso(NOW - 90 * 24 * HOUR),
    packages: [],
    content_status: 'full',
  }));
  let published = new Set();
  const asked = [];
  const service = async (url) => {
    const { pathname } = new URL(url);
    if (pathname === '/api/v1/entries') return json({ entries: [] });
    const id = decodeURIComponent(pathname.split('/').pop());
    asked.push(id);
    return published.has(id)
      ? json({
          id,
          status: 'published',
          title: id,
          originalDescription: 'Acme router flaw',
          publishedAt: iso(NOW - HOUR),
          modifiedAt: iso(NOW - HOUR),
        })
      : { status: 404, headers: {}, body: '' };
  };
  let checkpoints = { cve_now: iso(NOW - 30 * 60_000) };
  let stored = stories;
  const poll = async (now) => {
    asked.length = 0;
    const result = await collectSources(inventory, sources, checkpoints, service, now, stored);
    assert.deepEqual(result.errors, []);
    checkpoints = result.checkpoints;
    stored = [...stories, ...result.evidence];
    return asked.length;
  };
  assert.equal(await poll(NOW), 30, 'each is asked for once');
  assert.equal(JSON.parse(checkpoints['cve_now:missing']).length, 30);
  assert.equal(await poll(NOW + 30 * 60_000), 0);
  assert.equal(await poll(NOW + 23 * HOUR), 0);
  // A day later they are asked for again, and one of them now exists.
  published = new Set(['CVE-2025-20007']);
  assert.equal(await poll(NOW + 25 * HOUR), 30);
  assert.equal(JSON.parse(checkpoints['cve_now:missing']).length, 29);
  // A list that cannot be read only costs one more round of requests.
  checkpoints = { ...checkpoints, 'cve_now:missing': '{not json' };
  assert.equal(await poll(NOW + 26 * HOUR), 30, 'the 29 missing ones and the stored one');
});

// ---- Plain HTTP is checked again on the addresses a name resolves to -----------------------------

test('a plain-HTTP request to a name is refused when the name resolves to a public address', async (t) => {
  const real = dns.lookup;
  let answer = ['127.0.0.1'];
  dns.lookup = (_host, _options, callback) =>
    callback(
      null,
      answer.map((address) => ({ address, family: address.includes(':') ? 6 : 4 })),
    );
  syncBuiltinESMExports();
  let hits = 0;
  const server = http.createServer((_request, response) => {
    hits++;
    response.end('ok');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    dns.lookup = real;
    syncBuiltinESMExports();
    server.close();
  });
  const url = `http://gpu.internal:${server.address().port}/`;
  const request = (addresses) => {
    answer = addresses;
    return safeHttp(url, { timeoutMs: 2000, allowPrivate: true });
  };
  assert.equal((await request(['127.0.0.1'])).status, 200);
  assert.equal(hits, 1);
  for (const addresses of [['8.8.8.8'], ['127.0.0.1', '8.8.8.8'], ['64:ff9b::808:808']]) {
    await assert.rejects(request(addresses), JSON.stringify(addresses));
    assert.equal(hits, 1, `nothing is sent for ${JSON.stringify(addresses)}`);
  }
});

// ---- Release options ------------------------------------------------------------------------------

test('the release command passes on only a rehearsal flag and a one-time code', () => {
  assert.deepEqual(releaseOptions([]), []);
  assert.deepEqual(releaseOptions(['--dry-run', '--otp=123456']), ['--dry-run', '--otp=123456']);
  for (const option of [
    '--ignore-scripts',
    '--tag',
    '--tag=latest',
    'latest',
    '--registry=https://example.com',
    '--otp',
    '--otp=abc',
    '--force',
  ])
    assert.throws(() => releaseOptions([option]), /accepts only --dry-run and --otp=CODE/, option);
});

test('the release environment states the tag and inherits no tag setting', () => {
  const env = releaseEnvironment({ npm_config_tag: 'latest', NPM_CONFIG_TAG: 'beta', PATH: '/bin' }, 'next');
  assert.deepEqual(env, { PATH: '/bin', SECURITY_WATCH_RELEASE_TAG: 'next' });
});

test('a packed file that is not in git is found, apart from the build output', () => {
  const tracked = ['package.json', 'README.md', 'docs/configuration.md', 'examples/systems.yaml'];
  assert.deepEqual(
    untrackedPackedFiles(['package.json', 'dist/index.js', 'docs/configuration.md', 'README.md'], tracked),
    [],
  );
  assert.deepEqual(
    untrackedPackedFiles(['dist/cli.js', 'docs/local-notes.txt', 'examples/notes.db', 'README.md'], tracked),
    ['docs/local-notes.txt', 'examples/notes.db'],
  );
});

// ---- Import warnings are bounded and single-line -------------------------------------------------

test('a broken import yields a bounded number of single-line warnings', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'sw-warnings-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const components = Array.from({ length: 1500 }, (_, index) => ({
    type: 'library',
    name: `bad-${index}`,
    // A line break inside the package URL, percent-encoded so that the document itself is valid.
    purl: `pkg:npm/x%0ARule:%20forged%20${index}@not a version`,
  }));
  writeFileSync(
    join(directory, 'bom.json'),
    JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components }),
  );
  writeFileSync(
    join(directory, 'systems.json'),
    JSON.stringify({ systems: [{ id: 'api', name: 'API', updated_at: iso(NOW), sbom: './bom.json' }] }),
  );
  const inventory = loadInventory(join(directory, 'systems.json'));
  assert.equal(inventory.import_warnings.length, 201);
  assert.equal(inventory.import_warnings.at(-1), '1300 more import warning(s) are not shown.');
  const lineBreak = (code) =>
    code <= 0x1f || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029;
  for (const warning of inventory.import_warnings) {
    assert.ok(warning.length <= 400);
    assert.ok(![...warning].some((character) => lineBreak(character.charCodeAt(0))), JSON.stringify(warning));
  }
});

// ---- The mail transcript --------------------------------------------------------------------------

test('the mail transcript proves nothing was handed over only when it can be relied on', () => {
  const session = (...lines) => {
    const transcript = smtpTranscript();
    for (const [entry, line] of lines) transcript.observe(entry, line);
    return transcript;
  };
  const client = { tnx: 'client' };
  const server = { tnx: 'server' };
  // Nothing logged at all: the log is not working, so nothing is assumed.
  assert.equal(session().nothingHandedOver(), false);
  // The session ended before the server said anything: there was nothing to write.
  assert.equal(session([{ tnx: 'network' }, 'Connection failed']).nothingHandedOver(), true);
  assert.equal(session([{}, 'TLS handshake failed']).nothingHandedOver(), true);
  // The server spoke and the client is seen answering, without starting an envelope.
  assert.equal(
    session([server, '220 mail.example ESMTP'], [client, 'EHLO monitor.example']).nothingHandedOver(),
    true,
  );
  // Server replies without a single client command: the log does not report what the client writes.
  assert.equal(
    session(
      [server, '220 mail.example ESMTP'],
      [server, '250 ok'],
      ['text', 'MAIL FROM:<a@example.com>'],
    ).nothingHandedOver(),
    false,
  );
  for (const command of ['MAIL FROM:<a@example.com>', 'RCPT TO:<b@example.com>', 'DATA', 'BDAT 12 LAST']) {
    const started = session([server, '220 ok'], [client, 'EHLO monitor.example'], [client, command]);
    assert.equal(started.envelopeStarted(), true, command);
    assert.equal(started.nothingHandedOver(), false, command);
  }
  // A server line that mentions MAIL is not the client writing it.
  assert.equal(session([client, 'EHLO x'], [server, '250 MAIL ok']).envelopeStarted(), false);
});

// ---- Version ranges in citations ------------------------------------------------------------------

test('either end of a hyphenated version range is a citation; a number joined to an identifier is not', () => {
  const at = iso(NOW);
  const check = (quote, versions) => {
    const story = {
      id: 'feed:x:entry:9',
      source: 'feed:x',
      kind: 'news',
      title: 'Example Database remote code execution',
      url: 'https://example.com/s',
      description: quote,
      aliases: [],
      severity: 'unknown',
      modified_at: at,
      fetched_at: at,
      packages: [],
      content_status: 'full',
    };
    return () =>
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
            affected_versions: versions,
            prerequisites: [],
            rationale: 'Version 4.7 is later than the fixed release.',
            quotes: [{ evidence_id: story.id, quote }],
          },
        },
        [story],
      );
  };
  const range = 'Example Database versions 2.0-2.4 and 1.0.0-1.2.3 are affected by CVE-2026-40001.';
  for (const versions of [['2.0'], ['2.4'], ['1.0.0'], ['1.2.3'], ['2.0', '2.4']])
    assert.doesNotThrow(check(range, versions), JSON.stringify(versions));
  for (const versions of [['2'], ['0'], ['4'], ['2026'], ['40001'], ['1.2'], ['0.0']])
    assert.throws(check(range, versions), /MODEL_UNSUPPORTED_NEWS_CLAIM/, JSON.stringify(versions));
  // A package revision is one identifier, not a range.
  const revision = 'Example Database 1.0.0-1 is affected; 3.1-beta is not.';
  assert.throws(check(revision, ['1']), /MODEL_UNSUPPORTED_NEWS_CLAIM/);
  assert.throws(check(revision, ['1.0.0']), /MODEL_UNSUPPORTED_NEWS_CLAIM/);
  assert.doesNotThrow(check(revision, ['3.1']));
});

// ---- Verification model identity ------------------------------------------------------------------

test('a verification model spelled differently at the same address is still the same model', () => {
  const pair = (analysis, verification) => () =>
    parseConfig({ version: 1, models: { enabled: true, analysis, verification } });
  const openai = { provider: 'openai', model: 'gpt-x' };
  for (const verification of [
    { ...openai, endpoint: 'https://api.openai.com./v1/responses' },
    { ...openai, endpoint: 'https://api.openai.com//v1/responses' },
    { ...openai, endpoint: 'https://api.openai.com/v1/response%73' },
    { ...openai, endpoint: 'https://api.openai.com/v1/Responses' },
    { ...openai, endpoint: 'https://api.openai.com:443/v1/responses/' },
  ])
    assert.throws(
      pair(openai, verification),
      /must differ from the analysis model/,
      JSON.stringify(verification),
    );
  assert.doesNotThrow(pair(openai, { provider: 'openai', model: 'gpt-y' }));
});

// ---- Published type names --------------------------------------------------------------------------

test('the exported type names match the committed list', () => {
  const declaration = readFileSync(new URL('../dist/index.d.ts', import.meta.url), 'utf8');
  const names = [...declaration.matchAll(/export type \{([^}]*)\}/g)]
    .flatMap((match) => match[1].split(','))
    .map((name) => name.trim())
    .filter(Boolean)
    .sort();
  // Removing or renaming a type breaks a TypeScript consumer just as a removed function does:
  // update scripts/public-types.json, CHANGELOG.md and docs/compatibility.md together.
  assert.deepEqual(
    names,
    JSON.parse(readFileSync(new URL('../scripts/public-types.json', import.meta.url), 'utf8')),
  );
});
