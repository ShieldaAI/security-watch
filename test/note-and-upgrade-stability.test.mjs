// Two things that must not create a new revision, review, model request or alert:
// editing a note or owner in the inventory, and upgrading from an earlier release.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig } from '../dist/config.js';
import { assess, decide } from '../dist/assessment.js';
import { deliverPending } from '../dist/delivery.js';
import { runScan } from '../dist/engine.js';
import { Store, SCHEMA_VERSION } from '../dist/store.js';

const now = Date.parse('2026-10-24T12:00:00Z');
const at = new Date(now).toISOString();
const credentials = { STABLE_HOOK: 'https://hooks.slack.com/services/T/B/X' };

const modelConfig = parseConfig({
  version: 1,
  digest_interval_hours: 1,
  sources: { cve_now: false, hacker_news: false, osv: false, github: false, kev: false },
  models: {
    enabled: true,
    analysis: {
      provider: 'openai-compatible',
      model: 'test-model',
      api_key_env: 'STABLE_UNUSED_KEY',
      endpoint: 'http://127.0.0.1:1234',
      allow_private_endpoint: true,
    },
  },
  policy: { news: { levels: ['high', 'critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'STABLE_HOOK' } },
});
const productInventory = ({ note, productNote, owner }) => ({
  systems: [
    {
      id: 'prod',
      name: 'Production',
      ...(note ? { note } : {}),
      ...(owner ? { owner } : {}),
      environment: 'production',
      exposure: 'internal',
      criticality: 'high',
      updated_at: at,
      components: [],
      products: [
        {
          name: 'Example Database',
          version: '4.2',
          keywords: [],
          ...(productNote ? { note: productNote } : {}),
        },
      ],
      keywords: [],
    },
  ],
});
const story = (description) => ({
  id: 'feed:example',
  source: 'feed:test',
  kind: 'news',
  title: 'Example Database community news',
  url: 'https://example.com/story',
  description,
  aliases: [],
  severity: 'unknown',
  modified_at: at,
  fetched_at: at,
  packages: [],
  content_status: 'full',
});
/** A model endpoint and Slack in one stub; counts what each received. */
function services(analysis) {
  const seen = { model: [], slack: [] };
  const http = async (url, request) => {
    if (url.startsWith('https://hooks.slack.com')) {
      seen.slack.push(JSON.parse(request.body).text);
      return { status: 200, headers: {}, body: 'ok' };
    }
    seen.model.push(request.body);
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(analysis) } }],
      }),
    };
  };
  return { seen, http };
}
const snapshot = (store, seen) => {
  const finding = store.findings().find((item) => item.category === 'news');
  return {
    revisions: store.history(finding.id).length,
    jobs: store
      .jobs()
      .map((job) => [job.revision, job.status])
      .sort(),
    reviews: store.reviews({ includeResolved: true }).map((review) => [review.revision, review.status]),
    modelRequests: seen.model.length,
    slackMessages: seen.slack.length,
  };
};

test('editing notes or the owner creates no revision, review, model request or digest for a reviewed dismissal', async () => {
  const quote = 'Example Database announces a new community conference with no security fixes.';
  const evidence = story(quote);
  const { seen, http } = services({
    relevance: 'irrelevant',
    priority: 'low',
    summary: 'General conference coverage without a vulnerability.',
    evidence_ids: [evidence.id],
    quotes: [{ evidence_id: evidence.id, quote }],
    news_analysis: {
      classification: 'general_news',
      impact: 'not_applicable',
      affected_products: [],
      affected_versions: [],
      prerequisites: [],
      rationale: 'conference',
      quotes: [{ evidence_id: evidence.id, quote }],
    },
  });
  const store = new Store(':memory:');
  store.saveEvidence([evidence], {});
  await runScan({ config: modelConfig, inventory: productInventory({ note: 'rack A' }), store, http, now });
  await deliverPending(store, modelConfig, http, { now: now + 3_600_000, credentials });
  const finding = store.findings().find((item) => item.category === 'news');
  store.reviewFinding(
    finding.id,
    store.reviews()[0].revision,
    { disposition: 'dismiss', reviewer: 'op', reason: 'checked' },
    now + 1000,
  );
  const settled = snapshot(store, seen);
  assert.equal(settled.slackMessages, 1);
  assert.deepEqual(
    settled.reviews.map(([, status]) => status),
    ['dismissed'],
  );
  for (const [step, edit] of [
    { note: 'rack B (moved)' },
    { note: 'rack B (moved)', productNote: 'primary cluster' },
    { note: 'rack B (moved)', productNote: 'replica cluster', owner: 'Database team' },
    {},
  ].entries()) {
    await runScan({
      config: modelConfig,
      inventory: productInventory(edit),
      store,
      http,
      now: now + 2000 + step * 1000,
    });
    await deliverPending(store, modelConfig, http, { now: now + (step + 2) * 3_600_000, credentials });
    assert.deepEqual(snapshot(store, seen), settled, JSON.stringify(edit));
  }
  assert.ok(
    !seen.model.some((body) => /rack|cluster|Database team/.test(body)),
    'notes never reach the model',
  );
  // The stored finding still shows the latest note to whoever opens it.
  await runScan({
    config: modelConfig,
    inventory: productInventory({ note: 'rack C' }),
    store,
    http,
    now: now + 9000,
  });
  assert.equal(store.getFinding(finding.id).location.system_note, 'rack C');
});

test('editing a product note does not send a second immediate alert for an affected finding', async () => {
  const quote = 'Example Database version 4.2 is affected by the newly disclosed vulnerability.';
  const evidence = story(quote);
  const { seen, http } = services({
    relevance: 'relevant',
    priority: 'high',
    summary: 'Installed database version is reported affected.',
    evidence_ids: [evidence.id],
    quotes: [{ evidence_id: evidence.id, quote }],
    news_analysis: {
      classification: 'new_vulnerability',
      impact: 'affected',
      affected_products: ['Example Database'],
      affected_versions: ['4.2'],
      prerequisites: [],
      rationale: 'r',
      quotes: [{ evidence_id: evidence.id, quote }],
    },
  });
  const store = new Store(':memory:');
  store.saveEvidence([evidence], {});
  await runScan({
    config: modelConfig,
    inventory: productInventory({ productNote: 'db team, cluster A' }),
    store,
    http,
    now,
  });
  await deliverPending(store, modelConfig, http, { now, credentials });
  const settled = snapshot(store, seen);
  assert.equal(settled.slackMessages, 1);
  await runScan({
    config: modelConfig,
    inventory: productInventory({ productNote: 'db team, cluster B' }),
    store,
    http,
    now: now + 2000,
  });
  await deliverPending(store, modelConfig, http, { now: now + 3000, credentials });
  assert.deepEqual(snapshot(store, seen), settled);
});

test('a change the model does see still starts a new analysis', async () => {
  const quote = 'Example Database announces a new community conference with no security fixes.';
  const evidence = story(quote);
  const { seen, http } = services({
    relevance: 'irrelevant',
    priority: 'low',
    summary: 'General conference coverage without a vulnerability.',
    evidence_ids: [evidence.id],
    quotes: [{ evidence_id: evidence.id, quote }],
    news_analysis: {
      classification: 'general_news',
      impact: 'not_applicable',
      affected_products: [],
      affected_versions: [],
      prerequisites: [],
      rationale: 'conference',
      quotes: [{ evidence_id: evidence.id, quote }],
    },
  });
  const store = new Store(':memory:');
  store.saveEvidence([evidence], {});
  await runScan({ config: modelConfig, inventory: productInventory({}), store, http, now });
  assert.equal(seen.model.length, 1);
  const upgraded = productInventory({});
  upgraded.systems[0].products[0].version = '4.3';
  await runScan({ config: modelConfig, inventory: upgraded, store, http, now: now + 1000 });
  assert.equal(seen.model.length, 2);
});

// ---- Upgrade from 0.1.0-alpha.0 -------------------------------------------------------------

const libraryConfig = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'STABLE_HOOK' } },
});
const shop = {
  systems: [
    {
      id: 'shop',
      name: 'Web shop',
      environment: 'production',
      exposure: 'internet',
      criticality: 'high',
      updated_at: at,
      components: [
        { id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' },
        { id: 'beta', ecosystem: 'npm', name: 'beta', version: '1.0.0' },
      ],
      products: [],
      keywords: [],
    },
  ],
};
const advisory = (id, name) => ({
  id,
  source: 'fixture',
  kind: 'advisory',
  title: `${name} remote code execution`,
  url: `https://example.com/${id}`,
  description: `${name} before 2.0.0`,
  aliases: [],
  severity: 'critical',
  modified_at: at,
  fetched_at: at,
  packages: [{ ecosystem: 'npm', name, range: '<2.0.0', fixed: '2.0.0' }],
});
const fixture = [advisory('CVE-2026-40001', 'alpha'), advisory('CVE-2026-40002', 'beta')];
const sha = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
/** The fingerprint 0.1.0-alpha.0 stored: these fields, in this order. */
const alphaFingerprint = (a, action) =>
  sha({
    event: a.event_id,
    system: a.system_id,
    component: a.component_id,
    category: a.category,
    applicability: a.applicability,
    severity: a.source_severity,
    priority: a.priority,
    exploited: a.exploited,
    withdrawn: a.withdrawn ?? false,
    active: a.active !== false,
    fix: a.fix ?? null,
    action,
  });
/** The tables 0.1.0-alpha.0 created (schema 4), with two delivered findings, one acknowledged. */
function alphaDatabase(path, findings) {
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE evidence (source TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(source,id));
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE findings (id TEXT PRIMARY KEY, payload TEXT NOT NULL, fingerprint TEXT NOT NULL, revision INTEGER NOT NULL,
      acknowledged_revision INTEGER, suppressed_until INTEGER, suppression_reason TEXT);
    CREATE TABLE notifications (id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id), revision INTEGER NOT NULL,
      channel TEXT NOT NULL CHECK(channel IN ('slack','email')), payload TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending','sending','accepted','unknown','failed')),
      attempts INTEGER NOT NULL DEFAULT 0, available_at INTEGER NOT NULL, last_error TEXT,
      UNIQUE(finding_id,revision,channel));
    CREATE INDEX notifications_due ON notifications(status,available_at);
    CREATE TABLE budgets (day TEXT PRIMARY KEY, requests INTEGER NOT NULL, tokens INTEGER NOT NULL, usd REAL NOT NULL);
    CREATE TABLE finding_revisions (finding_id TEXT NOT NULL REFERENCES findings(id), revision INTEGER NOT NULL,
      payload TEXT NOT NULL, decision TEXT NOT NULL, recorded_at INTEGER NOT NULL, PRIMARY KEY(finding_id,revision));
    CREATE TABLE evidence_revisions (source TEXT NOT NULL, id TEXT NOT NULL, content_hash TEXT NOT NULL,
      payload TEXT NOT NULL, recorded_at INTEGER NOT NULL, PRIMARY KEY(source,id,content_hash));
    CREATE INDEX evidence_by_id ON evidence(id);
    PRAGMA user_version = 4;`);
  for (const [index, finding] of findings.entries()) {
    const decision = decide(finding, libraryConfig);
    const payload = JSON.stringify(finding);
    db.prepare(
      'INSERT INTO findings(id,payload,fingerprint,revision,acknowledged_revision) VALUES(?,?,?,1,?)',
    ).run(finding.id, payload, alphaFingerprint(finding, decision.action), index === 0 ? 1 : null);
    db.prepare(
      'INSERT INTO finding_revisions(finding_id,revision,payload,decision,recorded_at) VALUES(?,1,?,?,?)',
    ).run(finding.id, payload, JSON.stringify(decision), now);
    db.prepare(
      "INSERT INTO notifications(id,finding_id,revision,channel,payload,status,attempts,available_at) VALUES(?,?,1,'slack',?,'accepted',1,?)",
    ).run(
      `job-${index}`,
      finding.id,
      JSON.stringify({ assessment: finding, reason: decision.reason, mode: decision.action }),
      now,
    );
  }
  db.close();
  chmodSync(path, 0o600);
}

test('upgrading a 0.1.0-alpha.0 database keeps revisions, alerts and acknowledgements of unchanged findings', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'security-watch-upgrade-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'watch.db');
  // What the alpha stored: the plain assessment, with none of the fields added since.
  const findings = assess(shop, fixture, libraryConfig, now);
  assert.equal(findings.length, 2);
  assert.ok(findings.every((finding) => finding.applicability === 'affected'));
  alphaDatabase(path, findings);

  const store = new Store(path);
  t.after(() => store.close());
  assert.equal(SCHEMA_VERSION, 7);
  const report = await runScan({
    config: libraryConfig,
    inventory: shop,
    store,
    fixture,
    now: now + 120_000,
  });
  const current = report.findings.filter((finding) => finding.category !== 'health');
  assert.deepEqual(current.map((finding) => finding.id).sort(), findings.map((finding) => finding.id).sort());
  // The new release does add fields to the stored finding; they are not a new security event.
  assert.ok(
    findings.every((finding) => {
      const saved = store.getFinding(finding.id);
      return saved.remediation && saved.location;
    }),
  );
  for (const finding of findings) assert.equal(store.history(finding.id).length, 1, 'no new revision');
  assert.deepEqual(
    store
      .jobs()
      .map((job) => [job.id, job.revision, job.status])
      .sort(),
    [
      ['job-0', 1, 'accepted'],
      ['job-1', 1, 'accepted'],
    ],
    'no new delivery job',
  );
  const controls = store.controls(findings[0].id);
  assert.equal(controls.acknowledged, true, 'the acknowledgement survives');
  assert.equal(controls.revision, 1);

  // A second scan, now comparing against fingerprints in the current format, is equally quiet.
  await runScan({ config: libraryConfig, inventory: shop, store, fixture, now: now + 240_000 });
  for (const finding of findings) assert.equal(store.history(finding.id).length, 1);
  assert.equal(store.jobs().length, 2);

  // A real change after the upgrade is still a new revision with its own alert.
  const exploited = fixture.map((item) =>
    item.id === 'CVE-2026-40002' ? { ...item, exploited: true } : item,
  );
  await runScan({ config: libraryConfig, inventory: shop, store, fixture: exploited, now: now + 360_000 });
  const changed = findings.find((finding) => finding.event_id === 'CVE-2026-40002');
  assert.equal(store.history(changed.id).length, 2);
  assert.ok(
    store
      .jobs()
      .some((job) => job.finding_id === changed.id && job.revision === 2 && job.status === 'pending'),
  );
});
