import test from 'node:test';
import { removeAcceptanceSchema } from './helpers/legacy-notifications.mjs';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { Store, parseConfig, decide, verifyBackup, runScan } from '../dist/index.js';

const NOW = Date.parse('2026-11-04T12:00:00Z');
const at = new Date(NOW).toISOString();
const source = {
  id: 'feed:alpha',
  source: 'fixture',
  kind: 'news',
  content_status: 'full',
  title: 'Alpha conference',
  description: 'Alpha 1.0.0 conference announcement has no security fixes.',
  aliases: [],
  packages: [],
  severity: 'low',
  url: 'https://example.com/story',
  modified_at: at,
  fetched_at: at,
};
const news = (classification = 'general_news', impact = 'not_applicable') => ({
  classification,
  impact,
  affected_products: [],
  affected_versions: [],
  prerequisites: [],
  rationale: 'The source describes a conference.',
  quotes: [{ evidence_id: source.id, quote: source.description }],
});
const finding = (extra = {}) => ({
  id: 'finding',
  event_id: source.id,
  system_id: 'prod',
  component_id: 'alpha',
  category: 'news',
  news_only: true,
  news_candidate: true,
  applicability: 'relevant',
  source_severity: 'low',
  priority: 'low',
  title: source.title,
  summary: 'General coverage of Alpha.',
  reasons: [],
  evidence_ids: [source.id],
  urls: [source.url],
  exploited: false,
  updated_at: at,
  ai: { status: 'complete', model: 'synthetic', provider: 'openai', prompt_version: 'test' },
  news_analysis: news(),
  ...extra,
});
const config = (policy = {}) => parseConfig({ version: 1, policy });
function memory(t) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  store.saveEvidence([source], {});
  return store;
}
function directory(t) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-ai-review-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
const verdict = (disposition = 'dismiss') => ({
  disposition,
  reviewer: 'local-operator',
  reason: 'Inspected the source and installed version.',
});

test('both AI quiet paths require durable review by default even without a notification route', () => {
  for (const analysis of [news(), news('known_vulnerability_update', 'not_affected')]) {
    const result = decide(finding({ news_analysis: analysis }), config());
    assert.equal(result.action, 'digest');
    assert.deepEqual(result.channels, []);
    assert.equal(result.review, analysis.impact === 'not_affected' ? 'ai_not_affected' : 'ai_general_news');
  }
  assert.equal(
    decide(
      finding({ news_only: false, news_candidate: false, news_analysis: undefined, relevance: 'irrelevant' }),
      config(),
    ).review,
    'ai_irrelevant',
  );
});

test('policy migration is explicit, safe by default and rejects contradictory settings', () => {
  assert.equal(config().policy.ai_dismissals, 'review');
  for (const [legacy, current] of [
    [true, 'review'],
    [false, 'record'],
  ]) {
    const cfg = config({ review_before_news_suppression: legacy });
    assert.equal(cfg.policy.ai_dismissals, current);
    assert.equal(cfg.policy.review_before_news_suppression, undefined);
    assert.equal(Boolean(decide(finding(), cfg).review), legacy);
    assert.throws(() =>
      config({
        review_before_news_suppression: legacy,
        ai_dismissals: current === 'review' ? 'record' : 'review',
      }),
    );
  }
  for (const invalid of [true, null, 'Review', 'ignore'])
    assert.throws(() => config({ ai_dismissals: invalid }));
});

test('authoritative exclusions, inactive/withdrawn findings and urgency override AI dismissals', () => {
  const cfg = parseConfig({
    version: 1,
    policy: { news: { channels: ['slack'], levels: ['high', 'critical'] } },
    notifications: { slack: { webhook_url_env: 'SYNTHETIC_WEBHOOK' } },
  });
  for (const extra of [{ applicability: 'not_affected' }, { withdrawn: true }, { active: false }]) {
    const decision = decide(finding(extra), cfg);
    assert.equal(decision.action, 'record');
    assert.equal(decision.review, undefined);
  }
  for (const extra of [{ source_severity: 'critical' }, { exploited: true }]) {
    const decision = decide(finding(extra), cfg);
    assert.equal(decision.action, 'notify');
    assert.equal(decision.review, undefined);
  }
  for (const status of ['unavailable', 'conflicting'])
    assert.equal(decide(finding({ ai: { ...finding().ai, status } }), cfg).review, undefined);
});

test('local review survives restart and closes only the exact current finding revision', (t) => {
  const path = join(directory(t), 'watch.db');
  let store = new Store(path);
  store.saveEvidence([source], {});
  const a = finding();
  store.saveAssessment(a, decide(a, config()), NOW);
  assert.equal(store.jobs().length, 0);
  const first = store.reviews()[0];
  assert.equal(first.revision, 1);
  assert.equal(first.evidence[0].id, source.id);
  store.close();
  store = new Store(path);
  t.after(() => store.close());
  store.reviewFinding(a.id, first.revision, verdict(), NOW + 1);
  assert.equal(store.reviews().length, 0);
  assert.equal(store.reviews({ includeResolved: true })[0].reviewer, 'local-operator');
  store.saveAssessment(
    { ...a, updated_at: new Date(NOW + 1000).toISOString() },
    decide(a, config()),
    NOW + 1000,
  );
  assert.equal(store.reviews().length, 0);
  assert.equal(store.controls(a.id).revision, 1);
  store.saveEvidence(
    [
      {
        ...source,
        description: 'New evidence names the same Alpha conference with a security correction.',
        modified_at: new Date(NOW + 2000).toISOString(),
      },
    ],
    {},
  );
  store.saveAssessment(a, decide(a, config()), NOW + 2000);
  assert.equal(store.reviews()[0].revision, 2);
  assert.equal(store.controls(a.id).acknowledged, false);
  assert.throws(() => store.reviewFinding(a.id, 1, verdict(), NOW + 2001), /stale/);
  assert.equal(store.reviews()[0].status, 'pending');
});

test('inventory/model basis changes reopen reviews while scan timestamps and source refreshes do not', (t) => {
  const store = memory(t),
    a = finding(),
    d = decide(a, config());
  store.saveAssessment(a, d, NOW, 0, 'inventory-v1');
  store.reviewFinding(a.id, 1, verdict(), NOW + 1);
  store.saveEvidence([{ ...source, fetched_at: new Date(NOW + 1000).toISOString() }], {});
  store.saveAssessment(
    { ...a, updated_at: new Date(NOW + 1000).toISOString() },
    d,
    NOW + 1000,
    0,
    'inventory-v1',
  );
  assert.equal(store.reviews().length, 0);
  store.saveAssessment(a, d, NOW + 2000, 0, 'inventory-v2');
  assert.equal(store.reviews()[0].revision, 2);
});

test('review dismissal cancels pending digest only, a new review revision can notify again', (t) => {
  const store = memory(t),
    a = finding(),
    d = { ...decide(a, config()), channels: ['slack'] };
  store.saveAssessment(a, d, NOW, 0);
  store.reviewFinding(a.id, 1, verdict(), NOW + 1);
  assert.equal(store.claimDue(NOW + 2), undefined);
  store.saveAssessment(
    { ...a, news_analysis: news('known_vulnerability_update', 'not_affected') },
    { ...d, review: 'ai_not_affected' },
    NOW + 3,
    0,
  );
  assert.equal(store.claimDue(NOW + 4).finding_id, a.id);
});

test('investigate stays actionable and superseded policy or source state cannot retain a pending review', (t) => {
  const store = memory(t),
    a = finding();
  store.saveAssessment(a, decide(a, config()), NOW);
  store.reviewFinding(a.id, 1, verdict('investigate'), NOW + 1);
  assert.equal(store.reviews()[0].status, 'investigate');
  assert.equal(store.reviewSummary(NOW + 100).oldest_open_age_ms, 100);
  for (const next of [finding({ active: false }), finding({ withdrawn: true }), finding()]) {
    store.saveAssessment(next, decide(next, config({ ai_dismissals: 'record' })), NOW + 2);
    assert.equal(store.reviews().length, 0);
    assert.throws(() => store.reviewFinding(a.id, 1, verdict(), NOW + 3), /stale/);
  }
});

test('concurrent store handles cannot apply a stale verdict after a scan updates the review', (t) => {
  const path = join(directory(t), 'watch.db'),
    worker = new Store(path),
    operator = new Store(path);
  t.after(() => {
    operator.close();
    worker.close();
  });
  const a = finding(),
    d = decide(a, config());
  worker.saveAssessment(a, d, NOW);
  const listed = operator.reviews()[0];
  worker.saveAssessment({ ...a, priority: 'high' }, d, NOW + 1);
  assert.throws(() => operator.reviewFinding(a.id, listed.revision, verdict(), NOW + 2), /stale/);
  assert.equal(worker.reviews()[0].status, 'pending');
});

test('review history, source evidence and pending work survive retention and backup restore', async (t) => {
  const dir = directory(t),
    path = join(dir, 'watch.db'),
    store = new Store(path);
  t.after(() => store.close());
  store.saveEvidence([source], {});
  const a = finding();
  store.saveAssessment(a, decide(a, config()), NOW);
  store.saveAssessment({ ...a, active: false }, decide({ ...a, active: false }, config()), NOW + 1);
  store.prune(
    {
      finding_history_days: 1,
      evidence_history_days: 1,
      inactive_findings_days: 1,
      unreferenced_evidence_days: 1,
    },
    NOW + 100 * 86400000,
    true,
  );
  assert.equal(store.reviews({ includeResolved: true }).length, 1);
  assert.equal(store.evidence().length, 1);
  const backup = join(dir, 'backup.db');
  await store.backup(backup);
  const result = await verifyBackup(backup);
  assert.equal(result.verified_schema_version, 7);
});

test('schema 5 migration adds an empty queue and the next assessment enrolls existing dismissals', (t) => {
  const path = join(directory(t), 'watch.db');
  const old = new Store(path);
  const a = finding();
  old.saveAssessment(a, decide(a, config({ ai_dismissals: 'record' })), NOW);
  old.close();
  const db = new DatabaseSync(path);
  removeAcceptanceSchema(db);
  db.exec('DROP TABLE ai_reviews; PRAGMA user_version=5;');
  db.close();
  const store = new Store(path);
  t.after(() => store.close());
  assert.equal(store.reviews().length, 0);
  store.saveAssessment(a, decide(a, config()), NOW + 1);
  assert.equal(store.reviews().length, 1);
});

test('CLI reviews are paged and adjudication is local with required revision and attribution', (t) => {
  const dir = directory(t),
    path = join(dir, 'watch.db');
  const store = new Store(path);
  for (const id of ['one', 'two']) {
    const a = finding({ id });
    store.saveAssessment(a, decide(a, config()), NOW);
  }
  store.close();
  writeFileSync(join(dir, 'security-watch.yaml'), JSON.stringify({ version: 1, database: path }));
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { cwd: dir, encoding: 'utf8' });
  const first = run('reviews', '--limit', '1');
  assert.equal(first.status, 0, first.stderr);
  const page = JSON.parse(first.stdout);
  assert.equal(page.reviews.length, 1);
  assert(page.next_cursor);
  const second = run('reviews', '--limit', '1', '--after', page.next_cursor);
  assert.equal(second.status, 0, second.stderr);
  assert.notEqual(JSON.parse(second.stdout).reviews[0].finding_id, page.reviews[0].finding_id);
  assert.notEqual(run('review', 'one', '--disposition', 'dismiss').status, 0);
  const done = run(
    'review',
    'one',
    '--revision',
    '1',
    '--disposition',
    'dismiss',
    '--reviewer',
    'test-operator',
    '--reason',
    'Source checked',
  );
  assert.equal(done.status, 0, done.stderr);
  assert.equal(JSON.parse(done.stdout).delivery_sent, false);
  assert.equal(JSON.parse(run('status').stdout).reviews.pending, 1);
  assert.notEqual(
    run(
      'review',
      'one',
      '--revision',
      '1',
      '--disposition',
      'dismiss',
      '--reviewer',
      'test-operator',
      '--reason',
      'Replay',
    ).status,
    0,
  );
});

test('evidence arriving between review and final reassessment invalidates a local verdict immediately', (t) => {
  const store = memory(t),
    a = finding();
  store.saveAssessment(a, decide(a, config()), NOW);
  store.saveEvidence(
    [
      {
        ...source,
        description: 'An urgent correction changes the article.',
        modified_at: new Date(NOW + 1000).toISOString(),
      },
    ],
    {},
  );
  assert.throws(() => store.reviewFinding(a.id, 1, verdict(), NOW + 1001), /evidence is stale/);
  assert.equal(store.controls(a.id).acknowledged, false);
});

test('object key order does not reopen an unchanged reviewed finding', (t) => {
  const store = memory(t),
    a = finding(),
    d = decide(a, config());
  store.saveAssessment(a, d, NOW);
  store.reviewFinding(a.id, 1, verdict(), NOW + 1);
  const reorder = (value) =>
    Array.isArray(value)
      ? value.map(reorder)
      : value && typeof value === 'object'
        ? Object.fromEntries(
            Object.entries(value)
              .reverse()
              .map(([key, item]) => [key, reorder(item)]),
          )
        : value;
  store.saveAssessment(reorder(a), reorder(d), NOW + 2);
  assert.equal(store.reviews().length, 0);
  assert.equal(store.controls(a.id).revision, 1);
});

test('normal scans preserve a dismissal on unchanged input and reopen it after installed context changes', async (t) => {
  const store = memory(t);
  const cfg = parseConfig({
    version: 1,
    sources: { cve_now: false, hacker_news: false },
    models: {
      enabled: true,
      analysis: {
        provider: 'openai-compatible',
        model: 'synthetic',
        endpoint: 'http://127.0.0.1:1234',
        allow_private_endpoint: true,
      },
    },
  });
  const inventory = {
    systems: [
      {
        id: 'prod',
        name: 'Production',
        environment: 'production',
        exposure: 'internal',
        criticality: 'high',
        updated_at: at,
        components: [],
        products: [{ name: 'Alpha', version: '1.0.0', keywords: [] }],
        keywords: [],
      },
    ],
  };
  let requests = 0;
  const http = async () => {
    requests++;
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        choices: [
          {
            finish_reason: 'stop',
            message: {
              content: JSON.stringify({
                relevance: 'irrelevant',
                priority: 'low',
                summary: 'Conference announcement.',
                evidence_ids: [source.id],
                quotes: [{ evidence_id: source.id, quote: source.description }],
                news_analysis: news(),
              }),
            },
          },
        ],
      }),
    };
  };
  await runScan({ config: cfg, inventory, store, http, now: NOW });
  const first = store.reviews()[0];
  assert(first);
  assert.equal(store.jobs().length, 0);
  store.reviewFinding(first.finding_id, first.revision, verdict(), NOW + 1);
  await runScan({ config: cfg, inventory, store, http, now: NOW + 1000 });
  assert.equal(store.reviews().length, 0);
  assert.equal(requests, 1);
  inventory.systems[0].products[0].version = '2.0.0';
  await runScan({ config: cfg, inventory, store, http, now: NOW + 2000 });
  const next = store.reviews()[0];
  assert(next.revision > first.revision);
  assert.equal(requests, 2);
  assert.throws(() => store.reviewFinding(first.finding_id, first.revision, verdict(), NOW + 2001), /stale/);
});
