import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../dist/store.js';

const DAY = 86_400_000;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const OLD = NOW - 100 * DAY;
const iso = (time) => new Date(time).toISOString();
const record = { action: 'record', channels: [], reason: 'Retention fixture' };
const notify = { action: 'notify', channels: ['slack'], reason: 'Retention fixture' };
const all = {
  analysis_cache_days: 30,
  evidence_history_days: 30,
  finding_history_days: 30,
  accepted_delivery_days: 30,
  inactive_findings_days: 30,
  unreferenced_evidence_days: 30,
};

function disk(t) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-retention-'));
  const path = join(dir, 'watch.db');
  const store = new Store(path);
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return { store, path };
}
function evidence(id, description = 'Original claim', fetched = OLD, modified = OLD) {
  return {
    id,
    source: 'fixture',
    kind: 'advisory',
    title: 'Synthetic advisory',
    description,
    url: 'https://example.com/advisory',
    aliases: [],
    severity: 'high',
    packages: [],
    modified_at: iso(modified),
    fetched_at: iso(fetched),
  };
}
function finding(id, changes = {}) {
  return {
    id,
    event_id: id,
    system_id: 'app',
    category: 'library',
    component_id: 'dep',
    applicability: 'affected',
    source_severity: 'high',
    priority: 'high',
    title: 'Synthetic finding',
    summary: 'Retention fixture',
    reasons: [],
    evidence_ids: [id],
    urls: [],
    exploited: false,
    updated_at: iso(OLD),
    ...changes,
  };
}
function oldEvidence(store, id) {
  store.saveEvidence([evidence(id)], {});
  store.saveEvidence([evidence(id, 'Updated claim', OLD + DAY, OLD + DAY)], {});
}
function resolved(store, id, status = 'accepted') {
  oldEvidence(store, id);
  store.saveAssessment(finding(id), notify, OLD);
  const job = store.claimDue(OLD);
  assert.equal(job.finding_id, id);
  if (status !== 'sending')
    store.completeJob(
      job.id,
      status,
      OLD + 1000,
      status === 'accepted' ? undefined : 'Synthetic unresolved delivery',
    );
  store.saveAssessment(
    finding(id, { active: false, applicability: 'not_affected', updated_at: iso(OLD + DAY) }),
    record,
    OLD + DAY,
  );
  store.setMeta(`assessment-basis:${id}`, 'retained basis', OLD);
}

test('retention defaults to a read-only plan and touches only selected aged analysis caches', (t) => {
  const { store, path } = disk(t);
  store.setMeta('analysis:old', '{}', OLD);
  store.setMeta('analysis:recent', '{}', NOW);
  store.setMeta('checkpoint:osv', 'keep-checkpoint', OLD);
  store.setMeta('unpriced:2026-10-24', '1', OLD);
  store.reserveBudget('2026-10-24', 10, 1000, undefined, 20, undefined);
  const reader = new Store(path, { readOnly: true });
  const plan = reader.prune({ analysis_cache_days: 30 }, NOW);
  reader.close();
  assert.equal(plan.applied, false);
  assert.equal(plan.counts.analysis_cache, 1);
  assert.equal(plan.total, 1);
  assert.equal(store.getMeta('analysis:old'), '{}');
  const result = store.prune({ analysis_cache_days: 30 }, NOW, true);
  assert.deepEqual(result.counts, plan.counts);
  assert.equal(result.applied, true);
  assert.equal(store.getMeta('analysis:old'), undefined);
  assert.equal(store.getMeta('analysis:recent'), '{}');
  assert.equal(store.checkpoints().osv, 'keep-checkpoint');
  assert.equal(store.getMeta('unpriced:2026-10-24'), '2');
  assert.equal(store.budgets()[0].requests, 1);
});

test('a batch bound counts every deleted row and reports additional work', (t) => {
  const { store } = disk(t);
  for (let i = 0; i < 5; i++) store.setMeta(`analysis:${i}`, '{}', OLD);
  const results = Array.from({ length: 3 }, () =>
    store.prune({ analysis_cache_days: 30, batch_size: 2 }, NOW, true),
  );
  assert.deepEqual(
    results.map((result) => result.total),
    [2, 2, 1],
  );
  assert.deepEqual(
    results.map((result) => result.more_available),
    [true, true, false],
  );
  for (const policy of [
    {},
    { analysis_cache_days: 0 },
    { analysis_cache_days: 1.5 },
    { analysis_cache_days: 3651 },
    { analysis_cache_days: 1, batch_size: 0 },
    { analysis_cache_days: 1, batch_size: 10001 },
    { unexpected: 3 },
  ])
    assert.throws(() => store.prune(policy, NOW, true));
  assert.throws(() => store.prune({ analysis_cache_days: 1 }, NaN, true));
  assert.throws(() => store.prune({ analysis_cache_days: 1 }, NOW, 'false'));
});

test('obsolete evidence history can expire while the exact current revision stays intact', (t) => {
  const { store } = disk(t);
  const original = evidence('current');
  store.saveEvidence([original], {});
  store.saveEvidence([evidence('current', 'Different claim', OLD + DAY)], {});
  store.saveEvidence([{ ...original, fetched_at: iso(OLD + 2 * DAY) }], {});
  assert.equal(store.evidenceHistory('fixture', 'current').length, 2);
  const report = store.prune({ evidence_history_days: 30 }, NOW, true);
  assert.equal(report.counts.evidence_history, 1);
  assert.equal(store.evidence().length, 1);
  assert.equal(store.evidence()[0].description, 'Original claim');
  assert.equal(store.evidenceHistory('fixture', 'current')[0].evidence.description, 'Original claim');
});

test('active and unresolved findings protect their history, evidence and delivery audit', (t) => {
  const { store } = disk(t);
  for (const [id, changes] of [
    ['active', {}],
    ['active-exclusion', { applicability: 'not_affected' }],
    ['inactive-affected', { active: false }],
    ['inactive-unknown', { active: false, applicability: 'unknown' }],
    ['inactive-conflicting', { active: false, applicability: 'conflicting' }],
  ]) {
    oldEvidence(store, id);
    store.saveAssessment(finding(id, changes), record, OLD);
    store.saveAssessment(finding(id, { ...changes, priority: 'critical' }), record, OLD + DAY);
  }
  for (const status of ['failed', 'unknown', 'sending']) resolved(store, `delivery-${status}`, status);
  oldEvidence(store, 'pending');
  store.saveAssessment(
    finding('pending', { active: false, applicability: 'not_affected' }),
    notify,
    NOW + DAY,
  );
  const before = { findings: store.findings(), evidence: store.evidence(), jobs: store.jobs() };
  const report = store.prune(all, NOW, true);
  assert.equal(report.total, 0);
  assert.deepEqual({ findings: store.findings(), evidence: store.evidence(), jobs: store.jobs() }, before);
  for (const value of before.findings) assert.equal(store.evidenceHistory('fixture', value.id).length, 2);
});

test('resolved inactive records and unreferenced evidence expire in dependency order within one-row batches', (t) => {
  const { store } = disk(t);
  resolved(store, 'resolved');
  store.setMeta('checkpoint:fixture', 'never-prune', OLD);
  store.reserveBudget('2026-01-01', 10, 1000, undefined, 50, undefined);
  const policy = { inactive_findings_days: 30, unreferenced_evidence_days: 30, batch_size: 1 };
  const initial = store.prune(policy, NOW);
  assert.equal(initial.total, 1);
  assert.equal(initial.counts.accepted_deliveries, 1);
  let total = 0;
  for (let i = 0; i < 20; i++) {
    const report = store.prune(policy, NOW, true);
    assert(report.total <= 1);
    total += report.total;
    if (!report.more_available) break;
  }
  assert.equal(
    total,
    8,
    'One accepted job, two finding revisions, basis, finding, two evidence revisions and evidence',
  );
  assert.deepEqual(store.findings(), []);
  assert.deepEqual(store.evidence(), []);
  assert.deepEqual(store.jobs(), []);
  assert.equal(store.getMeta('assessment-basis:resolved'), undefined);
  assert.equal(store.checkpoints().fixture, 'never-prune');
  assert.equal(store.budgets()[0].requests, 1);
});

test('recent delivery receipts keep an otherwise old inactive finding and its audit', (t) => {
  const { store } = disk(t);
  oldEvidence(store, 'recent-receipt');
  store.saveAssessment(finding('recent-receipt'), notify, OLD);
  const job = store.claimDue(OLD);
  store.completeJob(job.id, 'accepted', NOW);
  store.saveAssessment(
    finding('recent-receipt', { active: false, applicability: 'not_affected' }),
    record,
    OLD + DAY,
  );
  const report = store.prune({ inactive_findings_days: 30, unreferenced_evidence_days: 30 }, NOW, true);
  assert.equal(report.counts.accepted_deliveries, 0);
  assert.equal(report.counts.inactive_findings, 0);
  assert.equal(store.jobs()[0].status, 'accepted');
  assert.equal(
    store.history('recent-receipt').some((entry) => entry.revision === 1),
    true,
  );
  assert.equal(store.evidence().length, 1);
});

test('a failed prune rolls back cache and delivery deletions together', (t) => {
  const { store, path } = disk(t);
  resolved(store, 'atomic');
  store.setMeta('analysis:old', '{}', OLD);
  const editor = new DatabaseSync(path);
  editor.exec(
    "CREATE TRIGGER stop_prune BEFORE DELETE ON finding_revisions BEGIN SELECT RAISE(ABORT,'Synthetic failure'); END",
  );
  editor.close();
  assert.throws(() => store.prune(all, NOW, true), /Synthetic failure/);
  assert.equal(store.getMeta('analysis:old'), '{}');
  assert.equal(store.jobs().length, 1);
  assert.equal(store.history('atomic').length, 2);
  assert.equal(store.findings().length, 1);
});

test('apply reevaluates protections instead of executing an earlier dry-run plan', (t) => {
  const { store } = disk(t);
  resolved(store, 'changed');
  assert(store.prune(all, NOW).total > 0);
  store.saveAssessment(store.findings()[0], notify, NOW);
  const applied = store.prune(all, NOW, true);
  assert.equal(applied.total, 0);
  assert.equal(store.findings().length, 1);
  assert(store.jobs().some((job) => job.status === 'pending'));
});

test('schema 4 migration starts unknown cache ages conservatively and records the current evidence hash', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'watch-retention-migration-'));
  const path = join(directory, 'old.db');
  let store = new Store(path);
  t.after(() => {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  });
  store.setMeta('analysis:legacy', '{}', OLD);
  oldEvidence(store, 'legacy');
  store.close();
  const legacy = new DatabaseSync(path);
  legacy.exec(`DROP INDEX metadata_age; DROP INDEX evidence_age; DROP INDEX findings_age;
    DROP INDEX evidence_revisions_age; DROP INDEX finding_revisions_age;
    ALTER TABLE metadata DROP COLUMN updated_at; ALTER TABLE evidence DROP COLUMN content_hash;
    ALTER TABLE evidence DROP COLUMN fetched_at; ALTER TABLE findings DROP COLUMN updated_at;
    PRAGMA user_version=4;`);
  legacy.close();
  store = new Store(path);
  const report = store.prune({ analysis_cache_days: 30, evidence_history_days: 30 }, Date.now(), true);
  assert.equal(report.counts.analysis_cache, 0);
  assert.equal(store.getMeta('analysis:legacy'), '{}');
  assert.equal(report.counts.evidence_history, 1);
  assert.equal(store.evidenceHistory('fixture', 'legacy').length, 1);
  assert.equal(store.evidenceHistory('fixture', 'legacy')[0].evidence.description, 'Updated claim');
});
