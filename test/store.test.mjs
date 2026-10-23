import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../dist/store.js';

const base = (overrides = {}) => ({ id: 'finding-1', event_id: 'CVE-2026-1', system_id: 'prod', component_id: 'library-1', category: 'library', applicability: 'affected', source_severity: 'critical', priority: 'critical', title: 'Affected library', summary: 'Evidence summary', reasons: ['version match'], evidence_ids: ['osv:1'], urls: ['https://example.com/advisory'], exploited: false, updated_at: new Date().toISOString(), ...overrides });
const notify = { action: 'notify', channels: ['slack', 'email'], reason: 'source critical' };
function memory(t) { const store = new Store(':memory:'); t.after(() => store.close()); return store; }
function disk(t) { const dir = mkdtempSync(join(tmpdir(), 'watch-store-')); t.after(() => rmSync(dir, { force: true, recursive: true })); return { dir, path: join(dir, 'watch.db') }; }

test('assessment and per-channel delivery jobs commit atomically', t => {
  const store = memory(t);
  assert.throws(() => store.saveAssessment(base(), { ...notify, channels: ['slack', 'invalid'] }, 1000));
  assert.deepEqual(store.findings(), []);
  assert.deepEqual(store.jobs(), []);
  store.saveAssessment(base(), notify, 1000);
  assert.equal(store.findings().length, 1);
  assert.deepEqual(store.jobs().map(j => j.channel).sort(), ['email', 'slack']);
  assert.equal(JSON.parse(store.jobs()[0].payload).assessment.id, 'finding-1');
});

test('wording, timestamps and added articles do not duplicate meaningful alerts', t => {
  const store = memory(t);
  store.saveAssessment(base(), notify, 1000);
  store.saveAssessment(base({ summary: 'Rephrased', title: 'Updated title', reasons: ['same conclusion'], updated_at: '2030-01-01', evidence_ids: ['article', 'osv:1'], urls: ['https://example.com/new'] }), notify, 2000);
  assert.equal(store.jobs().length, 2);
  assert.equal(store.findings()[0].summary, 'Rephrased');
  store.saveAssessment(base({ exploited: true }), notify, 3000);
  assert.equal(store.jobs().filter(j => j.status === 'pending').length, 2);
  assert.equal(store.jobs().filter(j => j.status === 'failed').length, 2);
});

test('each deployment is independent and routing changes add only new destinations', t => {
  const store = memory(t);
  store.saveAssessment(base(), { ...notify, channels: ['slack'] }, 1000);
  store.saveAssessment(base(), notify, 1000);
  store.saveAssessment(base({ id: 'finding-stage', system_id: 'stage', applicability: 'not_affected' }), { action: 'record', channels: [], reason: 'fixed' }, 1000);
  assert.equal(store.findings().length, 2);
  assert.equal(store.jobs().length, 2);
  assert(store.jobs().every(j => j.finding_id === 'finding-1'));
});

test('digest does not move forward on each scan; claim is exclusive', t => {
  const store = memory(t);
  const digest = { ...notify, action: 'digest', channels: ['slack'] };
  store.saveAssessment(base(), digest, 1000, 100);
  store.saveAssessment(base(), digest, 1050, 100);
  assert.equal(store.claimDue(1099), undefined);
  const job = store.claimDue(1100);
  assert.equal(job.attempts, 1);
  assert.equal(store.claimDue(1100), undefined);
  store.completeJob(job.id, 'accepted', 1100);
  assert.throws(() => store.completeJob(job.id, 'accepted', 1100), /not in flight/);
});

test('suppression expires without losing a pending finding and acknowledgement ends at material change', t => {
  const store = memory(t); const now = Date.now();
  store.saveAssessment(base(), { ...notify, channels: ['slack'] }, now);
  assert.throws(() => store.suppress('finding-1', now + 5000, ' '));
  store.suppress('finding-1', now + 5000, 'Maintenance investigation');
  assert.equal(store.claimDue(now + 4999), undefined);
  assert.equal(store.claimDue(now + 5000)?.finding_id, 'finding-1');
  store.recoverSending(now + 5001);
  store.acknowledge('finding-1');
  store.saveAssessment(base(), notify, now + 5002);
  assert.equal(store.claimDue(now + 5002), undefined);
  store.saveAssessment(base({ exploited: true }), notify, now + 5003);
  assert.equal(store.claimDue(now + 5003)?.finding_id, 'finding-1');
});

test('suppressed revision discovered during silence queues once after expiry', t => {
  const store = memory(t); const now = Date.now();
  store.saveAssessment(base(), notify, now);
  store.suppress('finding-1', now + 5000, 'Investigating');
  store.saveAssessment(base({ exploited: true }), notify, now + 1000);
  assert.equal(store.jobs().filter(j => j.status === 'pending').length, 0);
  store.saveAssessment(base({ exploited: true }), notify, now + 5000);
  assert.equal(store.jobs().filter(j => j.status === 'pending').length, 2);
});

test('evidence and checkpoints commit together and different sources retain same advisory ID', t => {
  const store = memory(t);
  store.saveEvidence([{ id: 'CVE-1', source: 'a', modified_at: '2026-10-24', fetched_at: '2026-10-24' }, { id: 'CVE-1', source: 'b', modified_at: '2026-10-24', fetched_at: '2026-10-24' }], { sourceA: '10' });
  const circular = { id: 'bad', source: 'a', modified_at: '2026-10-24', fetched_at: '2026-10-24' }; circular.self = circular;
  assert.throws(() => store.saveEvidence([{ id: 'new', source: 'a', modified_at: '2026-10-24', fetched_at: '2026-10-24' }, circular], { sourceA: '20' }));
  assert.equal(store.evidence().length, 2);
  assert.deepEqual(store.checkpoints(), { sourceA: '10' });
});

test('restart preserves revisions and marks interrupted deliveries unknown without resend', t => {
  const { path } = disk(t);
  let store = new Store(path);
  store.saveAssessment(base(), { ...notify, channels: ['slack'] }, 1000);
  const job = store.claimDue(1000);
  store.close();
  store = new Store(path); t.after(() => store.close());
  store.recoverSending(2000);
  assert.equal(store.jobs()[0].id, job.id);
  assert.equal(store.jobs()[0].status, 'unknown');
  store.saveAssessment(base(), notify, 2000);
  assert.equal(store.jobs().filter(j => j.channel === 'slack').length, 1);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test('budget reservations are durable and atomic across separate database connections', t => {
  const { path } = disk(t); const a = new Store(path); const b = new Store(path);
  t.after(() => { a.close(); b.close(); });
  assert.equal(a.reserveBudget('2026-10-24', 2, 100, 1, 40, 0.4), true);
  assert.equal(b.reserveBudget('2026-10-24', 2, 100, 1, 40, 0.4), true);
  assert.equal(a.reserveBudget('2026-10-24', 2, 100, 1, 1, 0), false);
  assert.equal(a.reserveBudget('2026-10-25', 2, 100, 1, 101, 0), false);
  assert.equal(a.reserveBudget('2026-10-25', 2, 100, 1, 1, 1.1), false);
  assert.deepEqual(b.budgets(), [{ day: '2026-10-24', requests: 2, tokens: 80, usd: 0.8 }]);
  assert.throws(() => a.reserveBudget('2026-10-24', 2, 100, 1, 1, NaN));
});

test('backup restores complete database state and will not overwrite an existing file', async t => {
  const { dir, path } = disk(t); const store = new Store(path); t.after(() => store.close());
  store.saveAssessment(base(), notify, 1000); store.setMeta('cache:test', 'value');
  const backup = join(dir, 'backup.db'); await store.backup(backup);
  const restored = new Store(backup); t.after(() => restored.close());
  assert.equal(restored.findings().length, 1); assert.equal(restored.jobs().length, 2);
  assert.equal(restored.getMeta('cache:test'), 'value'); assert.equal(statSync(backup).mode & 0o777, 0o600);
  await assert.rejects(store.backup(backup), /already exists/);
});

test('future database schemas are refused', t => {
  const { path } = disk(t); const db = new DatabaseSync(path); db.exec('PRAGMA user_version=99'); db.close();
  assert.throws(() => new Store(path), /newer than supported/);
});

test('manual retry requires failed or unknown current unacknowledged revision', t => {
  const store = memory(t); store.saveAssessment(base(), { ...notify, channels: ['slack'] }, 1000);
  const job = store.claimDue(1000); store.completeJob(job.id, 'unknown', 1000, 'timeout');
  store.retryJob(job.id, 2000);
  assert.equal(store.jobs()[0].attempts, 0); assert.equal(store.jobs()[0].available_at, 2000);
  assert.throws(() => store.retryJob(job.id), /Only failed or unknown/);
  store.claimDue(2000); store.completeJob(job.id, 'failed', 2000);
  store.saveAssessment(base({ exploited: true }), notify, 3000);
  assert.throws(() => store.retryJob(job.id), /superseded/);
});

test('digest uses fixed UTC buckets and additional claims exclude immediate notifications', t => {
  const store = memory(t); const digest = { ...notify, action: 'digest', channels: ['slack'] };
  store.saveAssessment(base(), digest, 1001, 1000);
  store.saveAssessment(base({ id: 'two' }), digest, 1999, 1000);
  store.saveAssessment(base({ id: 'urgent' }), { ...notify, channels: ['slack'] }, 1999);
  assert.deepEqual(store.jobs().filter(j => j.finding_id !== 'urgent').map(j => j.available_at), [2000, 2000]);
  const batch = store.claimAdditionalDigest('slack', 2000);
  assert.equal(batch.length, 2); assert(batch.every(j => j.finding_id !== 'urgent'));
  assert.equal(store.claimDue(2000).finding_id, 'urgent');
});

test('inventory removal and withdrawal cancel pending deliveries without claiming safety', t => {
  const store = memory(t); store.saveAssessment(base(), notify, 1000);
  store.saveAssessment(base({ active: false }), { action: 'record', channels: [], reason: 'removed from inventory' }, 1001);
  assert.equal(store.claimDue(1001), undefined);
  assert.equal(store.findings()[0].applicability, 'affected');
  store.saveAssessment(base({ withdrawn: true, applicability: 'unknown' }), { action: 'record', channels: [], reason: 'withdrawn' }, 1002);
  assert.equal(store.findings()[0].withdrawn, true); assert.equal(store.claimDue(1002), undefined);
});

test('meaningful record-only transitions retain history, wording noise does not create revisions', t => {
  const store = memory(t); const record = { action: 'record', channels: [], reason: 'below threshold' };
  store.saveAssessment(base({ priority: 'low' }), record, 1000);
  store.saveAssessment(base({ priority: 'low', summary: 'new wording' }), record, 1001);
  store.saveAssessment(base({ priority: 'high' }), record, 1002);
  assert.equal(store.history('finding-1').length, 2);
  assert.equal(store.history('finding-1')[0].assessment.priority, 'low');
  assert.equal(store.history('finding-1')[1].assessment.priority, 'high');
  assert.deepEqual(store.jobs(), []);
});

test('schema 1 databases migrate existing findings into initial history', t => {
  const { path } = disk(t); const original = new Store(path);
  original.saveAssessment(base(), notify, 1000); original.close();
  const old = new DatabaseSync(path); old.exec('DROP TABLE evidence_revisions; DROP TABLE finding_revisions; PRAGMA user_version=1'); old.close();
  const migrated = new Store(path); t.after(() => migrated.close());
  assert.equal(migrated.findings().length, 1); assert.equal(migrated.jobs().length, 2);
  assert.equal(migrated.history('finding-1').length, 1);
  assert.match(migrated.history('finding-1')[0].decision.reason, /Imported/);
});

test('stale advisory replay cannot undo a newer withdrawal or advance malformed evidence checkpoints', t => {
  const store = memory(t); const evidence = { id: 'CVE-1', source: 'vendor', modified_at: '2026-10-24T10:00:00Z', fetched_at: '2026-10-24T10:01:00Z', withdrawn: true };
  store.saveEvidence([evidence], { vendor: '1' });
  store.saveEvidence([{ ...evidence, modified_at: '2026-10-23T10:00:00Z', fetched_at: '2026-10-24T11:00:00Z', withdrawn: false }], { vendor: '2' });
  assert.equal(store.evidence()[0].withdrawn, true);
  store.saveEvidence([{ ...evidence, fetched_at: '2026-10-24T10:00:30Z', withdrawn: false }], {});
  assert.equal(store.evidence()[0].withdrawn, true);
  assert.throws(() => store.saveEvidence([{ ...evidence, modified_at: 'invalid' }], { vendor: '3' }), /timestamps/);
  assert.equal(store.checkpoints().vendor, '2');
});

test('unpriced model reservations remain visibly unknown and cannot claim compliance with dollar caps', t => {
  const store = memory(t);
  assert.equal(store.reserveBudget('2026-10-24', 10, 1000, 5, 10, undefined), false);
  assert.equal(store.reserveBudget('2026-10-24', 10, 1000, undefined, 10, undefined), true);
  assert.equal(store.reserveBudget('2026-10-24', 10, 1000, undefined, 20, 0.1), true);
  assert.deepEqual(store.budgets(), [{ day: '2026-10-24', requests: 2, tokens: 30, usd: null, known_usd: 0.1, unpriced_requests: 1 }]);
  assert.equal(store.reserveBudget('2026-10-24', 10, 1000, 5, 10, 0.1), false);
});

test('evidence revisions preserve previous claims while fetched-at-only refreshes do not duplicate history', t => {
  const store = memory(t); const evidence = { source: 'vendor', id: 'CVE-1', title: 'Original', modified_at: '2026-10-24T10:00:00Z', fetched_at: '2026-10-24T10:01:00Z' };
  store.saveEvidence([evidence], { vendor: '1' });
  store.saveEvidence([{ ...evidence, fetched_at: '2026-10-24T11:00:00Z' }], { vendor: '2' });
  assert.equal(store.evidenceHistory('vendor', 'CVE-1').length, 1);
  store.saveEvidence([{ ...evidence, title: 'Withdrawn', withdrawn: true, modified_at: '2026-10-24T12:00:00Z', fetched_at: '2026-10-24T12:01:00Z' }], { vendor: '3' });
  const history = store.evidenceHistory('vendor', 'CVE-1');
  assert.equal(history.length, 2); assert.equal(history[0].evidence.title, 'Original'); assert.equal(history[1].evidence.withdrawn, true);
  assert.notEqual(history[0].content_hash, history[1].content_hash);
});

test('schema 2 databases import current evidence into revision history', t => {
  const { path } = disk(t); const original = new Store(path);
  original.saveEvidence([{ id: 'CVE-1', source: 'vendor', modified_at: '2026-10-24', fetched_at: '2026-10-24' }], { vendor: '1' }); original.close();
  const old = new DatabaseSync(path); old.exec('DROP TABLE evidence_revisions; PRAGMA user_version=2'); old.close();
  const migrated = new Store(path); t.after(() => migrated.close());
  assert.equal(migrated.evidenceHistory('vendor', 'CVE-1').length, 1); assert.equal(migrated.checkpoints().vendor, '1');
});

test('read-only connections inspect a live database without permitting writes or migrations', t => {
  const { path } = disk(t); const writer = new Store(path); t.after(() => writer.close());
  writer.saveAssessment(base(), notify, 1000);
  const reader = new Store(path, { readOnly: true }); t.after(() => reader.close());
  assert.equal(reader.findings().length, 1); assert.equal(reader.history('finding-1').length, 1);
  assert.throws(() => reader.setMeta('test', 'value'), /readonly|read-only/i);
  assert.equal(writer.getMeta('test'), undefined);
});

test('live control connections require current schema and do not silently migrate or initialize', t => {
  const { path, dir } = disk(t);
  assert.throws(() => new Store(join(dir, 'missing.db'), { migrate: false }), /does not exist/);
  const store = new Store(path); store.saveAssessment(base(), notify, 1000); store.close();
  const control = new Store(path, { migrate: false }); control.acknowledge('finding-1'); control.close();
  const old = new DatabaseSync(path); old.exec('PRAGMA user_version=2'); old.close();
  assert.throws(() => new Store(path, { readOnly: true }), /migration required/);
  assert.throws(() => new Store(path, { migrate: false }), /migration required/);
  const unchanged = new DatabaseSync(path); assert.equal(unchanged.prepare('PRAGMA user_version').get().user_version, 2); unchanged.close();
});

test('reenabling a policy-canceled destination restores its unsent job without reviving delivery outcomes', t => {
  const store = memory(t); const emailOnly = { ...notify, channels: ['email'] };
  store.saveAssessment(base(), notify, 1000);
  const original = store.jobs().find(job => job.channel === 'slack');
  store.saveAssessment(base(), emailOnly, 1001);
  assert.equal(store.jobs().find(job => job.channel === 'slack').status, 'failed');
  store.saveAssessment(base(), notify, 1002);
  const restored = store.jobs().find(job => job.channel === 'slack');
  assert.equal(restored.id, original.id); assert.equal(restored.status, 'pending');
  assert.equal(store.jobs().filter(job => job.channel === 'email').length, 1);
  for (const status of ['accepted', 'unknown', 'failed']) {
    const isolated = new Store(':memory:');
    try {
      isolated.saveAssessment(base(), { ...notify, channels: ['slack'] }, 1000);
      const job = isolated.claimDue(1000); isolated.completeJob(job.id, status, 1000, status === 'failed' ? 'Slack rejected request with HTTP 403' : undefined);
      isolated.saveAssessment(base(), emailOnly, 1001); isolated.saveAssessment(base(), notify, 1002);
      assert.equal(isolated.jobs().find(item => item.channel === 'slack').status, status);
    } finally { isolated.close(); }
  }
});

test('summary and indexed finding controls expose state without loading notification payloads', t => {
  const store = memory(t); const now = Date.now(); store.saveAssessment(base(), notify, now);
  assert.equal(store.getFinding('finding-1').id, 'finding-1'); assert.equal(store.getFinding('missing'), undefined);
  assert.equal(store.summary().pending, 2); assert.equal(store.summary().active_findings, 1);
  store.suppress('finding-1', now + 5000, 'Deployment investigation');
  assert.equal(store.controls('finding-1', now).suppression_reason, 'Deployment investigation'); assert.equal(store.controls('finding-1', now).suppressed, true);
  assert.equal(store.controls('finding-1', now + 5000).suppressed, false);
  store.acknowledge('finding-1'); assert.equal(store.controls('finding-1').acknowledged, true);
  assert.equal(store.summary().pending, 0); assert.equal(store.summary().next_pending_at, null);
  assert.equal(store.controls('missing'), undefined);
});
