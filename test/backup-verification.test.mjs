import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, symlinkSync, linkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../dist/store.js';
import { verifyBackup } from '../dist/maintenance.js';

function setup(t) {
  const directory = mkdtempSync(join(tmpdir(), 'watch-backup-verify-'));
  const path = join(directory, 'live.db');
  const backup = join(directory, 'snapshot with spaces.db');
  const store = new Store(path);
  t.after(() => {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  });
  store.setMeta(
    'last_scan',
    JSON.stringify({ at: '2026-10-24T12:00:00Z', private_detail: 'synthetic-secret-never-report' }),
  );
  store.setMeta('checkpoint:fixture', 'preserved');
  store.reserveBudget('2026-10-24', 10, 10000, undefined, 100, undefined);
  return { directory, path, backup, store };
}

test('verification restores a separate copy and returns only safe counts and timestamps', async (t) => {
  const { store, backup } = setup(t);
  await store.backup(backup);
  const before = readFileSync(backup);
  const result = await verifyBackup(backup);
  assert.equal(result.ok, true);
  assert.equal(result.schema_version, 5);
  assert.equal(result.verified_schema_version, 5);
  assert.equal(result.counts.budgets, 1);
  assert.equal(result.last_scan_at, '2026-10-24T12:00:00.000Z');
  assert.equal(JSON.stringify(result).includes('synthetic-secret'), false);
  assert.deepEqual(readFileSync(backup), before);
  store.setMeta('still-live', 'yes');
  assert.equal(store.getMeta('still-live'), 'yes');
});

test('older supported backups migrate only in the verification copy', async (t) => {
  const { store, backup } = setup(t);
  await store.backup(backup);
  const old = new DatabaseSync(backup);
  old.exec(`DROP INDEX metadata_age; DROP INDEX evidence_age; DROP INDEX findings_age;
    DROP INDEX evidence_revisions_age; DROP INDEX finding_revisions_age;
    ALTER TABLE metadata DROP COLUMN updated_at; ALTER TABLE evidence DROP COLUMN content_hash;
    ALTER TABLE evidence DROP COLUMN fetched_at; ALTER TABLE findings DROP COLUMN updated_at;
    PRAGMA user_version=4;`);
  old.close();
  const before = readFileSync(backup);
  const result = await verifyBackup(backup);
  assert.equal(result.schema_version, 4);
  assert.equal(result.verified_schema_version, 5);
  assert.equal(result.counts.budgets, 1);
  assert.deepEqual(readFileSync(backup), before);
});

test('verification rejects live sidecars, oversized inputs and unsupported schemas', async (t) => {
  const { store, path, backup } = setup(t);
  await assert.rejects(verifyBackup(path), /standalone snapshot/);
  await store.backup(backup);
  await assert.rejects(verifyBackup(backup, { max_bytes: 1 }), /byte limit/);
  for (const max_bytes of [0, -1, NaN, Infinity, 1.5, 21 * 1024 ** 3])
    await assert.rejects(verifyBackup(backup, { max_bytes }), /byte limit/);
  const future = new DatabaseSync(backup);
  future.exec('PRAGMA user_version=99');
  future.close();
  await assert.rejects(verifyBackup(backup), /unsupported schema/);
  assert.equal(store.getMeta('checkpoint:fixture'), 'preserved');
});

test('verification rejects malformed files, broken relationships and link inputs without leaking contents', async (t) => {
  const { directory, store, backup } = setup(t);
  const malformed = join(directory, 'malformed.db');
  writeFileSync(malformed, 'synthetic-secret-invalid-sqlite', { mode: 0o600 });
  await assert.rejects(
    verifyBackup(malformed),
    (error) => /Backup verification/.test(error.message) && !error.message.includes('synthetic-secret'),
  );
  await store.backup(backup);
  const symbolic = join(directory, 'symbolic.db');
  symlinkSync(backup, symbolic);
  await assert.rejects(verifyBackup(symbolic), /Backup verification/);
  const hard = join(directory, 'hard.db');
  linkSync(backup, hard);
  await assert.rejects(verifyBackup(hard), /without links/);
  rmSync(hard);
  const broken = new DatabaseSync(backup);
  broken.exec(
    "PRAGMA foreign_keys=OFF; INSERT INTO notifications(id,finding_id,revision,channel,payload,status,available_at) VALUES('orphan','missing',1,'slack','{}','accepted',0)",
  );
  broken.close();
  await assert.rejects(verifyBackup(backup), /relationship verification/);
});
