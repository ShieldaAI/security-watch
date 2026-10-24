import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  readdirSync,
  writeFileSync,
  readFileSync,
  statSync,
  mkdirSync,
  symlinkSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Store } from '../dist/store.js';
import { parseConfig } from '../dist/config.js';
import { MaintenanceScheduler } from '../dist/operations.js';
import { verifyBackup } from '../dist/maintenance.js';
import { checkHealth } from '../dist/health.js';

const now = Date.parse('2026-10-24T12:00:00Z');
function setup(t, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-operations-'));
  const store = new Store(join(dir, 'watch.db'));
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const directory = join(dir, 'backups');
  const config = parseConfig({
    version: 1,
    maintenance: { interval_hours: 1, backup: { directory, keep: 1 }, ...extra },
  });
  return { dir, store, directory, config };
}
test('scheduled backups are restored and checked before old verified backups are rotated', async (t) => {
  const { store, directory, config } = setup(t);
  store.setMeta('last_scan', JSON.stringify({ at: new Date(now).toISOString(), degraded: false }));
  const scheduler = new MaintenanceScheduler();
  const first = await scheduler.tick(store, config, now);
  assert.equal(first.ok, true);
  assert.equal(first.backup_created, true);
  const initial = readdirSync(directory).find((name) => name.endsWith('.db'));
  assert.equal(statSync(join(directory, initial)).mode & 0o777, 0o600);
  assert.equal((await verifyBackup(join(directory, initial))).ok, true);
  writeFileSync(join(directory, 'my-manual-backup.txt'), 'keep');
  assert.equal(await scheduler.tick(store, config, now + 1000), undefined);
  const second = await new MaintenanceScheduler().tick(store, config, now + 3600000);
  assert.equal(second.ok, true);
  assert.equal(second.backups_removed, 1);
  assert(!readdirSync(directory).includes(initial));
  assert.equal(readdirSync(directory).filter((name) => name.endsWith('.db')).length, 1);
  assert.equal(readFileSync(join(directory, 'my-manual-backup.txt'), 'utf8'), 'keep');
  assert.equal(JSON.parse(store.getMeta('maintenance:last_run')).ok, true);
  const future = readdirSync(directory).find((name) => name.endsWith('.db'));
  const afterClockChange = await new MaintenanceScheduler().tick(store, config, now - 3600000);
  assert.equal(afterClockChange.ok, true);
  assert.equal(afterClockChange.backups_removed, 1);
  assert(
    !readdirSync(directory).includes(future),
    'The newly verified backup survives a backward clock change',
  );
});
test('failed backup verification preserves previous backups and skips pruning', async (t) => {
  const { store, directory, config } = setup(t, { retention: { analysis_cache_days: 1 } });
  assert.equal((await new MaintenanceScheduler().tick(store, config, now)).ok, true);
  const initial = readdirSync(directory).filter((name) => name.endsWith('.db'));
  config.maintenance.backup.max_bytes = 1;
  let pruned = false;
  store.prune = () => {
    pruned = true;
    throw new Error('must not prune');
  };
  const failed = await new MaintenanceScheduler().tick(store, config, now + 3600000);
  assert.equal(failed.ok, false);
  assert.equal(pruned, false);
  assert.deepEqual(
    readdirSync(directory).filter((name) => name.endsWith('.db')),
    initial,
  );
  assert(!readdirSync(directory).some((name) => name.startsWith('.verify-backup-')));
  assert(
    checkHealth(store, config, now + 3600000, false).issues.some((issue) =>
      issue.includes('maintenance failed'),
    ),
  );
});
test('backup directory links are rejected without writing to their targets', async (t) => {
  const { dir, store, directory, config } = setup(t);
  const target = join(dir, 'target');
  mkdirSync(target, { mode: 0o700 });
  symlinkSync(target, directory);
  const report = await new MaintenanceScheduler().tick(store, config, now);
  assert.equal(report.ok, false);
  assert.deepEqual(readdirSync(target), []);
});
