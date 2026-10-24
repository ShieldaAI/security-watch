import { linkSync, lstatSync, mkdirSync, mkdtempSync, opendirSync, rmSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Config } from './types.js';
import type { Store } from './store.js';
import { verifyBackup } from './maintenance.js';

export interface MaintenanceRun {
  ok: boolean;
  attempted_at: string;
  last_success_at: string | null;
  backup_created: boolean;
  backups_removed: number;
  rows_removed: number;
  more_available: boolean;
  error: string | null;
}

function backupFiles(directory: string): string[] {
  const result: string[] = [];
  const folder = opendirSync(directory);
  try {
    let count = 0;
    for (let entry = folder.readSync(); entry; entry = folder.readSync()) {
      if (++count > 10_000) throw new Error('Backup directory contains too many entries');
      if (!/^security-watch-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-[a-f0-9-]{36}\.db$/.test(entry.name))
        continue;
      const stat = lstatSync(join(directory, entry.name));
      if (!stat.isFile() || stat.nlink !== 1 || (process.platform !== 'win32' && stat.mode & 0o077))
        throw new Error('Backup files must be private regular files without links');
      result.push(entry.name);
    }
  } finally {
    folder.closeSync();
  }
  return result.sort().reverse();
}

function savedRun(store: Store): MaintenanceRun | undefined {
  const raw = store.getMeta('maintenance:last_run');
  try {
    const parsed: unknown = JSON.parse(raw ?? 'null');
    if (
      parsed &&
      typeof parsed === 'object' &&
      'ok' in parsed &&
      typeof parsed.ok === 'boolean' &&
      'attempted_at' in parsed &&
      typeof parsed.attempted_at === 'string' &&
      Number.isFinite(Date.parse(parsed.attempted_at))
    )
      return parsed as MaintenanceRun;
  } catch {
    // Invalid history does not postpone maintenance indefinitely.
  }
  return undefined;
}

/** Opt-in maintenance. Backups are verified before rotation or retention removes anything. */
export class MaintenanceScheduler {
  private nextAt = 0;

  async tick(store: Store, config: Config, now = Date.now()): Promise<MaintenanceRun | undefined> {
    const settings = config.maintenance;
    if (!settings) return undefined;
    const previous = savedRun(store);
    if (!this.nextAt && previous) {
      const attempted = Date.parse(previous.attempted_at);
      if (attempted <= now)
        this.nextAt =
          attempted +
          (previous.ok ? settings.interval_hours : Math.min(settings.interval_hours, 1)) * 3_600_000;
    }
    if (now < this.nextAt) return undefined;
    this.nextAt = now + Math.min(settings.interval_hours, 1) * 3_600_000;
    const report: MaintenanceRun = {
      ok: false,
      attempted_at: new Date(now).toISOString(),
      last_success_at: typeof previous?.last_success_at === 'string' ? previous.last_success_at : null,
      backup_created: false,
      backups_removed: 0,
      rows_removed: 0,
      more_available: false,
      error: null,
    };
    try {
      if (settings.backup) {
        const { directory, max_bytes } = settings.backup;
        mkdirSync(directory, { recursive: true, mode: 0o700 });
        const folder = lstatSync(directory);
        if (
          !folder.isDirectory() ||
          folder.isSymbolicLink() ||
          (process.platform !== 'win32' && folder.mode & 0o077)
        )
          throw new Error('Backup directory must be private');
        backupFiles(directory);
        const filename = `security-watch-${report.attempted_at.replace(/[:.]/g, '-')}-${randomUUID()}.db`;
        const path = join(directory, filename);
        const temporary = mkdtempSync(join(directory, '.verify-backup-'));
        try {
          const candidate = join(temporary, 'snapshot.db');
          await store.backup(candidate);
          await verifyBackup(candidate, { max_bytes });
          linkSync(candidate, path);
        } finally {
          rmSync(temporary, { recursive: true, force: true });
        }
        report.backup_created = true;
        for (const old of backupFiles(directory)
          .filter((name) => name !== filename)
          .slice(settings.backup.keep - 1)) {
          unlinkSync(join(directory, old));
          report.backups_removed++;
        }
      }
      if (settings.retention) {
        const pruning = store.prune(settings.retention, now, true);
        report.rows_removed = pruning.total;
        report.more_available = pruning.more_available;
      }
      report.ok = true;
      report.last_success_at = report.attempted_at;
      this.nextAt = now + settings.interval_hours * 3_600_000;
    } catch {
      report.error = 'Maintenance failed. Check storage space, backup permissions and retention settings.';
    }
    store.setMeta('maintenance:last_run', JSON.stringify(report));
    return report;
  }
}
