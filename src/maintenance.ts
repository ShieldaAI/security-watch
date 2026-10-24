import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface RetentionPolicy {
  analysis_cache_days?: number;
  evidence_history_days?: number;
  finding_history_days?: number;
  accepted_delivery_days?: number;
  inactive_findings_days?: number;
  unreferenced_evidence_days?: number;
  batch_size?: number;
}
export interface PruneCounts {
  analysis_cache: number;
  evidence_history: number;
  finding_history: number;
  accepted_deliveries: number;
  inactive_findings: number;
  unreferenced_evidence: number;
  assessment_bases: number;
}
export interface PruneReport {
  applied: boolean;
  planned_at: string;
  counts: PruneCounts;
  total: number;
  more_available: boolean;
}
export interface BackupVerification {
  ok: true;
  schema_version: number;
  verified_schema_version: number;
  bytes: number;
  counts: { evidence: number; findings: number; notifications: number; budgets: number };
  last_scan_at?: string;
}

export function validateRetentionPolicy(
  policy: RetentionPolicy,
): Required<Pick<RetentionPolicy, 'batch_size'>> & RetentionPolicy {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy))
    throw new Error('Invalid retention policy');
  const periods = new Set([
    'analysis_cache_days',
    'evidence_history_days',
    'finding_history_days',
    'accepted_delivery_days',
    'inactive_findings_days',
    'unreferenced_evidence_days',
  ]);
  let selected = false;
  for (const [key, value] of Object.entries(policy)) {
    if (key !== 'batch_size' && !periods.has(key)) throw new Error('Unknown retention option');
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value < 1 || value > (key === 'batch_size' ? 10000 : 3650))
      throw new Error('Retention periods must be 1–3650 days and batch_size must be 1–10000');
    if (key !== 'batch_size') selected = true;
  }
  if (!selected) throw new Error('Choose at least one retention period');
  return { ...policy, batch_size: policy.batch_size ?? 1000 };
}

const runFile = promisify(execFile);
const DEFAULT_BACKUP_LIMIT = 512 * 1024 ** 2;

/** Restore and inspect a temporary copy. No live database or original backup is replaced. */
export async function verifyBackup(
  path: string,
  options: { max_bytes?: number } = {},
): Promise<BackupVerification> {
  const maxBytes = options.max_bytes ?? DEFAULT_BACKUP_LIMIT;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 20 * 1024 ** 3)
    throw new Error('Backup byte limit must be between 1 byte and 20 GiB');
  const temporary = mkdtempSync(join(tmpdir(), 'security-watch-verify-'));
  try {
    // Copying an existing SQLite inode in this process could release a live Store's locks.
    // A bounded subprocess also keeps a damaged backup from blocking the worker indefinitely.
    const result = await runFile(
      process.execPath,
      [fileURLToPath(import.meta.url), '--verify-copy', resolve(path), temporary, String(maxBytes)],
      {
        timeout: 60_000,
        killSignal: 'SIGKILL',
        maxBuffer: 32_768,
        env: { NODE_NO_WARNINGS: '1' },
        windowsHide: true,
      },
    );
    const report = JSON.parse(result.stdout) as BackupVerification | { ok: false; error: string };
    if (!report.ok) throw new Error(report.error);
    return report;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Backup ')) throw error;
    throw new Error('Backup verification failed or exceeded its time limit; the original was not changed');
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function requireStandalone(path: string): void {
  for (const suffix of ['-wal', '-shm', '-journal']) {
    try {
      lstatSync(path + suffix);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    throw new Error('Backup must be a standalone snapshot without SQLite sidecar files');
  }
}

async function inspectCopy(source: string, directory: string, maxBytes: number): Promise<BackupVerification> {
  requireStandalone(source);
  const destination = join(directory, 'restored.db');
  const input = openSync(source, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let bytes = 0;
  try {
    const before = fstatSync(input);
    if (!before.isFile() || before.nlink !== 1)
      throw new Error('Backup must be a regular file without links');
    if (before.size > maxBytes) throw new Error('Backup exceeds the configured byte limit');
    const output = openSync(
      destination,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      const buffer = Buffer.alloc(65_536);
      for (;;) {
        const length = readSync(input, buffer, 0, Math.min(buffer.length, maxBytes - bytes + 1), null);
        if (!length) break;
        bytes += length;
        if (bytes > maxBytes) throw new Error('Backup exceeds the configured byte limit');
        let offset = 0;
        while (offset < length) offset += writeSync(output, buffer, offset, length - offset);
      }
    } finally {
      closeSync(output);
    }
    const after = fstatSync(input);
    const current = lstatSync(source);
    if (
      before.dev !== current.dev ||
      before.ino !== current.ino ||
      !current.isFile() ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs ||
      bytes !== before.size
    )
      throw new Error('Backup changed during verification; create a new snapshot and retry');
  } finally {
    closeSync(input);
  }
  requireStandalone(source);
  const { Store, SCHEMA_VERSION } = await import('./store.js');
  let database = new DatabaseSync(destination, { readOnly: true });
  let sourceVersion: number;
  try {
    database.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;');
    sourceVersion = Number(database.prepare('PRAGMA user_version').get()!.user_version);
    if (sourceVersion < 1 || sourceVersion > SCHEMA_VERSION)
      throw new Error('Backup has an unsupported schema version');
    if (database.prepare('PRAGMA quick_check(1)').get()!.quick_check !== 'ok')
      throw new Error('Backup failed SQLite integrity verification');
  } finally {
    database.close();
  }
  // This exercises the same migrations as a restore, exclusively on the private temporary copy.
  const restored = new Store(destination);
  restored.close();
  database = new DatabaseSync(destination, { readOnly: true });
  try {
    database.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;');
    if (
      database.prepare('PRAGMA quick_check(1)').get()!.quick_check !== 'ok' ||
      database.prepare('PRAGMA foreign_key_check').get()
    )
      throw new Error('Backup failed SQLite integrity or relationship verification');
    const requiredColumns: Record<string, string[]> = {
      evidence: ['source', 'id', 'payload', 'content_hash', 'fetched_at'],
      metadata: ['key', 'value', 'updated_at'],
      findings: [
        'id',
        'payload',
        'fingerprint',
        'revision',
        'acknowledged_revision',
        'suppressed_until',
        'suppression_reason',
        'updated_at',
      ],
      notifications: [
        'id',
        'finding_id',
        'revision',
        'channel',
        'payload',
        'status',
        'attempts',
        'available_at',
        'last_error',
      ],
      budgets: ['day', 'requests', 'tokens', 'usd'],
      finding_revisions: ['finding_id', 'revision', 'payload', 'decision', 'recorded_at'],
      evidence_revisions: ['source', 'id', 'content_hash', 'payload', 'recorded_at'],
    };
    for (const [table, required] of Object.entries(requiredColumns)) {
      if (database.prepare('SELECT type FROM sqlite_schema WHERE name=?').get(table)?.type !== 'table')
        throw new Error('Backup is missing required application tables');
      const columns = new Set(
        database
          .prepare(`PRAGMA table_info(${table})`)
          .all()
          .map((row) => String(row.name)),
      );
      if (required.some((column) => !columns.has(column)))
        throw new Error('Backup is missing required application columns');
    }
    for (const table of ['evidence', 'findings', 'notifications', 'finding_revisions', 'evidence_revisions'])
      if (database.prepare(`SELECT 1 FROM ${table} WHERE NOT json_valid(payload) LIMIT 1`).get())
        throw new Error('Backup contains invalid saved JSON');
    const count = (table: string) =>
      Number(database.prepare(`SELECT count(*) AS total FROM ${table}`).get()!.total);
    const rawScan = database.prepare("SELECT value FROM metadata WHERE key='last_scan'").get()?.value;
    let lastScanAt: string | undefined;
    if (rawScan !== undefined) {
      const scan = JSON.parse(String(rawScan)) as { completed_at?: unknown; at?: unknown };
      const at = scan?.completed_at ?? scan?.at;
      if (typeof at !== 'string' || !Number.isFinite(Date.parse(at)))
        throw new Error('Backup has invalid scan metadata');
      lastScanAt = new Date(at).toISOString();
    }
    return {
      ok: true,
      schema_version: sourceVersion,
      verified_schema_version: SCHEMA_VERSION,
      bytes,
      counts: {
        evidence: count('evidence'),
        findings: count('findings'),
        notifications: count('notifications'),
        budgets: count('budgets'),
      },
      ...(lastScanAt ? { last_scan_at: lastScanAt } : {}),
    };
  } finally {
    database.close();
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url) &&
  process.argv[2] === '--verify-copy'
) {
  // Let module initialization finish before the restore imports Store, which uses the policy types above.
  void inspectCopy(process.argv[3]!, process.argv[4]!, Number(process.argv[5])).then(
    (result) => {
      process.stdout.write(JSON.stringify(result));
    },
    (error: unknown) => {
      const message =
        error instanceof Error && error.message.startsWith('Backup ')
          ? error.message
          : 'Backup verification failed; the snapshot is not a readable application database';
      process.stdout.write(JSON.stringify({ ok: false, error: message }));
    },
  );
}
