import { mkdirSync, writeFileSync, readFileSync, unlinkSync, openSync, closeSync, fstatSync, fchmodSync, ftruncateSync, constants } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

function openPrivateFile(path: string): number {
  let fd: number;
  try { fd = openSync(path, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ELOOP') throw new Error('Worker lock files must not be symbolic links');
    throw error;
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) throw new Error('Worker lock files must be regular files without hard links');
    fchmodSync(fd, 0o600);
    return fd;
  } catch (error) { closeSync(fd); throw error; }
}

/** An OS-released SQLite lock in a separate file. Process death releases it, including container PID reuse. */
export function acquireLock(database: string): () => void {
  if (database === ':memory:') return () => {};
  const path = `${database}.worker-lock`;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  // Precreate privately and reject dangling symlinks before SQLite opens its path.
  closeSync(openPrivateFile(path));
  const connection = new DatabaseSync(path);
  try { connection.exec('PRAGMA busy_timeout=0; BEGIN EXCLUSIVE;'); }
  catch { connection.close(); throw new Error('Another scan or worker is using this database.'); }
  const nonce = randomUUID(); const metadata = `${database}.lock`;
  try {
    const fd = openPrivateFile(metadata);
    try {
      // Truncate only after verifying the opened file, so links cannot redirect this write.
      ftruncateSync(fd, 0);
      writeFileSync(fd, JSON.stringify({ pid: process.pid, nonce, started_at: new Date().toISOString() }));
    } finally { closeSync(fd); }
  } catch (error) { connection.exec('ROLLBACK'); connection.close(); throw error; }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    try {
      const fd = openSync(metadata, constants.O_RDONLY | constants.O_NOFOLLOW);
      try { if (fstatSync(fd).isFile() && JSON.parse(readFileSync(fd, 'utf8')).nonce === nonce) unlinkSync(metadata); }
      finally { closeSync(fd); }
    } catch { /* Metadata is informational. */ }
    finally { connection.exec('ROLLBACK'); connection.close(); }
  };
}
export function unlockStoppedWorker(database: string): void {
  // Successfully acquiring the OS lock proves no other worker owns it. Never delete the SQLite lock file.
  acquireLock(database)();
}
