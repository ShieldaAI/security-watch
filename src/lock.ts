import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  unlinkSync,
  openSync,
  closeSync,
  fstatSync,
  fchmodSync,
  ftruncateSync,
  lstatSync,
  constants,
} from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

function privateLockDatabase(path: string): void {
  try {
    lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    try {
      const fd = openSync(
        path,
        constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
        0o600,
      );
      closeSync(fd);
    } catch (createError) {
      if ((createError as NodeJS.ErrnoException).code !== 'EEXIST') throw createError;
    }
  }
  // Closing another descriptor for an existing SQLite file would release this process's locks.
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) throw new Error('Worker lock files must not be symbolic links');
  if (!stat.isFile() || stat.nlink !== 1)
    throw new Error('Worker lock files must be regular files without hard links');
  if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)
    throw new Error('Worker lock database must have private permissions; stop the worker and set mode 0600');
}

function openPrivateFile(path: string): number {
  let fd: number;
  try {
    fd = openSync(
      path,
      constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      0o600,
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ELOOP')
      throw new Error('Worker lock files must not be symbolic links');
    throw error;
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1)
      throw new Error('Worker lock files must be regular files without hard links');
    fchmodSync(fd, 0o600);
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

/** Hold a SQLite lock in a separate file. Process exit releases it, so reused PIDs cannot keep it locked. */
export function acquireLock(database: string): () => void {
  if (database === ':memory:') return () => {};
  const path = `${database}.worker-lock`;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  privateLockDatabase(path);
  const connection = new DatabaseSync(path);
  try {
    connection.exec('PRAGMA busy_timeout=0; BEGIN EXCLUSIVE;');
  } catch {
    connection.close();
    throw new Error('Another scan or worker is using this database.');
  }
  const nonce = randomUUID();
  const metadata = `${database}.lock`;
  try {
    const fd = openPrivateFile(metadata);
    try {
      // Truncate only after verifying the opened file, so links cannot redirect this write.
      ftruncateSync(fd, 0);
      writeFileSync(fd, JSON.stringify({ pid: process.pid, nonce, started_at: new Date().toISOString() }));
    } finally {
      closeSync(fd);
    }
  } catch (error) {
    connection.exec('ROLLBACK');
    connection.close();
    throw error;
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    try {
      const fd = openSync(metadata, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        if (fstatSync(fd).isFile() && JSON.parse(readFileSync(fd, 'utf8')).nonce === nonce)
          unlinkSync(metadata);
      } finally {
        closeSync(fd);
      }
    } catch {
      /* Metadata is informational. */
    } finally {
      connection.exec('ROLLBACK');
      connection.close();
    }
  };
}
export function unlockStoppedWorker(database: string): void {
  // Successfully acquiring the OS lock proves no other worker owns it. Never delete the SQLite lock file.
  acquireLock(database)();
}
