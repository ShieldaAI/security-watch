import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  mkdirSync,
  statSync,
  symlinkSync,
  linkSync,
  chmodSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { acquireLock, unlockStoppedWorker } from '../dist/lock.js';

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-lock-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return join(dir, 'watch.db');
}
async function waitFor(fn) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (fn()) return;
    await delay(20);
  }
  assert.fail('Timed out waiting for lock process');
}

test('exclusive worker lock excludes another worker and releases cleanly without deleting lock database', (t) => {
  const path = fixture(t);
  const release = acquireLock(path);
  assert.throws(() => acquireLock(path), /Another scan or worker/);
  assert.throws(() => unlockStoppedWorker(path), /Another scan or worker/);
  assert.equal(statSync(`${path}.worker-lock`).mode & 0o777, 0o600);
  release();
  assert(!existsSync(`${path}.lock`));
  assert(existsSync(`${path}.worker-lock`));
  const again = acquireLock(path);
  again();
});

test('failed same-process acquisitions preserve the first worker lock against other processes', (t) => {
  const path = fixture(t);
  const release = acquireLock(path);
  t.after(release);
  const module = new URL('../dist/lock.js', import.meta.url).href;
  const code = `import {acquireLock} from ${JSON.stringify(module)};
    try { const release = acquireLock(process.argv[1]); release(); console.log('acquired'); }
    catch (error) { if (!/Another scan or worker/.test(error.message)) throw error; console.log('blocked'); }`;
  const attempt = () => {
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', code, path], {
      encoding: 'utf8',
      timeout: 5000,
    });
    assert.equal(child.status, 0, child.stderr || child.error?.message);
    return child.stdout.trim();
  };
  assert.throws(() => acquireLock(path), /Another scan or worker/);
  assert.equal(attempt(), 'blocked');
  assert.throws(() => unlockStoppedWorker(path), /Another scan or worker/);
  assert.equal(attempt(), 'blocked');
  release();
  assert.equal(attempt(), 'acquired');
});

test('existing worker lock database permissions must be private and are not repaired online', (t) => {
  if (process.platform === 'win32') return t.skip('POSIX file permissions');
  const path = fixture(t);
  const release = acquireLock(path);
  release();
  chmodSync(`${path}.worker-lock`, 0o644);
  assert.throws(() => acquireLock(path), /private permissions/);
  assert.equal(statSync(`${path}.worker-lock`).mode & 0o777, 0o644);
  chmodSync(`${path}.worker-lock`, 0o600);
  acquireLock(path)();
});

test('existing worker lock hard links and nonregular files are rejected', (t) => {
  const path = fixture(t);
  const target = `${path}.target`;
  writeFileSync(target, 'keep', { mode: 0o600 });
  linkSync(target, `${path}.worker-lock`);
  assert.throws(() => acquireLock(path), /hard links/);
  assert.equal(readFileSync(target, 'utf8'), 'keep');
  rmSync(`${path}.worker-lock`);
  mkdirSync(`${path}.worker-lock`);
  assert.throws(() => acquireLock(path), /regular files/);
});

test('stale metadata with a reused active PID does not block an unowned OS lock', (t) => {
  const path = fixture(t);
  writeFileSync(`${path}.lock`, JSON.stringify({ pid: process.pid, nonce: 'old-container' }));
  const release = acquireLock(path);
  assert.notEqual(JSON.parse(readFileSync(`${path}.lock`, 'utf8')).nonce, 'old-container');
  release();
});

test('abrupt child death releases OS ownership without relying on PID files or cleanup hooks', async (t) => {
  const path = fixture(t);
  const module = new URL('../dist/lock.js', import.meta.url).href;
  const code = `import {acquireLock} from ${JSON.stringify(module)}; const release=acquireLock(process.argv[1]); console.log('locked'); setInterval(()=>{void release},1000);`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code, path], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (chunk) => {
    output += chunk;
  });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  });
  await waitFor(() => output.includes('locked'));
  assert.throws(() => acquireLock(path), /Another scan or worker/);
  child.kill('SIGKILL');
  await waitFor(() => child.signalCode !== null);
  assert(existsSync(`${path}.lock`));
  const release = acquireLock(path);
  release();
  assert(!existsSync(`${path}.lock`));
});

test('metadata write failure does not retain the SQLite ownership transaction', (t) => {
  const path = fixture(t);
  mkdirSync(`${path}.lock`);
  assert.throws(() => acquireLock(path));
  rmSync(`${path}.lock`, { recursive: true });
  const release = acquireLock(path);
  release();
});

test('worker lock database symlink is rejected without modifying its target', (t) => {
  const path = fixture(t);
  const target = `${path}.target`;
  writeFileSync(target, 'keep');
  symlinkSync(target, `${path}.worker-lock`);
  assert.throws(() => acquireLock(path), /symbolic link/);
  assert.equal(readFileSync(target, 'utf8'), 'keep');
});

test('informational lock metadata symlink cannot overwrite an unrelated file', (t) => {
  const path = fixture(t);
  const target = `${path}.target`;
  writeFileSync(target, 'keep');
  symlinkSync(target, `${path}.lock`);
  let release;
  try {
    assert.throws(() => {
      release = acquireLock(path);
    }, /symbolic link|link|ELOOP/i);
  } finally {
    if (release) release();
  }
  assert.equal(readFileSync(target, 'utf8'), 'keep');
});

test('dangling lock-file symlinks are rejected without creating targets', (t) => {
  const path = fixture(t);
  const databaseTarget = `${path}.missing-database`;
  symlinkSync(databaseTarget, `${path}.worker-lock`);
  assert.throws(() => acquireLock(path), /symbolic link|ELOOP/i);
  assert(!existsSync(databaseTarget));
  rmSync(`${path}.worker-lock`);
  const metadataTarget = `${path}.missing-metadata`;
  symlinkSync(metadataTarget, `${path}.lock`);
  assert.throws(() => acquireLock(path), /symbolic link|ELOOP/i);
  assert(!existsSync(metadataTarget));
});
