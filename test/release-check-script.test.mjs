// The release check as npm runs it (`prepublishOnly`): the real script in a throwaway git
// repository, with real git and a stand-in for npm that answers `config get`, `run check` and
// `pack`. Nothing is published and nothing reaches a registry.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scripts = fileURLToPath(new URL('../scripts/', import.meta.url));
const STUB = `
import { appendFileSync } from 'node:fs';
const args = process.argv.slice(2);
appendFileSync(process.env.STUB_LOG, JSON.stringify({ args, dryRun: process.env.npm_config_dry_run ?? null }) + '\\n');
if (args[0] === 'config' && args[1] === 'get')
  console.log(args[2] === 'registry' ? (process.env.STUB_REGISTRY ?? 'https://registry.npmjs.org/') : 'undefined');
else if (args[0] === 'run' && args[1] === 'check') process.exit(Number(process.env.STUB_CHECK_EXIT ?? 0));
else if (args[0] === 'pack')
  console.log(JSON.stringify([{ files: process.env.STUB_PACKED.split(',').map((path) => ({ path })) }]));
else process.exit(9);
`;

function workspace(t) {
  const root = mkdtempSync(join(tmpdir(), 'sw-release-check-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repo = join(root, 'repo');
  const outside = join(root, 'outside');
  mkdirSync(join(repo, 'scripts'), { recursive: true });
  mkdirSync(join(repo, 'docs'));
  mkdirSync(outside);
  for (const file of ['release-check.mjs', 'release-tag.mjs'])
    copyFileSync(join(scripts, file), join(repo, 'scripts', file));
  writeFileSync(
    join(repo, 'package.json'),
    JSON.stringify({
      name: '@shieldaai/security-watch',
      version: '1.0.0-rc.1',
      publishConfig: { tag: 'next' },
    }),
  );
  writeFileSync(join(repo, 'docs', 'guide.md'), '# Guide\n');
  writeFileSync(join(repo, '.gitignore'), 'docs/notes.db\n');
  const git = (...args) =>
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', ...args], {
      cwd: repo,
      stdio: 'pipe',
    });
  git('init', '-q');
  git('add', '-A');
  git('commit', '-q', '-m', 'init');
  writeFileSync(join(outside, 'npm.mjs'), STUB);
  const log = join(outside, 'log.jsonl');
  writeFileSync(log, '');
  // The environment of a publish started by `npm run release`, without anything inherited from the
  // npm run that runs these tests.
  const base = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) => !/^npm_/i.test(key) && key !== 'SECURITY_WATCH_RELEASE_TAG',
    ),
  );
  const run = (extra = {}) => {
    const result = spawnSync(process.execPath, [join(repo, 'scripts', 'release-check.mjs')], {
      cwd: repo,
      encoding: 'utf8',
      timeout: 30_000,
      env: {
        ...base,
        npm_execpath: join(outside, 'npm.mjs'),
        npm_config_dry_run: 'true',
        SECURITY_WATCH_RELEASE_TAG: 'next',
        STUB_LOG: log,
        STUB_PACKED: 'package.json,docs/guide.md,dist/index.js',
        ...extra,
      },
    });
    const calls = readFileSync(log, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    writeFileSync(log, '');
    return { ...result, calls };
  };
  return { repo, run };
}

test('the release check passes a clean checkout and runs the full check without the publish options', (t) => {
  const { run } = workspace(t);
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(
    result.calls.map(({ args }) => args.slice(0, 2).join(' ')),
    ['config get', 'config get', 'run check', 'pack --dry-run'],
  );
  const check = result.calls.find(({ args }) => args[0] === 'run');
  assert.equal(check.dryRun, null, 'the dry-run setting is not passed to the check');
});

test('the release check refuses a bare publish, another registry and a failing check', (t) => {
  const { run } = workspace(t);
  const bare = run({ SECURITY_WATCH_RELEASE_TAG: '' });
  assert.notEqual(bare.status, 0);
  assert.match(bare.stderr, /npm run release/);
  const wrongTag = run({ SECURITY_WATCH_RELEASE_TAG: 'latest' });
  assert.notEqual(wrongTag.status, 0);
  assert.match(wrongTag.stderr, /must be published under the next tag/);
  const registry = run({ STUB_REGISTRY: 'https://npm.example.com/' });
  assert.notEqual(registry.status, 0);
  assert.match(registry.stderr, /npm\.example\.com/);
  assert.ok(!registry.calls.some(({ args }) => args[0] === 'run'), 'refused before the check runs');
  const failing = run({ STUB_CHECK_EXIT: '1' });
  assert.notEqual(failing.status, 0);
  assert.ok(!failing.calls.some(({ args }) => args[0] === 'pack'), 'nothing is packed after a failed check');
});

test('the release check refuses an ignored file the package would include, and a dirty checkout', (t) => {
  const { repo, run } = workspace(t);
  // An ignored file does not show in git status, but npm would pack it.
  writeFileSync(join(repo, 'docs', 'notes.db'), 'private');
  const ignored = run({ STUB_PACKED: 'package.json,docs/guide.md,docs/notes.db,dist/index.js' });
  assert.notEqual(ignored.status, 0);
  assert.match(ignored.stderr, /not in git: docs\/notes\.db/);
  writeFileSync(join(repo, 'docs', 'guide.md'), '# Changed\n');
  const dirty = run();
  assert.notEqual(dirty.status, 0);
  assert.match(dirty.stderr, /clean committed checkout/);
  assert.deepEqual(dirty.calls, [], 'nothing runs from a dirty checkout');
});
