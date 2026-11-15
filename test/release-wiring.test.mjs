// `npm run release` end to end, with npm replaced by a stub that records what it was asked to do.
// Nothing is published: the stub only writes a log.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { registryProblem, releaseTag } from '../scripts/release-tag.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const tag = releaseTag(manifest.version);

function workspace(t) {
  const directory = mkdtempSync(join(tmpdir(), 'sw-release-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const stub = join(directory, 'npm-stub.mjs');
  writeFileSync(
    stub,
    `import { appendFileSync } from 'node:fs';
const args = process.argv.slice(2);
appendFileSync(process.env.STUB_LOG, JSON.stringify({
  args,
  stated: process.env.SECURITY_WATCH_RELEASE_TAG ?? null,
  inheritedTag: process.env.npm_config_tag ?? null,
}) + '\\n');
if (args[0] === 'config') {
  const value = args[2] === 'registry' ? process.env.STUB_REGISTRY : process.env.STUB_SCOPED;
  process.stdout.write(value ?? 'undefined');
}
`,
  );
  return { stub, log: join(directory, 'calls.log') };
}

/** Runs scripts/release.mjs as `npm run release` would, with npm replaced by the stub. */
function release(t, { args = [], env = {} } = {}) {
  const { stub, log } = workspace(t);
  const clean = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.toLowerCase().startsWith('npm_config_')),
  );
  const result = spawnSync(process.execPath, [join(root, 'scripts/release.mjs'), ...args], {
    cwd: root,
    encoding: 'utf8',
    timeout: 30_000,
    env: { ...clean, npm_execpath: stub, STUB_LOG: log, ...env },
  });
  const calls = existsSync(log)
    ? readFileSync(log, 'utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line))
    : [];
  return { result, calls, publish: calls.find((call) => call.args[0] === 'publish') };
}

test('the release command publishes under the tag chosen from the version', (t) => {
  const { result, publish } = release(t, { env: { npm_config_tag: 'latest' } });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(publish.args, ['publish', '--tag', tag]);
  assert.equal(publish.stated, tag, 'the tag is stated to the release check');
  assert.equal(publish.inheritedTag, null, 'a tag setting from the environment is not passed on');
  const rehearsal = release(t, { args: ['--dry-run'] });
  assert.deepEqual(rehearsal.publish.args, ['publish', '--tag', tag, '--dry-run']);
});

test('the release command refuses before publishing when npm would skip the checks or go elsewhere', (t) => {
  for (const [label, options, message] of [
    ['ignore-scripts before the --', { env: { npm_config_ignore_scripts: 'true' } }, /ignore scripts/],
    [
      'another registry',
      { env: { STUB_REGISTRY: 'https://registry.example.com/' } },
      /registry\.example\.com/,
    ],
    [
      'a scoped registry in .npmrc',
      { env: { STUB_SCOPED: 'http://127.0.0.1:4873/' } },
      /@shieldaai packages to http:\/\/127\.0\.0\.1:4873/,
    ],
    ['an option after the --', { args: ['--ignore-scripts'] }, /accepts only --dry-run and --otp=CODE/],
    ['a tag after the --', { args: ['--tag=latest'] }, /accepts only --dry-run and --otp=CODE/],
  ]) {
    const { result, publish } = release(t, options);
    assert.notEqual(result.status, 0, label);
    assert.match(result.stderr, message, label);
    assert.equal(publish, undefined, `${label}: nothing is published`);
  }
});

test('a registry setting is refused unless it is the public npm registry', () => {
  for (const settings of [
    {},
    { registry: 'https://registry.npmjs.org/', scoped: 'undefined' },
    { registry: 'https://registry.npmjs.org', scoped: '' },
    { registry: 'undefined', scoped: 'null' },
  ])
    assert.equal(registryProblem(settings), undefined, JSON.stringify(settings));
  assert.match(registryProblem({ scoped: 'https://npm.example.com/' }), /@shieldaai packages/);
  assert.match(registryProblem({ registry: 'https://registry.npmjs.org.example.com/' }), /releases go to/);
});
