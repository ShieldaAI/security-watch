import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as api from '../dist/index.js';
import { Store } from '../dist/index.js';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

test('the exported names match the committed public API list', () => {
  // Adding, renaming or removing an export is a compatibility decision: update
  // scripts/public-api.json, CHANGELOG.md and docs/compatibility.md together.
  assert.deepEqual(Object.keys(api).sort(), JSON.parse(read('../scripts/public-api.json')));
});

test('worker internals are absent from the published Store type', () => {
  const declaration = read('../dist/store.d.ts');
  for (const internal of [
    'claimDue',
    'claimAdditionalDigest',
    'completeJob',
    'completeBatch',
    'deferJob',
    'recoverSending',
    'markUncertain',
    'getMeta',
    'setMeta',
    'reserveBudget',
  ])
    assert.ok(!new RegExp(`\\b${internal}\\(`).test(declaration), internal);
  for (const stable of [
    'findings',
    'getFinding',
    'history',
    'jobs',
    'summary',
    'acknowledge',
    'suppress',
    'backup',
    'saveEvidence',
    'saveAssessment',
  ])
    assert.ok(new RegExp(`\\b${stable}\\(`).test(declaration), stable);
  assert.equal(typeof Store.prototype.acknowledge, 'function');
});

test('the version is defined once and the documents agree with it', () => {
  const { version, engines, publishConfig } = JSON.parse(read('../package.json'));
  const lock = JSON.parse(read('../package-lock.json'));
  assert.equal(lock.version, version);
  assert.equal(lock.packages[''].version, version);
  const images = [
    ...read('../compose.yaml').matchAll(/image: ghcr\.io\/shieldaai\/security-watch:(\S+)/g),
  ].map(([, tag]) => tag);
  assert.ok(images.length >= 2, 'both services name the image');
  for (const tag of images) assert.equal(tag, version, 'compose.yaml');
  assert.ok(read('../CHANGELOG.md').includes(`## ${version}`));
  assert.equal(engines.node, '>=24.10.0');
  // A prerelease never publishes to the default tag, and a stable release always does.
  assert.equal(publishConfig.tag === 'latest', !version.split('+')[0].includes('-'));
  // Every place that names the package with a version names this one.
  for (const file of ['../README.md', '../docs/offline-advisory-preview.md', '../scripts/check-docker.mjs']) {
    const named = [
      ...read(file).matchAll(/security-watch`?[@:\- ](\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.\d+)*)?)/g),
    ];
    assert.ok(named.length, `${file} names the version`);
    for (const [, found] of named) assert.equal(found, version, file);
  }
  assert.ok(!/console\.log\('\d+\.\d+\.\d+/.test(read('../src/cli.ts')), 'no hard-coded version in the CLI');
});
