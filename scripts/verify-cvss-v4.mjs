// Offline, exhaustive adaptation check against the separately retrieved, pinned FIRST browser files.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import vm from 'node:vm';
import { cvssV4BaseScore } from '../dist/cvss4.js';

if (process.argv.length !== 3)
  throw new Error('Usage: node scripts/verify-cvss-v4.mjs /path/to/pinned-reference-files');
const manifest = JSON.parse(
  readFileSync(new URL('../docs/vendor/cvss-v4-provenance.json', import.meta.url), 'utf8'),
);
const hash = (value) => createHash('sha256').update(value).digest('hex');
const executedFiles = Object.fromEntries(
  ['dist/cvss4.js', 'dist/vendor/cvss4-reference.js'].map((name) => [
    name,
    hash(readFileSync(new URL('../' + name, import.meta.url))),
  ]),
);
const files = new Map();
for (const [name, entry] of Object.entries(manifest.files)) {
  const content = readFileSync(resolve(process.argv[2], name));
  assert.equal(hash(content), entry.sha256, `Pinned reference hash mismatch: ${name}`);
  files.set(name, content.toString('utf8'));
}
// Execute only after every original file has passed the checked-in hash manifest.
const reference = vm.createContext({});
for (const [name, content] of files) {
  if (name.endsWith('.js')) vm.runInContext(content, reference, { filename: name, timeout: 1000 });
}
const metrics = Object.entries(reference.expectedMetricOrder);
const base = metrics.slice(0, 11);
const count = base.reduce((total, [, values]) => total * values.length, 1);
const scores = {};
for (let sample = 0; sample < count; sample++) {
  let index = sample;
  const selected = Object.fromEntries(metrics.map(([metric]) => [metric, 'X']));
  for (const [metric, values] of base) {
    selected[metric] = values[index % values.length];
    index = Math.floor(index / values.length);
  }
  const vector = 'CVSS:4.0/' + base.map(([metric]) => `${metric}:${selected[metric]}`).join('/');
  const expected = reference.cvss_score(
    selected,
    reference.cvssLookup_global,
    reference.maxSeverity,
    reference.macroVector(selected),
  );
  assert.equal(cvssV4BaseScore(vector)?.score, expected, vector);
  scores[expected] = (scores[expected] ?? 0) + 1;
}
console.log(
  JSON.stringify(
    {
      version: 1,
      checked_at: new Date().toISOString(),
      node: process.version,
      reference_commit: manifest.commit,
      reference_files_sha256: Object.fromEntries(
        Object.entries(manifest.files).map(([name, entry]) => [name, entry.sha256]),
      ),
      adapted_source_sha256: hash(readFileSync(new URL('../src/vendor/cvss4-reference.ts', import.meta.url))),
      wrapper_source_sha256: hash(readFileSync(new URL('../src/cvss4.ts', import.meta.url))),
      executed_files_sha256: executedFiles,
      compared_base_vectors: count,
      matched_base_vectors: count,
      mismatches: 0,
      score_distribution: scores,
      limits: [
        'Adaptation parity with the pinned upstream implementation; not independent proof of CVSS correctness.',
        'Fourteen published FIRST example scores are asserted separately in test/cvss4.test.mjs.',
        'No contextual threat/environment scores or production alert accuracy are measured.',
      ],
    },
    null,
    2,
  ),
);
