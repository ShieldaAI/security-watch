import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { prepare, score } from '../scripts/review-advisory-holdout.mjs';

const sum = (data) => createHash('sha256').update(data).digest('hex');
const save = (path, doc) => {
  const bytes = Buffer.from(JSON.stringify(doc));
  writeFileSync(path, bytes, { mode: 0o600 });
  return sum(bytes);
};
const read = (path) => JSON.parse(readFileSync(path));
function fixture(t, withMissing = false) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-test-holdout-')),
    output = join(dir, 'review');
  t.after(() => rmSync(dir, { force: true, recursive: true }));
  mkdirSync(join(dir, 'sources'));
  mkdirSync(join(dir, 'registry'));
  const policy = {
    version: 1,
    replay_at: '2025-01-10T12:00:00.000Z',
    window: { from: '2025-01-10', until: '2025-01-11' },
    library_rule: { levels: ['high', 'critical'], basis: 'source_severity', channels: ['slack'] },
    urgent_unknown: true,
    gate: {
      min_cases: 100,
      min_risk: 60,
      min_urgent: 1,
      min_benign: 1,
      require_every_case_resolved: true,
      max_quiet_risk: 0,
      require_all_urgent_immediate: true,
      max_unnecessary_immediate: 0,
    },
  };
  save(join(dir, 'review-policy.json'), policy);
  // Both archives name the package; the second REST document lost its affected package.
  // An independent source still identifies a deployed vulnerable version.
  const advisory = (id, omitted) => {
    const source_file = 'sources/' + id + '.json',
      github_file = 'sources/' + id + '.github.json';
    const source_sha256 = save(join(dir, source_file), {
      id,
      aliases: [],
      published: '2025-01-07T00:00:00Z',
      modified: '2025-01-08T00:00:00Z',
      affected: [{ package: { ecosystem: 'npm', name: 'alpha' }, versions: ['1.0.0'] }],
    });
    const github_sha256 = save(join(dir, github_file), {
      ghsa_id: id,
      type: 'reviewed',
      updated_at: '2025-01-08T00:00:00Z',
      published_at: '2025-01-07T00:00:00Z',
      severity: 'critical',
      summary: 'Source record',
      vulnerabilities: omitted
        ? []
        : [{ package: { ecosystem: 'npm', name: 'alpha' }, vulnerable_version_range: '< 2.0.0' }],
    });
    return {
      id,
      aliases: [],
      published: '2025-01-07T00:00:00Z',
      modified: '2025-01-08T00:00:00Z',
      source_file,
      source_sha256,
      github_file,
      github_sha256,
    };
  };
  const matched = advisory('GHSA-abcd-efgh-1234', false),
    absent = advisory('GHSA-ijkl-mnop-5678', true);
  const cases = Array.from({ length: 100 }, (_, i) => ({
    case_id: 'sw-' + i.toString(16).padStart(16, '0'),
    advisory: withMissing && i === 0 ? absent : matched,
    deployment: {
      system_id: 'system-' + i,
      component_id: 'component',
      ecosystem: 'npm',
      package_name: 'alpha',
      version: i < 60 ? '1.0.0' : '2.0.0',
      exposure: 'internal',
      criticality: 'medium',
      environment: 'staging',
    },
  }));
  const roster = save(join(dir, 'case-inputs.json'), { version: 1, cases });
  const releases = cases.map(({ case_id, deployment: d }) => ({
    case_id,
    ecosystem: d.ecosystem,
    package_name: d.package_name,
    version: d.version,
    released_at: '2025-01-07T00:00:00Z',
  }));
  const release_documents = releases.map((row) => {
    const source_file = 'registry/' + row.case_id + '.json',
      source_sha256 = save(join(dir, source_file), { name: row.package_name, version: row.version });
    return { case_id: row.case_id, source_file, source_sha256 };
  });
  save(join(dir, 'registry/index.json'), { version: 1, case_inputs_sha256: roster, release_documents });
  save(join(dir, 'release-evidence.json'), { version: 1, case_inputs_sha256: roster, releases });
  return { dir, output };
}
function labelSyntheticBallot(output, slot) {
  const path = join(output, 'ballot-' + slot + '.json'),
    ballot = read(path);
  ballot.reviewer = 'fixture-' + slot;
  ballot.blinded = true;
  ballot.reviews.forEach((row, i) => {
    row.label = i < 60 ? 'urgent' : 'benign';
    row.applicability = i < 60 ? 'affected' : 'not_affected';
    row.evidence_support = 'supported';
    row.rationale = 'Synthetic unit test evidence.';
  });
  save(path, ballot);
  return ballot;
}
test('a frozen external roster requires independent resolved votes and unchanged evidence before passing', async (t) => {
  const { dir, output } = fixture(t);
  const receipt = await prepare(dir, output),
    grade = () => score(dir, output, receipt.enrollment_id);
  const pending = await grade();
  assert.equal(pending.coverage.unreviewed, 100);
  assert.equal(pending.policy.urgent_immediate.rate, null);
  assert.equal(pending.status, 'inconclusive');
  await assert.rejects(prepare(dir, output), /exist/i);
  await assert.rejects(score(dir, output, 'a'.repeat(64)), /changed/);
  labelSyntheticBallot(output, 'a');
  assert.equal((await grade()).coverage.single_review, 100);
  const second = labelSyntheticBallot(output, 'b');
  const b = join(output, 'ballot-b.json');
  const accepted = await grade();
  assert.equal(accepted.status, 'passed');
  assert.equal(accepted.policy.urgent_immediate.denominator, 60);
  second.reviews[0].evidence_support = 'uncertain';
  save(b, second);
  const disagreement = await grade();
  assert.equal(disagreement.coverage.unresolved_conflicts, 1);
  assert.equal(disagreement.status, 'inconclusive');
  const adjudication = join(dir, 'adjudication.json');
  save(adjudication, {
    version: 1,
    enrollment_id: receipt.enrollment_id,
    adjudications: [
      {
        ...second.reviews[0],
        adjudicator: 'third-reviewer',
        evidence_support: 'supported',
        rationale: 'Independent fixture clarification.',
      },
    ],
  });
  assert.equal((await score(dir, output, receipt.enrollment_id, adjudication)).status, 'passed');
  second.reviews[0].rationale = '';
  save(b, second);
  await assert.rejects(grade, /private rationale/);
  second.reviews[0].rationale = 'Synthetic unit test evidence.';
  second.reviews[0].evidence_support = 'supported';
  second.reviews[0].label = 'abstain';
  save(b, second);
  assert.equal((await grade()).status, 'inconclusive');
  second.reviewer = 'fixture-a';
  save(b, second);
  await assert.rejects(grade, /distinct reviewers/);
  second.reviewer = 'fixture-b';
  second.reviews[0].case_id = second.reviews[1].case_id;
  save(b, second);
  await assert.rejects(grade, /repeated ballot/);
  save(join(dir, 'sources/GHSA-abcd-efgh-1234.github.json'), {});
  await assert.rejects(grade, /Source bytes/);
});
test('when a vulnerable deployment has no matching finding it stays in the enrolled denominator as a quiet miss', async (t) => {
  const { dir, output } = fixture(t, true);
  const receipt = await prepare(dir, output);
  labelSyntheticBallot(output, 'a');
  labelSyntheticBallot(output, 'b');
  const result = await score(dir, output, receipt.enrollment_id);
  assert.equal(result.status, 'failed');
  assert.equal(result.roster_cases, 100);
  assert.equal(result.cases_without_a_finding, 1);
  assert.deepEqual(result.policy.quiet_risk, { numerator: 1, denominator: 60, rate: 1 / 60 });
  assert.equal(result.policy.urgent_immediate.numerator, 59);
});

test('preparation rejects missing releases, post-cutoff evidence and unmeasurable gates before issuing ballots', async (t) => {
  const { dir, output } = fixture(t);
  const releasePath = join(dir, 'release-evidence.json'),
    policyPath = join(dir, 'review-policy.json');
  const releases = read(releasePath),
    policy = read(policyPath);
  save(releasePath, { ...releases, releases: [] });
  await assert.rejects(prepare(dir, output), /release evidence/);
  const [first, ...rest] = releases.releases;
  save(releasePath, { ...releases, releases: [{ ...first, released_at: '2027-01-01T00:00:00Z' }, ...rest] });
  await assert.rejects(prepare(dir, output), /cutoff/);
  save(releasePath, releases);
  for (const x of ['100', 100.5, 101]) {
    save(policyPath, { ...policy, gate: { ...policy.gate, min_cases: x } });
    await assert.rejects(prepare(dir, output), /gate/);
  }
});
