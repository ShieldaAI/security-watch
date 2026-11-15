import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { scorePilotRecall, scorePilotResponses, Store } from '../dist/index.js';

const window = { from: '2025-09-20', until: '2025-09-21' };
const iso = (time) => new Date(time).toISOString();
const available = Date.parse(window.from) + 3600_000,
  deadline = available + 3600_000,
  through = Date.parse(window.until) + 3600_000;
const canary = 'PrivateEvidence-7D0f',
  reviewer = 'private-analyst',
  curator = 'private-curator';
const names = ['both', 'provider', 'human', 'triage-only', 'blank', 'missing', 'deadline'];
const id = (name) => 'PrivateIncident-' + name;
const incident = (name) => ({
  incident_id: id(name),
  event_refs: ['event-' + name],
  system_ref: 'private-deployment',
  component_ref: null,
  available_at: iso(available),
  deadline_at: iso(deadline),
});
const reference = (cases = names) => ({
  version: 1,
  window: { ...window },
  curator,
  selected_independently: true,
  incidents: cases.map(incident),
});
const stage = (status, time = null, source = null) => ({
  status,
  at: time === null ? null : iso(time),
  evidence_ref: source,
});
const row = (name, acknowledgement = stage('unreviewed'), triage = stage('unreviewed')) => ({
  incident_id: id(name),
  acknowledgement,
  triage,
});
const register = (binding, responses = []) => ({
  version: 1,
  recall_evaluation_id: binding,
  reviewer,
  reviewed_independently: true,
  reviewed_through: iso(through),
  responses,
});
async function setup(t, ref = reference()) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-independent-response-'));
  const store = new Store(join(dir, 'live.db'));
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  for (const name of ['both', 'provider']) {
    const finding = {
      id: 'finding-' + name,
      event_id: 'event-' + name,
      system_id: 'private-deployment',
      category: 'product',
      applicability: 'affected',
      source_severity: 'critical',
      priority: 'critical',
      title: canary,
      summary: canary,
      evidence_ids: [],
      reasons: [],
      urls: [],
      exploited: true,
      updated_at: iso(available),
    };
    store.saveAssessment(finding, { action: 'notify', channels: ['slack'], reason: canary }, available);
    store.completeJob(store.claimDue(available).id, 'accepted', available, undefined, available + 9);
    // An internal operator action supplies no external human-response evidence.
    store.acknowledge(finding.id);
  }
  const backup = join(dir, 'frozen.db');
  await store.backup(backup);
  const recall = await scorePilotRecall(backup, window, ref);
  return { dir, store, backup, ref, recall };
}
function privateResult(result) {
  const text = JSON.stringify(result);
  for (const value of [
    canary,
    reviewer,
    curator,
    'PrivateIncident',
    'finding-',
    'event-',
    'private-deployment',
  ])
    assert(!text.includes(value));
}

test('compares external human actions with frozen same-incident provider receipts and retains every incident in each denominator', async (t) => {
  const { ref, recall, backup } = await setup(t);
  const responses = register(recall.evaluation_id, [
    row('both', stage('observed', available + 2, canary), stage('observed', available, canary)),
    row('provider', stage('unresolved'), stage('no_record', null, 'scope-a')),
    row('human', stage('observed', available + 4, 'case-b'), stage('observed', through, 'case-b')),
    row('triage-only', stage('no_record', null, 'scope-a'), stage('observed', deadline - 1, 'case-c')),
    row('blank', stage('unreviewed'), stage('unresolved')),
    row('deadline', stage('observed', deadline, 'case-d')),
  ]);
  const bytes = readFileSync(backup);
  const report = await scorePilotResponses(backup, window, ref, responses);
  assert.equal(report.mode, 'pilot_responses');
  assert.equal(report.recall_evaluation_id, recall.evaluation_id);
  assert.equal(report.reference_incidents, 7);
  assert.equal(report.reviewed_through, iso(through));
  assert.deepEqual(report.acknowledgement.outcomes, {
    on_time: 2,
    late: 1,
    no_record: 1,
    unresolved: 1,
    unreviewed: 2,
  });
  assert.deepEqual(report.triage.outcomes, {
    on_time: 2,
    late: 1,
    no_record: 1,
    unresolved: 1,
    unreviewed: 2,
  });
  for (const outcome of [report.acknowledgement, report.triage]) {
    assert.deepEqual(outcome.on_time, { numerator: 2, denominator: 7, rate: 2 / 7 });
    assert.deepEqual(outcome.reviewed, { numerator: 5, denominator: 7, rate: 5 / 7 });
    assert.deepEqual(outcome.resolved, { numerator: 4, denominator: 7, rate: 4 / 7 });
    assert.deepEqual(outcome.paired_with_on_time_provider, {
      both: 1,
      provider_only_confirmed: 1,
      human_only_confirmed: 1,
      neither_confirmed: 4,
    });
  }
  assert.deepEqual(report.acknowledgement.first_response_after_availability, {
    count: 3,
    median_ms: 4,
    p95_ms: deadline - available,
  });
  assert.deepEqual(report.triage.first_response_after_availability, {
    count: 3,
    median_ms: deadline - available - 1,
    p95_ms: through - available,
  });
  privateResult(report);
  assert.deepEqual(readFileSync(backup), bytes);
  for (const suffix of ['-wal', '-shm', '-journal']) assert(!existsSync(backup + suffix));
});

test('empty response evidence and zero reference preserve null rates and absence of measured latency', async (t) => {
  for (const keys of [[], ['both']]) {
    const { ref, recall, backup } = await setup(t, reference(keys));
    const report = await scorePilotResponses(backup, window, ref, register(recall.evaluation_id));
    for (const s of [report.acknowledgement, report.triage]) {
      assert.equal(s.outcomes.unreviewed, keys.length);
      assert.deepEqual(s.first_response_after_availability, { count: 0, median_ms: null, p95_ms: null });
      for (const metric of [s.on_time, s.resolved, s.reviewed])
        assert.deepEqual(metric, { numerator: 0, denominator: keys.length, rate: keys.length ? 0 : null });
    }
  }
});

test('freezes both public inputs before backup I/O; binds evidence, review and exact recall scope, independent of row ordering', async (t) => {
  const { ref, recall, backup, store, dir } = await setup(t);
  const evidence = register(recall.evaluation_id, [
    row('both', stage('observed', available, 'source-a')),
    row('blank'),
  ]);
  const copy = structuredClone(evidence),
    refCopy = structuredClone(ref);
  const pending = scorePilotResponses(backup, window, ref, evidence);
  evidence.responses[0].acknowledgement.at = iso(deadline);
  ref.incidents.length = 0;
  const report = await pending;
  assert.equal(report.acknowledgement.on_time.numerator, 1);
  copy.responses.reverse();
  assert.deepEqual(await scorePilotResponses(backup, window, refCopy, copy), report);
  const changed = structuredClone(copy);
  changed.responses[1].acknowledgement.evidence_ref = 'other-record';
  assert.notEqual(
    (await scorePilotResponses(backup, window, refCopy, changed)).evaluation_id,
    report.evaluation_id,
  );
  for (const alternate of [
    { ...copy, reviewer: 'second-reviewer' },
    { ...copy, reviewed_through: iso(through + 1) },
  ])
    assert.notEqual(
      (await scorePilotResponses(backup, window, refCopy, alternate)).evaluation_id,
      report.evaluation_id,
    );
  const next = join(dir, 'new.db');
  store.setMeta('private', 'later-state');
  await store.backup(next);
  await assert.rejects(() => scorePilotResponses(next, window, refCopy, copy), /Invalid pilot response/);
  await assert.rejects(
    () => scorePilotResponses(backup, window, { ...refCopy, curator: 'someone-else' }, copy),
    /Invalid pilot response/,
  );
});

test('rejects invalid attestations, ambiguous response records, incoherent times and wrong scope before opening backup', async () => {
  const ref = reference();
  const good = register('b'.repeat(64));
  for (const register of [
    { ...good, reviewer: curator },
    { ...good, reviewer: 'Not Canonical' },
    { ...good, reviewed_independently: false },
    { ...good, recall_evaluation_id: 'x' },
    { ...good, reviewed_through: iso(Date.now() + 86400_000) },
    { ...good, reviewed_through: iso(Date.parse(window.until) - 1) },
    { ...good, reviewed_through: '2025-09-31T00:00:00.000Z' },
    { ...good, responses: [row('both'), row('both')] },
    { ...good, responses: [row('not-enrolled')] },
    { ...good, responses: Array(1001).fill(row('both')) },
    {
      ...good,
      responses: [
        row('both', stage('observed', available, 'same')),
        row('human', stage('unreviewed'), stage('observed', available, 'same')),
      ],
    },
    ...[
      stage('observed', available - 1, 'early'),
      stage('observed', through + 1, 'future'),
      stage('observed', available, null),
      stage('observed', available, 'https://secret.invalid'),
      stage('no_record', null, null),
      stage('no_record', available, 'scope'),
      stage('unreviewed', null, 'foo'),
      stage('unresolved', available),
      stage('accepted'),
      { ...stage('unreviewed'), note: canary },
    ].map((answer) => ({ ...good, responses: [row('both', answer)] })),
  ])
    await assert.rejects(
      () => scorePilotResponses('missing', window, ref, register),
      (error) => error.message.includes('Invalid pilot response') && !error.message.includes(canary),
    );
});

test('arbitrary JavaScript evidence objects cannot invoke getters, proxies or sparse array hooks', async () => {
  let invoked = 0;
  function trap() {
    invoked++;
    throw new Error(canary);
  }
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  const malicious = stage('unreviewed');
  Object.defineProperty(malicious, 'at', { get: trap, enumerable: true });
  const list = [];
  Object.defineProperty(list, '0', { get: trap, enumerable: true });
  for (const input of [
    revoked.proxy,
    { ...register('a'.repeat(64)), responses: list },
    register('a'.repeat(64), Array(1)),
    register('a'.repeat(64), [row('both', malicious)]),
    new Proxy(register('a'.repeat(64)), { getPrototypeOf: trap, get: trap }),
  ])
    await assert.rejects(
      () => scorePilotResponses('missing', window, reference(), input),
      /Invalid pilot response/,
    );
  assert.equal(invoked, 0);
});

test('CLI reads a private response register, accepts a response file over 1 MiB, creates only an exclusive aggregate and redacts input errors', async (t) => {
  const { ref, recall, backup, dir } = await setup(t);
  const input = join(dir, 'incidents.json'),
    responseFile = join(dir, canary + '.json'),
    output = join(dir, 'score.json');
  const evidence = register(recall.evaluation_id, [row('human', stage('observed', available, canary))]);
  writeFileSync(input, JSON.stringify(ref), { mode: 0o600 });
  writeFileSync(responseFile, JSON.stringify(evidence) + ' '.repeat(1024 * 1024), { mode: 0o600 });
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const run = (extra = []) =>
    spawnSync(
      process.execPath,
      [
        cli,
        'pilot-recall',
        '--backup',
        backup,
        '--from',
        window.from,
        '--until',
        window.until,
        '--input',
        input,
        '--responses',
        responseFile,
        ...extra,
      ],
      { encoding: 'utf8', env: { NODE_NO_WARNINGS: '1' } },
    );
  const expected = await scorePilotResponses(backup, window, ref, evidence);
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), expected);
  privateResult(expected);
  const published = run(['--output', output]);
  assert.equal(published.status, 0, published.stderr);
  assert.equal(published.stdout, '');
  assert.deepEqual(JSON.parse(readFileSync(output)), expected);
  if (process.platform !== 'win32') assert.equal(statSync(output).mode & 0o777, 0o600);
  assert.notEqual(run(['--output', output]).status, 0);
  const fail = () => {
    const r = run();
    assert.notEqual(r.status, 0);
    assert.equal(r.stdout, '');
    for (const secret of [canary, dir, reviewer]) assert(!r.stderr.includes(secret));
  };
  writeFileSync(
    responseFile,
    JSON.stringify(evidence).replace(
      '"reviewed_independently":true',
      '"reviewed_independen\\u0074ly":false,"reviewed_independently":true',
    ),
  );
  fail();
  writeFileSync(responseFile, ' '.repeat(2 * 1024 * 1024 + 1));
  fail();
  rmSync(responseFile);
  symlinkSync(input, responseFile);
  fail();
  rmSync(responseFile);
  writeFileSync(responseFile, JSON.stringify(evidence), { mode: 0o600 });
  linkSync(responseFile, join(dir, 'alias'));
  fail();
  rmSync(join(dir, 'alias'));
  if (process.platform !== 'win32') {
    chmodSync(responseFile, 0o644);
    fail();
  }
});
