import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import {
  chmodSync,
  copyFileSync,
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
import { createPilotCasePacket, scorePilotCases, Store, verifyBackup } from '../dist/index.js';

const window = { from: '2025-05-04', until: '2025-05-05' };
const start = Date.parse(window.from),
  end = Date.parse(window.until);
const secret = 'PRIVATE_AI_TEXT_AND_REASON',
  reviewer = 'private-reviewer',
  system = 'private-deployment';
function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-cohort-')),
    dbPath = join(dir, 'current.db');
  const store = new Store(dbPath);
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  function add(name, action = 'record', channels = [], changes = {}, time = start, review) {
    const finding = {
      id: 'internal-finding-' + name,
      system_id: system,
      component_id: 'internal-component',
      event_id: 'source-event-' + name,
      title: secret,
      summary: secret,
      reasons: [secret],
      evidence_ids: ['source-ref-' + name],
      urls: ['https://private.invalid/' + secret],
      category: 'library',
      applicability: 'affected',
      source_severity: 'critical',
      priority: 'critical',
      exploited: false,
      updated_at: new Date(time).toISOString(),
      ...changes,
    };
    store.saveAssessment(finding, { action, channels, ...(review ? { review } : {}), reason: secret }, time);
  }
  async function backup(name = 'standalone.db') {
    const path = join(dir, name);
    await store.backup(path);
    return path;
  }
  return { dir, store, add, backup, dbPath };
}
const empty = (packet) => ({ version: 1, packet_id: packet.packet_id, reviews: [], adjudications: [] });
function label(feedback, item, label, who = reviewer) {
  feedback.reviews.push({ case_id: item.case_id, reviewer: who, label, blinded: true });
}
async function rejected(fn, secretValue = secret) {
  await assert.rejects(fn, (error) => !error.message.includes(secretValue) && /pilot/i.test(error.message));
}
function assertPrivateScore(score, packet) {
  const json = JSON.stringify(score);
  for (const value of [
    packet.packet_id,
    packet.cases[0]?.case_id,
    secret,
    reviewer,
    system,
    'source-event-',
    'internal-component',
    'internal-finding-',
  ].filter(Boolean))
    assert.equal(json.includes(value), false);
}
test('research packet binds a complete half-open backup cohort and exports only local lookup fields', async (t) => {
  const f = setup(t);
  f.add('before', 'record', [], {}, start - 1);
  f.add('after', 'record', [], {}, end);
  f.add('one');
  f.add('one', 'notify', ['slack'], { priority: 'low' }, start + 300);
  f.add('two', 'digest', [], { category: 'news', evidence_ids: [] }, end - 1);
  f.add('retired', 'record', [], { active: false });
  f.add('withdrawn', 'record', [], { withdrawn: true });
  f.add('health', 'notify', ['email'], { category: 'health' });
  const path = await f.backup(),
    before = readFileSync(path);
  const packet = await createPilotCasePacket(path, window);
  assert.equal(packet.excluded_revisions, 3);
  assert.equal(packet.cases.length, 3);
  assert.equal(new Set(packet.cases.map((c) => c.case_id)).size, 3);
  assert.deepEqual(
    packet.cases.map((c) => c.event_ref),
    ['source-event-one', 'source-event-one', 'source-event-two'],
  );
  for (const c of packet.cases) {
    assert.deepEqual(Object.keys(c).sort(), [
      'case_id',
      'component_ref',
      'event_ref',
      'evidence_refs',
      'recorded_at',
      'system_ref',
    ]);
    assert.match(c.case_id, /^[0-9a-f]{64}$/);
    assert.equal(c.system_ref, system);
  }
  for (const value of [
    secret,
    'internal-finding-',
    'private.invalid',
    'digest',
    'notify',
    'affected',
    '"action"',
    '"priority"',
    '"reviewer"',
  ])
    assert(!JSON.stringify(packet).includes(value));
  assert.deepEqual(readFileSync(path), before);
  assert((await verifyBackup(path)).ok);
  for (const x of ['-wal', '-shm', '-journal']) assert(!existsSync(path + x));
  const clone = join(f.dir, 'copy.db');
  copyFileSync(path, clone);
  assert.deepEqual(await createPilotCasePacket(clone, window), packet);
  await rejected(() => createPilotCasePacket(f.dbPath, window));
});
test('pairs score actual saved routing eligibility regardless of delivery success or model conclusions', async (t) => {
  const f = setup(t);
  f.add('urgent-visible', 'notify', ['email', 'slack']);
  f.add('urgent-quiet', 'notify', []);
  f.add('review', 'digest', [], {}, start, 'ai_general_news');
  f.add('benign-page', 'notify', ['slack']);
  f.add('digest', 'digest', ['email']);
  const job = f.store.claimDue(start);
  f.store.completeJob(job.id, 'unknown', start);
  const path = await f.backup(),
    packet = await createPilotCasePacket(path, window);
  const feedback = empty(packet);
  for (const c of packet.cases) {
    const grading = {
      'source-event-urgent-visible': 'urgent',
      'source-event-urgent-quiet': 'urgent',
      'source-event-review': 'must_review',
      'source-event-benign-page': 'benign',
      'source-event-digest': 'benign',
    }[c.event_ref];
    label(feedback, c, grading);
    label(feedback, c, grading, 'second');
  }
  const score = await scorePilotCases(path, window, feedback);
  assert.equal(score.coverage.scored, 5);
  assert.equal(score.coverage.agreements, 5);
  assert.deepEqual(score.policy, {
    urgent_immediate: { numerator: 1, denominator: 2, rate: 0.5 },
    quiet_risk: { numerator: 1, denominator: 3, rate: 1 / 3 },
    unnecessary_immediate: { numerator: 1, denominator: 2, rate: 0.5 },
  });
  assert.equal(score.unmeasured.population_urgent_recall, null);
  assert.equal(score.unmeasured.delivered_false_alert_rate, null);
  assertPrivateScore(score, packet);
});
test('partial reviews, abstentions, disagreements and adjudications have explicit populations', async (t) => {
  const f = setup(t);
  for (let i = 0; i < 6; i++) f.add(String(i));
  const path = await f.backup(),
    p = await createPilotCasePacket(path, window),
    feedback = empty(p);
  const [single, abstain, pending, resolved, alsoAbstains] = p.cases;
  label(feedback, single, 'benign');
  for (const [c, first, second] of [
    [abstain, 'abstain', 'abstain'],
    [pending, 'benign', 'urgent'],
    [resolved, 'benign', 'urgent'],
    [alsoAbstains, 'abstain', 'urgent'],
  ]) {
    label(feedback, c, first);
    label(feedback, c, second, 'analyst-b');
  }
  feedback.adjudications.push(
    { case_id: resolved.case_id, adjudicator: 'third', label: 'must_review' },
    { case_id: alsoAbstains.case_id, adjudicator: 'third', label: 'abstain' },
  );
  const score = await scorePilotCases(path, window, feedback);
  assert.deepEqual(score.coverage, {
    eligible: 6,
    excluded: 0,
    unreviewed: 1,
    single_review: 1,
    agreements: 1,
    disagreements: 3,
    adjudicated: 2,
    unresolved_conflicts: 1,
    abstained: 2,
    scored: 1,
  });
  assert.equal(score.policy.quiet_risk.rate, 1);
  assert.equal(score.policy.urgent_immediate.rate, null);
  const blank = await scorePilotCases(path, window, empty(p));
  assert.equal(blank.coverage.unreviewed, 6);
  assert(Object.values(blank.policy).every((m) => m.denominator === 0 && m.rate === null));
});
test('rejects incomplete identity, forged cases, repeated reviews, self-adjudication and overrides of agreement', async (t) => {
  const f = setup(t);
  f.add('example');
  const path = await f.backup(),
    p = await createPilotCasePacket(path, window);
  const c = p.cases[0],
    row = { case_id: c.case_id, reviewer: 'one', blinded: true, label: 'urgent' },
    two = { ...row, reviewer: 'two', label: 'benign' },
    arb = { case_id: c.case_id, adjudicator: 'three', label: 'urgent' };
  for (const [reviews, adjudications] of [
    [[row, row], []],
    [[row, { ...two, reviewer: 'ONE' }], []],
    [[row, { ...two, reviewer: ' one' }], []],
    [[{ ...row, blinded: false }], []],
    [[{ ...row, case_id: '0'.repeat(64) }], []],
    [[row, two, { ...two, reviewer: 'three' }], []],
    [[row], [arb]],
    [[row, two], [{ ...arb, adjudicator: 'two' }]],
    [[row, { ...two, label: 'urgent' }], [arb]],
    [
      [row, two],
      [arb, arb],
    ],
  ])
    await rejected(() => scorePilotCases(path, window, { ...empty(p), reviews, adjudications }));
});
test('feedback is bound to the exact backup and dates; caller mutation during verification cannot retarget a label', async (t) => {
  const f = setup(t);
  f.add('one');
  const path = await f.backup(),
    p = await createPilotCasePacket(path, window),
    fb = empty(p);
  label(fb, p.cases[0], 'urgent');
  label(fb, p.cases[0], 'urgent', 'two');
  const scoring = scorePilotCases(path, window, fb);
  fb.reviews[0].label = 'benign';
  fb.reviews[1].label = 'benign';
  assert.equal((await scoring).policy.quiet_risk.numerator, 1);
  await rejected(() => scorePilotCases(path, { from: '2025-05-03', until: window.until }, fb));
  f.store.setMeta('independent-change', secret);
  const other = await f.backup('other.db');
  await rejected(() => scorePilotCases(other, window, fb));
  const p2 = await createPilotCasePacket(other, window);
  assert.notEqual(p.packet_id, p2.packet_id);
  await rejected(() => scorePilotCases(other, window, { ...fb, packet_id: p2.packet_id }));
});
test('excess history and malformed stored routing fail closed without publishing partial totals', async (t) => {
  const f = setup(t);
  f.add('first');
  const db = new DatabaseSync(f.dbPath);
  try {
    db.exec("UPDATE finding_revisions SET decision='{}'");
    const invalid = await f.backup('invalid.db');
    await rejected(() => createPilotCasePacket(invalid, window));
    db.exec(`WITH RECURSIVE n(x) AS (VALUES(2) UNION ALL SELECT x+1 FROM n WHERE x<1001)
      INSERT INTO finding_revisions SELECT finding_id,x,payload,decision,recorded_at FROM finding_revisions,n WHERE revision=1`);
    const large = await f.backup('large.db');
    await rejected(() => createPilotCasePacket(large, window));
  } finally {
    db.close();
  }
});
const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
test('CLI keeps private case pointers off stdout, rejects unsafe feedback/outputs and preserves standalone backup', async (t) => {
  const f = setup(t);
  f.add('one');
  const path = await f.backup();
  const args = ['--backup', path, '--from', window.from, '--until', window.until];
  const run = (command, ...flags) =>
    spawnSync(process.execPath, [cli, command, ...args, ...flags], { cwd: f.dir, encoding: 'utf8' });
  const output = join(f.dir, 'private.json');
  assert.notEqual(run('pilot-cases').status, 0);
  const created = run('pilot-cases', '--output', output);
  assert.equal(created.status, 0, created.stderr);
  assert.equal(created.stdout, '');
  if (process.platform !== 'win32') assert.equal(statSync(output).mode & 0o777, 0o600);
  const original = readFileSync(output, 'utf8'),
    packet = JSON.parse(original),
    fb = empty(packet);
  assert.notEqual(run('pilot-cases', '--output', output).status, 0);
  assert.equal(readFileSync(output, 'utf8'), original);
  const data = join(f.dir, 'labels.json');
  writeFileSync(data, JSON.stringify(fb), { mode: 0o600 });
  const scored = run('pilot-score', '--input', data);
  assert.equal(scored.status, 0, scored.stderr);
  assert.equal(JSON.parse(scored.stdout).coverage.eligible, 1);
  label(fb, packet.cases[0], 'urgent');
  label(fb, packet.cases[0], 'urgent', 'two');
  const ambiguous = JSON.stringify(fb).replace(
    '"label":"urgent"',
    String.raw`"la\u0062el":"benign","label":"urgent"`,
  );
  writeFileSync(data, ambiguous);
  const dup = run('pilot-score', '--input', data);
  assert.notEqual(dup.status, 0);
  assert.equal(dup.stdout, '');
  assert(!dup.stderr.includes(packet.cases[0].case_id));
  writeFileSync(data, JSON.stringify(fb));
  const malformed = join(f.dir, 'bad.json');
  writeFileSync(malformed, secret, { mode: 0o600 });
  const bad = run('pilot-score', '--input', malformed, '--output', join(f.dir, 'absent.json'));
  assert.notEqual(bad.status, 0);
  assert.equal(bad.stdout, '');
  assert(!bad.stderr.includes(secret));
  assert(!existsSync(join(f.dir, 'absent.json')));
  const link = join(f.dir, 'linked.json');
  symlinkSync(data, link);
  assert.notEqual(run('pilot-score', '--input', link).status, 0);
  const hard = join(f.dir, 'hard.json');
  linkSync(data, hard);
  assert.notEqual(run('pilot-score', '--input', data).status, 0);
  rmSync(hard);
  if (process.platform !== 'win32') {
    chmodSync(data, 0o644);
    assert.notEqual(run('pilot-score', '--input', data).status, 0);
  }
  assert.notEqual(run('pilot-cases', '--output', path + '-wal').status, 0);
  assert.equal(existsSync(path + '-wal'), false);
  assert((await verifyBackup(path)).ok);
});

test('public case and score APIs reject accessors, inherited votes and proxies before loading a backup', async () => {
  let touched = 0;
  const unsafe = () => {
    touched++;
    throw Error(secret);
  };
  const fd = { version: 1, packet_id: '0'.repeat(64), reviews: [], adjudications: [] };
  const ballot = { case_id: '0'.repeat(64), reviewer: 'one', blinded: true, label: 'urgent' };
  const arrays = [];
  Object.defineProperty(arrays, '0', { enumerable: true, get: unsafe });
  const revoked = Proxy.revocable([], {});
  revoked.revoke();
  for (const input of [
    {
      ...fd,
      get reviews() {
        return unsafe();
      },
    },
    Object.create(fd),
    new Proxy(fd, { ownKeys: unsafe }),
    { ...fd, reviews: arrays },
    { ...fd, reviews: revoked.proxy },
    { ...fd, reviews: new Array(1) },
    { ...fd, reviews: [Object.create(ballot)] },
    {
      ...fd,
      reviews: [
        {
          ...ballot,
          get label() {
            return unsafe();
          },
        },
      ],
    },
    {
      ...fd,
      adjudications: [
        {
          case_id: ballot.case_id,
          get adjudicator() {
            return unsafe();
          },
          label: 'benign',
        },
      ],
    },
    { ...fd, reviews: [{ ...ballot, reviewer: new Proxy({}, { get: unsafe }) }] },
  ])
    await assert.rejects(
      scorePilotCases(secret, window, input),
      (error) => error.message.startsWith('Invalid pilot feedback') && !error.message.includes(secret),
    );
  for (const input of [
    {
      get from() {
        return unsafe();
      },
      until: window.until,
    },
    new Proxy(window, { getOwnPropertyDescriptor: unsafe }),
    Object.create(window),
  ]) {
    await assert.rejects(createPilotCasePacket(secret, input), /complete UTC days/);
    await assert.rejects(scorePilotCases(secret, input, fd), /complete UTC days/);
  }
  assert.equal(touched, 0);
});
