import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
import { DatabaseSync } from 'node:sqlite';
import { createPilotResponseTemplate, Store, scorePilotRecall, verifyBackup } from '../dist/index.js';
import { removeAcceptanceSchema } from './helpers/legacy-notifications.mjs';

const window = { from: '2025-08-01', until: '2025-08-02' };
const start = Date.parse(window.from),
  end = Date.parse(window.until),
  iso = (t) => new Date(t).toISOString();
const available = start + 3600000,
  deadline = start + 7200000;
const curator = 'private-reviewer',
  system = 'private-tenant',
  component = 'component-secret',
  canary = 'PRIVATE-PROVIDER-TEXT';

function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'watch-pilot-recall-')),
    database = join(dir, 'monitor.db');
  const store = new Store(database);
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  function save(
    event,
    time,
    action = 'record',
    changes = {},
    channels = action === 'notify' ? ['slack'] : [],
    digestMs,
  ) {
    store.saveAssessment(
      {
        id: 'private-finding-' + event,
        event_id: event,
        system_id: system,
        component_id: component,
        category: 'library',
        applicability: 'affected',
        source_severity: 'critical',
        priority: 'critical',
        title: canary,
        summary: canary,
        evidence_ids: [],
        reasons: [],
        urls: [],
        exploited: false,
        updated_at: iso(time),
        ...changes,
      },
      { action, channels, reason: canary },
      time,
      digestMs,
    );
  }
  async function backup(name = 'standalone.db') {
    const path = join(dir, name);
    await store.backup(path);
    return path;
  }
  return { dir, database, store, save, backup };
}

function incident(name, changes = {}) {
  return {
    incident_id: 'private-case-' + name,
    event_refs: [name],
    system_ref: system,
    component_ref: component,
    available_at: iso(available),
    deadline_at: iso(deadline),
    ...changes,
  };
}
function reference(incidents = []) {
  return { version: 1, window: { ...window }, curator, selected_independently: true, incidents };
}
function safe(score) {
  for (const secret of [
    canary,
    curator,
    system,
    component,
    'private-case',
    'private-finding',
    'CVE-20',
    'GHSA-',
  ])
    assert(!JSON.stringify(score).includes(secret));
}

test('reviewer worksheet snapshots the entire external roster and conceals which incidents had alerts', async (t) => {
  const fixture = setup(t);
  fixture.save('second', available, 'notify');
  const backup = await fixture.backup();
  const roster = reference([incident('second'), incident('first')]);
  const recall = await scorePilotRecall(backup, window, roster);
  const pending = createPilotResponseTemplate(backup, window, roster);
  roster.incidents[0].incident_id = canary;
  roster.incidents.pop();
  const sheet = await pending;
  assert.equal(sheet.recall_evaluation_id, recall.evaluation_id);
  assert.deepEqual(
    sheet.responses.map((row) => row.incident_id),
    ['private-case-first', 'private-case-second'],
  );
  for (const row of sheet.responses) {
    assert.deepEqual(row.acknowledgement, { status: 'unreviewed', at: null, evidence_ref: null });
    assert.deepEqual(row.triage, row.acknowledgement);
  }
  for (const sensitive of [canary, curator, component, system, 'private-finding', 'provider_acceptance']) {
    assert.equal(JSON.stringify(sheet).includes(sensitive), false);
  }
});
function rejected(fn) {
  return assert.rejects(
    fn,
    (e) => /pilot|incident|window|UTC/i.test(e.message) && !e.message.includes(canary),
  );
}

test('external denominator includes unseen incidents and credits each timely deployment only once', async (t) => {
  const f = setup(t);
  const ref = reference([
    incident('CVE-2025-8888', { event_refs: ['cve-2025-8888', 'ghsa-xxxx-yyyy-zzzz'] }),
    incident('digest'),
    incident('prior'),
    incident('late'),
    incident('absent'),
    incident('empty-channels'),
  ]);
  f.save('GHSA-XXXX-YYYY-ZZZZ', available, 'record');
  f.save('GHSA-XXXX-YYYY-ZZZZ', deadline - 1, 'notify', { priority: 'high' });
  f.save('CVE-2025-8888', deadline - 2, 'notify');
  f.save('digest', available, 'digest', {}, ['slack']);
  f.save('digest', deadline, 'notify', { priority: 'low' });
  f.save('prior', available - 1, 'notify');
  f.save('late', available - 1, 'record');
  f.save('late', deadline, 'notify', { priority: 'high' });
  f.save('empty-channels', available, 'notify', {}, []);
  const path = await f.backup(),
    original = readFileSync(path);
  const result = await scorePilotRecall(path, window, ref);
  assert.equal(result.reference_incidents, 6);
  assert.deepEqual(result.outcomes, {
    on_time_immediate: 1,
    on_time_other: 2,
    late_only: 0,
    prior_and_late: 1,
    prior_only: 1,
    no_retained_match: 1,
  });
  assert.deepEqual(result.metrics, {
    on_time_observed: { numerator: 3, denominator: 6, rate: 0.5 },
    on_time_immediate: { numerator: 1, denominator: 6, rate: 1 / 6 },
  });
  assert.equal(result.unmeasured.population_urgent_recall, null);
  assert.equal(result.unmeasured.monitor_window_completeness, null);
  assert.equal(result.unmeasured.delivered_alert_recall, null);
  assert.deepEqual(readFileSync(path), original);
  for (const extra of ['-wal', '-shm', '-journal']) assert(!existsSync(path + extra));
  assert((await verifyBackup(path)).ok);
  safe(result);
});

test('matches exact event and target without credentials, title, evidence or component wildcard joins', async (t) => {
  const f = setup(t);
  f.save('different-event', available, 'notify', { title: 'reference-1', evidence_ids: ['reference-1'] });
  f.save('foreign', available, 'notify', { system_id: 'other-system' });
  f.save('component', available, 'notify', { component_id: 'other-component' });
  f.save('system-only', available, 'notify', { component_id: undefined });
  f.save('withdrawn', available, 'notify', { withdrawn: true });
  f.save('retired', available, 'notify', { active: false });
  f.save('health', available, 'notify', { category: 'health' });
  f.save('outside', end, 'notify');
  f.save('before', start - 1, 'notify');
  const names = [
    'reference-1',
    'foreign',
    'component',
    'withdrawn',
    'retired',
    'health',
    'outside',
    'before',
  ];
  const ref = reference([
    ...names.map((n) => incident(n)),
    incident('system-only'),
    incident('system-null', { event_refs: ['system-only'], component_ref: null }),
  ]);
  const score = await scorePilotRecall(await f.backup(), window, ref);
  assert.equal(score.outcomes.on_time_immediate, 1);
  assert.equal(score.outcomes.no_retained_match, 9);
  assert.equal(score.metrics.on_time_immediate.rate, 0.1);
});

test('availability starts the response interval, the deadline is exclusive, and the last UTC midnight is outside the snapshot query', async (t) => {
  const f = setup(t);
  f.save('available', available, 'notify');
  f.save('deadline', deadline, 'notify');
  f.save('last-millisecond', end - 1, 'notify');
  f.save('ending-midnight', end, 'notify');
  const r = await scorePilotRecall(
    await f.backup(),
    window,
    reference([
      incident('available'),
      incident('deadline'),
      incident('last-millisecond', { deadline_at: iso(end) }),
      incident('ending-midnight', { deadline_at: iso(end) }),
    ]),
  );
  assert.deepEqual(r.outcomes, {
    on_time_immediate: 2,
    on_time_other: 0,
    late_only: 1,
    prior_and_late: 0,
    prior_only: 0,
    no_retained_match: 1,
  });
});

test('empty external denominator stays unmeasured even when monitor decisions exist', async (t) => {
  const f = setup(t);
  f.save('one', available, 'notify');
  const r = await scorePilotRecall(await f.backup(), window, reference());
  assert.equal(r.reference_incidents, 0);
  for (const metric of Object.values(r.metrics))
    assert.deepEqual(metric, { numerator: 0, denominator: 0, rate: null });
  assert.deepEqual(r.provider_acceptance.on_time, { numerator: 0, denominator: 0, rate: null });
  assert.deepEqual(r.provider_acceptance.first_acceptance_after_availability, {
    count: 0,
    median_ms: null,
    p95_ms: null,
  });
  safe(r);
});

test('actual provider acknowledgements include carried-over digests, distinguish queue states, and deduplicate across aliases, revisions and destinations', async (t) => {
  const f = setup(t);
  const finish = (name, when, status, receipt) => {
    const job = f.store.claimDue(when);
    assert.equal(job?.finding_id, 'private-finding-' + name);
    if (status !== 'sending') f.store.completeJob(job.id, status, when, undefined, receipt);
  };
  f.save('multi-alias', available - 5, 'notify', {}, ['slack', 'email']);
  finish('multi-alias', available - 5, 'accepted', available - 1);
  finish('multi-alias', available - 5, 'accepted', available + 10);
  f.save('multi-alias', available, 'notify', { priority: 'high' });
  finish('multi-alias', available, 'accepted', available + 20);
  f.save('multi-other-alias', available, 'notify');
  finish('multi-other-alias', available, 'accepted', deadline);
  f.save('cross-midnight', start - 4, 'digest', {}, ['email'], 4);
  finish('cross-midnight', start, 'accepted', available);
  f.save('late', available, 'notify');
  finish('late', available, 'accepted', end + 15);
  f.save('clock-reversed', available, 'notify');
  finish('clock-reversed', available, 'accepted', available - 1);
  f.save('no-timestamp', available, 'notify');
  finish('no-timestamp', available, 'accepted');
  f.save('wrong-deployment', available, 'notify', { system_id: 'another' });
  finish('wrong-deployment', available, 'accepted', available + 1);
  f.save('older-expired', start - 2, 'notify');
  finish('older-expired', start - 2, 'accepted', end);
  for (const status of ['failed', 'unknown', 'sending']) {
    f.save(status, available, 'notify');
    finish(status, available, status);
  }
  f.save('pending', available, 'notify');
  f.save('record', available);
  const names = [
    'cross-midnight',
    'late',
    'clock-reversed',
    'no-timestamp',
    'wrong-deployment',
    'older-expired',
    'failed',
    'unknown',
    'sending',
    'pending',
    'record',
    'absent',
  ];
  const ref = reference([
    incident('multiple', { event_refs: ['multi-alias', 'multi-other-alias'] }),
    ...names.map((name) => incident(name)),
  ]);
  const result = await scorePilotRecall(await f.backup(), window, ref);
  assert.deepEqual(result.provider_acceptance, {
    on_time: { numerator: 2, denominator: 13, rate: 2 / 13 },
    on_time_immediate: { numerator: 1, denominator: 13, rate: 1 / 13 },
    incidents_with: {
      on_time: 2,
      before_availability: 1,
      at_or_after_deadline: 2,
      accepted_time_unknown: 2,
      pending: 1,
      sending: 1,
      unknown: 1,
      failed: 1,
    },
    without_retained_job: 4,
    first_acceptance_after_availability: { count: 3, median_ms: 10, p95_ms: end + 15 - available },
  });
  assert.equal(result.outcomes.no_retained_match, 4);
  safe(result);
});

test('a notification follows its own frozen revision and target even if the latest finding points elsewhere', async (t) => {
  const f = setup(t);
  f.save('old', start - 20, 'notify', { id: 'shared-finding' });
  const inFlight = f.store.claimDue(start);
  f.save('new', available, 'notify', { id: 'shared-finding' });
  f.store.completeJob(inFlight.id, 'accepted', start, undefined, available + 1);
  const path = await f.backup();
  const older = await scorePilotRecall(path, window, reference([incident('old')]));
  assert.deepEqual(older.provider_acceptance.on_time, { numerator: 1, denominator: 1, rate: 1 });
  assert.equal(older.outcomes.no_retained_match, 1);
  const newer = await scorePilotRecall(path, window, reference([incident('new')]));
  assert.equal(newer.provider_acceptance.on_time.numerator, 0);
  assert.equal(newer.provider_acceptance.incidents_with.pending, 1);
  assert.equal(newer.metrics.on_time_immediate.numerator, 1);
});

test('verified schema-6 backup retains untimed acceptance and exact original bytes', async (t) => {
  const f = setup(t);
  f.save('before-upgrade', available, 'notify');
  const job = f.store.claimDue(available);
  f.store.completeJob(job.id, 'accepted', available, undefined, available + 5);
  const path = await f.backup();
  const db = new DatabaseSync(path);
  try {
    db.exec('PRAGMA journal_mode=DELETE');
    removeAcceptanceSchema(db);
    db.exec('PRAGMA user_version=6');
  } finally {
    db.close();
  }
  const bytes = readFileSync(path);
  const r = await scorePilotRecall(path, window, reference([incident('before-upgrade')]));
  assert.equal(r.provider_acceptance.incidents_with.accepted_time_unknown, 1);
  assert.deepEqual(r.provider_acceptance.on_time, { numerator: 0, denominator: 1, rate: 0 });
  assert.equal(r.provider_acceptance.first_acceptance_after_availability.count, 0);
  assert.equal(r.metrics.on_time_immediate.numerator, 1);
  assert.deepEqual(readFileSync(path), bytes);
  for (const extra of ['-wal', '-shm', '-journal']) assert(!existsSync(path + extra));
});

test('a manual retry credits the eventual response only in the later backup', async (t) => {
  const f = setup(t);
  const ref = reference([incident('retry'), incident('second')]);
  f.save('retry', available, 'notify');
  const job = f.store.claimDue(available);
  f.store.completeJob(job.id, 'unknown', available, canary);
  const first = await f.backup('before-retry.db');
  f.store.retryJob(job.id, available + 1);
  assert.equal(f.store.claimDue(available + 1).id, job.id);
  f.store.completeJob(job.id, 'accepted', available + 1, undefined, available + 4);
  f.save('second', available, 'notify');
  f.store.completeJob(f.store.claimDue(available).id, 'accepted', available, undefined, available + 5);
  const second = await f.backup('after-retry.db');
  const before = await scorePilotRecall(first, window, ref);
  assert.equal(before.provider_acceptance.incidents_with.unknown, 1);
  assert.equal(before.provider_acceptance.on_time.numerator, 0);
  const after = await scorePilotRecall(second, window, ref);
  assert.equal(after.provider_acceptance.incidents_with.unknown, 0);
  assert.deepEqual(after.provider_acceptance.on_time, { numerator: 2, denominator: 2, rate: 1 });
  assert.deepEqual(after.provider_acceptance.first_acceptance_after_availability, {
    count: 2,
    median_ms: 4.5,
    p95_ms: 5,
  });
  assert.notEqual(after.evaluation_id, before.evaluation_id);
  safe(before);
  safe(after);
});

test('oversized or invalid saved job metadata fails privately before publication', async (t) => {
  const f = setup(t);
  f.save('one', available, 'notify');
  for (const [index, payload] of [
    JSON.stringify({ mode: canary }),
    JSON.stringify({ mode: 'notify', value: 'x'.repeat(512 * 1024) }),
  ].entries()) {
    const path = await f.backup('invalid-' + index + '.db');
    const db = new DatabaseSync(path);
    try {
      db.exec('PRAGMA journal_mode=DELETE');
      db.prepare('UPDATE notifications SET payload=?').run(payload);
    } finally {
      db.close();
    }
    const before = readFileSync(path);
    await assert.rejects(
      () => scorePilotRecall(path, window, reference([incident('one')])),
      (error) => /could not validate|size limit/i.test(error.message) && !error.message.includes(canary),
    );
    assert.deepEqual(readFileSync(path), before);
  }
});

test('an accepted job whose payload identifies a different finding or deployment fails privately', async (t) => {
  const f = setup(t);
  f.save('one', available, 'notify');
  f.store.completeJob(f.store.claimDue(available).id, 'accepted', available, undefined, available);
  for (const key of ['id', 'event_id', 'system_id', 'component_id']) {
    const path = await f.backup('different-' + key + '.db');
    const db = new DatabaseSync(path);
    try {
      db.exec('PRAGMA journal_mode=DELETE');
      db.prepare('UPDATE notifications SET payload=json_set(payload,?,?)').run('$.assessment.' + key, canary);
      if (key === 'system_id') {
        removeAcceptanceSchema(db);
        db.exec('PRAGMA user_version=6');
      }
    } finally {
      db.close();
    }
    const before = readFileSync(path);
    await assert.rejects(
      () => scorePilotRecall(path, window, reference([incident('one')])),
      (error) => /could not validate/i.test(error.message) && !error.message.includes(canary),
    );
    assert.deepEqual(readFileSync(path), before);
  }
});

test('evaluation ID binds original backup, window, target aliases, timeliness and curator; input mutation cannot regrade', async (t) => {
  const f = setup(t);
  f.save('one', available, 'notify');
  const path = await f.backup(),
    list = reference([incident('one'), incident('two')]);
  const pending = scorePilotRecall(path, window, list);
  list.incidents[0].event_refs[0] = 'substituted';
  const first = await pending;
  assert.equal(first.outcomes.on_time_immediate, 1);
  const change = await scorePilotRecall(path, window, list);
  assert.equal(change.outcomes.on_time_immediate, 0);
  assert.notEqual(change.evaluation_id, first.evaluation_id);
  const copy = join(f.dir, 'copy.db');
  copyFileSync(path, copy);
  assert.deepEqual(
    await scorePilotRecall(copy, window, reference([incident('two'), incident('one')])),
    first,
  );
  f.save('out-of-cohort', available, 'record');
  const other = await scorePilotRecall(
    await f.backup('next.db'),
    window,
    reference([incident('one'), incident('two')]),
  );
  assert.deepEqual(other.outcomes, first.outcomes);
  assert.notEqual(other.evaluation_id, first.evaluation_id);
  assert.notEqual(
    (
      await scorePilotRecall(path, window, {
        ...reference([incident('one'), incident('two')]),
        curator: 'other',
      })
    ).evaluation_id,
    first.evaluation_id,
  );
  const longerWindow = { ...window, until: '2025-08-03' };
  assert.notEqual(
    (
      await scorePilotRecall(path, longerWindow, {
        ...reference([incident('one'), incident('two')]),
        window: longerWindow,
      })
    ).evaluation_id,
    first.evaluation_id,
  );
});

test('rejects duplicate incidents and aliases, incomplete observation windows and ambiguous scope before reading backup', async () => {
  const one = incident('CVE-2025-0101');
  for (const list of [
    [one, one],
    [one, incident('different', { event_refs: ['cve-2025-0101'] })],
    [{ ...one, event_refs: ['CVE-2025-0101', 'cve-2025-0101'] }],
    [{ ...one, event_refs: [] }],
    [{ ...one, event_refs: Array.from({ length: 17 }, (_, i) => String(i)) }],
    [{ ...one, event_refs: [canary + '\0'] }],
    [{ ...one, system_ref: 3 }],
    [{ ...one, component_ref: undefined }],
    [{ ...one, available_at: iso(start - 1) }],
    [{ ...one, deadline_at: iso(end + 1) }],
    [{ ...one, available_at: one.deadline_at }],
    [{ ...one, available_at: '2025-07-32T00:00:00.000Z' }],
    [{ ...one, available_at: 'August 1 2025' }],
    Array(1001).fill(one),
  ])
    await assert.rejects(
      () => scorePilotRecall('missing', window, reference(list)),
      /Invalid independent incident reference/,
    );
  for (const ref of [
    { ...reference(), selected_independently: false },
    { ...reference(), curator: 'a b' },
    { ...reference(), window: { from: '2025-07-31', until: window.until } },
  ]) {
    await assert.rejects(
      () => scorePilotRecall('missing', window, ref),
      /Invalid independent incident reference/,
    );
  }
});

test('refuses getters, sparse arrays and proxies without invoking caller code or echoing input', async () => {
  let calls = 0;
  const angry = () => {
    calls++;
    throw new Error(canary);
  };
  const bad = incident('one');
  Object.defineProperty(bad, 'component_ref', { get: angry, enumerable: true });
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  const aliases = [];
  Object.defineProperty(aliases, '0', { get: angry, enumerable: true });
  for (const ref of [
    reference([bad]),
    reference(Array(2)),
    reference([incident('two', { event_refs: aliases })]),
    revoked.proxy,
    reference([Object.assign(Object.create({}), incident('three'))]),
  ])
    await rejected(() => scorePilotRecall('missing', window, ref));
  await rejected(() =>
    scorePilotRecall(
      'missing',
      {
        get from() {
          return angry();
        },
        until: window.until,
      },
      reference([]),
    ),
  );
  assert.equal(calls, 0);
});

test('CLI accepts a private incident register, publishes an aggregate exclusively and preserves backup integrity', async (t) => {
  const f = setup(t);
  f.save('one', available, 'notify');
  const path = await f.backup();
  const input = join(f.dir, 'private-reference.json'),
    output = join(f.dir, 'score.json');
  const ref = reference([incident('one'), incident('missing')]);
  writeFileSync(input, JSON.stringify(ref), { mode: 0o600 });
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const run = (args = []) =>
    spawnSync(
      process.execPath,
      [
        cli,
        'pilot-recall',
        '--backup',
        path,
        '--from',
        window.from,
        '--until',
        window.until,
        '--input',
        input,
        ...args,
      ],
      { encoding: 'utf8', cwd: f.dir },
    );
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.metrics.on_time_observed.rate, 0.5);
  safe(report);
  const written = run(['--output', output]);
  assert.equal(written.status, 0, written.stderr);
  assert.equal(written.stdout, '');
  assert.deepEqual(JSON.parse(readFileSync(output)), report);
  if (process.platform !== 'win32') assert.equal(statSync(output).mode & 0o777, 0o600);
  assert.notEqual(run(['--output', output]).status, 0);
  const raw = JSON.stringify(ref).replace(
    '"selected_independently":true',
    String.raw`"selected_indepe\u006edently":false,"selected_independently":true`,
  );
  writeFileSync(input, raw);
  const bad = run();
  assert.notEqual(bad.status, 0);
  assert.equal(bad.stdout, '');
  assert(!bad.stderr.includes(curator));
  assert(!bad.stderr.includes(input));
  rmSync(input);
  symlinkSync(path, input);
  assert.notEqual(run().status, 0);
  rmSync(input);
  writeFileSync(input, JSON.stringify(ref), { mode: 0o600 });
  linkSync(input, join(f.dir, 'another-link'));
  assert.notEqual(run().status, 0);
  rmSync(join(f.dir, 'another-link'));
  if (process.platform !== 'win32') {
    chmodSync(input, 0o644);
    assert.notEqual(run().status, 0);
  }
  assert((await verifyBackup(path)).ok);
});
