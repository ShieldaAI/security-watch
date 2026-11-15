// What a job becomes after each way a real SMTP conversation can end. Every case runs the built-in
// sender against a loopback server, so the error shapes are the ones the mail library really produces.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig } from '../dist/config.js';
import { deliverPending } from '../dist/delivery.js';
import { decide } from '../dist/assessment.js';
import { Store } from '../dist/store.js';
import { smtpsFixture } from './helpers/smtp-fixture.mjs';

const now = Date.parse('2026-11-13T10:00:00Z');
const config = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false },
  policy: { library: { levels: ['critical'], channels: ['email'] } },
  notifications: {
    email: { smtp_url_env: 'OUTCOME_SMTP', from: 'watch@example.org', to: ['ops@example.org'] },
    max_attempts: 3,
  },
});
const finding = {
  id: 'F1',
  event_id: 'CVE-2026-50001',
  system_id: 'prod',
  component_id: 'alpha',
  category: 'library',
  applicability: 'affected',
  source_severity: 'critical',
  priority: 'critical',
  title: 'alpha remote code execution',
  summary: 'alpha in prod: affected.',
  reasons: [],
  evidence_ids: [],
  urls: [],
  exploited: false,
  updated_at: new Date(now).toISOString(),
};
const noHttp = async () => {
  throw new Error('no network');
};
/** Runs delivery until the job leaves `pending` or the attempts run out; returns what happened. */
async function deliver(t, behaviour) {
  const { state, url } = await smtpsFixture(t, behaviour);
  const store = new Store(':memory:');
  store.saveAssessment(finding, decide(finding, config), now);
  const statuses = [];
  let at = now;
  for (let attempt = 0; attempt < 4; attempt++) {
    await deliverPending(store, config, noHttp, { now: at, credentials: { OUTCOME_SMTP: url } });
    const [job] = store.jobs();
    statuses.push(job.status);
    if (job.status !== 'pending') break;
    at = job.available_at + 1;
  }
  const [job] = store.jobs();
  return { state, statuses, job };
}

test('a normal SMTP conversation is accepted once', { timeout: 20_000 }, async (t) => {
  const { state, statuses } = await deliver(t, 'accept');
  assert.deepEqual(statuses, ['accepted']);
  assert.equal(state.messages, 1);
});

test(
  'a connection dropped after the message body was transferred is uncertain and never resent',
  { timeout: 20_000 },
  async (t) => {
    const { state, statuses, job } = await deliver(t, 'drop-after-data');
    assert.deepEqual(statuses, ['unknown']);
    assert.equal(state.messages, 1, 'the server must receive the message exactly once');
    assert.match(job.last_error, /receipt is unknown/);
  },
);

test('a connection dropped after MAIL FROM is uncertain', { timeout: 20_000 }, async (t) => {
  const { state, statuses } = await deliver(t, 'drop-after-mail');
  assert.deepEqual(statuses, ['unknown']);
  assert.equal(state.connections, 1);
});

test(
  'failures that precede the envelope are retried up to the limit and send nothing',
  { timeout: 30_000 },
  async (t) => {
    for (const behaviour of ['untrusted', 'drop-after-ehlo']) {
      const { state, statuses, job } = await deliver(t, behaviour);
      assert.deepEqual(statuses, ['pending', 'pending', 'failed'], behaviour);
      assert.match(job.last_error, /before sending; retry limit reached/, behaviour);
      assert.equal(state.messages, 0, behaviour);
      assert.ok(!state.commands.includes('MAIL'), behaviour);
    }
  },
);

test(
  'a rejected sign-in fails at once; a temporary sign-in refusal is retried',
  { timeout: 30_000 },
  async (t) => {
    const rejected = await deliver(t, 'auth-535');
    assert.deepEqual(rejected.statuses, ['failed']);
    assert.match(rejected.job.last_error, /status 535/);
    assert.equal(rejected.state.messages, 0);
    const temporary = await deliver(t, 'auth-454');
    assert.deepEqual(temporary.statuses, ['pending', 'pending', 'failed']);
    assert.equal(temporary.state.messages, 0);
  },
);

test('an explicit refusal of the finished message follows its reply code', { timeout: 30_000 }, async (t) => {
  const permanent = await deliver(t, 'data-554');
  assert.deepEqual(permanent.statuses, ['failed']);
  assert.equal(permanent.state.messages, 1);
  const temporary = await deliver(t, 'data-451');
  assert.deepEqual(temporary.statuses, ['pending', 'pending', 'failed']);
});

test('an error label from a replacement sender is not proof that nothing was sent', async () => {
  for (const failure of [
    Object.assign(new Error('socket closed'), { code: 'ESOCKET', command: 'CONN' }),
    Object.assign(new Error('certificate has expired'), { code: 'ETLS' }),
    Object.assign(new Error('auth'), { code: 'EAUTH', command: 'AUTH PLAIN' }),
  ]) {
    const store = new Store(':memory:');
    store.saveAssessment(finding, decide(finding, config), now);
    const result = await deliverPending(store, config, noHttp, {
      now,
      credentials: { OUTCOME_SMTP: 'smtps://alerts:secret@mail.example.org' },
      emailSender: async () => {
        throw failure;
      },
    });
    assert.deepEqual(result, { accepted: 0, failed: 0, unknown: 1 }, failure.message);
  }
});
