import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../dist/store.js';
import { deliverPending, notificationText, sendEmail } from '../dist/delivery.js';
import { NetworkError } from '../dist/http.js';

const assessment = (id = 'finding-1') => ({
  id,
  event_id: 'CVE-2026-1',
  system_id: 'prod',
  component_id: 'library',
  category: 'library',
  applicability: 'affected',
  source_severity: 'critical',
  priority: 'critical',
  title: 'Untrusted <!here> @everyone & title',
  summary: 'Investigate <script>alert(1)</script>',
  reasons: ['version match'],
  evidence_ids: ['osv:1'],
  urls: ['https://example.com/advisory', 'javascript:alert(1)'],
  exploited: true,
  updated_at: '2026-10-24T00:00:00Z',
});
const rule = { levels: ['critical'], basis: 'source_severity', channels: ['slack', 'email'] };
const config = {
  digest_interval_hours: 24,
  policy: {
    library: rule,
    product: rule,
    news: rule,
    health_channels: ['slack', 'email'],
    urgent_unknown: true,
    exploited_override: true,
    malware_override: true,
  },
  notifications: {
    max_attempts: 3,
    slack: { webhook_url_env: 'WATCH_TEST_SLACK' },
    email: {
      smtp_url_env: 'WATCH_TEST_SMTP',
      from: 'watch@example.com',
      to: ['security@example.com', 'ops@example.com'],
    },
  },
};
function setup(t, channels = ['slack']) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  process.env.WATCH_TEST_SLACK = 'https://hooks.slack.com/services/T/B/secret';
  process.env.WATCH_TEST_SMTP = 'smtps://user:password@mail.example.com';
  t.after(() => {
    delete process.env.WATCH_TEST_SLACK;
    delete process.env.WATCH_TEST_SMTP;
  });
  store.saveAssessment(assessment(), { action: 'notify', channels, reason: 'source critical' }, 1000);
  return store;
}
const noHttp = async () => {
  throw new Error('Unexpected HTTP call');
};

test('aborted delivery does not claim queued work or charge attempts', async (t) => {
  const store = setup(t, ['slack', 'email']);
  const controller = new AbortController();
  controller.abort();
  assert.deepEqual(await deliverPending(store, config, noHttp, 1000, noHttp, controller.signal), {
    accepted: 0,
    failed: 0,
    unknown: 0,
  });
  assert(store.jobs().every((job) => job.status === 'pending' && job.attempts === 0));
});

test('cancelling SMTP closes its socket and leaves later deliveries queued', { timeout: 3000 }, async (t) => {
  const store = setup(t, ['email']);
  store.saveAssessment(
    assessment('finding-2'),
    { action: 'notify', channels: ['email'], reason: 'critical' },
    1000,
  );
  const sockets = new Set();
  let connected;
  const ready = new Promise((resolve) => {
    connected = resolve;
  });
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    connected();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  process.env.WATCH_TEST_SMTP = `smtp://127.0.0.1:${server.address().port}`;
  const controller = new AbortController();
  const pending = deliverPending(store, config, noHttp, 1000, sendEmail, controller.signal);
  await ready;
  const closed = new Promise((resolve) => [...sockets][0].once('close', resolve));
  controller.abort();
  assert.deepEqual(await pending, { accepted: 0, failed: 0, unknown: 1 });
  await closed;
  assert.equal(sockets.size, 0);
  assert.equal(store.jobs().filter((job) => job.status === 'unknown' && job.attempts === 1).length, 1);
  assert.equal(store.jobs().filter((job) => job.status === 'pending' && job.attempts === 0).length, 1);
});

test('SMTP refuses plaintext authentication when STARTTLS is unavailable', { timeout: 3000 }, async (t) => {
  const commands = [];
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.write('220 fixture ESMTP\r\n');
    socket.on('data', (data) => {
      commands.push(data.toString());
      if (data.toString().startsWith('EHLO')) socket.write('250-fixture\r\n250 AUTH PLAIN\r\n');
      else socket.write('504 TLS unavailable\r\n');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  await assert.rejects(
    sendEmail({
      url: `smtp://user:password@127.0.0.1:${server.address().port}`,
      from: 'watch@example.com',
      to: ['security@example.com'],
      subject: 'Fixture',
      text: 'Fixture',
    }),
    /TLS|STARTTLS/i,
  );
  assert(commands.some((line) => line.startsWith('STARTTLS')));
  assert(!commands.some((line) => /^(AUTH|MAIL|DATA)/.test(line)));
});

test(
  'SMTPS starts with a TLS handshake and cancellation closes that socket',
  { timeout: 3000 },
  async (t) => {
    const controller = new AbortController();
    const sockets = new Set();
    let firstByte;
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      socket.once('data', (data) => {
        firstByte = data[0];
        controller.abort();
      });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    });
    await assert.rejects(
      sendEmail({
        url: `smtps://user:password@127.0.0.1:${server.address().port}`,
        from: 'watch@example.com',
        to: ['security@example.com'],
        subject: 'Fixture',
        text: 'Fixture',
        signal: controller.signal,
      }),
      /aborted/i,
    );
    assert.equal(firstByte, 22, 'The first record must be a TLS handshake, before SMTP or authentication');
  },
);

test('Slack uses plain text, stable IDs, no mentions/unfurls and no credentials in durable payload', async (t) => {
  const store = setup(t);
  const result = await deliverPending(
    store,
    config,
    async (url, options) => {
      assert.equal(url, process.env.WATCH_TEST_SLACK);
      assert.equal(options.redirects, 0);
      const body = JSON.parse(options.body);
      assert.equal(body.blocks[0].text.type, 'plain_text');
      assert.equal(body.unfurl_links, false);
      assert(!body.text.includes('<!here>'));
      assert(!body.text.includes('@everyone'));
      assert(!body.text.includes('javascript:'));
      assert(body.text.includes('Finding: finding-1'));
      assert(body.text.includes('Delivery: '));
      return { status: 200, body: 'ok', headers: {} };
    },
    1000,
  );
  assert.deepEqual(result, { accepted: 1, failed: 0, unknown: 0 });
  assert(!JSON.stringify(store.jobs()).includes('/services/'));
  assert(!JSON.stringify(store.jobs()).includes('password'));
});

test('Slack rate limit honors Retry-After and does not spin or lose delivery', async (t) => {
  const store = setup(t);
  let calls = 0;
  const http = async () => {
    calls++;
    return calls === 1
      ? { status: 429, body: 'limited', headers: { 'Retry-After': '20' } }
      : { status: 200, body: 'ok', headers: {} };
  };
  await deliverPending(store, config, http, 1000);
  assert.equal(store.jobs()[0].available_at, 21000);
  assert.equal(store.jobs()[0].status, 'pending');
  await deliverPending(store, config, http, 20999);
  assert.equal(calls, 1);
  await deliverPending(store, config, http, 21000);
  assert.equal(calls, 2);
  assert.equal(store.jobs()[0].status, 'accepted');
});

test('multiple Slack jobs are paced without charging waiting as a send attempt', async (t) => {
  const store = setup(t);
  store.saveAssessment(
    assessment('finding-2'),
    { action: 'notify', channels: ['slack'], reason: 'critical' },
    1000,
  );
  let calls = 0;
  const http = async () => {
    calls++;
    return { status: 200, body: 'ok', headers: {} };
  };
  await deliverPending(store, config, http, 1000);
  assert.equal(calls, 1);
  assert.equal(store.jobs().find((j) => j.status === 'pending').attempts, 0);
  await deliverPending(store, config, http, 2000);
  assert.equal(calls, 2);
});

test('Slack ambiguous timeout is retained as unknown and never automatically retried', async (t) => {
  const store = setup(t);
  let calls = 0;
  const http = async () => {
    calls++;
    throw new Error('timeout with https://hooks.slack.com/services/SECRET');
  };
  assert.deepEqual(await deliverPending(store, config, http, 1000), { accepted: 0, failed: 0, unknown: 1 });
  await deliverPending(store, config, http, 900000);
  assert.equal(calls, 1);
  assert(!JSON.stringify(store.jobs()).includes('SECRET'));
});

test('a failed or uncertain destination does not stop other queued notifications', async (t) => {
  for (const failure of ['slack-rejected', 'slack-unknown', 'email-rejected']) {
    await t.test(failure, async (t) => {
      const store = setup(t, ['slack', 'email']);
      const http = async () => {
        if (failure === 'slack-unknown') throw new Error('Receipt lost');
        return { status: failure === 'slack-rejected' ? 403 : 200, body: 'ok', headers: {} };
      };
      const sender = async () => {
        if (failure === 'email-rejected') throw Object.assign(new Error('Rejected'), { responseCode: 550 });
        return { accepted: config.notifications.email.to, rejected: [] };
      };
      const result = await deliverPending(store, config, http, 1000, sender);
      assert.equal(result.accepted, 1);
      assert.equal(result.failed + result.unknown, 1);
      assert(!store.jobs().some((job) => ['pending', 'sending'].includes(job.status)));
    });
  }
});

test('Slack connection retries survive a restart and leave email delivery independent', async (t) => {
  setup(t, []);
  const dir = mkdtempSync(join(tmpdir(), 'watch-delivery-'));
  const path = join(dir, 'watch.db');
  let store = new Store(path);
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  store.saveAssessment(
    assessment(),
    { action: 'notify', channels: ['slack', 'email'], reason: 'critical' },
    1000,
  );
  let calls = 0;
  const http = async () => {
    calls++;
    if (calls < 3) throw new NetworkError(calls === 1 ? 'DNS_FAILED' : 'CONNECTION_FAILED');
    return { status: 200, body: 'ok', headers: {} };
  };
  let emails = 0;
  const sender = async () => {
    emails++;
    return { accepted: config.notifications.email.to, rejected: [] };
  };
  assert.deepEqual(await deliverPending(store, config, http, 1000, sender), {
    accepted: 1,
    failed: 0,
    unknown: 0,
  });
  store.close();
  store = new Store(path);
  store.recoverSending(2000);
  assert.equal(store.jobs().find((job) => job.channel === 'slack').available_at, 31000);
  await deliverPending(store, config, http, 30999, sender);
  assert.equal(calls, 1);
  await deliverPending(store, config, http, 31000, sender);
  assert.equal(store.jobs().find((job) => job.channel === 'slack').available_at, 91000);
  await deliverPending(store, config, http, 91000, sender);
  assert.equal(calls, 3);
  assert.equal(emails, 1);
  assert(store.jobs().every((job) => job.status === 'accepted'));
});

test('Slack connection retries stop at the configured attempt limit', async (t) => {
  const store = setup(t);
  let calls = 0;
  const http = async () => {
    calls++;
    throw new NetworkError('CONNECTION_FAILED');
  };
  for (const now of [1000, 31000, 91000, 999999]) await deliverPending(store, config, http, now);
  assert.equal(calls, 3);
  assert.equal(store.jobs()[0].status, 'failed');
  assert.match(store.jobs()[0].last_error, /retry limit reached/);
});

test(
  'a refused SMTP connection is safely retried before any message was sent',
  { timeout: 3000 },
  async (t) => {
    const store = setup(t, ['email']);
    const server = createServer();
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    await new Promise((resolve) => server.close(resolve));
    process.env.WATCH_TEST_SMTP = `smtp://127.0.0.1:${port}`;
    assert.deepEqual(await deliverPending(store, config, noHttp, 1000, sendEmail), {
      accepted: 0,
      failed: 0,
      unknown: 0,
    });
    assert.equal(store.jobs()[0].status, 'pending');
    assert.equal(store.jobs()[0].available_at, 31000);
    let calls = 0;
    const sender = async () => {
      calls++;
      return { accepted: config.notifications.email.to, rejected: [] };
    };
    await deliverPending(store, config, noHttp, 30999, sender);
    assert.equal(calls, 0);
    await deliverPending(store, config, noHttp, 31000, sender);
    assert.equal(calls, 1);
    assert.equal(store.jobs()[0].status, 'accepted');
  },
);

test('permanent rejection and repeated transient rejection produce visible failure', async (t) => {
  const store = setup(t);
  await deliverPending(
    store,
    config,
    async () => ({ status: 403, body: 'secret error text', headers: {} }),
    1000,
  );
  assert.equal(store.jobs()[0].status, 'failed');
  assert(!store.jobs()[0].last_error.includes('secret error'));
  store.saveAssessment(
    assessment('finding-2'),
    { action: 'notify', channels: ['slack'], reason: 'critical' },
    1000,
  );
  const retry = async () => ({ status: 503, body: '', headers: {} });
  await deliverPending(store, config, retry, 2000);
  await deliverPending(store, config, retry, 32000);
  await deliverPending(store, config, retry, 92000);
  assert.equal(store.jobs().find((j) => j.finding_id === 'finding-2').status, 'failed');
});

test('Slack redirects, arbitrary hosts and unexpected success responses cannot be mistaken for delivery', async (t) => {
  const store = setup(t);
  process.env.WATCH_TEST_SLACK = 'https://attacker.example/services/T/B/secret';
  await deliverPending(store, config, noHttp, 1000);
  assert.equal(store.jobs()[0].status, 'failed');
  process.env.WATCH_TEST_SLACK = 'https://hooks.slack.com/services/T/B/secret';
  store.saveAssessment(
    assessment('second'),
    { action: 'notify', channels: ['slack'], reason: 'critical' },
    1000,
  );
  await deliverPending(store, config, async () => ({ status: 200, body: 'unexpected', headers: {} }), 1000);
  assert.equal(store.jobs().find((j) => j.finding_id === 'second').status, 'unknown');
});

test('email accepted means SMTP acceptance; text is bounded and credentials are not persisted', async (t) => {
  const store = setup(t, ['email']);
  let calls = 0;
  const receipt = await deliverPending(store, config, noHttp, 1000, async (message) => {
    calls++;
    assert.equal(message.url, process.env.WATCH_TEST_SMTP);
    assert.equal(message.to.length, 2);
    assert(message.text.includes('Finding: finding-1'));
    assert(!message.subject.includes('\n'));
    return { accepted: ['security@example.com', 'ops@example.com'], rejected: [] };
  });
  assert.equal(calls, 1);
  assert.equal(receipt.accepted, 1);
  assert(!JSON.stringify(store.jobs()).includes('password'));
  assert(notificationText(store.jobs()[0]).text.length <= 2900);
});

test('partial SMTP acceptance is unknown and never resends the successful recipients', async (t) => {
  const store = setup(t, ['email']);
  let calls = 0;
  const sender = async () => {
    calls++;
    return { accepted: ['security@example.com'], rejected: ['ops@example.com'] };
  };
  await deliverPending(store, config, noHttp, 1000, sender);
  await deliverPending(store, config, noHttp, 100000, sender);
  assert.equal(calls, 1);
  assert.equal(store.jobs()[0].status, 'unknown');
});

test('SMTP rejection retries only explicit temporary responses and redacts transport errors', async (t) => {
  const store = setup(t, ['email']);
  let calls = 0;
  const sender = async () => {
    calls++;
    if (calls === 1) throw Object.assign(new Error('password secret'), { responseCode: 451 });
    throw new Error('ambiguous password secret');
  };
  await deliverPending(store, config, noHttp, 1000, sender);
  assert.equal(store.jobs()[0].status, 'pending');
  await deliverPending(store, config, noHttp, 31000, sender);
  assert.equal(store.jobs()[0].status, 'unknown');
  assert(!JSON.stringify(store.jobs()).includes('password secret'));
});

test('email URL cannot disable TLS through query options', async (t) => {
  const store = setup(t, ['email']);
  process.env.WATCH_TEST_SMTP = 'smtp://mail.example.com?ignoreTLS=true';
  await deliverPending(store, config, noHttp, 1000, async () => {
    throw new Error('Must not send');
  });
  assert.equal(store.jobs()[0].status, 'failed');
});

test('due digests batch up to five findings into one send and retain individual stable IDs', async (t) => {
  const store = setup(t, []);
  for (let i = 0; i < 7; i++)
    store.saveAssessment(
      {
        ...assessment(`digest-${i}`),
        applicability: 'unknown',
        source_severity: 'low',
        priority: 'low',
        exploited: false,
      },
      { action: 'digest', channels: ['slack'], reason: 'review daily' },
      1000,
      1000,
    );
  let calls = 0;
  const http = async (_url, options) => {
    calls++;
    const body = JSON.parse(options.body);
    const text = body.blocks[0].text.text;
    if (calls === 1) {
      assert.equal((text.match(/Finding: /g) ?? []).length, 5);
      assert.equal((text.match(/Delivery: /g) ?? []).length, 5);
    }
    assert(text.length <= 3000);
    return { status: 200, body: 'ok', headers: {} };
  };
  assert.deepEqual(await deliverPending(store, config, http, 2000), { accepted: 5, failed: 0, unknown: 0 });
  assert.equal(calls, 1);
  assert.equal(store.jobs().filter((j) => j.status === 'pending').length, 2);
  assert.deepEqual(await deliverPending(store, config, http, 3000), { accepted: 2, failed: 0, unknown: 0 });
  assert.equal(calls, 2);
  assert.equal(store.jobs().filter((j) => j.status === 'accepted').length, 7);
});

test('large Slack digests split without dropping IDs or charging unsent entries', async (t) => {
  const store = setup(t, []);
  for (let i = 0; i < 5; i++)
    store.saveAssessment(
      {
        ...assessment(`${i}`.repeat(64)),
        title: 'Long advisory title '.repeat(10),
        system_id: 'system'.repeat(20),
        component_id: 'component'.repeat(20),
        applicability: 'unknown',
        source_severity: 'low',
        priority: 'low',
        exploited: false,
        urls: [`https://example.com/${'advisory/'.repeat(30)}`],
        news_analysis: { classification: 'known_vulnerability_update', impact: 'unknown' },
      },
      { action: 'digest', channels: ['slack'], reason: 'review daily' },
      1000,
      1000,
    );
  const sent = new Set();
  let calls = 0;
  const http = async (_url, options) => {
    calls++;
    const text = JSON.parse(options.body).blocks[0].text.text;
    assert(text.length <= 2900);
    const included = store.jobs().filter((job) => text.includes(`Delivery: ${job.id}`));
    assert(included.length > 0);
    for (const job of included) {
      assert(text.includes(`Finding: ${job.finding_id}`));
      assert(!sent.has(job.id), 'a digest entry must not be delivered twice');
      sent.add(job.id);
    }
    return { status: 200, body: 'ok', headers: {} };
  };
  const first = await deliverPending(store, config, http, 2000);
  assert(first.accepted > 0 && first.accepted < 5);
  assert.equal(first.failed, 0);
  assert.equal(first.unknown, 0);
  assert(
    store
      .jobs()
      .filter((job) => job.status === 'pending')
      .every((job) => job.attempts === 0),
  );
  for (const now of [3000, 4000, 5000, 6000]) await deliverPending(store, config, http, now);
  assert.equal(sent.size, 5);
  assert(calls > 1);
  assert(store.jobs().every((job) => job.status === 'accepted' && job.attempts === 1));
});

test('a malformed digest entry does not discard its valid neighbors', async (t) => {
  const store = setup(t, []);
  for (const id of ['valid-1', 'malformed', 'valid-2'])
    store.saveAssessment(
      {
        ...assessment(id),
        applicability: 'unknown',
        source_severity: 'low',
        priority: 'low',
        exploited: false,
        ...(id === 'malformed' ? { urls: null } : {}),
      },
      { action: 'digest', channels: ['slack'], reason: 'review daily' },
      1000,
      1000,
    );
  const result = await deliverPending(
    store,
    config,
    async (_url, options) => {
      const text = JSON.parse(options.body).blocks[0].text.text;
      assert(text.includes('Finding: valid-1'));
      assert(text.includes('Finding: valid-2'));
      assert(!text.includes('Finding: malformed'));
      return { status: 200, body: 'ok', headers: {} };
    },
    2000,
  );
  assert.deepEqual(result, { accepted: 2, failed: 1, unknown: 0 });
  assert.equal(store.jobs().find((job) => job.finding_id === 'malformed').status, 'failed');
});

test('a database failure while claiming a digest propagates without sending or rewriting delivery state', async (t) => {
  const store = setup(t, []);
  for (const id of ['digest-1', 'digest-2'])
    store.saveAssessment(
      {
        ...assessment(id),
        applicability: 'unknown',
        source_severity: 'low',
        priority: 'low',
        exploited: false,
      },
      { action: 'digest', channels: ['slack'], reason: 'review daily' },
      1000,
      1000,
    );
  const databaseError = new Error('Database is unavailable');
  store.claimAdditionalDigest = () => {
    throw databaseError;
  };
  let sends = 0;
  const http = async () => {
    sends++;
    return { status: 200, body: 'ok', headers: {} };
  };
  await assert.rejects(deliverPending(store, config, http, 2000), (error) => error === databaseError);
  assert.equal(sends, 0);
  assert.deepEqual(
    store
      .jobs()
      .map((job) => job.status)
      .sort(),
    ['pending', 'sending'],
  );
  assert(store.jobs().every((job) => job.last_error === undefined));
});

test('ambiguous digest delivery marks every included finding unknown and never automatically resends', async (t) => {
  const store = setup(t, []);
  for (let i = 0; i < 3; i++)
    store.saveAssessment(
      {
        ...assessment(`digest-${i}`),
        applicability: 'unknown',
        source_severity: 'low',
        priority: 'low',
        exploited: false,
      },
      { action: 'digest', channels: ['email'], reason: 'review daily' },
      1000,
      1000,
    );
  let calls = 0;
  const sender = async () => {
    calls++;
    throw new Error('timeout');
  };
  assert.deepEqual(await deliverPending(store, config, noHttp, 2000, sender), {
    accepted: 0,
    failed: 0,
    unknown: 3,
  });
  await deliverPending(store, config, noHttp, 999999, sender);
  assert.equal(calls, 1);
});

test('incomplete SMTP receipt cannot claim acceptance for unaccounted recipients', async (t) => {
  const store = setup(t, ['email']);
  const result = await deliverPending(store, config, noHttp, 1000, async () => ({
    accepted: ['security@example.com'],
    rejected: [],
  }));
  assert.equal(result.accepted, 0);
  assert.equal(result.unknown, 1);
  assert.equal(store.jobs()[0].status, 'unknown');
});

test('Slack backlog uses channel gating without claiming or rewriting every waiting job', async (t) => {
  const store = setup(t);
  for (let i = 0; i < 200; i++)
    store.saveAssessment(
      assessment(`backlog-${i}`),
      { action: 'notify', channels: ['slack'], reason: 'critical' },
      1000,
    );
  let claims = 0;
  const original = store.claimDue.bind(store);
  store.claimDue = (...args) => {
    claims++;
    return original(...args);
  };
  let calls = 0;
  await deliverPending(
    store,
    config,
    async () => {
      calls++;
      return { status: 200, body: 'ok', headers: {} };
    },
    1000,
  );
  assert.equal(calls, 1);
  assert(claims <= 2);
  assert(
    store
      .jobs()
      .filter((job) => job.status === 'pending')
      .every((job) => job.attempts === 0 && job.available_at === 1000),
  );
  await deliverPending(
    store,
    config,
    async () => {
      calls++;
      return { status: 200, body: 'ok', headers: {} };
    },
    1500,
  );
  assert.equal(calls, 1);
  assert.equal(store.summary().next_pending_at, 2000);
});

test('queued notifications obey changed routes and thresholds before the first rescan', async (t) => {
  const store = setup(t);
  let calls = 0;
  const changed = { ...config, policy: { ...config.policy, library: { ...rule, channels: ['email'] } } };
  await deliverPending(
    store,
    changed,
    async () => {
      calls++;
      return { status: 200, body: 'ok', headers: {} };
    },
    1000,
  );
  assert.equal(calls, 0);
  assert.equal(store.jobs()[0].status, 'failed');
  assert.match(store.jobs()[0].last_error, /policy/);
  store.saveAssessment(
    { ...assessment('below-threshold'), exploited: false },
    { action: 'notify', channels: ['slack'], reason: 'old threshold' },
    1000,
  );
  const narrowed = { ...config, policy: { ...config.policy, library: { ...rule, levels: ['high'] } } };
  await deliverPending(store, narrowed, noHttp, 2000);
  assert.equal(store.jobs().find((job) => job.finding_id === 'below-threshold').status, 'failed');
});

test('changed urgency reschedules queued jobs without sending at the old urgency', async (t) => {
  const store = setup(t, []);
  const uncertain = { ...assessment('uncertain'), applicability: 'unknown', exploited: false };
  store.saveAssessment(
    uncertain,
    { action: 'notify', channels: ['slack'], reason: 'old immediate review' },
    1000,
  );
  const changed = {
    ...config,
    policy: { ...config.policy, urgent_unknown: false, library: { ...rule, channels: ['slack'] } },
  };
  await deliverPending(store, changed, noHttp, 1000);
  const due = store.jobs().filter((job) => job.status === 'pending');
  assert.equal(due.length, 1);
  assert.equal(JSON.parse(due[0].payload).mode, 'digest');
  assert.equal(due[0].available_at, 86400000);
  const urgent = { ...changed, policy: { ...changed.policy, urgent_unknown: true } };
  let calls = 0;
  await deliverPending(
    store,
    urgent,
    async () => {
      calls++;
      return { status: 200, body: 'ok', headers: {} };
    },
    86400000,
  );
  assert.equal(calls, 1);
  assert.equal(store.jobs().filter((job) => job.status === 'accepted').length, 1);
  assert.equal(JSON.parse(store.jobs().find((job) => job.status === 'accepted').payload).mode, 'notify');
});

test('immediate alerts overtake an older digest backlog', async (t) => {
  const store = setup(t, []);
  for (let i = 0; i < 12; i++)
    store.saveAssessment(
      {
        ...assessment(`old-digest-${i}`),
        applicability: 'unknown',
        priority: 'low',
        source_severity: 'low',
        exploited: false,
      },
      { action: 'digest', channels: ['slack'], reason: 'review' },
      1000,
      1000,
    );
  store.saveAssessment(
    assessment('urgent-new'),
    { action: 'notify', channels: ['slack'], reason: 'critical' },
    5000,
  );
  let calls = 0;
  await deliverPending(
    store,
    config,
    async (_url, options) => {
      calls++;
      assert(JSON.parse(options.body).text.includes('Finding: urgent-new'));
      return { status: 200, body: 'ok', headers: {} };
    },
    5000,
  );
  assert.equal(calls, 1);
  assert.equal(store.jobs().filter((job) => job.status === 'pending').length, 12);
});

test('inactive findings cannot be sent even when an old saved decision selected notification', async (t) => {
  const store = setup(t, []);
  store.saveAssessment(
    { ...assessment(), active: false },
    { action: 'notify', channels: ['slack'], reason: 'obsolete route' },
    1000,
  );
  await deliverPending(store, config, noHttp, 1000);
  assert.equal(store.jobs()[0].status, 'failed');
  assert.match(store.jobs()[0].last_error, /no longer active/);
});

test('maximum-size generated digest entries stay inside Slack limits and preserve every finding ID', async (t) => {
  const store = setup(t, []);
  const ids = Array.from({ length: 5 }, (_, i) => String(i).repeat(64));
  for (const id of ids)
    store.saveAssessment(
      {
        ...assessment(id),
        title: 'T'.repeat(10000),
        system_id: 'S'.repeat(200),
        component_id: 'C'.repeat(200),
        applicability: 'conflicting',
        source_severity: 'unknown',
        priority: 'unknown',
        exploited: false,
        urls: [`https://example.com/${'a'.repeat(500)}`],
      },
      { action: 'digest', channels: ['slack'], reason: 'review' },
      1000,
      1000,
    );
  await deliverPending(
    store,
    config,
    async (_url, options) => {
      const body = JSON.parse(options.body);
      const text = body.blocks[0].text.text;
      assert(text.length <= 3000);
      for (const id of ids) assert(text.includes(`Finding: ${id}`));
      return { status: 200, body: 'ok', headers: {} };
    },
    2000,
  );
  assert.equal(store.jobs().filter((job) => job.status === 'accepted').length, 5);
});

test('digest retry limits are applied per finding rather than to the batch leader', async (t) => {
  const store = setup(t, []);
  const digest = { action: 'digest', channels: ['slack'], reason: 'review' };
  const uncertain = (id) => ({
    ...assessment(id),
    applicability: 'unknown',
    priority: 'low',
    source_severity: 'low',
    exploited: false,
  });
  store.saveAssessment(uncertain('experienced'), digest, 1000, 1000);
  let job = store.claimDue(2000);
  store.completeJob(job.id, 'pending', 2000);
  job = store.claimDue(2000);
  store.completeJob(job.id, 'pending', 2000);
  store.saveAssessment(uncertain('newcomer'), digest, 1000, 1000);
  await deliverPending(store, config, async () => ({ status: 503, body: '', headers: {} }), 2000);
  assert.equal(store.jobs().find((job) => job.finding_id === 'experienced').status, 'failed');
  assert.equal(store.jobs().find((job) => job.finding_id === 'newcomer').status, 'pending');
  assert.equal(store.jobs().find((job) => job.finding_id === 'newcomer').attempts, 1);
});

test('notification text strips bidirectional controls from untrusted source strings', (t) => {
  const store = setup(t, []);
  store.saveAssessment(
    { ...assessment(), title: 'safe\u202eevil\u202c', summary: 'Review\u2066hidden\u2069details' },
    { action: 'notify', channels: ['slack'], reason: 'critical' },
    1000,
  );
  const text = notificationText(store.jobs()[0]);
  assert(!/[\u202a-\u202e\u2066-\u2069]/.test(text.text));
  assert(!/[\u202a-\u202e\u2066-\u2069]/.test(text.subject));
});
