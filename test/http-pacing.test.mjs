import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { performance } from 'node:perf_hooks';
import { safeHttp } from '../dist/http.js';

async function server(t, handler) {
  const instance = createServer(handler);
  await new Promise((resolve) => instance.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => instance.close(resolve)));
  return `http://127.0.0.1:${instance.address().port}`;
}

test('HTTP origin pacing spaces concurrent starts without serializing response completion', async (t) => {
  const starts = [];
  let active = 0;
  let maximumActive = 0;
  const origin = await server(t, (_request, response) => {
    starts.push(performance.now());
    maximumActive = Math.max(maximumActive, ++active);
    setTimeout(() => {
      active--;
      response.end('ok');
    }, 200);
  });
  const results = await Promise.all(
    Array.from({ length: 4 }, () => safeHttp(origin, { allowPrivate: true, minIntervalMs: 80 })),
  );
  assert(results.every((result) => result.status === 200));
  assert.equal(starts.length, 4);
  for (let index = 1; index < starts.length; index++)
    assert(starts[index] - starts[index - 1] >= 60, 'Requests must not start in a burst');
  assert(maximumActive >= 2, 'A slow response need not hold the origin admission queue');
});

test('queued HTTP requests cancel promptly and consume their timeout before reaching the server', async (t) => {
  let calls = 0;
  const origin = await server(t, (_request, response) => {
    calls++;
    response.end('ok');
  });
  await safeHttp(origin, { allowPrivate: true, minIntervalMs: 1000 });
  const controller = new AbortController();
  const started = performance.now();
  const canceled = safeHttp(origin, { allowPrivate: true, signal: controller.signal, timeoutMs: 2000 });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(canceled, /REQUEST_ABORTED/);
  assert(performance.now() - started < 300, 'Cancellation must not wait for its reserved start time');
  await assert.rejects(safeHttp(origin, { allowPrivate: true, timeoutMs: 30 }), /REQUEST_TIMEOUT/);
  assert.equal(calls, 1);
  const other = await server(t, (_request, response) => response.end('separate origin'));
  assert.equal((await safeHttp(other, { allowPrivate: true, timeoutMs: 300 })).body, 'separate origin');
});

test('Retry-After on 403 and 429 delays already queued requests without retrying the failed request', async (t) => {
  for (const status of [403, 429])
    await t.test(String(status), async (t) => {
      const starts = [];
      const paths = [];
      const origin = await server(t, (request, response) => {
        starts.push(performance.now());
        paths.push(request.url);
        if (request.url === '/first') {
          response.writeHead(status, { 'Retry-After': '1' });
          response.end('limited');
        } else response.end('ok');
      });
      const options = { allowPrivate: true, minIntervalMs: 40, timeoutMs: 2500 };
      const [first, second] = await Promise.all([
        safeHttp(`${origin}/first`, options),
        safeHttp(`${origin}/second`, options),
      ]);
      assert.equal(first.status, status);
      assert.equal(second.status, 200);
      assert.deepEqual(paths, ['/first', '/second']);
      assert(starts[1] - starts[0] >= 900, 'Retry-After must extend an existing queue wait');
    });
});

test('Retry-After HTTP dates hold future requests and canceled waits do not clear the cooldown', async (t) => {
  let calls = 0;
  const origin = await server(t, (_request, response) => {
    calls++;
    response.writeHead(429, { 'Retry-After': new Date(Date.now() + 2000).toUTCString() });
    response.end('limited');
  });
  await safeHttp(origin, { allowPrivate: true, minIntervalMs: 1 });
  const controller = new AbortController();
  const pending = safeHttp(origin, { allowPrivate: true, signal: controller.signal });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(pending, /REQUEST_ABORTED/);
  await assert.rejects(safeHttp(origin, { allowPrivate: true, timeoutMs: 50 }), /REQUEST_TIMEOUT/);
  assert.equal(calls, 1);
});

test('invalid pacing options fail before HTTP and oversized Retry-After values stay bounded', async (t) => {
  let calls = 0;
  const origin = await server(t, (_request, response) => {
    calls++;
    if (calls === 1) response.writeHead(403, { 'Retry-After': '9'.repeat(400) });
    response.end(calls === 1 ? 'limited' : 'ok');
  });
  for (const minIntervalMs of [-1, Infinity, NaN, 3_600_001])
    await assert.rejects(safeHttp(origin, { allowPrivate: true, minIntervalMs }), /INVALID_REQUEST_INTERVAL/);
  assert.equal(calls, 0);
  await safeHttp(origin, { allowPrivate: true, minIntervalMs: 1 });
  await assert.rejects(safeHttp(origin, { allowPrivate: true, timeoutMs: 30 }), /REQUEST_TIMEOUT/);
  assert.equal(calls, 1);
  const now = Date.now;
  try {
    Date.now = () => now() + 3_600_001;
    assert.equal((await safeHttp(origin, { allowPrivate: true, timeoutMs: 200 })).status, 200);
    await new Promise((resolve) => setTimeout(resolve, 10));
  } finally {
    Date.now = now;
  }
  assert.equal(calls, 2, 'Even an overflowing Retry-After value must expire within one hour');
});
