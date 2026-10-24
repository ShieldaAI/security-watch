import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { safeHttp } from '../dist/http.js';

test('HTTP distinguishes a refused connection from an ambiguous failure after connecting', async (t) => {
  const server = createServer((request) => request.socket.destroy());
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  const options = { allowPrivate: true, method: 'POST', body: 'test message', timeoutMs: 1000 };
  await assert.rejects(safeHttp(url, options), (error) => error.code === 'REQUEST_FAILED');
  await new Promise((resolve) => server.close(resolve));
  await assert.rejects(safeHttp(url, options), (error) => error.code === 'CONNECTION_FAILED');
});

test('an HTTP timeout after request acceptance remains ambiguous', async (t) => {
  let received = 0;
  const server = createServer(() => {
    received++;
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  await assert.rejects(
    safeHttp(`http://127.0.0.1:${server.address().port}`, {
      allowPrivate: true,
      method: 'POST',
      body: 'test message',
      timeoutMs: 250,
    }),
    (error) => error.code === 'REQUEST_TIMEOUT',
  );
  assert.equal(received, 1);
});
