import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { safeHttp } from '../dist/http.js';

test('article redirect allowlists are enforced before contacting an unrelated origin', async (t) => {
  const servers = [];
  const start = async (handler) => {
    const server = http.createServer(handler);
    servers.push(server);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${server.address().port}`;
  };
  t.after(async () => {
    for (const server of servers) {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  });
  let unrelatedRequests = 0;
  const unrelated = await start((_req, res) => {
    unrelatedRequests++;
    res.end('must not fetch');
  });
  const target = await start((req, res) => {
    if (req.url === '/escape') {
      res.writeHead(302, { location: unrelated });
      res.end();
    } else res.end('full article');
  });
  const origin = await start((req, res) => {
    res.writeHead(302, { location: `${target}${req.url}` });
    res.end();
  });
  const options = { allowPrivate: true, redirects: 3, allowedRedirectOrigins: [origin, target] };
  assert.equal((await safeHttp(`${origin}/article`, options)).body, 'full article');
  await assert.rejects(safeHttp(`${origin}/escape`, options), /REDIRECT_DENIED/);
  assert.equal(unrelatedRequests, 0);
  await assert.rejects(
    safeHttp(`${origin}/article`, { ...options, allowedRedirectOrigins: [origin] }),
    /REDIRECT_DENIED/,
  );
});
