import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { generateSbom, loadInventory, parseConfig, startIntake, uploadSbom } from '../dist/index.js';
import { intakeAddress } from '../dist/upload.js';
import { writeProject } from './helpers/polyglot.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const cli = join(root, 'dist/cli.js');
const TOKEN = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);

function temp(t) {
  const directory = mkdtempSync(join(tmpdir(), 'sw-intake-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}
/** A monitor folder with an SBOM folder, one hand-written system and an intake configuration. */
function monitor(t, intake = {}) {
  const directory = temp(t);
  mkdirSync(join(directory, 'sboms'));
  writeFileSync(
    join(directory, 'systems.yaml'),
    `sbom_directory: ./sboms
systems:
  - id: web-shop
    name: Web shop
    updated_at: '${new Date().toISOString()}'
    libraries: ['npm:express@4.21.2']
`,
  );
  const config = parseConfig({
    version: 1,
    inventory: join(directory, 'systems.yaml'),
    intake: {
      listen: '127.0.0.1:0',
      tokens: [
        { token_env: 'TEST_INTAKE_ALL', systems: ['*'] },
        { token_env: 'TEST_INTAKE_CHECKOUT', systems: ['checkout-*', 'billing'] },
      ],
      ...intake,
    },
  });
  return { directory, sboms: join(directory, 'sboms'), config };
}
function tokens(t) {
  process.env.TEST_INTAKE_ALL = TOKEN;
  process.env.TEST_INTAKE_CHECKOUT = OTHER;
  t.after(() => {
    delete process.env.TEST_INTAKE_ALL;
    delete process.env.TEST_INTAKE_CHECKOUT;
  });
}
async function running(t, config, logs = []) {
  const intake = await startIntake(config, { log: (line) => logs.push(line) });
  t.after(() => intake.close());
  return intake;
}
const cyclonedx = (purls, properties = []) =>
  JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    metadata: { timestamp: new Date().toISOString(), component: { name: 'Checkout API' }, properties },
    components: purls.map((purl) => ({ purl })),
  });
async function put(base, path, body, token = TOKEN, method = 'PUT') {
  const response = await fetch(new URL(path, base), {
    method,
    headers: token ? { authorization: `Bearer ${token}`, 'content-type': 'application/json' } : {},
    ...(body === undefined ? {} : { body }),
  });
  const text = await response.text();
  return { status: response.status, headers: response.headers, body: text ? JSON.parse(text) : undefined };
}

test('intake configuration refuses tokens in clear text over a network', () => {
  const base = { version: 1 };
  const parsed = parseConfig({ ...base, intake: {} });
  assert.deepEqual(parsed.intake, {
    listen: '127.0.0.1:8787',
    tokens: [{ token_env: 'SECURITY_WATCH_INTAKE_TOKEN', systems: ['*'] }],
    allow_plain_http: false,
  });
  assert.equal(parseConfig({ ...base, intake: { listen: '[::1]:9000' } }).intake.listen, '[::1]:9000');
  for (const listen of ['127.0.0.2:9000', 'LOCALHOST:9000', '[0:0:0:0:0:0:0:1]:9000'])
    assert.equal(parseConfig({ ...base, intake: { listen } }).intake.listen, listen);
  for (const [intake, message] of [
    [{ listen: '0.0.0.0:8787' }, /set tls_cert_file and tls_key_file, or allow_plain_http/],
    [{ listen: 'watch.internal:8787' }, /allow_plain_http/],
    // A name that starts like a loopback address is a name: it can resolve anywhere.
    [{ listen: '127.example.com:8787' }, /allow_plain_http/],
    [{ listen: '127.0.0.1.nip.io:8787' }, /allow_plain_http/],
    [{ listen: '[::2]:8787' }, /allow_plain_http/],
    [{ listen: '8787' }, /HOST:PORT/],
    [{ listen: '127.0.0.1:70000' }, /Invalid port/],
    [{ tls_cert_file: 'cert.pem' }, /both tls_cert_file and tls_key_file/],
    [
      {
        tokens: [
          { token_env: 'A', systems: ['*'] },
          { token_env: 'A', systems: ['x'] },
        ],
      },
      /own token_env/,
    ],
    [{ tokens: [{ token_env: 'A', systems: ['../x'] }] }, /system ID, an ID prefix/],
    [{ tokens: [] }, /too small|>=1/i],
    [{ unknown: true }, /Unrecognized key/],
  ])
    assert.throws(() => parseConfig({ ...base, intake }), message, JSON.stringify(intake));
  assert.equal(
    parseConfig({ ...base, intake: { listen: '0.0.0.0:8787', allow_plain_http: true } }).intake
      .allow_plain_http,
    true,
  );
  assert.ok(
    parseConfig({ ...base, intake: { listen: '[::]:8787', tls_cert_file: 'c', tls_key_file: 'k' } }).intake,
  );
});

test('the intake does not start without strong tokens and an SBOM folder', async (t) => {
  const { config, directory } = monitor(t);
  await assert.rejects(startIntake(config), /Missing environment variable TEST_INTAKE_ALL/);
  process.env.TEST_INTAKE_ALL = 'short';
  process.env.TEST_INTAKE_CHECKOUT = OTHER;
  t.after(() => {
    delete process.env.TEST_INTAKE_ALL;
    delete process.env.TEST_INTAKE_CHECKOUT;
  });
  await assert.rejects(
    startIntake(config),
    /at least 32 characters without spaces; create one with: openssl/,
  );
  process.env.TEST_INTAKE_ALL = TOKEN;
  writeFileSync(join(directory, 'systems.yaml'), 'systems: []\n');
  await assert.rejects(startIntake(config), /The inventory has no sbom_directory/);
  await assert.rejects(startIntake({ ...config, intake: undefined }), /Configure intake/);
});

test('an authenticated upload is checked, written atomically and watched from the next scan', async (t) => {
  tokens(t);
  const { config, sboms, directory } = monitor(t);
  const logs = [];
  const intake = await running(t, config, logs);
  assert.match(intake.url, /^http:\/\/127\.0\.0\.1:\d+$/);

  const body = cyclonedx(
    ['pkg:npm/express@4.21.2', 'pkg:deb/debian/openssl@3.0.11'],
    [{ name: 'security-watch:owner', value: 'Dana' }],
  );
  const accepted = await put(intake.url, '/v1/sboms/checkout-api', body);
  assert.equal(accepted.status, 200);
  assert.deepEqual(accepted.body, {
    system_id: 'checkout-api',
    file: 'checkout-api.cdx.json',
    format: 'CycloneDX',
    packages: 1,
    warnings: 1,
    warning_examples: [
      '1 package in this SBOM is of a kind Security Watch does not match against advisories (deb): operating-system packages and CI actions need your image or repository scanner. The other packages are watched.',
    ],
  });
  assert.equal(accepted.headers.get('cache-control'), 'no-store');
  assert.equal(readFileSync(join(sboms, 'checkout-api.cdx.json'), 'utf8'), body);
  // Staging folders are removed; nothing but the SBOM is left behind.
  assert.deepEqual(readdirSync(sboms), ['checkout-api.cdx.json']);
  const inventory = loadInventory(join(directory, 'systems.yaml'));
  const system = inventory.systems.find((entry) => entry.id === 'checkout-api');
  assert.equal(system.owner, 'Dana');
  assert.equal(system.components[0].name, 'express');

  // The same system in another format replaces the earlier file instead of being read twice.
  const spdx = JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    creationInfo: { created: new Date().toISOString() },
    packages: [
      {
        SPDXID: 'SPDXRef-a',
        externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/koa@2.15.0' }],
      },
    ],
  });
  const replaced = await put(intake.url, '/v1/sboms/checkout-api', spdx, OTHER, 'POST');
  assert.equal(replaced.status, 200, JSON.stringify(replaced.body));
  assert.equal(replaced.body.file, 'checkout-api.spdx.json');
  assert.deepEqual(readdirSync(sboms), ['checkout-api.spdx.json']);

  // Log lines say what happened and never contain a token.
  assert.equal(logs.length, 2);
  for (const line of logs) {
    assert.ok(!line.includes(TOKEN) && !line.includes(OTHER));
    assert.equal(JSON.parse(line).intake.system_id, 'checkout-api');
  }
  assert.equal(JSON.parse(logs[1]).intake.token_env, 'TEST_INTAKE_CHECKOUT');
  // The scheme name is case-insensitive (RFC 9110).
  const lower = await fetch(new URL('/v1/sboms/checkout-api', intake.url), {
    method: 'PUT',
    headers: { authorization: `bearer ${TOKEN}` },
    body,
  });
  assert.equal(lower.status, 200);
});

test('the intake refuses what it should, with an answer a pipeline can act on', async (t) => {
  tokens(t);
  const { config, sboms } = monitor(t);
  const logs = [];
  const intake = await running(t, config, logs);
  const good = cyclonedx(['pkg:npm/express@4.21.2']);
  const cases = [
    ['GET', '/healthz', undefined, undefined, 200, /"ok":true/],
    ['POST', '/healthz', undefined, undefined, 405, /Use GET/],
    ['GET', '/v1/sboms/x', undefined, TOKEN, 405, /Use PUT/],
    ['PUT', '/v1/other', good, TOKEN, 404, /PUT \/v1\/sboms\/SYSTEM_ID/],
    ['PUT', '/v1/sboms/checkout-api', good, undefined, 401, /valid bearer token/],
    ['PUT', '/v1/sboms/checkout-api', good, 'c'.repeat(64), 401, /valid bearer token/],
    ['PUT', '/v1/sboms/..%2F..%2Fetc', good, TOKEN, 400, /system ID is 1 to 100/],
    ['PUT', '/v1/sboms/%E0%A4%A', good, TOKEN, 400, /system ID/],
    ['PUT', '/v1/sboms/.hidden', good, TOKEN, 400, /system ID/],
    // Lower case only: on a case-insensitive disk BILLING.cdx.json would replace billing.cdx.json.
    ['PUT', '/v1/sboms/BILLING', good, TOKEN, 400, /lower-case/],
    ['PUT', '/v1/sboms/web-checkout', good, OTHER, 403, /may not upload system web-checkout/],
    ['PUT', '/v1/sboms/checkout-api', '', TOKEN, 400, /body is empty/],
    ['PUT', '/v1/sboms/checkout-api', '{', TOKEN, 422, /Not a usable SBOM: SBOM is not valid JSON/],
    ['PUT', '/v1/sboms/checkout-api', '{"hello":1}', TOKEN, 422, /Expected a CycloneDX JSON/],
    [
      'PUT',
      '/v1/sboms/checkout-api',
      cyclonedx(['pkg:deb/debian/zlib@1']),
      TOKEN,
      422,
      /no package Security Watch can watch/,
    ],
    [
      'PUT',
      '/v1/sboms/checkout-api',
      cyclonedx(['pkg:npm/express@4.21.2'], [{ name: 'security-watch:system-id', value: 'billing' }]),
      TOKEN,
      409,
      /The SBOM is for system billing, not checkout-api/,
    ],
    [
      'PUT',
      '/v1/sboms/web-shop',
      good,
      TOKEN,
      409,
      /written in the inventory file; uploads cannot replace it/,
    ],
    // A system description the scanner would refuse is refused now, not silently left unwatched.
    [
      'PUT',
      '/v1/sboms/checkout-api',
      cyclonedx(
        ['pkg:npm/express@4.21.2'],
        [{ name: 'security-watch:source-url', value: 'http://example.com/x' }],
      ),
      TOKEN,
      422,
      /Not a usable SBOM: source_url/,
    ],
    [
      'PUT',
      '/v1/sboms/checkout-api',
      cyclonedx(['pkg:npm/express@4.21.2'], [{ name: 'security-watch:owner', value: 'x'.repeat(600) }]),
      TOKEN,
      422,
      /Not a usable SBOM: owner: Too big/,
    ],
  ];
  for (const [method, path, body, token, status, message] of cases) {
    const response = await fetch(new URL(path, intake.url), {
      method,
      headers: token ? { authorization: `Bearer ${token}` } : {},
      ...(body === undefined ? {} : { body }),
    });
    const text = await response.text();
    assert.equal(response.status, status, `${method} ${path}: ${text}`);
    assert.match(text, message, `${method} ${path}`);
  }
  assert.deepEqual(readdirSync(sboms), []);
  assert.ok(logs.some((line) => JSON.parse(line).intake.refused === 'unauthenticated'));

  // A file under another name that already describes the system would win at scan time; say so now.
  writeFileSync(
    join(sboms, 'made-by-init.cdx.json'),
    cyclonedx(['pkg:npm/koa@2.15.0'], [{ name: 'security-watch:system-id', value: 'billing' }]),
  );
  writeFileSync(join(sboms, 'unreadable.json'), '{');
  const claimed = await put(intake.url, '/v1/sboms/billing', good);
  assert.equal(claimed.status, 409);
  assert.match(
    claimed.body.error,
    /made-by-init\.cdx\.json in the SBOM folder already describes system billing/,
  );
  rmSync(join(sboms, 'made-by-init.cdx.json'));
  rmSync(join(sboms, 'unreadable.json'));

  // A body over 20 MiB is refused whether or not its size is declared up front.
  const huge = Buffer.alloc(20 * 1024 * 1024 + 1, 0x20);
  // The receiver answers 413 and closes the connection at once; on some platforms (macOS) the client
  // is still sending and sees the closed connection instead of the answer.
  const declared = await put(intake.url, '/v1/sboms/checkout-api', huge).catch((error) => {
    if (['EPIPE', 'ECONNRESET'].includes(error?.cause?.code)) return { status: 413 };
    throw error;
  });
  assert.equal(declared.status, 413);
  const streamed = await new Promise((resolve, reject) => {
    const url = new URL('/v1/sboms/checkout-api', intake.url);
    const request = httpRequest(
      url,
      { method: 'PUT', headers: { authorization: `Bearer ${TOKEN}`, 'transfer-encoding': 'chunked' } },
      (response) => {
        response.resume();
        resolve(response.statusCode);
      },
    );
    request.on('error', (error) =>
      error.code === 'ECONNRESET' || error.code === 'EPIPE' ? resolve(413) : reject(error),
    );
    for (let index = 0; index < 21; index++) request.write(Buffer.alloc(1024 * 1024, 0x20));
    request.end();
  });
  assert.equal(streamed, 413);
  assert.deepEqual(readdirSync(sboms), []);

  // Repeated bad tokens from one address are slowed down and no longer logged; the right token still works.
  const logged = logs.length;
  for (let index = 0; index < 20; index++) await put(intake.url, '/v1/sboms/x', good, 'd'.repeat(64));
  const limited = await put(intake.url, '/v1/sboms/checkout-api', good, 'd'.repeat(64));
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('retry-after'), '60');
  assert.ok(logs.length - logged < 20, 'refusals beyond the limit are not logged');
  assert.equal((await put(intake.url, '/v1/sboms/checkout-api', good, TOKEN)).status, 200);
});

test('uploads travel only over HTTPS or to this machine, and retry what is worth retrying', async () => {
  assert.equal(
    intakeAddress('https://watch.example.com:8787', 'checkout').href,
    'https://watch.example.com:8787/v1/sboms/checkout',
  );
  assert.equal(
    intakeAddress('https://example.com/security/', 'a.b').href,
    'https://example.com/security/v1/sboms/a.b',
  );
  assert.equal(intakeAddress('http://127.0.0.1:8787', 'a').protocol, 'http:');
  assert.equal(intakeAddress('http://[::1]:8787', 'a').protocol, 'http:');
  assert.equal(intakeAddress('http://watch.internal', 'a', true).protocol, 'http:');
  for (const [url, id, message] of [
    ['http://watch.internal:8787', 'a', /must use HTTPS/],
    ['https://user:pass@watch.example.com', 'a', /must not contain credentials/],
    ['https://watch.example.com/?token=x', 'a', /must not contain credentials, a query/],
    ['not a url', 'a', /must be a URL/],
    ['https://watch.example.com', '../x', /system ID/],
  ])
    assert.throws(() => intakeAddress(url, id), message);

  const calls = [];
  const answers = [
    () => {
      throw new TypeError('fetch failed', { cause: new Error('connect ECONNREFUSED') });
    },
    () =>
      new Response(JSON.stringify({ error: 'Busy; retry shortly.' }), {
        status: 503,
        headers: { 'retry-after': '5' },
      }),
    () =>
      new Response(JSON.stringify({ system_id: 'a', packages: 3, warnings: 0, warning_examples: [] }), {
        status: 200,
      }),
  ];
  const sleeps = [];
  const result = await uploadSbom({
    url: 'https://watch.example.com',
    systemId: 'a',
    body: '{}',
    token: TOKEN,
    fetch: async (url, init) => {
      calls.push({ url: String(url), init });
      return answers[calls.length - 1]();
    },
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  assert.equal(result.packages, 3);
  assert.deepEqual(sleeps, [2000, 5000]);
  assert.equal(calls[0].url, 'https://watch.example.com/v1/sboms/a');
  assert.equal(calls[0].init.method, 'PUT');
  assert.equal(calls[0].init.redirect, 'error');
  assert.equal(calls[0].init.headers.authorization, `Bearer ${TOKEN}`);

  let refusals = 0;
  await assert.rejects(
    uploadSbom({
      url: 'https://watch.example.com',
      systemId: 'a',
      body: '{}',
      token: TOKEN,
      fetch: async () => {
        refusals++;
        return new Response(JSON.stringify({ error: 'This token may not upload system a.' }), {
          status: 403,
        });
      },
    }),
    /Upload refused \(403\): This token may not upload system a\./,
  );
  assert.equal(refusals, 1, 'a refusal is not retried');
  await assert.rejects(
    uploadSbom({
      url: 'https://watch.example.com',
      systemId: 'a',
      body: '{}',
      token: TOKEN,
      attempts: 2,
      sleep: async () => {},
      fetch: async () => new Response('<html>proxy error</html>', { status: 502 }),
    }),
    /failed after 2 attempts: HTTP 502: HTTP 502 without a Security Watch answer/,
  );
});

function spawnCli(args, options = {}) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 30_000, ...options });
}

test('sbom --upload and upload reach a TLS intake run by the CLI, and start runs the intake too', async (t) => {
  const openssl = spawnSync('openssl', ['version']);
  const directory = temp(t);
  const watch = join(directory, 'watch');
  mkdirSync(join(watch, 'sboms'), { recursive: true });
  writeFileSync(join(watch, 'systems.yaml'), 'sbom_directory: ./sboms\n');
  const tls = openssl.status === 0;
  if (tls) {
    const made = spawnSync('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-subj',
      '/CN=localhost',
      '-addext',
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
      '-keyout',
      join(watch, 'key.pem'),
      '-out',
      join(watch, 'cert.pem'),
    ]);
    assert.equal(made.status, 0, made.stderr?.toString());
  }
  const port = 20000 + Math.floor(Math.random() * 20000);
  writeFileSync(
    join(watch, 'security-watch.yaml'),
    `version: 1
inventory: ./systems.yaml
database: ./watch.db
intake:
  listen: 127.0.0.1:${port}
${tls ? '  tls_cert_file: ./cert.pem\n  tls_key_file: ./key.pem\n' : ''}`,
  );
  const env = {
    ...process.env,
    SECURITY_WATCH_INTAKE_TOKEN: TOKEN,
    ...(tls ? { NODE_EXTRA_CA_CERTS: join(watch, 'cert.pem') } : {}),
  };
  const doctor = spawnCli(['doctor', '--config', join(watch, 'security-watch.yaml')], { env });
  const report = JSON.parse(doctor.stdout);
  assert.deepEqual(report.problems, []);
  assert.deepEqual(report.intake.tokens, [
    { token_env: 'SECURITY_WATCH_INTAKE_TOKEN', systems: ['*'], present: true },
  ]);
  const noToken = spawnCli(['doctor', '--config', join(watch, 'security-watch.yaml')], {
    env: { ...env, SECURITY_WATCH_INTAKE_TOKEN: '' },
  });
  assert.equal(JSON.parse(noToken.stdout).ok, false);
  assert.match(noToken.stdout, /SECURITY_WATCH_INTAKE_TOKEN: the intake upload token is not set/);

  const child = spawn(process.execPath, [cli, 'intake', '--config', join(watch, 'security-watch.yaml')], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (chunk) => (output += chunk));
  child.stderr.on('data', (chunk) => (output += chunk));
  t.after(() => child.kill('SIGKILL'));
  const deadline = Date.now() + 10_000;
  while (!output.includes('Receiving SBOMs') && Date.now() < deadline) await delay(50);
  assert.match(
    output,
    new RegExp(`Receiving SBOMs at ${tls ? 'https' : 'http'}://127\\.0\\.0\\.1:${port}/v1/sboms/SYSTEM_ID`),
  );
  const base = `${tls ? 'https://localhost' : 'http://127.0.0.1'}:${port}`;

  const project = writeProject(join(directory, 'project'));
  const uploaded = spawnCli(
    ['sbom', '--project', join(project, 'go'), '--system-id', 'go-api', '--upload', base],
    { env },
  );
  assert.equal(uploaded.status, 0, uploaded.stderr);
  assert.match(uploaded.stderr, /^Uploaded go-api: 4 packages will be watched from the next scan\.$/m);
  assert.equal(uploaded.stdout, '');
  assert.ok(existsSync(join(watch, 'sboms', 'go-api.cdx.json')));

  writeFileSync(
    join(directory, 'rust.cdx.json'),
    JSON.stringify(generateSbom({ project: join(project, 'rust') }).bom),
  );
  const file = spawnCli(['upload', '--input', join(directory, 'rust.cdx.json'), '--url', base], { env });
  assert.equal(file.status, 0, file.stderr);
  // The system comes from the SBOM's own ID; the file name is only a fallback.
  assert.ok(existsSync(join(watch, 'sboms', 'rust.cdx.json')));
  const renamed = spawnCli(
    ['upload', '--input', join(directory, 'rust.cdx.json'), '--url', base, '--system-id', 'other'],
    { env },
  );
  assert.equal(renamed.status, 1);
  assert.match(renamed.stderr, /Upload refused \(409\): The SBOM is for system rust, not other/);
  const wrongToken = spawnCli(['upload', '--input', join(directory, 'rust.cdx.json'), '--url', base], {
    env: { ...env, SECURITY_WATCH_INTAKE_TOKEN: OTHER },
  });
  assert.match(wrongToken.stderr, /Upload refused \(401\)/);
  for (const [args, extra, message] of [
    [
      ['upload', '--input', join(directory, 'rust.cdx.json'), '--url', base],
      { SECURITY_WATCH_INTAKE_TOKEN: '' },
      /Set SECURITY_WATCH_INTAKE_TOKEN to the intake upload token/,
    ],
    [
      ['upload', '--input', join(directory, 'rust.cdx.json')],
      {},
      /upload needs --input FILE\.json and --url URL/,
    ],
    [
      ['upload', '--input', join(directory, 'rust.cdx.json'), '--url', base, '--token-env', 'bad-name'],
      {},
      /--token-env must name an environment variable/,
    ],
    [
      ['upload', '--input', join(directory, 'rust.cdx.json'), '--url', 'http://watch.internal:1'],
      {},
      /must use HTTPS/,
    ],
    [
      ['sbom', '--project', project, '--token-env', 'X'],
      {},
      /--token-env and --allow-http apply to --upload/,
    ],
  ]) {
    const result = spawnCli(args, { env: { ...env, ...extra } });
    assert.equal(result.status, 1, args.join(' '));
    assert.match(result.stderr, message);
  }
  assert.equal(loadInventory(join(watch, 'systems.yaml')).systems.length, 2);
  child.kill('SIGTERM');
  await new Promise((resolve) => child.once('exit', resolve));

  // start receives uploads too, alongside scanning.
  const worker = spawn(process.execPath, [cli, 'start', '--config', join(watch, 'security-watch.yaml')], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: watch,
  });
  let workerOutput = '';
  worker.stdout.on('data', (chunk) => (workerOutput += chunk));
  worker.stderr.on('data', (chunk) => (workerOutput += chunk));
  t.after(() => worker.kill('SIGKILL'));
  const started = Date.now() + 10_000;
  while (!workerOutput.includes('Receiving SBOMs') && Date.now() < started) await delay(50);
  assert.match(workerOutput, /Receiving SBOMs at/);
  const viaStart = spawnCli(
    ['sbom', '--project', join(project, 'elixir'), '--system-id', 'elixir', '--upload', base],
    { env },
  );
  assert.equal(viaStart.status, 0, viaStart.stderr);
  worker.kill('SIGTERM');
  const code = await new Promise((resolve) => worker.once('exit', (exitCode) => resolve(exitCode)));
  assert.equal(code, 0, workerOutput);
  assert.ok(existsSync(join(watch, 'sboms', 'elixir.cdx.json')));
});

test('the GitHub Action uploads to the intake when given an address and a token', async (t) => {
  tokens(t);
  const { config, sboms } = monitor(t);
  const intake = await running(t, config);
  const directory = temp(t);
  const project = writeProject(join(directory, 'project'));
  // Asynchronous: the intake answering these uploads runs in this process.
  const run = (env) =>
    new Promise((resolve) => {
      const child = spawn('bash', [join(root, 'scripts/action-sbom.sh')], {
        cwd: directory,
        env: {
          PATH: process.env.PATH,
          HOME: process.env.HOME,
          SW_PACKAGE: '@shieldaai/security-watch@0.0.0-never-installed',
          SW_CLI: `${process.execPath} ${cli}`,
          SW_PROJECT: join(project, 'rust'),
          SW_OUTPUT: 'rust.cdx.json',
          SW_SYSTEM_ID: 'checkout-rust',
          SW_UPLOAD_URL: intake.url,
          ...env,
        },
      });
      const result = { stdout: '', stderr: '' };
      child.stdout.on('data', (chunk) => (result.stdout += chunk));
      child.stderr.on('data', (chunk) => (result.stderr += chunk));
      child.on('close', (status) => resolve({ ...result, status }));
    });
  const sent = await run({ SECURITY_WATCH_INTAKE_TOKEN: OTHER });
  assert.equal(sent.status, 0, sent.stderr);
  assert.match(sent.stderr, /Uploaded checkout-rust: 2 packages/);
  assert.ok(existsSync(join(sboms, 'checkout-rust.cdx.json')));
  const missing = await run({ SECURITY_WATCH_INTAKE_TOKEN: '' });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /upload-url is set but upload-token is empty/);
  const refused = await run({ SECURITY_WATCH_INTAKE_TOKEN: OTHER, SW_SYSTEM_ID: 'web-api' });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /Upload refused \(403\)/);
  // sbom lower-cases the system ID; the upload sends the ID the SBOM carries, not the input as typed.
  const capitals = await run({ SECURITY_WATCH_INTAKE_TOKEN: OTHER, SW_SYSTEM_ID: 'Checkout-Caps' });
  assert.equal(capitals.status, 0, capitals.stderr);
  assert.ok(existsSync(join(sboms, 'checkout-caps.cdx.json')));
});
