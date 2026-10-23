import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns';
import { syncBuiltinESMExports } from 'node:module';
import { safeHttp, validateDestination, isPublicAddress } from '../dist/http.js';
import { ModelAnalyzer, validateAnalysis } from '../dist/models.js';
import { parseConfig } from '../dist/config.js';
import { decide } from '../dist/assessment.js';

async function server(handler) {
  const instance = http.createServer(handler);
  await new Promise(resolve => instance.listen(0, '127.0.0.1', resolve));
  const port = instance.address().port;
  return { url: `http://127.0.0.1:${port}`, close: async () => { instance.closeAllConnections(); await new Promise(resolve => instance.close(resolve)); } };
}

test('destination validation rejects private, encoded, credential-bearing and non-HTTPS inputs', () => {
  for (const address of ['127.0.0.1', '10.2.3.4', '192.168.1.1', '169.254.169.254', '100.64.0.1', '::1', '::ffff:127.0.0.1', 'fc00::1', 'fe80::1']) assert.equal(isPublicAddress(address), false, address);
  for (const url of ['http://example.com', 'https://localhost', 'https://sub.localhost', 'https://127.0.0.1', 'https://2130706433', 'https://0x7f000001', 'https://[::ffff:127.0.0.1]', 'https://user:secret@example.com', 'https://example.com/#secret', 'file:///etc/passwd']) assert.throws(() => validateDestination(url), /DESTINATION_DENIED/, url);
  assert.equal(validateDestination('https://example.com/public').href, 'https://example.com/public');
  assert.equal(validateDestination('http://127.0.0.1:1234', true).hostname, '127.0.0.1');
});

test('the socket resolver rejects private and mixed DNS answers instead of trusting a prior hostname check', async () => {
  const original = dns.lookup;
  try {
    for (const addresses of [[{ address: '127.0.0.1', family: 4 }], [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }]]) {
      let lookups = 0;
      dns.lookup = (_hostname, _options, callback) => { lookups++; queueMicrotask(() => callback(null, addresses)); };
      syncBuiltinESMExports();
      await assert.rejects(safeHttp('https://dns-fixture.invalid', { timeoutMs: 1000 }), /DESTINATION_DENIED/);
      assert.equal(lookups, 1);
    }
  } finally { dns.lookup = original; syncBuiltinESMExports(); }
});

test('GET redirects strip credentials across origins and POST redirects are rejected', async () => {
  const received = [];
  const target = await server((req, res) => { received.push(req.headers); res.end('ok'); });
  const origin = await server((_req, res) => { res.writeHead(302, { location: `${target.url}/destination` }); res.end(); });
  try {
    const result = await safeHttp(origin.url, { allowPrivate: true, headers: { authorization: 'Bearer PRIVATE', cookie: 'secret=cookie', 'x-api-key': 'PRIVATE', accept: 'text/plain' } });
    assert.equal(result.body, 'ok');
    assert.equal(received.length, 1);
    assert.equal(received[0].authorization, undefined);
    assert.equal(received[0].cookie, undefined);
    assert.equal(received[0]['x-api-key'], undefined);
    assert.equal(received[0].accept, 'text/plain');
    await assert.rejects(safeHttp(origin.url, { allowPrivate: true, method: 'POST', body: 'private' }), /REDIRECT_DENIED/);
    assert.equal(received.length, 1);
  } finally { await origin.close(); await target.close(); }
});

test('response bytes, request bytes, timeout and redirect loops are bounded', async () => {
  const target = await server((req, res) => {
    if (req.url === '/large') res.end('x'.repeat(1000));
    else if (req.url === '/loop') { res.writeHead(302, { location: '/loop' }); res.end(); }
    else if (req.url === '/slow') { res.writeHead(200); res.write('waiting'); }
    else res.end('ok');
  });
  try {
    await assert.rejects(safeHttp(`${target.url}/large`, { allowPrivate: true, maxBytes: 100 }), /RESPONSE_TOO_LARGE|RESPONSE_FAILED/);
    await assert.rejects(safeHttp(`${target.url}/loop`, { allowPrivate: true }), /REDIRECT_DENIED/);
    await assert.rejects(safeHttp(`${target.url}/slow`, { allowPrivate: true, timeoutMs: 25 }), /REQUEST_TIMEOUT|RESPONSE_FAILED/);
    await assert.rejects(safeHttp(`${target.url}/`, { allowPrivate: true, body: 'x'.repeat(2_097_153) }), /REQUEST_TOO_LARGE/);
  } finally { await target.close(); }
});

const evidence = { id: 'osv:example', source: 'osv', kind: 'advisory', title: 'Example vulnerability', description: 'The alpha package has a confirmed vulnerability in version 1.0.0. Upgrade to version 1.0.1.', aliases: ['CVE-2026-12345'], severity: 'critical', packages: [{ ecosystem: 'npm', name: 'alpha', range: '<1.0.1' }], modified_at: '2026-10-24T00:00:00Z', fetched_at: '2026-10-24T00:00:00Z', url: 'https://example.com/advisory' };
const system = { id: 'prod', name: 'Production', environment: 'production', exposure: 'internet', criticality: 'high', updated_at: '2026-10-24T00:00:00Z', components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }], products: [], keywords: [] };
const assessment = { id: 'finding', event_id: 'CVE-2026-12345', system_id: 'prod', component_id: 'alpha', category: 'library', applicability: 'affected', source_severity: 'critical', priority: 'critical', title: evidence.title, summary: 'Installed alpha version matches the advisory.', reasons: [], evidence_ids: [evidence.id], urls: [evidence.url], exploited: false, updated_at: '2026-10-24T00:00:00Z' };
const analysis = (extra = {}) => ({ relevance: 'relevant', priority: 'critical', summary: 'An upgrade is available.', evidence_ids: [evidence.id], quotes: [{ evidence_id: evidence.id, quote: 'The alpha package has a confirmed vulnerability in version 1.0.0.' }], ...extra });
function configuration(extra = {}) {
  return parseConfig({ version: 1, models: { enabled: true, analysis: { provider: 'openai-compatible', model: 'fixture', api_key_env: 'SECURITY_WATCH_UNUSED_FIXTURE', endpoint: 'http://127.0.0.1:1234/v1/chat/completions', allow_private_endpoint: true }, ...extra }, policy: { library: { levels: ['critical'], channels: ['slack'] } }, notifications: { slack: { webhook_url_env: 'SECURITY_WATCH_UNUSED_SLACK' } } });
}
function state() {
  const metadata = new Map(); const reservations = [];
  return { metadata, reservations, getMeta: key => metadata.get(key), setMeta: (key, value) => metadata.set(key, value), reserveBudget: (_day, maxRequests, _maxTokens, _maxUsd, tokens, usd) => { if (reservations.length >= maxRequests) return false; reservations.push({ tokens, usd }); return true; } };
}
function modelResponse(value = analysis(), finish = 'stop') { return { status: 200, headers: {}, body: JSON.stringify({ choices: [{ finish_reason: finish, message: { content: JSON.stringify(value) } }] }) }; }

test('AI cannot downgrade an affected critical library or suppress its deterministic alert', async () => {
  const config = configuration(); const store = state();
  const analyzer = new ModelAnalyzer(config, store, async () => modelResponse(analysis({ relevance: 'irrelevant', priority: 'low' })));
  const result = await analyzer.analyze(assessment, system, [evidence]);
  assert.equal(result.ai.status, 'complete');
  assert.equal(result.priority, 'critical');
  assert.equal(result.applicability, 'affected');
  assert.equal(decide(result, config).action, 'notify');
});

test('model citations must use supplied evidence IDs and exact supplied quotes', () => {
  assert.throws(() => validateAnalysis(analysis({ evidence_ids: ['invented'] }), [evidence]), /MODEL_UNKNOWN_EVIDENCE/);
  assert.throws(() => validateAnalysis(analysis({ quotes: [{ evidence_id: evidence.id, quote: 'An invented claim of safety unsupported by the evidence.' }] }), [evidence]), /MODEL_UNSUPPORTED_QUOTE/);
  assert.throws(() => validateAnalysis(analysis({ evidence_ids: [evidence.id, 'other'] }), [evidence, { ...evidence, id: 'other' }]), /MODEL_UNSUPPORTED_CITATION/);
  assert.equal(validateAnalysis(analysis(), [evidence]).priority, 'critical');
});

test('validated model cache avoids new budget reservations, and changed evidence invalidates it', async () => {
  let calls = 0; const store = state();
  const analyzer = new ModelAnalyzer(configuration(), store, async () => { calls++; return modelResponse(); });
  await analyzer.analyze(assessment, system, [evidence]);
  await analyzer.analyze(assessment, system, [evidence]);
  assert.equal(calls, 1);
  assert.equal(store.reservations.length, 1);
  await analyzer.analyze(assessment, system, [{ ...evidence, description: `${evidence.description} New vendor context.` }]);
  assert.equal(calls, 2);
});

test('verification is triggered by source criticality even if first analysis downplays it, and budget exhaustion retains the alert', async () => {
  let calls = 0; const store = state();
  const config = configuration({ daily_request_limit: 1, verification: { provider: 'openai-compatible', model: 'second', api_key_env: 'SECURITY_WATCH_UNUSED_FIXTURE', endpoint: 'http://127.0.0.1:1234/v1/chat/completions', allow_private_endpoint: true } });
  const analyzer = new ModelAnalyzer(config, store, async () => { calls++; return modelResponse(analysis({ priority: 'low' })); });
  const result = await analyzer.analyze(assessment, system, [evidence]);
  assert.equal(calls, 1);
  assert.equal(result.ai.status, 'unavailable');
  assert(result.reasons.some(reason => reason.startsWith('MODEL_BUDGET_EXHAUSTED')));
  assert.equal(decide(result, config).action, 'notify');
});

test('malformed, incomplete and failed model responses retain deterministic assessment and redact transport errors', async t => {
  for (const [name, reply] of [
    ['malformed', async () => ({ status: 200, headers: {}, body: 'not json' })],
    ['incomplete', async () => modelResponse(analysis(), 'length')],
    ['unknown evidence', async () => modelResponse(analysis({ evidence_ids: ['invented'] }))],
    ['transport', async () => { throw new Error('https://private-provider.example?api_key=SECRET_TOKEN'); }],
  ]) await t.test(name, async () => {
    const store = state(); const config = configuration();
    const result = await new ModelAnalyzer(config, store, reply).analyze(assessment, system, [evidence]);
    assert.equal(result.ai.status, 'unavailable');
    assert.equal(result.priority, 'critical');
    assert.equal(decide(result, config).action, 'notify');
    assert.equal(JSON.stringify(result).includes('SECRET_TOKEN'), false);
    assert.equal(store.reservations.length, 1, 'Failed requests retain their reservation');
  });
});

test('AI context remains usable for a single finding in a realistic large dependency inventory', async () => {
  const largeSystem = { ...system, components: [...system.components, ...Array.from({ length: 1000 }, (_, index) => ({ id: `component-${index}`, ecosystem: 'npm', name: `unrelated-package-${index}`, version: '1.0.0' }))] };
  let calls = 0;
  const analyzer = new ModelAnalyzer(configuration(), state(), async (_url, options) => {
    calls++;
    const input = JSON.parse(JSON.parse(options.body).messages[1].content);
    assert(input.system.components.some(component => component.id === 'alpha'));
    assert(input.system.components.length < 10, 'Only relevant components should leave the machine');
    return modelResponse();
  });
  const result = await analyzer.analyze(assessment, largeSystem, [evidence]);
  assert.equal(result.ai.status, 'complete', result.reasons.join('; '));
  assert.equal(calls, 1);
});

test('news analysis includes the installed component that matched article text and preserves stale-inventory uncertainty', async () => {
  const { component_id: _omitted, ...newsBase } = assessment;
  const newsAssessment = { ...newsBase, category: 'news', applicability: 'unknown' };
  const newsEvidence = { ...evidence, kind: 'news', source: 'feed:fixture', packages: [] };
  const largeSystem = { ...system, updated_at: '2025-01-01T00:00:00Z', components: [...system.components, ...Array.from({ length: 1000 }, (_, index) => ({ id: `component-${index}`, ecosystem: 'npm', name: `unrelated-package-${index}`, version: '1.0.0' }))] };
  let sent;
  const result = await new ModelAnalyzer(configuration(), state(), async (_url, options) => {
    sent = JSON.parse(JSON.parse(options.body).messages[1].content);
    return modelResponse();
  }).analyze(newsAssessment, largeSystem, [newsEvidence]);
  assert.equal(result.ai.status, 'complete', result.reasons.join('; '));
  assert.deepEqual(sent.system.components, system.components);
  assert.equal(result.relevance, 'relevant');
  assert.equal(result.applicability, 'unknown');
});
