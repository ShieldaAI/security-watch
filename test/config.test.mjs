import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseConfig, loadConfig, missingCredentials } from '../dist/config.js';

function directory(t) { const dir = mkdtempSync(join(tmpdir(), 'security-watch-config-')); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; }
function env(t, name, value) { const previous = process.env[name]; if (value === undefined) delete process.env[name]; else process.env[name] = value; t.after(() => { if (previous === undefined) delete process.env[name]; else process.env[name] = previous; }); }
function model(extra = {}) { return { provider: 'openai', model: 'fixture-model', api_key_env: 'WATCH_CONFIG_MODEL_KEY', ...extra }; }

test('environment substitution changes parsed scalar strings without injecting YAML structure', t => {
  const dir = directory(t); const path = join(dir, 'watch.yaml');
  const injected = 'fixture-model\nsources:\n  osv: false\nmodels:\n  enabled: false';
  env(t, 'WATCH_CONFIG_MODEL_NAME', injected);
  writeFileSync(path, 'version: 1\nsources:\n  osv: true\nmodels:\n  enabled: true\n  analysis:\n    provider: openai\n    model: "${WATCH_CONFIG_MODEL_NAME}"\n    api_key_env: WATCH_CONFIG_MODEL_KEY\n');
  const config = loadConfig(path);
  assert.equal(config.models.analysis.model, injected);
  assert.equal(config.models.enabled, true);
  assert.equal(config.sources.osv, true);
  assert.equal(config.notifications.slack, undefined);
});

test('configuration paths resolve relative to their file and environment substitutions remain literal', t => {
  const dir = directory(t); const child = join(dir, 'nested'); mkdirSync(child);
  env(t, 'WATCH_CONFIG_INVENTORY_NAME', '../systems.json');
  writeFileSync(join(child, 'watch.yaml'), 'version: 1\ninventory: "${WATCH_CONFIG_INVENTORY_NAME}"\ndatabase: ./state/watch.db\n');
  const config = loadConfig(join(child, 'watch.yaml'));
  assert.equal(config.inventory, resolve(dir, 'systems.json'));
  assert.equal(config.database, resolve(child, 'state/watch.db'));
});

test('undefined variables, YAML aliases, duplicate keys and oversized files fail validation', async t => {
  env(t, 'WATCH_CONFIG_UNSET', undefined);
  const cases = [
    ['undefined variable', 'version: 1\ninventory: "${WATCH_CONFIG_UNSET}"\n'],
    ['alias', 'version: 1\ninventory: &path ./systems.yaml\ndatabase: *path\n'],
    ['duplicate key', 'version: 1\nversion: 1\n'],
    ['oversized file', '#'.repeat(1_048_577)],
  ];
  for (const [name, content] of cases) await t.test(name, t => { const dir = directory(t); const path = join(dir, 'watch.yaml'); writeFileSync(path, content); assert.throws(() => loadConfig(path)); });
});

test('unknown configuration keys fail at every supported boundary', () => {
  for (const value of [
    { version: 1, typo: true },
    { version: 1, sources: { typo: true } },
    { version: 1, models: { typo: true } },
    { version: 1, models: { analysis: model({ typo: true }) } },
    { version: 1, policy: { library: { levels: ['critical'], typo: true } } },
    { version: 1, notifications: { slack: { webhook_url_env: 'SLACK_WEBHOOK_URL', typo: true } } },
  ]) assert.throws(() => parseConfig(value), /Unrecognized key/);
});

test('dollar caps require both prices for analysis and verification, including explicitly configured zero prices', () => {
  const priced = model({ input_usd_per_million: 1, output_usd_per_million: 2 });
  assert.throws(() => parseConfig({ version: 1, models: { enabled: true, analysis: model(), daily_budget_usd: 5 } }), /requires input and output pricing/);
  assert.throws(() => parseConfig({ version: 1, models: { enabled: true, analysis: priced, verification: model({ input_usd_per_million: 1 }), daily_budget_usd: 5 } }), /requires input and output pricing/);
  const config = parseConfig({ version: 1, models: { enabled: true, analysis: priced, verification: model({ input_usd_per_million: 0, output_usd_per_million: 0 }), daily_budget_usd: 5 } });
  assert.equal(config.models.verification.output_usd_per_million, 0);
  assert.throws(() => parseConfig({ version: 1, models: { enabled: true } }), /require an analysis model/);
});

test('every selected notification destination needs configuration and duplicate routes are rejected', () => {
  assert.throws(() => parseConfig({ version: 1, policy: { library: { levels: ['critical'], channels: ['slack'] } } }), /Missing slack notification configuration/);
  assert.throws(() => parseConfig({ version: 1, policy: { health_channels: ['email'] } }), /Missing email notification configuration/);
  assert.throws(() => parseConfig({ version: 1, policy: { news: { levels: ['high'], channels: ['slack', 'slack'] } }, notifications: { slack: { webhook_url_env: 'SLACK_WEBHOOK_URL' } } }), /Duplicate channel/);
  assert.equal(parseConfig({ version: 1, policy: { health_channels: ['email'] }, notifications: { email: { smtp_url_env: 'SMTP_URL', from: 'bot@example.com', to: ['security@example.com'] } } }).policy.health_channels[0], 'email');
});

test('provider endpoints require secure explicit destinations without embedded credentials, queries or fragments', () => {
  for (const endpoint of ['http://example.com/v1', 'https://user:secret@example.com/v1', 'https://example.com/v1?api_key=secret', 'https://example.com/v1#fragment', 'file:///tmp/model', 'javascript:alert(1)', 'not-a-url']) {
    assert.throws(() => parseConfig({ version: 1, models: { analysis: model({ endpoint }) } }), undefined, endpoint);
  }
  assert.throws(() => parseConfig({ version: 1, models: { analysis: model({ provider: 'openai-compatible' }) } }), /requires an endpoint/);
  const local = parseConfig({ version: 1, models: { analysis: model({ provider: 'openai-compatible', endpoint: 'http://127.0.0.1:11434/v1/chat/completions', allow_private_endpoint: true }) } });
  assert.equal(local.models.analysis.allow_private_endpoint, true);
  for (const feed of ['http://example.com/feed', 'https://user:secret@example.com/feed', 'file:///tmp/feed']) assert.throws(() => parseConfig({ version: 1, sources: { feeds: [feed] } }));
});

test('credentials health includes only enabled models and selected channels, with explicit local model exemption', t => {
  env(t, 'WATCH_CONFIG_MODEL_KEY', undefined); env(t, 'WATCH_CONFIG_SLACK_KEY', undefined); env(t, 'WATCH_CONFIG_EMAIL_KEY', undefined);
  const config = parseConfig({ version: 1, models: { enabled: true, analysis: model(), verification: model() }, policy: { library: { levels: ['critical'], channels: ['slack'] } }, notifications: { slack: { webhook_url_env: 'WATCH_CONFIG_SLACK_KEY' }, email: { smtp_url_env: 'WATCH_CONFIG_EMAIL_KEY', from: 'bot@example.com', to: ['security@example.com'] } } });
  assert.deepEqual(missingCredentials(config), ['WATCH_CONFIG_MODEL_KEY', 'WATCH_CONFIG_SLACK_KEY']);
  config.models.enabled = false;
  assert.deepEqual(missingCredentials(config), ['WATCH_CONFIG_SLACK_KEY']);
  const local = parseConfig({ version: 1, models: { enabled: true, analysis: model({ provider: 'openai-compatible', endpoint: 'http://127.0.0.1:1234/v1/chat/completions', allow_private_endpoint: true }) } });
  assert.deepEqual(missingCredentials(local), []);
});
