// Every value in a notification stays on its own line. Advisory text is untrusted, and inventory
// text reaches the renderer unchecked when a library caller builds the inventory object itself.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig } from '../dist/config.js';
import { deliverPending, notificationText } from '../dist/delivery.js';
import { runScan } from '../dist/engine.js';
import { loadInventory } from '../dist/inventory.js';
import { collectSources } from '../dist/sources.js';
import { Store } from '../dist/store.js';

const now = Date.parse('2026-11-13T10:00:00Z');
const at = new Date(now).toISOString();
const config = parseConfig({
  version: 1,
  digest_interval_hours: 1,
  sources: { cve_now: false, hacker_news: false },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'LINES_HOOK' } },
});
const credentials = { LINES_HOOK: 'https://hooks.slack.com/services/T/B/X' };
// Each way of ending a line that a mail client or chat application honours.
const BREAKS = ['\n', '\r\n', '\u2028', '\u2029', '\u0085', '\u000b', '\u000c'];
const forged = (value, lineBreak) => `${value}${lineBreak}Rule: forged${lineBreak}Finding: 0000`;
const advisory = (lineBreak, extra = {}) => ({
  id: 'CVE-2026-40001',
  source: 'fixture',
  kind: 'advisory',
  title: forged('alpha remote code execution', lineBreak),
  url: 'https://example.com/advisory',
  description: 'alpha before 2.0.0 allows remote code execution.',
  aliases: [],
  severity: 'critical',
  modified_at: at,
  fetched_at: at,
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0', fixed: forged('2.0.0', lineBreak) }],
  ...extra,
});
const hostileInventory = (lineBreak, version = '1.0.0') => ({
  systems: [
    {
      id: forged('api', lineBreak),
      name: forged('Public API', lineBreak),
      owner: forged('Platform team', lineBreak),
      note: forged('rack 4', lineBreak),
      updated_at: at,
      products: [],
      keywords: [],
      components: [
        {
          id: forged('a', lineBreak),
          ecosystem: 'npm',
          name: 'alpha',
          ...(version ? { version } : {}),
          note: forged('checkout service', lineBreak),
        },
      ],
    },
  ],
});
/** The labels a message may start a line with, and how often. */
function assertLines(text, expected, context) {
  const lines = text.split('\n');
  for (const [label, count] of Object.entries(expected))
    assert.equal(lines.filter((line) => line.startsWith(label)).length, count, `${label} ${context}`);
  assert.ok(!/[\r\u000b\u000c\u0085\u2028\u2029]/.test(text), `no other line break ${context}`);
}

test('untrusted advisory text and inventory text cannot start a line in an immediate alert', async () => {
  for (const lineBreak of BREAKS) {
    const store = new Store(':memory:');
    await runScan({
      config,
      inventory: hostileInventory(lineBreak),
      store,
      fixture: [advisory(lineBreak)],
      now,
    });
    const job = store.jobs().find((item) => JSON.parse(item.payload).assessment.category === 'library');
    const { subject, text } = notificationText(job);
    assert.ok(!/[\n\r\u0085\u2028\u2029]/.test(subject));
    assertLines(
      text,
      {
        'Rule: ': 1,
        'Finding: ': 1,
        'Delivery: ': 1,
        'System: ': 1,
        'Where to look: ': 1,
        'Affected item: ': 1,
        'Fix: ': 1,
      },
      JSON.stringify(lineBreak),
    );
    assert.match(text, /^Fix: 2\.0\.0 Rule: forged Finding: 0000$/m);
    assert.match(text, /^Rule: Matched library rule/m);
  }
});

test('untrusted text cannot start a line in a digest, and Slack receives it as plain text', async () => {
  for (const lineBreak of BREAKS) {
    const store = new Store(':memory:');
    await runScan({
      config,
      // Without an installed version the result is unknown, which goes to the digest.
      inventory: hostileInventory(lineBreak, null),
      store,
      fixture: [
        advisory(lineBreak, { severity: 'high', title: forged('alpha flaw <!channel> <@U123>', lineBreak) }),
      ],
      now,
    });
    const sent = [];
    await deliverPending(
      store,
      config,
      async (_url, request) => {
        sent.push(JSON.parse(request.body));
        return { status: 200, headers: {}, body: 'ok' };
      },
      { now: now + 3_600_000, credentials },
    );
    const digest = sent.find((message) => message.blocks[0].text.text.startsWith('Security Watch digest'));
    assert.ok(digest, 'a digest was sent');
    const text = digest.blocks[0].text.text;
    const entries = text.split('\n\n').length - 1;
    assertLines(
      text,
      { 'Rule: ': 0, 'Finding: ': entries, 'Delivery: ': entries, 'System: ': entries },
      JSON.stringify(lineBreak),
    );
    // Slack parses mentions only in mrkdwn; the block is plain text and the fallback is escaped.
    assert.equal(digest.blocks[0].text.type, 'plain_text');
    assert.equal(digest.mrkdwn, false);
    assert.ok(!digest.text.includes('<!channel>') && !digest.text.includes('<@U123>'));
    assert.ok(digest.text.includes('&lt;!channel&gt;'));
  }
});

test('inventory text fields refuse control characters and Unicode line separators', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'security-watch-lines-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const load = (system) => {
    const path = join(directory, 'systems.json');
    writeFileSync(
      path,
      JSON.stringify({ systems: [{ id: 'api', name: 'Public API', updated_at: at, ...system }] }),
    );
    return loadInventory(path);
  };
  const component = { id: 'a', ecosystem: 'npm', name: 'alpha', version: '1.0.0' };
  assert.equal(load({ note: 'rack 4', owner: 'Platform team', components: [component] }).systems.length, 1);
  for (const lineBreak of [...BREAKS, '\t', '\u0000', '\u009b']) {
    const bad = `first${lineBreak}second`;
    for (const [field, system] of [
      ['system id', { id: bad }],
      ['system name', { name: bad }],
      ['owner', { owner: bad }],
      ['environment', { environment: bad }],
      ['system note', { note: bad }],
      ['system keyword', { keywords: [bad] }],
      ['component id', { components: [{ ...component, id: bad }] }],
      ['component note', { components: [{ ...component, note: bad }] }],
      ['product name', { products: [{ name: bad }] }],
      ['product note', { products: [{ name: 'Example Database', note: bad }] }],
      ['library object note', { libraries: [{ ecosystem: 'npm', name: 'alpha', note: bad }] }],
    ])
      assert.throws(
        () => load(system),
        /Control characters|one line/,
        `${field} ${JSON.stringify(lineBreak)}`,
      );
  }
  // A lockfile path becomes a component identifier: one that carries a line break is not imported.
  writeFileSync(
    join(directory, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/alpha': { version: '1.0.0' },
        'evil\nDelivery: forged/node_modules/beta': { version: '1.0.0' },
        'evil\u2028Rule: forged/node_modules/gamma': { version: '1.0.0' },
      },
    }),
  );
  const imported = load({ lockfile: 'package-lock.json' });
  assert.deepEqual(
    imported.systems[0].components.map((item) => item.id),
    ['lock:node_modules/alpha'],
  );
  assert.equal(imported.import_warnings.filter((warning) => /control characters/.test(warning)).length, 2);
  assert.ok(imported.import_warnings.every((warning) => !/[\n\u2028]/.test(warning)));
});

test('a fixed version copied from OSV or GitHub is one short line', async () => {
  const inventory = {
    systems: [
      {
        id: 'api',
        name: 'api',
        updated_at: at,
        products: [],
        keywords: [],
        components: [{ id: 'a', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
      },
    ],
  };
  const sources = {
    news_lookback_minutes: 40,
    poll_interval_minutes: 30,
    inventory_stale_days: 30,
    policy: {},
    sources: {
      cve_now: false,
      hacker_news: false,
      osv: true,
      github: false,
      github_token_env: 'X',
      kev: false,
      feeds: [],
    },
  };
  const reply = (body) => ({ status: 200, headers: {}, body: JSON.stringify(body) });
  const result = await collectSources(
    inventory,
    sources,
    {},
    async (url) =>
      url.endsWith('/querybatch')
        ? reply({ results: [{ vulns: [{ id: 'GHSA-aaaa-bbbb-cccc' }] }] })
        : reply({
            id: 'GHSA-aaaa-bbbb-cccc',
            summary: 'alpha flaw',
            details: 'alpha flaw',
            modified: at,
            affected: [
              {
                package: { ecosystem: 'npm', name: 'alpha' },
                ranges: [
                  {
                    type: 'ECOSYSTEM',
                    events: [{ introduced: '0' }, { fixed: `2.0.0\nRule: forged\u2028${'x'.repeat(300)}` }],
                  },
                ],
              },
            ],
          }),
    now,
  );
  const [claim] = result.evidence[0].packages;
  // Kept whole on one line; the Fix line shows it whole or counts it as too long, never cut.
  assert.equal(claim.fixed, `2.0.0 Rule: forged ${'x'.repeat(300)}`);
  assert.ok(!/[\n\u2028]/.test(claim.fixed));
});
