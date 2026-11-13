import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadInventory, parseConfig, parseLibraryList, runScan, Store } from '../dist/index.js';
import { notificationText } from '../dist/delivery.js';

const now = Date.parse('2026-11-13T10:00:00Z');
const at = new Date(now).toISOString();
const config = parseConfig({
  version: 1,
  sources: { cve_now: false, hacker_news: false },
  policy: {
    library: { levels: ['critical'], channels: ['slack'] },
    product: { levels: ['high', 'critical'], channels: ['slack'] },
  },
  notifications: { slack: { webhook_url_env: 'LOCATION_NOTE_UNUSED' } },
});
const advisory = {
  id: 'CVE-2026-40001',
  source: 'fixture',
  kind: 'advisory',
  title: 'alpha remote code execution',
  url: 'https://example.com/advisory',
  description: 'alpha before 2.0.0 allows remote code execution.',
  aliases: [],
  severity: 'critical',
  modified_at: at,
  fetched_at: at,
  packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0', fixed: '2.0.0' }],
};
const productAdvisory = {
  ...advisory,
  id: 'CVE-2026-40002',
  title: 'Acme Gateway authentication bypass',
  description: 'Acme Gateway 7.x allows an authentication bypass.',
  packages: [],
};

function write(t, name, content) {
  const directory = mkdtempSync(join(tmpdir(), 'watch-location-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = join(directory, name);
  writeFileSync(file, content);
  return file;
}
const inventoryYaml = (libraryNote = 'checkout API, repo acme/checkout, file package.json') => `
systems:
  - id: shop
    name: Web shop
    owner: Dana (platform team)
    note: Runs on cluster eu-1, namespace shop
    updated_at: ${at}
    libraries:
      - "npm:alpha@1.0.0  # ${libraryNote}"
      - { ecosystem: npm, name: alpha, version: 1.0.0, note: "also in the admin panel" }
      - "npm:beta@3.0.0"
    products:
      - name: Acme Gateway
        version: "7.2"
        note: Edge proxy in front of the shop, managed by the network team
`;

test('library lists accept a trailing # note and keep every place a library is used', () => {
  const components = parseLibraryList(
    [
      '# full-line comments are still ignored',
      'npm:alpha@1.0.0   # checkout API',
      'npm:alpha@1.0.0 # admin panel',
      'npm:alpha@1.0.0 # checkout API',
      'python:requests==2.31.0 #billing worker, services/billing/requirements.txt',
      'npm:@scope/pkg@1.2.3',
      'npm:beta@2.0.0 #',
    ].join('\n'),
  );
  assert.deepEqual(
    components.map(({ name, version, note }) => [name, version, note]),
    [
      ['alpha', '1.0.0', 'checkout API | admin panel'],
      ['requests', '2.31.0', 'billing worker, services/billing/requirements.txt'],
      ['@scope/pkg', '1.2.3', undefined],
      ['beta', '2.0.0', undefined],
    ],
  );
  assert.equal(new Set(components.map((component) => component.id)).size, components.length);
  assert.throws(() => parseLibraryList(`npm:alpha # ${'x'.repeat(501)}`), /note must be/);
  assert.throws(() => parseLibraryList('npm:alpha # tab\there'), /note must be/);
});

test('inventory notes reach the notification so a reader knows where to check', async (t) => {
  const inventory = loadInventory(write(t, 'systems.yaml', inventoryYaml()));
  const [system] = inventory.systems;
  assert.equal(system.note, 'Runs on cluster eu-1, namespace shop');
  assert.equal(
    system.components.find((component) => component.name === 'alpha').note,
    'checkout API, repo acme/checkout, file package.json | also in the admin panel',
  );

  const store = new Store(':memory:');
  await runScan({ config, inventory, store, fixture: [advisory, productAdvisory], now });
  const library = store.findings().find((finding) => finding.category === 'library');
  assert.deepEqual(library.location, {
    system: 'Web shop',
    owner: 'Dana (platform team)',
    system_note: 'Runs on cluster eu-1, namespace shop',
    component: 'npm alpha 1.0.0',
    component_note: 'checkout API, repo acme/checkout, file package.json | also in the admin panel',
  });
  const job = store.jobs().find((item) => item.finding_id === library.id);
  const { text } = notificationText(job);
  assert.match(
    text,
    /^Where to look: Web shop \(owner: Dana \(platform team\)\) - Runs on cluster eu-1, namespace shop$/m,
  );
  assert.match(
    text,
    /^Affected item: npm alpha 1\.0\.0 - checkout API, repo acme\/checkout, file package\.json \| also in the admin panel$/m,
  );

  const product = store.findings().find((finding) => finding.category === 'product');
  assert.equal(product.location.component, 'Acme Gateway 7.2');
  assert.equal(
    product.location.component_note,
    'Edge proxy in front of the shop, managed by the network team',
  );
  assert.match(
    notificationText(store.jobs().find((item) => item.finding_id === product.id)).text,
    /^Affected item: Acme Gateway 7\.2 - Edge proxy in front of the shop/m,
  );
});

test('editing a note updates the waiting message without creating a new alert', async (t) => {
  const store = new Store(':memory:');
  const first = loadInventory(write(t, 'systems.yaml', inventoryYaml()));
  const scan = await runScan({ config, inventory: first, store, fixture: [advisory], now });
  const finding = scan.findings.find((item) => item.category === 'library');
  const second = loadInventory(write(t, 'systems.yaml', inventoryYaml('moved to repo acme/storefront')));
  await runScan({ config, inventory: second, store, fixture: [advisory], now: now + 60_000 });
  assert.equal(store.history(finding.id).length, 1);
  const jobs = store.jobs().filter((item) => item.finding_id === finding.id);
  assert.equal(jobs.length, 1);
  assert.match(notificationText(jobs[0]).text, /moved to repo acme\/storefront/);
});

test('a finding without notes still names the system and item in plain words', async (t) => {
  const inventory = loadInventory(
    write(
      t,
      'systems.yaml',
      `systems:\n  - id: api\n    name: Public API\n    updated_at: ${at}\n    libraries: ["npm:alpha@1.0.0"]\n`,
    ),
  );
  const store = new Store(':memory:');
  await runScan({ config, inventory, store, fixture: [advisory], now });
  const [finding] = store.findings().filter((item) => item.category === 'library');
  assert.deepEqual(finding.location, { system: 'Public API', component: 'npm alpha 1.0.0' });
  const { text } = notificationText(store.jobs()[0]);
  assert.match(text, /^Where to look: Public API$/m);
  assert.match(text, /^Affected item: npm alpha 1\.0\.0$/m);
});

test('notes cannot inject extra lines or mentions into a notification', async (t) => {
  const inventory = loadInventory(
    write(
      t,
      'systems.json',
      JSON.stringify({
        systems: [
          {
            id: 'api',
            name: 'Public API',
            note: 'ping @channel <!here> now',
            updated_at: at,
            components: [{ id: 'a', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
          },
        ],
      }),
    ),
  );
  const store = new Store(':memory:');
  await runScan({ config, inventory, store, fixture: [advisory], now });
  const { text } = notificationText(store.jobs()[0]);
  assert.ok(!text.includes('@channel'));
  assert.throws(
    () =>
      loadInventory(
        write(
          t,
          'bad.json',
          JSON.stringify({
            systems: [{ id: 'api', name: 'API', note: 'line one\nRule: forged', updated_at: at }],
          }),
        ),
      ),
    /Control characters/,
  );
});
