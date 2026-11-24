// The inventory, advisory answers and Slack endpoint behind watch-1.4.0-duplicates.db, shared by the
// script that wrote that database and by the test that upgrades it (UPG-02 in review-1.3.test.mjs).
//
// The database was written by the released 1.4.0 build, starting from watch-1.2.1.db:
//
//   git archive v1.4.0 | tar -x -C /tmp/sw-140 && cd /tmp/sw-140 && npm ci && npm run build
//   node test/fixtures/duplicates-1.4.0.mjs /tmp/sw-140/dist test/fixtures/watch-1.4.0-duplicates.db
//
// 1.4.0 made one finding, and one alert, for each listing of alpha 1.0.0: the declared component and
// the two SBOM entries with their own bom-refs. Every alert was delivered.
import { chmodSync, copyFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const t0 = Date.parse('2026-11-20T12:00:00Z');
export const written = t0 + 7_200_000;
const iso = (time) => new Date(time).toISOString();

export const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  components: [
    {
      'bom-ref': 'alpha-app',
      type: 'library',
      name: 'alpha',
      version: '1.0.0',
      purl: 'pkg:npm/alpha@1.0.0',
      evidence: { occurrences: [{ location: 'app/node_modules/alpha' }] },
    },
    {
      'bom-ref': 'alpha-tools',
      type: 'library',
      name: 'alpha',
      version: '1.0.0',
      purl: 'pkg:npm/alpha@1.0.0',
      evidence: { occurrences: [{ location: 'tools/node_modules/alpha' }] },
    },
    // Another version of the same package stays its own component and finding.
    {
      'bom-ref': 'alpha-legacy',
      type: 'library',
      name: 'alpha',
      version: '1.5.0',
      purl: 'pkg:npm/alpha@1.5.0',
      evidence: { occurrences: [{ location: 'legacy/node_modules/alpha' }] },
    },
  ],
  dependencies: [{ ref: 'alpha-tools', dependsOn: ['alpha-legacy'] }],
};

/** Writes the inventory into `dir` and returns the path of systems.yaml. */
export function writeInventory(dir, time) {
  writeFileSync(join(dir, 'web.cdx.json'), JSON.stringify(sbom));
  writeFileSync(
    join(dir, 'systems.yaml'),
    [
      'systems:',
      '  - id: web',
      '    name: Web',
      '    environment: production',
      '    exposure: internet',
      '    criticality: high',
      `    updated_at: ${iso(time)}`,
      '    components:',
      '      - { id: alpha, ecosystem: npm, name: alpha, version: 1.0.0 }',
      '      - { id: beta, ecosystem: PyPI, name: beta, version: 1.0.0 }',
      '    sbom: web.cdx.json',
      '',
    ].join('\n'),
  );
  return join(dir, 'systems.yaml');
}

export const configInput = {
  version: 1,
  poll_interval_minutes: 1440,
  sources: { cve_now: false, hacker_news: false, osv: true, github: false, kev: false },
  policy: { library: { levels: ['critical', 'high'], basis: 'source_severity', channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'UPGRADE_SLACK' } },
};
export const credentials = { UPGRADE_SLACK: 'https://hooks.slack.com/services/T/B/x' };

/** OSV as 1.2.1 and 1.4.0 saw it, and a Slack webhook that accepts every message. */
export function http(sent = []) {
  const record = (id, ecosystem, name, severity) => ({
    id,
    aliases: ['CVE-2026-20001'],
    summary: `Problem in ${name}`,
    details: `${name} deserializes untrusted input.`,
    modified: iso(t0),
    database_specific: { severity, cwe_ids: ['CWE-502'] },
    references: [{ type: 'WEB', url: `https://github.com/example/${name}/commit/abcdef1234` }],
    affected: [
      {
        package: { ecosystem, name },
        ranges: [
          {
            type: ecosystem === 'npm' ? 'SEMVER' : 'ECOSYSTEM',
            events: [{ introduced: '0' }, { fixed: '2.0.0' }],
          },
          {
            type: 'GIT',
            repo: `https://github.com/example/${name}`,
            events: [{ introduced: '0' }, { fixed: 'abcdef1234abcdef1234abcdef1234abcdef1234' }],
          },
        ],
      },
    ],
  });
  return async (url, request) => {
    if (url.startsWith('https://hooks.slack.com/')) {
      sent.push(request.body);
      return { status: 200, headers: {}, body: 'ok' };
    }
    if (url.endsWith('/querybatch'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          results: JSON.parse(request.body).queries.map((q) => ({
            vulns:
              q.package.name === 'alpha'
                ? [{ id: 'GHSA-aaaa-bbbb-cccc', modified: iso(t0) }]
                : q.package.name === 'beta'
                  ? [{ id: 'PYSEC-2026-9', modified: iso(t0) }]
                  : [],
          })),
        }),
      };
    if (url.endsWith('/vulns/GHSA-aaaa-bbbb-cccc'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify(record('GHSA-aaaa-bbbb-cccc', 'npm', 'alpha', 'CRITICAL')),
      };
    if (url.endsWith('/vulns/PYSEC-2026-9'))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify(record('PYSEC-2026-9', 'PyPI', 'beta', 'HIGH')),
      };
    return { status: 404, headers: {}, body: '' };
  };
}

// Run directly: write the database with the build in the first argument.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [dist, output] = process.argv.slice(2);
  const load = (name) => import(pathToFileURL(join(resolve(dist), name)).href);
  const { parseConfig } = await load('config.js');
  const { Store } = await load('store.js');
  const { runScan } = await load('engine.js');
  const { loadInventory } = await load('inventory.js');
  const { deliverPending } = await load('delivery.js');
  copyFileSync(fileURLToPath(new URL('./watch-1.2.1.db', import.meta.url)), output);
  chmodSync(output, 0o600);
  const dir = mkdtempSync(join(tmpdir(), 'sw-fixture-'));
  const config = parseConfig(configInput);
  const store = new Store(output);
  const client = http();
  await runScan({
    config,
    inventory: loadInventory(writeInventory(dir, written)),
    store,
    http: client,
    now: written,
  });
  // Slack is paced at one message at a time; a minute apart sends them all.
  for (let minute = 0; minute < 10; minute++)
    console.log(await deliverPending(store, config, client, { now: written + minute * 60_000, credentials }));
  store.close();
}
