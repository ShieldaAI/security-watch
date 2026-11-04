import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseConfig, loadInventory, readFixture, Store, runScan } from '@shieldaai/security-watch';

// Use fictional data distributed in the installed package, not private inventory.
const packageRoot = dirname(dirname(fileURLToPath(import.meta.resolve('@shieldaai/security-watch'))));
const inventory = loadInventory(join(packageRoot, 'examples/systems.example.yaml'));
const now = new Date().toISOString();
for (const system of inventory.systems) system.updated_at = now;
// Simulated fresh capture times for fictional evidence; nothing was fetched.
const fixture = readFixture(join(packageRoot, 'examples/advisories.json')).map((event) => ({
  ...event,
  modified_at: now,
  fetched_at: now,
}));
const config = parseConfig({ version: 1 });
const store = new Store(':memory:');
const previousFetch = globalThis.fetch;
globalThis.fetch = async () => {
  throw new Error('This fixture example must not use the network');
};
try {
  const report = await runScan({
    config,
    inventory,
    store,
    fixture,
  });
  assert(report.findings.some((f) => f.applicability === 'affected'));
  assert(report.findings.some((f) => f.applicability === 'not_affected'));
  for (const finding of report.findings) {
    console.log(
      `${finding.system_id}: ${finding.applicability}; source severity: ${finding.source_severity}`,
    );
  }
  console.log('All assertions passed. Fictional advisory and inventory; in-memory storage.');
  console.log('No network, model requests, credentials or notifications.');
} finally {
  store.close();
  globalThis.fetch = previousFetch;
}
