# Preview dependency advisory monitoring without sending alerts

Security Watch compares a system inventory with advisory evidence and records
why a finding applies. Begin with its published fictional inventory and advisory
fixture, then inspect the result before configuring real monitoring.

This example uses `@shieldaai/security-watch@0.1.0-alpha.0`, an in-memory database,
no provider credentials and no notification delivery. It is a fixture check of
matching behavior, not an audit of real dependencies.

## Install

Use Node.js 24.10 or newer in a new directory:

```sh
mkdir watch-demo
cd watch-demo
npm init -y
npm install --ignore-scripts --save-exact @shieldaai/security-watch@0.1.0-alpha.0
```

## Run the fictional inventory

Save this as `offline-advisory-preview.mjs`:

```js
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
```

```sh
node offline-advisory-preview.mjs
```

The findings include both of these lines; their order is not part of the API:

```text
payments-staging: not_affected; source severity: critical
payments-production: affected; source severity: critical
All assertions passed. Fictional advisory and inventory; in-memory storage.
No network, model requests, credentials or notifications.
```

The shipped fixture names `example-parser` and a fictional advisory. Production
uses version `1.2.0`, which matches the fixture's affected range; staging uses
`1.3.0`, which falls outside that range. The fixture's severity is separate from
the assessment of each inventory item. Inventory and advisory timestamps are
simulated as a fresh capture for these fictional records; no evidence was fetched.
Real monitoring retains actual source and capture times so freshness checks can
preserve unknown assessments. This simulated capture does not establish current
coverage of real advisories.

## Move to a real inventory

Follow the [setup instructions](../README.md#install-and-preview) to generate
configuration, then replace the example inventory with your installed package
versions and deployment context. Review configuration with `doctor`. Keep AI and
notification routes disabled for an initial review.

A live scan contacts configured advisory and feed sources. Some integrations
send dependency names and versions, and enabling a model sends relevant inventory
and evidence to that provider. A real scan with `--dry-run` can still contact
sources; the explicit fixture is what makes this example offline. Configure
Slack or email only after reviewing the findings and the
[privacy and coverage boundaries](../SECURITY.md).

An empty result does not prove complete advisory coverage or safe software.
Unsupported version forms, missing versions and deployment conditions can require
human evidence. The example sends no test notification and performs no patching.

See [configuration](configuration.md) and the
[standalone example](../examples/offline-advisory-preview.mjs). For controlling
agent tool calls rather than monitoring dependencies, see
[Agent Guard](https://github.com/ShieldaAI/agent-guard).
