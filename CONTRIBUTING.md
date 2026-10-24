# Contributing

Security Watch is an initial TypeScript alpha targeting Node.js 24+. Contributions should preserve the separation between source evidence, applicability, contextual priority and notification policy.

## Local development

```sh
npm ci
npm run check
```

`npm run build` cleans generated `dist` output and compiles with strict unused-code checks. `npm test` builds and runs the Node test suite. `npm run check` also checks formatting and verifies the packed package in a clean consumer. Use `npm run format` for consistent formatting; `npm pack` performs a fresh build. Tests should use synthetic data and injected HTTP/email clients; they must not require production model credentials, bill a provider or send Slack/email messages.

For an offline synthetic demonstration:

```sh
npm run demo
```

The demo loads `examples/systems.example.yaml` and `examples/advisories.json`, refreshes the synthetic timestamps, and makes no network, model or notification requests. For the fixture CLI itself, use `node dist/cli.js scan --config examples/security-watch.example.yaml --fixture examples/advisories.json --dry-run` after building. Dry runs disable models; tests of actual provider calls must retain budget accounting.

Do not commit `node_modules`, `dist`, generated tarballs, local configuration, real inventories, credentials or SQLite files. The project ignores common local paths, but inspect your diff before committing.

## Implementation responsibilities

| Area                                | Responsibility                                                                                       |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `src/config.ts`, `src/inventory.ts` | Strict validation, predictable paths, bounds and metadata-only inventory import                      |
| `src/http.ts`, `src/sources.ts`     | Safe network access, complete collection/checkpoints and explicit source uncertainty                 |
| `src/assessment.ts`                 | Identity/version evidence, advisory grouping, per-deployment assessment and deterministic policy     |
| `src/models.ts`                     | Bounded provider requests, evidence attribution, conservative budgets and visible model failure      |
| `src/store.ts`, `src/delivery.ts`   | Transactional history/outbox, deduplication, acknowledgement, suppression and honest delivery status |
| `src/engine.ts`, `src/cli.ts`       | Orchestration, persistent monitoring, useful health status and installation/operator workflows       |

Keep provider and source schemas explicit. Do not accept a new service's response as trustworthy merely because it is syntactically valid. Unsupported affected-range formats must remain unknown. New inventory adapters must describe what their data actually establishes about deployment.

## Required review evidence

For behavioral changes, include a concise reproduction, before/after behavior, relevant tests and any change to coverage or privacy. Tests should exercise outcomes rather than mirror implementation details.

Protect these invariants:

1. Source-critical library/product findings cannot disappear because a model downgrades them or is unavailable.
2. Missing configuration, stale versions, unsupported backports and no advisory matches never produce an unsupported safe result.
3. Deployment-specific affected/fixed outcomes remain distinct; articles about multiple vulnerabilities must not merge unrelated advisories.
4. Older source revisions cannot undo newer withdrawals or version evidence. Inventory changes reassess stored evidence.
5. Malicious article/model text cannot change recipients, use tools or cause arbitrary network requests.
6. Findings and delivery jobs survive restart together. Ambiguous acceptance remains visible instead of silently retrying as exactly-once delivery.
7. Model limits are reserved before calls, include verification, and do not reset through a new process or a dry-looking error path.

Use fixture-based affected/fixed pairs, conflicting sources, malformed input, source/model failures and delivery interruption where relevant. Never publish real private inventory or a working credential in a test fixture.

## Releases

The intended package is `@shieldaai/security-watch`, version `0.1.0-alpha.0`; this initial checkout is not an npm publication. Maintainers should review and commit the exact source, run required checks, inspect `npm pack` contents, verify installation of the tarball in a clean consumer, and publish only through the release procedure in the repository. `prepublishOnly` performs release checks; do not bypass it to work around a failed check.

Keep package metadata, CLI version output, lockfile and release documentation aligned when changing versions. State which provider protocols and runtime versions were actually tested; mocked provider tests are not live provider certification. Report hosted CI, Docker or provenance checks as unverified if they did not run successfully.

Security-sensitive reports should follow [SECURITY.md](SECURITY.md) rather than a public issue containing exploit details or secrets. Contributions use the repository's Apache-2.0 license.
