# Contributing

Security Watch uses TypeScript and requires Node.js 24 or newer. Keep source evidence, version applicability, contextual priority and notification policy separate when adding features.

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

## Live provider checks

The regular suite uses simulated provider responses, including real loopback HTTP tests for every provider profile. Live checks are separate and may incur provider charges. They send a short fictional bulletin through the production request, parsing and evidence-validation code, with no private inventory, tools or notifications.

Create a private `.env.live` file with the keys for the providers you want to test. Add exact model IDs available to your account:

```dotenv
OPENAI_API_KEY=your-key
ANTHROPIC_API_KEY=your-key
SECURITY_WATCH_SMOKE_OPENAI_MODEL=your-openai-model-id
SECURITY_WATCH_SMOKE_ANTHROPIC_MODEL=your-claude-model-id
```

```sh
chmod 600 .env.live
npm run build
node --env-file=.env.live scripts/check-models.mjs --live --providers openai,anthropic
```

If the variables are already exported, use `npm run check:models -- --live --providers openai,anthropic`. Omitting `--live` makes no requests. Each selected provider gets at most one request per invocation, with no automatic retry, a 30-second timeout and 1,024 output tokens by default. `--timeout-seconds` accepts 1–60 and `--max-output-tokens` accepts 128–2,048. Reservations are held in memory for this one-shot check; it does not use or change a monitor's persisted daily budget.

For other providers, use `SECURITY_WATCH_SMOKE_<PROVIDER>_MODEL`, replacing hyphens in the uppercase provider ID with underscores. `_ENDPOINT` selects a full endpoint, `_OUTPUT_FORMAT` selects an explicit format, and `_ALLOW_PRIVATE=1` permits an operator-selected private endpoint. Local profiles require an endpoint. Credential names come from `security-watch providers`.

The result reports passed, failed and skipped providers without raw model output or credentials. A pass confirms that one response met the application's schema and evidence checks; it does not measure general model accuracy. Exit status is 0 when at least one provider passes and none fail, 1 for failures, 2 for invalid options, and 3 when every provider is skipped. Missing credentials or configuration are reported as skips. Do not enable paid checks in routine CI.

## Code layout

| Area                                              | Responsibility                                                                                   |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `src/config.ts`, `src/inventory.ts`               | Configuration validation, path resolution and metadata-only inventory import                     |
| `src/http.ts`, `src/sources.ts`, `src/cve-now.ts` | Network restrictions, source collection, checkpoints and incomplete-source reporting             |
| `src/assessment.ts`                               | Identity/version evidence, advisory grouping, per-deployment assessment and deterministic policy |
| `src/models.ts`, `src/providers.ts`               | Provider protocols, bounded requests, evidence attribution, budgets and visible model failure    |
| `src/store.ts`, `src/delivery.ts`                 | Transactional history/outbox, deduplication, acknowledgement, suppression and delivery status    |
| `src/engine.ts`, `src/cli.ts`                     | Orchestration, persistent monitoring, useful health status and installation/operator workflows   |

Keep provider and source schemas explicit. Do not accept a new service's response as trustworthy merely because it is syntactically valid. Unsupported affected-range formats must remain unknown. New inventory adapters must describe what their data actually establishes about deployment.

## Pull requests

For behavioral changes, include a concise reproduction, before/after behavior, relevant tests and any change to coverage or privacy. Tests should exercise outcomes rather than mirror implementation details.

`main` and release branches require a pull request, one approving review, resolved review conversations and passing CI against the latest base branch. New commits dismiss stale approvals, and someone other than the last person to push must approve the latest changes. Direct pushes, force pushes, deletion and administrator bypass are blocked.

CI checks out source without saving its GitHub token and installs dependencies without lifecycle scripts. Pull requests also receive a dependency review. The CodeQL workflow scans TypeScript, JavaScript and GitHub Actions without building the project; Dependabot checks npm packages and pinned Actions weekly. New workflow checks must pass on GitHub before they become required merge checks.

Protect these invariants:

1. Source-critical library/product findings cannot disappear because a model downgrades them or is unavailable.
2. Missing configuration, stale versions, unsupported backports and no advisory matches never produce an unsupported safe result.
3. Deployment-specific affected/fixed outcomes remain distinct; articles about multiple vulnerabilities must not merge unrelated advisories.
4. Older source revisions cannot undo newer withdrawals or version evidence. Inventory changes reassess stored evidence.
5. Malicious article/model text cannot change recipients, use tools or cause arbitrary network requests.
6. Save findings and delivery jobs in the same transaction. If delivery may have succeeded, record it as uncertain and require a receipt check before retrying.
7. Reserve model budget before each call, including verification. Restarting the process or receiving an error must not reset the budget.

Use fixture-based affected/fixed pairs, conflicting sources, malformed input, source/model failures and delivery interruption where relevant. Never publish real private inventory or a working credential in a test fixture.

## Releases

The package is `@shieldaai/security-watch`; releases currently use the `alpha` tag. Before publishing, commit the reviewed changes, run `npm run check`, and inspect the output of `npm pack --dry-run`. The check command installs the tarball in a clean consumer and verifies the CLI, types and runtime exports. `prepublishOnly` repeats the checks and requires a clean checkout.

Only repository administrators can create `v*` release tags. These tags cannot be changed or deleted, including by administrators.

Update package metadata, CLI version output, the lockfile and release documentation together. Release notes should name the runtimes and provider protocols tested, and distinguish mocked checks from live integrations. Record any checks that could not run.

Security-sensitive reports should follow [SECURITY.md](SECURITY.md) rather than a public issue containing exploit details or secrets. Contributions use the repository's Apache-2.0 license.
