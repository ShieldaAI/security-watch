# Shielda Security Watch

An experimental TypeScript bot that compares security advisories and news with your system inventory, records its evidence, and routes findings to Slack or email.

**Alpha.** The package is `@shieldaai/security-watch`. It is not yet published to npm; build it locally using the steps below. See [coverage and security limits](SECURITY.md) before deploying it.

## Features

- YAML/JSON inventories, library lists across 12 ecosystems, and npm package-lock v2/v3 imports. Names alone are accepted; exact installed versions improve applicability checks.
- cve.now CVE updates and npm stack checks, plus The Hacker News security articles. Optional sources include OSV, GitHub, CISA KEV, official Node.js/Python/PHP feeds and other RSS/Atom feeds.
- Structured library checks without AI, with optional AI analysis to distinguish new vulnerabilities, updates to known vulnerabilities and general system news. Each finding records source severity, applicability and contextual priority separately.
- Separate alert thresholds for libraries, products and news, plus review digests and configurable overrides for potentially critical findings, known exploitation and malware.
- Slack incoming webhooks and SMTP email, backed by a SQLite delivery queue. Uncertain delivery is recorded for manual review and retry.
- Finding history, acknowledgement, suppression with an expiry, source checkpoints and model budgets. Optional external heartbeats, bounded retention and verified backups support ongoing operation.

| Inventory item                         | Alpha coverage                                                                                                                              |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| npm package with an exact version      | Match supported affected ranges or verified OSV query results; preserve uncertainty and conflicting sources                                 |
| Library in another supported ecosystem | Exact positive OSV query or explicitly listed affected version; unsupported version ranges remain unknown                                   |
| Library without an installed version   | Discover advisory candidates by package identity; applicability remains unknown                                                             |
| npm package-lock v2/v3                 | Import resolved transitive, development and optional dependency metadata; no installation or lifecycle scripts                              |
| Product, OS, database or SaaS name     | Whole-name/keyword candidates plus AI news/impact assessment; **no general product-version, vendor-backport or SaaS configuration adapter** |
| Unknown or stale version               | Review required; never infer safety from missing evidence                                                                                   |

`affected` means the declared package and installed version match supported advisory evidence. Only npm has version-range exclusion support; other ecosystems use exact positive OSV query results or explicitly listed affected versions. A missing version or empty search establishes neither affectedness nor safety. Lockfiles describe dependencies; you still need to verify what is deployed and reachable.

## Install and preview

Use Node.js **24 or newer**. From this checkout:

```sh
npm ci
npm run check
npm pack
npm install --global ./shieldaai-security-watch-0.1.0-alpha.0.tgz
```

Choose one setup command below. For a fictional example with AI disabled:

```sh
security-watch init --directory ./watch --yes
```

`init --yes` creates a private configuration, an example inventory and `.env.example`. It checks cve.now and The Hacker News every 30 minutes, with a 40-minute news window. AI and notification routes start disabled. Interactive `init` also asks for a provider, model, timing and notification channels. Existing files are never replaced.

Or start with Node.js, Python and OpenAI analysis:

```sh
security-watch templates
security-watch init --directory ./watch --yes --systems nodejs,python \
  --provider openai --model gpt-6-luna --poll-minutes 30 --lookback-minutes 40
```

After either setup command, create the private environment file:

```sh
cp ./watch/.env.example ./watch/.env
chmod 600 ./watch/.env
```

If you enabled OpenAI, edit `watch/.env` to set `OPENAI_API_KEY`. Use an exact model ID available to your account; `security-watch providers` lists the supported providers and their credential names. Omit `--provider` and `--model` to start without AI. Local services also need `--endpoint` and `--allow-private-endpoint`.

To configure notifications during setup, add `--notifications slack` to `init`, or use `--notifications email --email-from alerts@example.com --email-to security@example.com`. `--notifications slack,email` configures both. Fill in `SLACK_WEBHOOK_URL` or `SMTP_URL` in the private credentials file. `doctor` lists the active routes and warns when notifications are disabled.

Replace the example inventory in `watch/systems.yaml`, then edit `watch/security-watch.yaml`. For system news analysis, enable `models`, set your exact analysis model ID and provide its credential through the named environment variable. Configure notification routes separately. Without AI, matching system names remain candidates requiring review; a mention alone does not prove impact. See the [configuration guide](docs/configuration.md).

[Common systems](examples/common-systems.yaml) provides a sample list of 24 runtimes, operating systems, databases and infrastructure products, including Node.js and Python. It leaves installed versions unspecified. Add your versions and deployment context before using it to assess impact; broad language names also match applications and incidental mentions.

```sh
security-watch doctor --config ./watch/security-watch.yaml --credentials-file ./watch/.env
security-watch scan --config ./watch/security-watch.yaml --credentials-file ./watch/.env --dry-run
security-watch start --config ./watch/security-watch.yaml --credentials-file ./watch/.env
```

`start` activates configured routes and stays in the foreground. Run it under your service manager or Docker for continuous operation.

Verify a destination with `security-watch test-notification --channel slack --config ./watch/security-watch.yaml --credentials-file ./watch/.env`; use `--channel email` for SMTP. Each invocation sends one explicit test, reports acceptance or a safe failure reason, and leaves the monitor database unchanged.

To scan every 30 minutes and discover news from the last 40 minutes, set:

```yaml
poll_interval_minutes: 30
news_lookback_minutes: 40
```

Overlapping scans deduplicate findings. After downtime, the worker catches up from the last successful source checkpoint; older tracked advisories and exact package matches remain in scope. See [scan schedules and news windows](docs/configuration.md#scan-schedule-and-news-window).

`doctor` validates local configuration and required environment variables. It does not contact providers, validate a model by spending tokens, or send test messages. A dry run writes no application state, disables model calls and sends no notifications; public advisory/feed requests still occur. For an offline demonstration, run:

```sh
npm run demo
```

The demo refreshes synthetic inventory timestamps and uses in-memory state, with no network, models or messages. The underlying files are [example configuration](examples/security-watch.example.yaml), [example inventory](examples/systems.example.yaml) and [synthetic evidence](examples/advisories.json). You can also run:

```sh
security-watch scan --config examples/security-watch.example.yaml --fixture examples/advisories.json --dry-run
```

Fixture mode makes no source or AI requests. Do not combine a fixture with `--notify` unless you intend to send its synthetic findings. To test model analysis, run `security-watch scan --config ./watch/security-watch.yaml --credentials-file ./watch/.env` without `--dry-run` or `--notify`. This saves findings and budget reservations and may incur provider charges; it does not deliver notifications. The checkout also includes an opt-in [synthetic provider check](CONTRIBUTING.md#live-provider-checks).

## Library inventories

The supported ecosystems are npm, PyPI, Packagist, Go, Maven, crates.io, RubyGems, NuGet, Hex, Pub, Hackage and SwiftURL. Common language names such as `python`, `php` and `rust` are accepted as aliases. Run `security-watch ecosystems` for the canonical names.

Start from a file with one library per line:

```text
npm:express
python:requests
python:urllib3==2.2.3
php:symfony/http-foundation@6.4.0
maven:org.apache.logging.log4j:log4j-core
```

These are examples, not version recommendations. Use the registry's published package spelling, especially for NuGet. Omit a version you have not verified; do not substitute `latest`, a version constraint or a guessed release.

```sh
security-watch normalize-libraries --input ./libraries.txt
security-watch init --directory ./watch --yes --libraries ./libraries.txt
```

For a list containing only one ecosystem, use names without prefixes and add `--ecosystem php` or another supported alias. `init --libraries` creates one application inventory and enables OSV. It cannot be combined with `--systems`. Structured library matching needs no AI or model credentials. For a library-only monitor, disable news sources; see the [library configuration](examples/library-watch.example.yaml), [grouped inventory](examples/libraries.example.yaml) and [mixed library list](examples/libraries.example.txt).

To include official release/security news, add `--vendor-feeds nodejs,python,php` during setup or set `sources.vendor_feeds` in the configuration. These adapters extract bounded article text from fixed vendor hosts. A release announcement or database publication date alone does not establish a new vulnerability.

## LLM providers

There are 22 provider profiles:

- OpenAI, Azure OpenAI, Anthropic (Claude), Google Gemini, Cohere, xAI and Perplexity use their provider APIs.
- Groq, DeepSeek, Mistral, Together AI, Fireworks AI, OpenRouter, Cerebras, NVIDIA, SambaNova and Hugging Face use hosted Chat Completions endpoints.
- Ollama, LM Studio, vLLM and LiteLLM support configured local servers or gateways. A generic `openai-compatible` profile accepts other Chat Completions endpoints.

Run `security-watch providers` to list provider IDs, default endpoints, credential variable names and API documentation without loading a monitor configuration. Specify an exact model ID and choose a supported output format; capabilities vary by model and account. Local/private endpoints require explicit configuration. AWS Bedrock and Vertex AI credentials are not supported directly. See [provider configuration](docs/configuration.md#model-configuration) for defaults and examples.

## Run with Docker

Build the image locally:

```sh
docker build -t shielda-security-watch .
docker volume create security-watch-data
docker run --rm --user 0 --entrypoint chown \
  --mount type=volume,src=security-watch-data,dst=/data \
  shielda-security-watch "$(id -u):$(id -g)" /data
docker run --rm --name security-watch \
  --user "$(id -u):$(id -g)" \
  --env-file ./watch/.env \
  --mount type=bind,src="$(pwd)/watch/security-watch.yaml",dst=/config/security-watch.yaml,readonly \
  --mount type=bind,src="$(pwd)/watch/systems.yaml",dst=/config/systems.yaml,readonly \
  --mount type=volume,src=security-watch-data,dst=/data \
  shielda-security-watch start --config /config/security-watch.yaml
```

Before running, set `inventory: /config/systems.yaml` and `database: /data/watch.db` in the container's configuration. Create `watch/.env` privately with only the credentials you use; it is not loaded automatically by the npm CLI. Keep configuration, inventory and `.env` readable only by your user, for example with `chmod 600` on those files. The short initialization command assigns the data volume to your UID/GID; the application itself then runs as that user. Your Docker VM must be able to access the configuration/inventory bind mounts. Add a read-only mount for any imported lockfile under `/config` and use the matching path in the inventory.

SQLite stays on a native Docker volume rather than a desktop VM's shared host filesystem. This avoids depending on host-sharing behavior for database locking and write-ahead logging. Retain `security-watch-data` when recreating the container. The application needs outbound network access and no inbound port.

The included Compose file uses root-level `security-watch.yaml`, `systems.yaml` and `.env`:

```sh
cp examples/security-watch.example.yaml security-watch.yaml
cp examples/systems.example.yaml systems.yaml
cp .env.example .env
chmod 600 security-watch.yaml systems.yaml .env
export SECURITY_WATCH_UID=$(id -u) SECURITY_WATCH_GID=$(id -g)
```

Edit the copied inventory, notification routes and credentials, and apply the same `/config/systems.yaml` and `/data/watch.db` settings before running `docker compose up --build -d`. Inspect `docker compose logs --follow`. Compose requires the host UID/GID variables and automatically runs a short volume-ownership initializer before the application starts. Its `watch-data` named volume keeps SQLite on Docker's native filesystem, while the private configuration/inventory remain read-only host mounts. You may persist the UID/GID values in the private `.env` file for later Compose invocations. Add an explicit read-only mount if the inventory imports a lockfile. Retain the named volume when recreating containers; `docker compose down --volumes` removes it.

## How decisions work

1. Collect cve.now responses and The Hacker News articles within configured size and request limits. Preserve source revisions and group advisories that share verified aliases. News mentioning several existing advisories adds context to each finding separately.
2. Compare each deployment's library identity and declared version. npm supports range checks; other ecosystems require exact positive evidence. Generic product matches remain uncertain. Stale inventory cannot support a safe conclusion.
3. Ask the configured model to classify matched system news and assess the claimed impact on the declared deployment, using article evidence and version context. General news about a system is distinguished from a new vulnerability or an update to a known one. If configured, a second model reviews every news analysis and any critical, exploited, uncertain or conflicting finding. Disagreements remain visible.
4. Apply the category's notification policy. AI cannot reduce priority below the source severity or suppress a critical library/product finding. News with an advisory identifier and an exact installed package mention uses library policy even before structured advisory data arrives.
5. Commit finding changes and notification jobs together. Deliver meaningful changes without treating cosmetic article wording or AI phrasing as new events.

With the default rules, libraries select critical severity and products/news select high or critical; routes are empty until configured. Unknown/conflicting potentially critical findings notify immediately when `urgent_unknown` is enabled. Lower-priority uncertainty goes to a review digest. Known-exploitation and malicious-package overrides are separately configurable. A category with no channels sends nothing, including overrides.

For system news, the model records `new_vulnerability`, `known_vulnerability_update`, `general_news` or `unknown`, alongside its assessment of system impact. General coverage and supported exclusions are recorded without a vulnerability alert; uncertain analysis goes to review. A vulnerability that the model believes affects the system follows your severity policy. These rules also cover product articles linked to collected CVEs. Critical-source severity, configured exploitation overrides and deterministic library matches still take precedence. See [model configuration](docs/configuration.md#model-configuration) for evidence and version requirements.

General-news classifications remain in history after a story leaves RSS. Changes to the article, inventory or model settings trigger reassessment. Affected or excluded impact claims require fresh evidence.

Models cannot run tools, change recipients, edit version ranges or establish that a dependency is safe. Model outages and exhausted budgets retain deterministic results and create monitoring-health findings. There is no automatic provider fallback.

## Operate

Commands that operate on a configured monitor accept `--config PATH`; the default is `./security-watch.yaml`. Add `--credentials-file PATH` to load a private dotenv file, or export variables through your service manager. Existing environment values take precedence. Files are parsed as data, without shell evaluation; they are never loaded implicitly. `init` uses `--directory` instead. Unsupported flag/command combinations are rejected before activity.

| Command                                        | Behavior                                                                                                                  |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `providers`                                    | List supported provider profiles without configuration, credentials or network access                                     |
| `templates`                                    | List common system IDs available to `init --systems`                                                                      |
| `ecosystems`                                   | List supported library ecosystems                                                                                         |
| `normalize-libraries --input PATH`             | Parse a library list without network requests; optional `--ecosystem` sets the group and `--output` saves a new JSON file |
| `scan`                                         | Run once, save evidence/findings and queue notifications; does not deliver by default                                     |
| `scan --dry-run`                               | Use in-memory state, disable model calls and send no notifications; source requests still occur                           |
| `scan --notify`                                | Save a scan, attempt due delivery and report the remaining backlog; future or rate-limited jobs stay pending              |
| `scan --fixture PATH`                          | Use local evidence instead of network sources and AI                                                                      |
| `scan --no-ai`                                 | Keep structured matching and disable model calls for this invocation                                                      |
| `start`                                        | Run the scheduler and delivery worker in the foreground                                                                   |
| `findings`, `status`, `deliveries`, `budget`   | Inspect saved assessments, monitoring state, delivery outcomes and budget reservations                                    |
| `health`                                       | Check worker heartbeat, completed-scan freshness and actionable delivery problems; exits 2 when unhealthy                 |
| `health --scan-only`                           | Check completed scans and delivery without requiring a foreground worker, for external cron schedules                     |
| `explain FINDING_ID`                           | Show a finding, its current policy decision and acknowledgement/suppression controls                                      |
| `history FINDING_ID`                           | Show saved finding revisions                                                                                              |
| `acknowledge FINDING_ID`                       | Acknowledge the current revision; a material change creates a new revision                                                |
| `suppress FINDING_ID --hours 24 --reason TEXT` | Suppress until an explicit expiry                                                                                         |
| `retry DELIVERY_ID`                            | Requeue a failed/uncertain delivery after checking receipt; does not send immediately                                     |
| `backup --output PATH`                         | Create a consistent SQLite backup at a new destination and verify a temporary restored copy                               |
| `verify-backup --input PATH`                   | Verify a standalone backup without monitor configuration or replacing a live database                                     |
| `prune`                                        | Show a read-only plan using configured retention periods                                                                  |
| `prune --apply`                                | Apply one bounded retention batch atomically                                                                              |
| `unlock`                                       | Remove stale lock metadata only when no worker owns the SQLite lock                                                       |
| `test-notification --channel slack`            | Send an explicit test message; `email` is also supported                                                                  |

Only one scan/scheduler instance may write a given database. Inspection and acknowledgement use SQLite safely alongside the worker. Do not share a database between containers or hosts or put it on a network filesystem. Stop the worker before replacing a database with a backup; retain permissions and move aside stale SQLite sidecar files with the old database.

Digests use fixed UTC epoch-aligned time buckets, defaulting to midnight UTC, with at most five findings per delivery. Larger digests produce multiple messages. `scan --notify` does not wait for future digest times, retry timers or Slack rate limits; it prints the remaining backlog. Use `start` to keep draining the queue as jobs become due. Urgent deterministic results are attempted before optional AI work.

A notification marked `accepted` was accepted by the destination, not necessarily read. Interrupted or ambiguous delivery becomes `unknown`: inspect the destination before `retry`, because it may already have arrived. Automatic retries cover explicit transient rejections and DNS/connection failures known to occur before sending. Slack digests split to fit the message limit, and one malformed queued message does not block healthy messages. Delivery state remains available even when a destination fails.

`scan` exits with status 2 for degraded monitoring or failed/uncertain delivery, including an early urgent delivery attempt; setup/command failures use status 1. `health` is read-only, makes no network requests, and reports monitoring health rather than whether systems are secure. The Compose service includes this health check. Check `status`, service logs and delivery state rather than treating an empty findings list as an all-clear.

One failed source item, model response or notification does not stop unrelated work. Valid evidence and findings are saved, incomplete sources keep their previous checkpoints, and `start` continues scheduled scans and due deliveries. A one-shot `scan` finishes its work and reports degraded status; it does not stay running. Cancellation and failures that prevent reliable database writes still stop the worker.

SIGTERM/SIGINT cancels source/model requests and active delivery attempts, then stops further work. Interrupted or ambiguous receipt remains explicit. Before urgent sends, inventory exclusions, withdrawals and removals are reconciled. Every delivery rechecks current routing policy.

### Heartbeats, retention and backups

All three are opt-in. `init --heartbeat` adds an external success-ping route using the `HEARTBEAT_URL` environment variable. Configure the receiving service to alert when pings stop. The worker sends a bodyless request only while monitoring health is healthy; failed scans or delivery problems withhold success pings. This is separate from the local `health` command and sends no inventory or logs.

Configure `maintenance.retention`, inspect `security-watch prune --config PATH`, then use `--apply` for one cleanup batch. Once configured, `start` also applies retention on the maintenance schedule. Active or uncertain findings, unresolved deliveries, source checkpoints and budget records remain protected. Expiring an inactive finding requires a supported exclusion, withdrawal or confirmed general-news result; removing a system from inventory is not enough.

`maintenance.backup` schedules private snapshots, verifies them before rotation, and keeps the configured number. When both are enabled, a verified backup precedes pruning. `verify-backup` tests schema migration and structural restoration in a temporary copy; it does not prove that stored security claims are correct. See [maintenance configuration](docs/configuration.md#retention-and-verified-backups) before enabling either policy.

### Model evaluation from a checkout

```sh
npm run evaluate:models -- --help
npm run evaluate:models
```

Without `--live`, the script makes no provider calls and reports skipped cases. To run it, supply provider credentials and exact `SECURITY_WATCH_EVAL_<PROVIDER>_MODEL` values in the environment, then choose providers and a request cap:

```sh
npm run evaluate:models -- --live --providers openai,anthropic --max-requests 20
```

The corpus contains source-derived synthetic scenarios with fictional inventories. Its reference labels are marked `pending_human_review`. Reports distinguish output acceptance, coverage, label agreement, false exclusions, rejected outputs and model disagreements. Label agreement is not measured production accuracy. Live runs may incur charges, use a total request cap, and send no notifications; full options are in the script help.

## Boundaries and privacy

cve.now stack queries disclose deduplicated npm package names and versions; lockfiles and deployment metadata are not uploaded. The Hacker News feed and article servers receive normal HTTP requests. Optional OSV queries also disclose dependency names and versions; optional GitHub, CISA and additional feed sources receive normal HTTP requests. GitHub authentication is optional. The selected model provider receives relevant components/products/keywords and deployment context from the matched system, plus selected evidence. Slack/email receive findings and evidence links. Consider these disclosures before monitoring private dependencies.

Authentication credentials are read from environment variables. Findings, evidence, quoted model output, budget reservations and history are stored locally. There is no automatic application telemetry. An explicitly configured heartbeat service receives success pings and normal request metadata. Protect the configuration, SQLite database, backups and credentials as operational data. Details are in [SECURITY.md](SECURITY.md).

This alpha has no automatic patching, shell execution from news, hosted dashboard, Slack action buttons, general SBOM import, distributed workers, EPSS integration or independent security audit. CVSS v3.0/v3.1 vectors and supplied severity labels/scores are supported; there is no CVSS v4 calculator. Product backports, reachability and exploit prerequisites require human/vendor evidence. cve.now starts from recent entries, revisits tracked/news-cited CVEs and checks exact npm packages through its stack endpoint; this is not an exhaustive historical audit of every product. Existing configurations retain explicitly enabled legacy sources; set `osv`, `github` and `kev` to `false` to switch exclusively to the new defaults.

Current evidence and findings are loaded into memory during each scan. Retention is disabled until configured, and protected unresolved records may continue growing even after cleanup is enabled. This alpha targets small installations. Plan storage and review retention dry runs before increasing scale.

See the [configuration guide](docs/configuration.md), [security policy](SECURITY.md) and [contributing guide](CONTRIBUTING.md). Licensed under Apache-2.0.
