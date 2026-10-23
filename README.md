# Shielda Security Watch

An experimental TypeScript bot that compares security advisories and news with your system inventory, records its evidence, and routes findings to Slack or email.

**Status: initial alpha, not independently audited.** The intended npm package is `@shieldaai/security-watch`; this checkout has not been published to npm. Install from a locally built package for now. This is a monitoring aid, not a guarantee that a system is secure or exploitable.

## What works

- Manual YAML/JSON inventories and npm package-lock v2/v3 imports, with separate assessments for each deployment/component.
- OSV exact-version queries, GitHub reviewed and malware advisories, CISA known-exploitation enrichment, and selected public RSS/Atom feeds.
- Deterministic npm identity/version checks, optional AI context, and separate source severity, applicability and contextual priority.
- Configurable library, product and news thresholds; immediate critical uncertainty, exploitation and malware overrides; review digests.
- Slack incoming webhooks and SMTP email, with a durable SQLite outbox, explicit uncertain delivery status and manual retry.
- Finding history, acknowledgement, expiring suppression, source checkpoints, model budgets, backup and monitoring-health findings.

| Inventory item | Alpha coverage |
| --- | --- |
| npm package with an exact version | Match supported affected ranges or verified OSV query results; preserve uncertainty and conflicting sources |
| npm package-lock v2/v3 | Import resolved transitive, development and optional dependency metadata; no installation or lifecycle scripts |
| Product, OS, database or SaaS name | Whole-name/keyword relevance and AI context; **no general product-version, vendor-backport or SaaS configuration adapter** |
| Unknown or stale version | Review required; never infer safety from missing evidence |

`affected` means the declared npm identity/version matches affected advisory evidence. A lockfile does not establish what is deployed, which features are enabled or whether vulnerable code is reachable. `not_affected` requires supported version-range exclusions; an empty advisory search is not that conclusion.

## Install and preview

Use Node.js **24 or newer**. From this checkout:

```sh
npm ci
npm run check
npm pack
npm install --global ./shieldaai-security-watch-0.1.0-alpha.0.tgz

security-watch init --directory ./watch --yes
```

`init --yes` creates example inventory and configuration with AI and notification routes disabled. Interactive `init` can select an AI provider/model and enable Slack routes. Neither form sends messages or overwrites existing files.

Replace the example inventory in `watch/systems.yaml`, then edit `watch/security-watch.yaml`. Configure notification routes and put credentials in the named environment variables. See the [configuration guide](docs/configuration.md).

```sh
security-watch doctor --config ./watch/security-watch.yaml
security-watch scan --config ./watch/security-watch.yaml --dry-run
security-watch start --config ./watch/security-watch.yaml
```

`start` activates configured routes and stays in the foreground. Run it under your service manager or Docker for continuous operation. Preview is a recommended setup step, not an enforced approval gate.

`doctor` validates local configuration and required environment variables. It does not contact providers, validate a model by spending tokens, or send test messages. A dry run writes no application state, disables model calls and sends no notifications; public advisory/feed requests still occur. For the simplest offline demonstration, run this from the source checkout:

```sh
npm run demo
```

The demo refreshes synthetic inventory timestamps and uses in-memory state, with no network, models or messages. The underlying files are [example configuration](examples/security-watch.example.yaml), [example inventory](examples/systems.example.yaml) and [synthetic evidence](examples/advisories.json). You can also run:

```sh
security-watch scan --config examples/security-watch.example.yaml --fixture examples/advisories.json --dry-run
```

Fixture mode makes no source or AI requests. Do not combine a fixture with `--notify` unless you intend to send its synthetic findings. To test real model compatibility and keep its budget reservations, run a normal `scan` without `--notify`, then inspect the saved findings.

## Run with Docker

Build the image from this checkout; no published image is assumed:

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

1. Collect bounded source responses, preserve source revisions, and join advisory aliases. News mentioning several existing advisories enriches their separate findings.
2. Compare each deployment's npm identity and version. Generic product matches remain uncertain. Stale inventory cannot support a safe conclusion.
3. Optionally ask the configured model for evidence-backed context. A second configured model reviews critical, exploited, uncertain or conflicting cases. Model disagreement remains visible.
4. Apply category policy. Source severity is a floor; an AI downgrade cannot suppress a source-critical library/product finding. News with an advisory identifier and an exact installed package mention uses library policy even before structured advisory data arrives.
5. Commit finding changes and notification jobs together. Deliver meaningful changes without treating cosmetic article wording or AI phrasing as new events.

With the default rules, libraries select critical severity and products/news select high or critical; routes are empty until configured. Unknown/conflicting potentially critical findings notify immediately when `urgent_unknown` is enabled. Lower-priority uncertainty goes to a review digest. Known-exploitation and malicious-package overrides are separately configurable. A category with no channels sends nothing, including overrides.

Models cannot run tools, change recipients, edit version ranges or establish that a dependency is safe. Model outages and exhausted budgets retain deterministic results and create monitoring-health findings. There is no automatic provider fallback.

## Operate

All commands accept `--config PATH`; the default is `./security-watch.yaml`.

| Command | Behavior |
| --- | --- |
| `scan` | Run once, save evidence/findings and queue notifications; does not deliver by default |
| `scan --dry-run` | Use in-memory state, disable model calls and send no notifications; source requests still occur |
| `scan --notify` | Save a scan, attempt due delivery and report the remaining backlog; future or rate-limited jobs stay pending |
| `scan --fixture PATH` | Use local evidence instead of network sources and AI |
| `scan --no-ai` | Keep structured matching and disable model calls for this invocation |
| `start` | Run the scheduler and delivery worker in the foreground |
| `findings`, `status`, `deliveries`, `budget` | Inspect saved assessments, monitoring state, delivery outcomes and budget reservations |
| `explain FINDING_ID` | Show a finding, its current policy decision and acknowledgement/suppression controls |
| `history FINDING_ID` | Show saved finding revisions |
| `acknowledge FINDING_ID` | Acknowledge the current revision; a material change creates a new revision |
| `suppress FINDING_ID --hours 24 --reason TEXT` | Suppress until an explicit expiry |
| `retry DELIVERY_ID` | Requeue a failed/uncertain delivery after checking receipt; does not send immediately |
| `backup --output PATH` | Create a consistent SQLite backup at a new destination |
| `unlock` | Remove stale lock metadata only when no worker owns the SQLite lock |
| `test-notification --channel slack` | Send an explicit test message; `email` is also supported |

Only one scan/scheduler instance may write a given database. Inspection and acknowledgement use SQLite safely alongside the worker. Do not share a database between containers or hosts or put it on a network filesystem. Stop the worker before replacing a database with a backup; retain permissions and move aside stale SQLite sidecar files with the old database.

Digests use fixed UTC epoch-aligned time buckets, defaulting to midnight UTC, with at most five findings per delivery. Larger digests produce multiple messages. `scan --notify` does not wait for future digest times, retry timers or Slack rate limits; it prints the remaining backlog. Use `start` to keep draining the queue as jobs become due. Urgent deterministic results are attempted before optional AI work.

A notification marked `accepted` was accepted by the destination, not necessarily read. Interrupted or ambiguous delivery becomes `unknown`: inspect the destination before `retry`, because it may already have arrived. Automatic retry is reserved for explicit retryable rejection. Delivery state remains available even when the notification channel itself fails.

`scan` exits with status 2 for degraded monitoring; setup/command failures use status 1. Check `status`, service logs and delivery state rather than treating an empty findings list as an all-clear.

## Boundaries and privacy

OSV queries disclose dependency names and versions to OSV. GitHub, CISA and feed servers receive normal HTTP requests; GitHub authentication is optional. The selected model provider receives relevant components/products/keywords and deployment context from the matched system, plus selected evidence. Slack/email receive findings and evidence links. Consider these disclosures before monitoring private dependencies.

Authentication credentials are read from environment variables. Findings, evidence, quoted model output, budget reservations and history are stored locally. There is no application telemetry. Protect the configuration, SQLite database, backups and credentials as operational data. Details are in [SECURITY.md](SECURITY.md).

This alpha has no automatic patching, shell execution from news, hosted dashboard, Slack action buttons, general SBOM import, distributed workers, EPSS integration or independent security audit. CVSS v3.0/v3.1 vectors and supplied severity labels/scores are supported; there is no CVSS v4 calculator. Product backports, reachability and exploit prerequisites require human/vendor evidence. GitHub begins with recent modifications, while OSV queries exact installed npm versions; this is not an exhaustive historical audit of every product.

Current evidence and findings are loaded into memory during each scan; audit history and model caches have no automatic retention pruning. This alpha targets small installations. Plan storage, pagination and retention before using it for a large fleet.

Review [configuration](docs/configuration.md), [security boundaries](SECURITY.md) and [contribution guidance](CONTRIBUTING.md) before extending or deploying it. Licensed under Apache-2.0.
