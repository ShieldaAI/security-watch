# Shielda Security Watch

Security Watch tells you, within minutes, when a newly reported security problem concerns software you run, and tells you **where to look**. Point it at your code and it reads the lockfiles you already have (or give it a list of your systems by hand). It keeps watching public security advisories and security news, compares them with your list, and sends a message to Slack or email when something needs attention.

It runs on your own server or laptop. Your list of systems stays with you.

## The problem

There is far more security news than anyone can read, and most of it has nothing to do with you. Waiting for a CVE to be published, or checking once a day, is too late: you need to know quickly what affects _your_ stack. Security Watch does that reading for you. You choose how often it runs and how far back it looks, you set your own risk appetite (which findings alert at once and which wait for a digest), and you add context about your systems. It then sends Slack or email alerts with the evidence and a pointer to the affected system, so you can act right away.

## Why a daily check is not enough

- **Problems are used by attackers within hours.** A check that runs once a day, or once a week in a build pipeline, leaves most of that day uncovered. In the starter setup Security Watch checks every 30 minutes, and it catches up by itself after downtime.
- **The CVE entry often arrives late.** A vulnerability is usually discussed in vendor announcements and security news before a complete CVE record with affected versions exists. If you wait for the CVE, you start late. Security Watch reads the news as well as the advisory databases, and raises a "possibly affected, please check" finding as soon as a story names something on your list.
- **A list that was correct last month is not enough.** A library you already use can become vulnerable tomorrow without any change on your side. The check has to run continuously against the versions you run today, so keep your list current: let your CI pipeline send a fresh SBOM on every merge. In the starter setup Security Watch warns when the list has not been updated for a week.
- **Knowing the library is not knowing the place.** "lodash is vulnerable" does not tell anyone which service, repository or team has to act. Every system and library on your list can carry a short note, and the alert repeats that note.

## What an alert looks like

This is the message produced by the [hand-written example list](#describe-systems-by-hand) below and a fictional advisory:

```text
[CRITICAL] express request smuggling (fictional test record)
Finding: 8aa3f6df3875112d087d95f4ae8b23cd32a81fd24b7fdf01fb1a92720be41bf7
Delivery: f464faf4-d0e6-4c0f-9ff3-ff008fb808da
System: web-shop / library:ee5130742729fbc72bd45978
Where to look: Web shop (owner: Dana, platform team) - runs on cluster eu-1, namespace shop
Affected item: npm express 4.21.2 - checkout API, repository acme/checkout, file package.json
Applicability: affected; source severity: critical; priority: critical
Summary: express@4.21.2 in Web shop: affected.
• The exact npm identity express and installed version 4.21.2 match affected advisory evidence.
Fix: 4.22.0
Rule: Matched library rule at critical severity; source severity remains the minimum.
Assessment time: 2026-11-13T18:10:42.212Z
https://example.com/advisory
```

The `Where to look` and `Affected item` lines come from your own list: the system's name, owner and note, and the note you wrote beside the library. Whoever receives the alert can go straight to the right place and confirm it. The `Finding` value is what you pass to commands such as `security-watch explain`.

## Get started in four steps

You need a computer that stays on (a small server is enough) and [Node.js](https://nodejs.org/) version 24.10 or newer. In a terminal:

1. **Install it.**

   ```sh
   npm install --global @shieldaai/security-watch
   ```

2. **Point it at your code.** Give it the folder of a project you run. It reads the lockfiles and manifests already there (npm, Python, Go, Rust, PHP, Ruby, Java, .NET, Dart, Elixir, Swift and Haskell), writes them as an SBOM and creates a starter configuration. Nothing is installed, run or sent anywhere.

   ```sh
   security-watch init --directory ./watch --yes --project ./my-app --notifications slack
   ```

   ```text
   my-app: 412 packages (PyPI, npm) from 3 files: package-lock.json, services/billing/requirements.txt, services/billing/pyproject.toml.
   Wrote /home/dana/watch/sboms/my-app.cdx.json.
   ```

   Repeat `--project` for each project. Every SBOM in `watch/sboms` is one monitored system, and an alert names the file a package was found in. No code at hand? [Describe your systems by hand](#describe-systems-by-hand) instead.

3. **Add the Slack address.** Copy the secrets template, keep it private, then open `watch/.env` and paste your Slack incoming-webhook address after `SLACK_WEBHOOK_URL=`:

   ```sh
   cp ./watch/.env.example ./watch/.env
   chmod 600 ./watch/.env
   ```

4. **Check, then start.** The first command verifies your files, the second shows what a scan finds without sending anything, the third keeps watching. The first scan reads the last day of advisories at roughly one request a second, so expect it to take 15 to 20 minutes; later scans usually take a minute or two. You can skip the second command and go straight to the third.

   ```sh
   security-watch doctor --config ./watch/security-watch.yaml --credentials-file ./watch/.env
   security-watch scan --config ./watch/security-watch.yaml --credentials-file ./watch/.env --dry-run
   security-watch start --config ./watch/security-watch.yaml --credentials-file ./watch/.env
   ```

**Keep it current from CI.** Dependencies change with every merge, and an SBOM older than a week is reported as stale. Let your pipeline send a fresh one. Turn on the receiver in `watch/security-watch.yaml`, put a token made with `openssl rand -hex 32` in `watch/.env` as `SECURITY_WATCH_INTAKE_TOKEN` and in your CI secrets, and restart:

```yaml
intake:
  listen: 0.0.0.0:8787
  tls_cert_file: ./tls/cert.pem # or allow_plain_http: true behind a TLS proxy
  tls_key_file: ./tls/key.pem
```

```yaml
# GitHub Actions: makes the SBOM and sends it; the job fails if the monitor refuses it
- uses: ShieldaAI/security-watch@v1.2.1
  with:
    system-id: my-app
    owner: Dana, platform team
    upload-url: https://watch.example.com:8787
    upload-token: ${{ secrets.SECURITY_WATCH_INTAKE_TOKEN }}
```

```sh
# Any other pipeline with Node.js 24 and SECURITY_WATCH_INTAKE_TOKEN set
npx --yes @shieldaai/security-watch@1.2.1 sbom --system-id my-app --upload https://watch.example.com:8787
```

[Watch a project from its dependency files](docs/sbom.md) covers the files that are read, GitLab CI, the receiver (tokens limited to some systems, TLS, Docker), other ways to deliver SBOMs, and SBOMs from Trivy, Syft, cdxgen or GitHub's dependency graph, which are accepted as they are.

### Describe systems by hand

For products, databases and SaaS, or to add owners and notes yourself, write `watch/systems.yaml` (create the folder with `security-watch init --directory ./watch --yes --notifications slack`, which writes an example):

```yaml
sbom_directory: ./sboms # optional: SBOMs from step 2 or your pipelines
systems:
  - id: web-shop
    name: Web shop
    owner: Dana, platform team
    note: runs on cluster eu-1, namespace shop
    updated_at: '2026-11-13T09:00:00Z' # when you last checked this list; older than 7 days counts as stale
    libraries:
      - 'npm:express@4.21.2   # checkout API, repository acme/checkout, file package.json'
      - 'python:requests==2.32.3   # billing worker, services/billing/requirements.txt'
    products:
      - name: PostgreSQL
        version: '16.4'
        note: managed database "shop-prod", owned by the data team
```

Everything after `#` on a library line is the note for that library. Keep the quotes around each library line: without them the note is ignored. Notes are optional, but they are what makes an alert easy to act on.

If your list contains libraries that are not npm packages (Python, PHP, Java, Go and so on), also open `watch/security-watch.yaml` and change `osv: false` to `osv: true`. That turns on the advisory database that covers those ecosystems; it receives the library names and versions you list. `init --project` does this for you when it finds such packages.

**What gets sent.** With the starter settings you get an immediate message for a critical finding in a library, anything reported as actively exploited, a malicious package, and a possibly critical finding that still needs checking (a critical product or news finding is one of these until it is confirmed). High findings for a product or in the news usually arrive in the daily digest: a product match cannot be confirmed from version ranges, and news is sent at once only when a configured model confirms that it affects you, or when an article reports that something on your list is being exploited. News that no advisory has scored yet takes the CVSS score or vendor rating an article states for it ([news signals](docs/configuration.md#news-signals)). Less urgent findings that need a look arrive together in one daily digest. Everything else is recorded and shown by `security-watch findings`. The `policy` section of the configuration file changes these thresholds.

To try it with no network access and fictional data first, follow the [offline advisory preview](docs/offline-advisory-preview.md). The rest of this page covers the options in detail.

**Version 1.2.1.** This is `@shieldaai/security-watch` 1.2.1, a patch release of 1.2.0, the minor release of the first stable version (1.0.0) that reads CVSS scores, vendor ratings and exploitation reports from news for findings that no advisory has scored yet, and can show FIRST's EPSS for each CVE; 1.1 added SBOM generation from dependency files, an SBOM folder for pipelines, SPDX import and a GitHub Action. It is published under the default `latest` tag and has no independent security audit. Read the [coverage and security limits](SECURITY.md) before relying on it, the [compatibility policy](docs/compatibility.md) for what stays stable, and the [changelog](CHANGELOG.md) for what changed.

Related projects: [Agent Guard](https://github.com/ShieldaAI/agent-guard) for tool permissions and approvals, and [SafeCall Node](https://github.com/GuardianMesh/llm-safecall-node) or [SafeCall Python](https://github.com/GuardianMesh/llm-safecall) for model response validation. The [package selection guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/package-guide.md) explains how they fit together.

## Features

- Inventories from your code: `security-watch sbom` and `init --project` read the lockfiles and manifests of 12 ecosystems and write a CycloneDX SBOM; an SBOM folder turns every SBOM your pipelines deliver into a monitored system. A [GitHub Action](docs/sbom.md#github-actions) and a one-line command for other CI are included. Hand-written YAML/JSON inventories and library lists still work. Names alone are accepted; exact installed versions improve applicability checks.
- cve.now CVE updates and npm stack checks, plus The Hacker News security articles. Optional sources include OSV, GitHub, CISA KEV, official Node.js/Python/PHP feeds and other RSS/Atom feeds.
- Structured library checks without AI, with optional AI analysis to distinguish new vulnerabilities, updates to known vulnerabilities and general system news. Each finding records source severity, applicability and contextual priority separately.
- Separate alert thresholds for libraries, products and news, plus review digests and configurable overrides for potentially critical findings, known exploitation and malware.
- Slack incoming webhooks and SMTP email, backed by a SQLite delivery queue. An email is retried automatically only when it provably never left. A Slack message is retried when Slack answers HTTP 429 or 5xx or the connection fails before the request is sent; in rare cases Slack may have posted a message it answered 5xx for. Any other uncertain delivery is recorded for manual review and retry.
- Per-source coverage receipts, bounded CycloneDX and SPDX import (output of Trivy, Syft, cdxgen and GitHub's dependency graph) with package URLs and dependency relationships, and inventory drift reports. Optional artifact kinds cover MCP servers/clients, plugins, skills and models; signature, attestation and remediation lifecycle fields record operator-supplied evidence. They do not perform verification or close findings. See [deployment evidence](docs/configuration.md#agent-deployment-evidence-sboms-and-drift).
- Finding history, revision-bound AI dismissal review, acknowledgement, suppression with an expiry, source checkpoints and model budgets. Optional external heartbeats, bounded retention and verified backups support ongoing operation.

| Inventory item                         | Coverage                                                                                                                                    |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| npm package with an exact version      | Match supported affected ranges or verified OSV query results; preserve uncertainty and conflicting sources                                 |
| PyPI package with a final release      | Match the documented PEP 440 final-release subset; other forms remain unknown                                                               |
| Library in another supported ecosystem | Exact positive OSV query or explicitly listed affected version; unsupported version ranges remain unknown                                   |
| Library without an installed version   | Discover advisory candidates by package identity; applicability remains unknown                                                             |
| Lockfiles and SBOMs                    | Import resolved transitive, development and optional dependency metadata; no installation or lifecycle scripts                              |
| Product, OS, database or SaaS name     | Whole-name/keyword candidates plus AI news/impact assessment; **no general product-version, vendor-backport or SaaS configuration adapter** |
| Unknown or stale version               | Review required; never infer safety from missing evidence                                                                                   |

`affected` means the declared package and installed version match supported advisory evidence. npm and the documented PyPI final-release subset support version-range exclusion; other ecosystems use exact positive OSV query results or explicitly listed affected versions. A missing version or empty search establishes neither affectedness nor safety. Lockfiles describe dependencies; you still need to verify what is deployed and reachable.

## Install and preview

Use Node.js **24.10.0 or newer**. Install it:

```sh
npm install --global @shieldaai/security-watch
```

To build and install from a source checkout:

```sh
npm ci
npm run check
npm pack
npm install --global ./shieldaai-security-watch-1.2.1.tgz
```

Choose one setup command below. To start from your own code, use `init --project` as in [step 2](#get-started-in-four-steps). For a fictional example with AI disabled:

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

Overlapping scans deduplicate findings. After downtime, the worker catches up from the last successful source checkpoint (for cve.now, up to about three months of records; a longer gap is reported); older tracked advisories and exact package matches remain in scope. See [scan schedules and news windows](docs/configuration.md#scan-schedule-and-news-window).

`doctor` validates local configuration and required environment variables, and lists inventory entries that were left out or will not match as written. It exits with status 2 whenever it prints `ok: false`. It does not contact providers, validate a model by spending tokens, or send test messages. A dry run writes no application state, disables model calls and sends no notifications; public advisory/feed requests still occur. For an offline demonstration, run:

```sh
npm run demo
```

The demo refreshes synthetic inventory timestamps and uses in-memory state, with no network, models or messages. The underlying files are [example configuration](examples/security-watch.example.yaml), [example inventory](examples/systems.example.yaml) and [synthetic evidence](examples/advisories.json). You can also run:

```sh
security-watch scan --config examples/security-watch.example.yaml --fixture examples/advisories.json --dry-run
```

Fixture mode makes no source or AI requests and counts the fixture's records as read now; with `--dry-run` it also counts the inventory as current, since it previews matching, not freshness. Do not combine a fixture with `--notify` unless you intend to send its synthetic findings. To test model analysis, run `security-watch scan --config ./watch/security-watch.yaml --credentials-file ./watch/.env` without `--dry-run` or `--notify`. This saves findings and budget reservations and may incur provider charges; it does not deliver notifications. The checkout also includes an opt-in [synthetic provider check](CONTRIBUTING.md#live-provider-checks).

Use the packaged [offline rehearsal](docs/offline-rehearsal.md) to exercise policy, outbox receipts and backup/restore in an isolated temporary database. `rehearse --config PATH --input SCENARIO.json --sink accepted --output NEW.json` uses simulated in-process delivery, disables sources/models and exports a sanitized report with per-run opaque references. It never opens the configured live database or loads credentials; `disabled` is the default sink.

For an opted-in pilot, `pilot-report --database PATH --from YYYY-MM-DD --until YYYY-MM-DD` reports observed policy workload, review response times and model reservations for complete UTC days. It also counts current queued and ambiguous deliveries using a single read-only database snapshot. Use `--backup PATH` for a standalone backup. [Pilot report guide](docs/pilot-report.md)

For independent analyst review, `pilot-cases` builds a private lookup packet from a frozen backup. `pilot-score` compares paired, blinded labels with the retained policy decision for each revision and gives the reviewed denominators. [Review a pilot’s policy decisions](docs/pilot-cases.md)

Use `pilot-recall` to measure timely findings, immediate routing decisions and Slack or SMTP acknowledgements against independently enumerated urgent incidents in a frozen backup. The report distinguishes immediate alerts from digest acknowledgements and includes incidents without a matching retained finding. [Measure recall on an incident reference](docs/pilot-recall.md)

To measure when an analyst acknowledged or triaged those incidents, use `pilot-response-template` to prepare a private worksheet. A second reviewer fills it from incident records. Score it with `pilot-recall --responses` to see how many met the deadline and how many still lack evidence. [Analyst response workflow](docs/pilot-recall.md)

## Library inventories

The quickest inventory is the one generated from your lockfiles with `security-watch sbom` or `init --project` ([guide](docs/sbom.md)). This section covers library lists written by hand.

Runtime requirement: Node **24.10.0 or newer**. PyPI final-release range evaluation uses a conservative PEP 440 subset; unsupported forms remain unknown (see [configuration](docs/configuration.md#python-version-range-coverage)).

The supported ecosystems are npm, PyPI, Packagist, Go, Maven, crates.io, RubyGems, NuGet, Hex, Pub, Hackage and SwiftURL. Common language names such as `python`, `php` and `rust` are accepted as aliases. Run `security-watch ecosystems` for the canonical names.

Start from a file with one library per line:

```text
npm:express
python:requests
python:urllib3==2.2.3
php:symfony/http-foundation@6.4.0
maven:org.apache.logging.log4j:log4j-core
```

Add a note after `#` to say where a library is used; it appears in every alert about that library:

```text
npm:express@4.21.2        # checkout API, repository acme/checkout, file package.json
python:requests==2.32.3   # billing worker, services/billing/requirements.txt
```

A line that starts with `#` is still an ordinary comment. When the same library is listed twice with different notes, both notes are kept. Systems and products accept a `note:` field in the inventory file. Notes stay on your machine and in your notifications; they are never sent to advisory sources or AI models. See [notes](docs/configuration.md#notes-telling-readers-where-to-look).

These are examples, not version recommendations. Use the registry's published package spelling, especially for NuGet. npm names are lower case and case-sensitive: `npm:Lodash` is kept but matches nothing published as `lodash`, and `doctor` lists it under `name_notices`. Omit a version you have not verified; do not substitute `latest`, a version constraint or a guessed release.

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
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp \
  --env-file ./watch/.env \
  --mount type=bind,src="$(pwd)/watch/security-watch.yaml",dst=/config/security-watch.yaml,readonly \
  --mount type=bind,src="$(pwd)/watch/systems.yaml",dst=/config/systems.yaml,readonly \
  --mount type=volume,src=security-watch-data,dst=/data \
  shielda-security-watch start --config /config/security-watch.yaml
```

Before running, set `inventory: /config/systems.yaml` and `database: /data/watch.db` in the container's configuration. Create `watch/.env` privately with only the credentials you use; it is not loaded automatically by the npm CLI. Keep configuration, inventory and `.env` readable only by your user, for example with `chmod 600` on those files. The short initialization command assigns the data volume to your UID/GID; the application itself then runs as that user. Your Docker VM must be able to access the configuration/inventory bind mounts. Add a read-only mount under `/config` for any imported lockfile or SBOM folder (for example `--mount type=bind,src="$(pwd)/watch/sboms",dst=/config/sboms,readonly`) and use the matching path in the inventory.

SQLite stays on a native Docker volume rather than a desktop VM's shared host filesystem. This avoids depending on host-sharing behavior for database locking and write-ahead logging. Retain `security-watch-data` when recreating the container. The application needs outbound network access, and an inbound port only if you turn on the SBOM receiver (`intake`).

The included Compose file uses root-level `security-watch.yaml`, `systems.yaml` and `.env`:

```sh
cp examples/security-watch.example.yaml security-watch.yaml
cp examples/systems.example.yaml systems.yaml
cp .env.example .env
chmod 600 security-watch.yaml systems.yaml .env
export SECURITY_WATCH_UID=$(id -u) SECURITY_WATCH_GID=$(id -g)
```

Edit the copied inventory, notification routes and credentials, and apply the same `/config/systems.yaml` and `/data/watch.db` settings before running `docker compose up --build -d`. Inspect `docker compose logs --follow`. Compose requires the host UID/GID variables and automatically runs a short volume-ownership initializer before the application starts. Its `watch-data` named volume keeps SQLite on Docker's native filesystem, while the private configuration/inventory remain read-only host mounts. You may persist the UID/GID values in the private `.env` file for later Compose invocations. Add an explicit read-only mount if the inventory imports a lockfile or reads an SBOM folder (`- ./sboms:/config/sboms:ro`). Retain the named volume when recreating containers; `docker compose down --volumes` removes it.

## How decisions work

1. Collect cve.now responses and The Hacker News articles within configured size and request limits. Preserve source revisions and group advisories that share verified aliases. News mentioning several existing advisories adds context to each finding separately.
2. Compare each deployment's library identity and declared version. npm and the PyPI final-release subset support range checks; other ecosystems require exact positive evidence. Generic product matches remain uncertain. Stale inventory cannot support a safe conclusion.
3. Ask the configured model to classify matched system news and assess the claimed impact on the declared deployment, using article evidence and version context. General news about a system is distinguished from a new vulnerability or an update to a known one. If configured, a second model reviews every news analysis and any critical, exploited, uncertain or conflicting finding. Disagreements remain visible.
4. Apply the category's notification policy. AI cannot reduce priority below the source severity or suppress a critical library/product finding. News with an advisory identifier and an exact installed package mention uses library policy even before structured advisory data arrives.
5. Commit finding changes and notification jobs together. Deliver meaningful changes without treating cosmetic article wording or AI phrasing as new events.

With the default rules, libraries select critical severity and products/news select high or critical; routes are empty until configured. Unknown/conflicting potentially critical findings notify immediately when `urgent_unknown` is enabled, except a version exclusion that is `unknown` only because its advisory evidence is out of date: that goes to the review digest, and the source's health finding reports the outage. Lower-priority uncertainty goes to a review digest. Known-exploitation and malicious-package overrides are separately configurable. A category with no channels sends nothing, including overrides.

AI dismissals now require local review by default (`policy.ai_dismissals: review`). Both general-news and model-only `not_affected` conclusions enter a durable queue, even without notification channels. Use `reviews` to inspect items and `review FINDING_ID --revision N --disposition dismiss|investigate --reviewer NAME --reason TEXT` to record a local decision. `record` explicitly opts out; the legacy boolean is normalized as documented in [configuration](docs/configuration.md#reviewing-ai-dismissals-locally).

For system news, the model records `new_vulnerability`, `known_vulnerability_update`, `general_news` or `unknown`, alongside its assessment of system impact. General coverage and supported model-only exclusions require review before dismissal; uncertain analysis goes to the review digest. A vulnerability that the model believes affects the system follows your severity policy. These rules also cover product articles linked to collected CVEs. Critical-source severity, configured exploitation overrides and deterministic library matches still take precedence. See [model configuration](docs/configuration.md#model-configuration) for evidence and version requirements.

General-news classifications remain in history after a story leaves RSS. Changes to the article, inventory or model settings trigger reassessment. Affected or excluded impact claims require fresh evidence.

Models cannot run tools, change recipients, edit version ranges or establish that a dependency is safe. Model outages and exhausted budgets retain deterministic results and create monitoring-health findings. There is no automatic provider fallback.

## Operate

Commands that operate on a configured monitor accept `--config PATH`; the default is `./security-watch.yaml`. For monitor commands, add `--credentials-file PATH` to load a private dotenv file, or export variables through your service manager. The offline `rehearse` command rejects credential files and uses simulated delivery. Existing environment values take precedence for monitor commands. Files are parsed as data, without shell evaluation; they are never loaded implicitly. `init` uses `--directory` instead. Unsupported flag/command combinations are rejected before activity.

| Command                                                                                           | Behavior                                                                                                                  |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `providers`                                                                                       | List supported provider profiles without configuration, credentials or network access                                     |
| `templates`                                                                                       | List common system IDs available to `init --systems`                                                                      |
| `ecosystems`                                                                                      | List supported library ecosystems                                                                                         |
| `sbom [--project PATH] [--output FILE]`                                                           | Read a project's lockfiles and manifests and write a CycloneDX SBOM; no network requests ([guide](docs/sbom.md))          |
| `upload --input FILE --url URL`                                                                   | Send an SBOM to a monitor's receiver (`intake`); `sbom --upload URL` makes and sends one in a step                        |
| `import-sbom --input PATH`                                                                        | Show what Security Watch reads from a CycloneDX or SPDX SBOM; exits 2 when some packages cannot be watched                |
| `normalize-libraries --input PATH`                                                                | Parse a library list without network requests; optional `--ecosystem` sets the group and `--output` saves a new JSON file |
| `scan`                                                                                            | Run once, save evidence/findings and queue notifications; does not deliver by default                                     |
| `scan --dry-run`                                                                                  | Use in-memory state, disable model calls and send no notifications; source requests still occur                           |
| `scan --notify`                                                                                   | Save a scan, attempt due delivery and report the remaining backlog; future or rate-limited jobs stay pending              |
| `scan --fixture PATH`                                                                             | Use local evidence instead of network sources and AI                                                                      |
| `scan --no-ai`                                                                                    | Keep structured matching and disable model calls for this invocation                                                      |
| `start`                                                                                           | Run the scheduler and delivery worker in the foreground                                                                   |
| `findings`, `status`, `deliveries`, `budget`                                                      | Inspect saved assessments, monitoring state, delivery outcomes and budget reservations                                    |
| `health`                                                                                          | Check worker heartbeat, completed-scan freshness and actionable delivery problems; exits 2 when unhealthy                 |
| `health --scan-only`                                                                              | Check completed scans and delivery without requiring a foreground worker, for external cron schedules                     |
| `reviews [--all] [--limit N] [--after CURSOR]`                                                    | Inspect the durable local AI dismissal queue and its backlog                                                              |
| `review FINDING_ID --revision N --disposition dismiss\|investigate --reviewer NAME --reason TEXT` | Adjudicate an exact current review locally without sending a notification                                                 |
| `explain FINDING_ID`                                                                              | Show a finding, its current policy decision and acknowledgement/suppression controls                                      |
| `history FINDING_ID`                                                                              | Show saved finding revisions                                                                                              |
| `acknowledge FINDING_ID`                                                                          | Acknowledge the current revision, or only revision N with `--revision N`                                                  |
| `suppress FINDING_ID --hours 24 --reason TEXT`                                                    | Suppress until an explicit expiry                                                                                         |
| `retry DELIVERY_ID`                                                                               | Requeue a failed/uncertain delivery after checking receipt; does not send immediately                                     |
| `backup --output PATH`                                                                            | Create a consistent SQLite backup at a new destination and verify a temporary restored copy                               |
| `verify-backup --input PATH`                                                                      | Verify a standalone backup without monitor configuration or replacing a live database                                     |
| `prune`                                                                                           | Show a read-only plan using configured retention periods                                                                  |
| `prune --apply`                                                                                   | Apply one bounded retention batch atomically                                                                              |
| `unlock`                                                                                          | Remove stale lock metadata only when no worker owns the SQLite lock                                                       |
| `test-notification --channel slack`                                                               | Send an explicit test message; `email` is also supported                                                                  |

Only one scan/scheduler instance may write a given database. Inspection and acknowledgement use SQLite safely alongside the worker. Do not share a database between containers or hosts or put it on a network filesystem. Stop the worker before replacing a database with a backup; retain permissions and move aside stale SQLite sidecar files with the old database.

Digests use fixed UTC epoch-aligned time buckets, defaulting to midnight UTC, with at most five findings per delivery. Larger digests produce multiple messages. `scan --notify` does not wait for future digest times, retry timers or Slack rate limits; it prints the remaining backlog. Use `start` to keep draining the queue as jobs become due. Urgent deterministic results are attempted before optional AI work.

A notification marked `accepted` was accepted by the destination, not necessarily read. Interrupted or ambiguous delivery becomes `unknown`: inspect the destination before `retry`, because it may already have arrived. Automatic retries cover explicit transient rejections and DNS/connection failures known to occur before sending. Slack digests split to fit the message limit, and one malformed queued message does not block healthy messages. Delivery state remains available even when a destination fails.

`scan` exits with status 2 for degraded monitoring or failed/uncertain delivery (running without an AI model is a supported setup and is reported under `notices`, not as degraded), including an early urgent delivery attempt; setup/command failures use status 1. `health` is read-only, makes no network requests, and reports monitoring health rather than whether systems are secure. The Compose service includes this health check. Check `status`, service logs and delivery state rather than treating an empty findings list as an all-clear.

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

Run `npm run evaluate:outcomes -- --output alert-evaluation.json` from a checkout for the offline final-outcome regression gate. It compares deterministic matching, one model and verification using production policy and a fresh local outbox, and reports false quiet dismissals, unnecessary immediate alerts and benign digest/review burden. See the [outcome evaluation guide](docs/alert-outcome-evaluation.md) for controls, human-label import and production-readiness limits.

The corpus contains source-derived synthetic scenarios with fictional inventories. Its reference labels are marked `pending_human_review`. Reports distinguish output acceptance, coverage, label agreement, false exclusions, rejected outputs and model disagreements. Label agreement is not measured production accuracy. Live runs may incur charges, use a total request cap, and send no notifications; full options are in the script help.

## Boundaries and privacy

cve.now stack queries disclose deduplicated npm package names and versions; lockfiles, SBOMs and deployment metadata are not uploaded. `security-watch sbom` makes no network requests. The Hacker News feed and article servers receive normal HTTP requests. Optional OSV queries also disclose dependency names and versions; optional GitHub, CISA and additional feed sources receive normal HTTP requests. GitHub authentication is optional. The selected model provider receives, under the default `minimal` disclosure profile, the matched package and product names and versions plus selected evidence; the `deployment-context` profile adds environment, exposure, criticality and matching keywords (see [SECURITY.md](SECURITY.md)). Slack/email receive findings and evidence links. Consider these disclosures before monitoring private dependencies.

Authentication credentials are read from environment variables. Findings, evidence, quoted model output, budget reservations and history are stored locally. There is no automatic application telemetry. An explicitly configured heartbeat service receives success pings and normal request metadata. Protect the configuration, SQLite database, backups and credentials as operational data. Details are in [SECURITY.md](SECURITY.md).

This release has no automatic patching, shell execution from news, hosted dashboard, Slack action buttons, VEX import, operating-system package matching, distributed workers, EPSS integration or independent security audit. CVSS v3.0/v3.1 vectors and supplied severity labels/scores are supported. OSV and GitHub also support [CVSS v4 base-vector scoring](docs/cvss-v4-support.md), with explicit base projection and unsupported-vector diagnostics. Product backports, reachability and exploit prerequisites require human/vendor evidence. cve.now starts from recent entries, revisits tracked/news-cited CVEs and checks exact npm packages through its stack endpoint; this is not an exhaustive historical audit of every product. Existing configurations retain explicitly enabled legacy sources; set `osv`, `github` and `kev` to `false` to switch exclusively to the new defaults.

Current evidence and findings are loaded into memory during each scan. Retention is disabled until configured, and protected unresolved records may continue growing even after cleanup is enabled. This release targets small installations. Plan storage and review retention dry runs before increasing scale.

See the [configuration guide](docs/configuration.md), [security policy](SECURITY.md) and [contributing guide](CONTRIBUTING.md). Licensed under Apache-2.0.
