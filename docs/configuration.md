# Configuration

Configuration is strict YAML or JSON: unknown fields and invalid values fail validation. The configuration file is limited to 1 MiB. `${VARIABLE}` substitution is supported in parsed string values; an undefined variable is an error. Credential settings contain the **name** of an environment variable, never its secret value.

Pass `--credentials-file ./watch/.env` to load credentials and configuration variables from a dotenv file. It is read as data, with no shell commands or variable expansion. Existing environment values take precedence. The file must be a regular file of at most 128 KiB; symlinks are rejected. On Unix, run `chmod 600` first. Shell, Node.js and TLS runtime settings belong in the service manager and are rejected in this file. Without this flag, the CLI uses only its environment and does not search for `.env` files.

`inventory` and `database` resolve relative to the configuration file. Inventory `lockfile` paths resolve relative to the inventory file. Configuration is read once per process; restart the worker after changing it. Inventory is loaded again on each scheduled scan. In the supplied Docker Compose setup, use `inventory: /config/systems.yaml`, `database: /data/watch.db`, and a root-level `.env` file copied from `.env.example`. Set `SECURITY_WATCH_UID`/`SECURITY_WATCH_GID` to your host user/group IDs; this preserves mode-0600 configuration/inventory access without widening host permissions. Compose initializes ownership of its `watch-data` named volume before starting the application. SQLite remains on Docker's native filesystem, while the VM must have access to the read-only configuration/inventory bind mounts. Retain the named volume when recreating containers.

## Minimal setup

`security-watch init --directory ./watch --systems nodejs,python --yes` creates a starter configuration, private inventory and `.env.example`. It selects a 30-minute polling interval and a 40-minute news window. Add `--provider NAME --model ID` to configure analysis, or use interactive `init` to choose a provider and Slack routing. `--poll-minutes` and `--lookback-minutes` set timing during setup. Run `security-watch templates` for system names and `security-watch providers` for provider IDs. Selected systems have no assumed installed version; edit the inventory before assessing deployment impact.

The following example uses the schema defaults of 15 and 60 minutes and enables Slack explicitly:

```yaml
version: 1
inventory: ./systems.yaml
database: ./data/watch.db
poll_interval_minutes: 15
news_lookback_minutes: 60
inventory_stale_days: 7
digest_interval_hours: 24

sources:
  cve_now: true
  hacker_news: true
  osv: false
  github: false
  github_token_env: GITHUB_TOKEN
  kev: false
  feeds: []

models:
  enabled: false

policy:
  library:
    levels: [critical]
    basis: source_severity
    channels: [slack]
  product:
    levels: [high, critical]
    basis: priority
    channels: [slack]
  news:
    levels: [high, critical]
    basis: priority
    channels: [slack]
  urgent_unknown: true
  exploited_override: true
  malware_override: true
  health_channels: [slack]

notifications:
  slack:
    webhook_url_env: SLACK_WEBHOOK_URL
  max_attempts: 3
```

Set `SLACK_WEBHOOK_URL` through your shell, service manager or secret manager. Its value must be an HTTPS `hooks.slack.com/services/…` incoming webhook. The webhook chooses the channel; the model never chooses it. No credential value is needed in this file. See [Slack incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/).

## Scan schedule and news window

The worker's scan interval and its news discovery window are separate settings. For a scan every 30 minutes covering the last 40 minutes:

```yaml
poll_interval_minutes: 30
news_lookback_minutes: 40
```

Run `security-watch start --config security-watch.yaml` to keep the worker running. `scan` performs one scan and exits. Both commands use the configured news window; restart `start` after changing the configuration. Poll intervals accept 1–1,440 minutes and news windows accept 1–10,080 minutes. The defaults are 15 and 60 minutes respectively.

The 10-minute overlap in this example catches stories that arrive late in a feed. Stable evidence and finding IDs prevent the overlap from creating duplicate notifications. After downtime or a source failure, discovery reaches back to the last successful checkpoint, with up to five minutes of additional overlap. Catch-up can therefore cover more than 40 minutes. Feed history and existing collection limits still constrain what can be recovered.

The window applies to discovery of news in The Hacker News and additional RSS/Atom feeds. Previously tracked relevant stories can still be refreshed, and stored findings and evidence remain available. Older CVEs, exact package matches, withdrawals and tracked advisory updates are checked independently of this news window.

Stories without usable publication/update dates remain reviewable, with a monitoring-health warning because their age cannot be established. Repeated scans retain their stable revision unless the source content changes.

To add email, configure it and add `email` to the desired category or health channel arrays:

```yaml
notifications:
  slack:
    webhook_url_env: SLACK_WEBHOOK_URL
  email:
    smtp_url_env: SMTP_URL
    from: security-watch@example.com
    to: [security@example.com]
  max_attempts: 3
```

`SMTP_URL` must name an `smtp:` or `smtps:` endpoint. STARTTLS/TLS is required, certificates are verified, and URL query options are rejected. SMTP destinations are operator-selected and may be internal. Up to 20 recipients are supported. Partial acceptance produces `unknown`, since automatically repeating the whole message could duplicate delivery to accepted recipients.

## System inventory

```yaml
systems:
  - id: production-api
    name: Production API
    environment: production
    owner: platform
    exposure: internet
    criticality: critical
    updated_at: '2026-10-24T12:00:00Z'
    components:
      - id: parser
        ecosystem: npm
        name: example-parser
        version: 1.2.0
    lockfile: ./api/package-lock.json
    products:
      - name: PostgreSQL
        version: '16.4'
        keywords: [Postgres]
    keywords: [our-runtime-name]
```

Replace the example names and timestamp with verified deployment information. `updated_at` is required; use an ISO timestamp with a timezone. Inventory freshness comes from this value, not file modification time. `id` and `name` are required; other lists default to empty, `environment` defaults to `unknown`, and exposure/criticality default to `unknown`.

| Field                                 | Meaning                                                                                                |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| System `id`                           | Stable, unique deployment identity; keep it unchanged when upgrading a package                         |
| `environment`, `owner`                | Inventory context; owner is metadata and does not route notifications in this alpha                    |
| `exposure`                            | `internet`, `internal` or `unknown`                                                                    |
| `criticality`                         | `unknown`, `low`, `medium`, `high` or `critical`; business importance, separate from advisory severity |
| Component `id`                        | Unique within its system; keep stable across upgrades                                                  |
| Component `ecosystem`                 | Only `npm` is supported for precise matching                                                           |
| Component `name`                      | Canonical exact npm name, including scope when present                                                 |
| Component `version`                   | Optional exact version; missing/unparseable versions remain uncertain                                  |
| Product `name`, `version`, `keywords` | Product context and matching terms; not a supported vendor version/backport decision                   |
| System `keywords`                     | Explicit terms for news matching                                                                       |

Lockfiles must be package-lock v2/v3 with a `packages` map. Imports include transitive, development and optional entries and skip workspace links. They read metadata only. Import IDs follow `lock:node_modules/…` paths. Imported and manual component IDs must be unique. The inventory is bounded to 2 MiB, individual lockfiles to 20 MiB, and each system to 20,000 components. Duplicate system IDs or product names within a system are rejected; YAML aliases are rejected.

Use longer explicit keywords for short product names: matching ignores terms shorter than three characters. Whole-name matching reduces substring/scope collisions but cannot disambiguate every product name. Inventory changes trigger reassessment of stored evidence. A removed finding becomes inactive; disappearance is not proof of remediation.

## Sources and coverage

| Setting                    | Default and behavior                                                                                                                                             |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sources.cve_now`          | `true`; collect recent CVE entries, revisit inventory-relevant tracked/news-cited IDs and query exact npm package/version pairs through cve.now's stack endpoint |
| `sources.hacker_news`      | `true`; collect The Hacker News security feed and bounded article text for system news analysis                                                                  |
| `sources.osv`              | `false`; optional exact npm name/version queries, full advisory records and tracked-advisory refreshes                                                           |
| `sources.github`           | `false`; optional reviewed and malware npm advisories, tracking modifications and withdrawals                                                                    |
| `sources.github_token_env` | `GITHUB_TOKEN`; optional authentication for the GitHub API                                                                                                       |
| `sources.kev`              | `false`; optional matching-CVE enrichment with CISA known-exploitation evidence; KEV alone does not invent a product finding                                     |
| `sources.feeds`            | `[]`; up to 30 selected public HTTPS RSS 2.0/Atom URLs, without URL credentials                                                                                  |

`hacker_news` means **The Hacker News** at `thehackernews.com`, the cybersecurity publication, not Y Combinator's Hacker News. Its feed is [The Hacker News RSS](https://feeds.feedburner.com/TheHackersNews). The bot fetches bounded article text only from allowed The Hacker News hosts, without executing scripts: at most 50 articles per scan, four concurrently, with a 2 MB HTML response cap and 16,000 characters of extracted text per article. Evidence records whether full article content, a feed excerpt or unavailable content was used. A failed or capped article fetch retains the feed excerpt and cannot support a new confident AI-only dismissal. Incomplete articles relevant to the inventory create a `hacker_news:articles` monitoring-health finding; the successful RSS collection and its checkpoint are still retained.

Additional `feeds` supply titles and summaries/content present in their RSS/Atom response; their article links are not fetched. The bot does not search the web or obtain paywalled content. Choose feed URLs deliberately. Public destinations, DNS results, redirects, response sizes and request durations are checked; a failing source retains its previous checkpoint and cached evidence and produces degraded status.

cve.now's first recent-entry collection looks back seven days; later scans use one hour of checkpoint overlap. Collection is bounded to 200 listing pages and 5,000 advisory records per scan. Historical refreshes are limited to cached records relevant to the current inventory and CVE/GHSA IDs in relevant cached/current news, so unrelated global history does not expand the refresh set forever.

The stack endpoint is queried separately for each deduplicated exact npm package/version pair, at most 1,000 pairs per scan and four requests concurrently. Separate requests preserve matches that cve.now would deduplicate in a multi-package request. Only those pairs are sent, not a lockfile or system/deployment metadata. Limits and request failures report incomplete collection and retain the previous checkpoint. Valid cve.now records collected before a failure are still assessed, so a failed listing request does not discard successful exact-package matches. Recent-entry pagination cannot guarantee discovery of every update to an older, previously unseen CVE. Structured affected ranges and original advisory descriptions are used as evidence; generated summaries do not establish affectedness. Unsupported statuses, including supersession without verified withdrawal semantics, fail visibly instead of being treated as a resolved vulnerability. This is not exhaustive historical product coverage.

Optional GitHub collection first looks back seven days of modifications; later scans use checkpoint overlap. Optional OSV exact-version queries supply existing advisory matches for the declared npm inventory. GitHub-only operation is not a full historical vulnerability scan. Pagination and collection have explicit caps; reaching a cap reports an incomplete source rather than an all-clear.

For an existing installation, configuration fields set to `true` stay enabled. To switch to cve.now and The Hacker News only, add the two new fields as shown above, explicitly set `osv`, `github` and `kev` to `false`, clear any unneeded additional feeds, and restart the worker. Omitting the old fields now defaults them to `false`; omitting the new fields defaults them to `true`. To run without any network sources, explicitly disable all five source switches and keep `feeds: []`. Existing cached evidence and history are retained.

References: [cve.now machine-readable API guide](https://cve.now/llms.txt), [The Hacker News](https://thehackernews.com/), [OSV batch queries](https://google.github.io/osv.dev/post-v1-querybatch/), [GitHub global advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories), [CISA KEV data](https://github.com/cisagov/kev-data).

## Model configuration

Models are disabled by default. To classify system news and assess impact, configure an analysis model and its credentials. Without a model, name/keyword matches remain candidates for review. Use an exact model ID supported by the provider. The model must support the structured JSON response and output limit required by this adapter.

```yaml
models:
  enabled: true
  analysis:
    provider: openai
    model: '${ANALYSIS_MODEL}'
    api_key_env: OPENAI_API_KEY
  verification:
    provider: anthropic
    model: '${VERIFICATION_MODEL}'
    api_key_env: ANTHROPIC_API_KEY
  daily_request_limit: 100
  daily_token_limit: 100000
  max_input_chars: 12000
  max_output_tokens: 1500
  timeout_seconds: 45
```

The `verification` entry is optional. It runs for every news analysis, source-critical, exploited, unknown/conflicting findings or when the first model proposes critical priority. It receives the evidence independently; disagreement leaves the result uncertain. Verification failure, exhausted budget or disagreement retains the highest validated proposed priority with an explicit unavailable/conflicting state. `scan --dry-run` disables models and does not spend model budget. Use a normal `scan` without `--notify` to test actual model behavior while persisting budget reservations and findings.

For matched system news, analysis records two distinct conclusions:

- News classification: `new_vulnerability`, `known_vulnerability_update`, `general_news` or `unknown`. A report about an existing CVE, exploitation or a patch is distinct from a newly reported vulnerability; a product announcement or a passing mention is general news.
- Claimed impact on the declared system: `affected`, `not_affected`, `unknown` or `not_applicable`, with cited evidence and an explanation. This is the model's contextual conclusion, separate from authoritative version-range `applicability`; it does not certify the system safe or establish general product-version support.

The model also records affected product names, affected versions and prerequisites from its supporting article quotes. A decisive `affected` or `not_affected` claim requires a known installed target version and source product/version evidence; missing deployment details stay uncertain. The quoted product must match the configured product name. Keywords help find candidate articles but cannot establish product identity, even when two products share a vendor.

For noncritical system news, a validated complete analysis of general news/no applicable vulnerability or no claimed system impact records the article without a vulnerability notification. Generic product findings retain this news analysis even when a cited CVE has been collected; deterministic npm applicability remains separate. A new vulnerability or known-vulnerability update with claimed impact follows the configured news/product severity policy. Unknown, conflicting, disabled or unavailable analysis goes to review. Incomplete article/context evidence and stale inventory cannot support a new confident AI-only dismissal. Initial news candidates are held for analysis before notification routing; source-critical and enabled exploitation safeguards still apply.

Completed `general_news`/`not_applicable` classifications remain in history after an article leaves RSS. Changes to the article, inventory, models, prompt or input settings trigger reassessment. This retention rule applies only to general news; `affected` and `not_affected` impact claims still require fresh evidence.

| `ModelSpec` field                                 | Meaning                                                                                             |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `provider`                                        | One of the profiles below; use the same fields for analysis and verification                        |
| `model`                                           | Required model ID available to your account, or an Azure deployment name; there is no default       |
| `api_key_env`                                     | Optional environment-variable name; defaults to the profile's key variable, never a literal API key |
| `endpoint`                                        | Complete API request URL; required for Azure, generic compatible endpoints and local profiles       |
| `output_format`                                   | `auto` by default; choose `json_schema`, `json_object` or `prompt` when supported                   |
| `allow_private_endpoint`                          | `false` by default; permits private destinations and HTTP for the configured model request          |
| `input_usd_per_million`, `output_usd_per_million` | Optional operator-supplied prices, each between 0 and 10,000                                        |

`auto` uses the profile's default format below. Profiles select API protocols and defaults; they do not establish that every model on a service supports those settings.

| Provider            | API              | Default key variable   | Default format |
| ------------------- | ---------------- | ---------------------- | -------------- |
| `openai`            | Responses        | `OPENAI_API_KEY`       | `json_schema`  |
| `azure-openai`      | Azure Responses  | `AZURE_OPENAI_API_KEY` | `json_schema`  |
| `anthropic`         | Messages         | `ANTHROPIC_API_KEY`    | `json_schema`  |
| `gemini`            | GenerateContent  | `GEMINI_API_KEY`       | `json_schema`  |
| `cohere`            | Chat v2          | `COHERE_API_KEY`       | `json_schema`  |
| `groq`              | Chat Completions | `GROQ_API_KEY`         | `json_object`  |
| `deepseek`          | Chat Completions | `DEEPSEEK_API_KEY`     | `json_object`  |
| `xai`               | Responses        | `XAI_API_KEY`          | `json_schema`  |
| `mistral`           | Chat Completions | `MISTRAL_API_KEY`      | `json_schema`  |
| `together`          | Chat Completions | `TOGETHER_API_KEY`     | `json_object`  |
| `fireworks`         | Chat Completions | `FIREWORKS_API_KEY`    | `json_object`  |
| `openrouter`        | Chat Completions | `OPENROUTER_API_KEY`   | `json_object`  |
| `cerebras`          | Chat Completions | `CEREBRAS_API_KEY`     | `json_object`  |
| `nvidia`            | Chat Completions | `NVIDIA_API_KEY`       | `prompt`       |
| `sambanova`         | Chat Completions | `SAMBANOVA_API_KEY`    | `json_object`  |
| `huggingface`       | Chat Completions | `HF_TOKEN`             | `prompt`       |
| `perplexity`        | Agent API        | `PERPLEXITY_API_KEY`   | `json_schema`  |
| `openai-compatible` | Chat Completions | `OPENAI_API_KEY`       | `json_schema`  |
| `ollama`            | Chat Completions | `OLLAMA_API_KEY`       | `json_schema`  |
| `lmstudio`          | Chat Completions | `LM_STUDIO_API_KEY`    | `json_schema`  |
| `vllm`              | Chat Completions | `VLLM_API_KEY`         | `json_schema`  |
| `litellm`           | Chat Completions | `LITELLM_API_KEY`      | `json_object`  |

Authentication uses `Authorization: Bearer` except Azure (`api-key`), Anthropic (`x-api-key` with an API-version header) and Gemini (`x-goog-api-key`). `api_key_env` changes the variable read, not the authentication protocol. Credentials are sent only to the configured endpoint; choose overrides deliberately. Endpoints must use HTTPS unless private access is enabled, and cannot contain URL credentials, a query string or a fragment. Supply the full request path, not a base URL.

`json_schema` requests provider-side schema constraints. `json_object` requests JSON without schema constraints. `prompt` includes the schema in the instructions without a provider-specific format parameter. Every mode still parses and validates the response locally, including evidence IDs and exact quotes. Refusals, incomplete output and provider format rejections leave analysis unavailable; there is no automatic format fallback. Anthropic defaults to [native structured output](https://platform.claude.com/docs/en/build-with-claude/structured-outputs) through `output_config.format`; choose `prompt` explicitly for a model without that capability. DeepSeek accepts `json_object` or `prompt`; Perplexity accepts `json_schema` or `prompt`. Other profiles expose all three modes, but support still depends on the selected model. OpenRouter requests compatible upstream routing when a JSON mode is selected. Perplexity uses the Agent API with tools disabled, not the legacy Sonar chat endpoint.

For Azure, set the full Responses endpoint and your deployment name in the environment:

```yaml
models:
  enabled: true
  analysis:
    provider: azure-openai
    endpoint: '${AZURE_OPENAI_ENDPOINT}'
    model: '${AZURE_OPENAI_DEPLOYMENT}'
```

`AZURE_OPENAI_ENDPOINT` must be the complete request URL supported by your Azure deployment. The key is read from `AZURE_OPENAI_API_KEY` unless overridden. Endpoints requiring query parameters are outside this adapter's endpoint rules.

Local profiles require both an explicit endpoint and `allow_private_endpoint: true`. For example, with an Ollama server and a model you have already installed:

```yaml
models:
  enabled: true
  analysis:
    provider: ollama
    endpoint: http://127.0.0.1:11434/v1/chat/completions
    model: '${LOCAL_MODEL}'
    allow_private_endpoint: true
    output_format: json_schema
```

The local profiles and `openai-compatible` may omit the actual key when private access is enabled; all named hosted profiles still require a key. A local model must support the selected format. In a container, `127.0.0.1` refers to that container, so use the reachable server address. Private access applies only to the model endpoint, not feeds or article links.

See the [provider registry](https://github.com/ShieldaAI/security-watch/blob/main/src/providers.ts) for endpoint defaults and official API references. `doctor` validates configuration; a live analysis is needed to check account access and the selected model's compatibility. From a source checkout, `node scripts/check-models.mjs --help` describes a bounded synthetic test with separate passed, failed and skipped results. A missing key or model is a skip, never a successful live test.

Set `daily_budget_usd` only after configuring both prices for **every** selected model. Without prices, dollar cost is unknown; request and token allowances still apply. Model calls reserve conservative input/output allowances before the request. Reservations are not provider invoices, are not refunded after a timeout or malformed response, and include verification calls. Daily counters use UTC days. Adding a dollar cap after unpriced calls prevents further billed requests for that UTC day because the prior spend is unknown. There are no automatic model retries or provider fallbacks. Cache hits reuse validated results without a new request reservation. Provider usage and billing remain authoritative.

The analysis includes relevant components/products/keywords from the matched system and its deployment context, with up to six bounded evidence excerpts. Authoritative and urgent evidence is prioritized, and omitted/truncated context is explicit. Selection is capped at 20 components and 20 products; excess or oversized context fails with an explicit model-context health finding. Partial context or stale inventory cannot support an AI dismissal; unknown relevance enters review. Models receive no tools or notification credentials. The adapter checks that evidence IDs exist and quotes match the source text, but these checks cannot establish whether the model interpreted the source correctly.

## Policy and scheduling

Each `library`, `product` and `news` rule has `levels`, `basis` and `channels`. Malware uses the library rule's destinations. Category defaults select critical libraries and high/critical products/news, but all channel arrays default to empty. A referenced channel requires matching notification configuration.

- `basis: source_severity` filters on source severity. `basis: priority` filters on the higher of source severity and contextual priority. Levels are explicit memberships, not numeric minimums: use `[high, critical]` for both.
- Source severity cannot be lowered by AI. Known exploitation raises contextual priority to at least high; a high advisory affecting an internet-exposed, business-critical system also receives critical contextual priority.
- `urgent_unknown: true` sends potentially critical unknown/conflicting findings immediately, even before affectedness can be established. Other uncertain findings go to a review digest, including uncertainty below the category's immediate levels.
- `exploited_override: true` and `malware_override: true` notify immediately even without a matching severity level. They do not override an empty channel list or a supported `not_affected` decision.
- Confirmed exclusions and all-source withdrawals are retained without new vulnerability notifications. Withdrawal alone does not prove a system safe. Withdrawal disagreement remains conflicting.
- AI distinguishes noncritical system news from vulnerability reports and evaluates claimed system impact before routing; general news and supported AI-only exclusions are recorded without vulnerability alerts. Generic product reports with linked CVEs use this analysis too. Uncertain analysis goes to review. AI cannot suppress source-critical news, an enabled exploitation override or deterministic package urgency by declaring it irrelevant. Advisory-linked package news uses library policy. Multi-advisory articles retain unmatched CVE/GHSA subjects separately until authoritative alias evidence joins them.
- `health_channels` routes monitoring failures independently from vulnerability thresholds. If every destination fails, inspect local status/logs; the bot cannot notify through an unavailable channel.

`poll_interval_minutes` is an integer from 1 to 1,440, default 15. `inventory_stale_days` is 1–365, default 7; timestamps more than five minutes in the future are also invalid for assessment. `digest_interval_hours` is an integer from 1 to 168, default 24. Digest boundaries are aligned to the Unix epoch in UTC, not a user's timezone. Each Slack/email digest contains at most five findings; additional groups are sent separately.

`notifications.max_attempts` is 1–10, default 3. Explicit Slack rate-limit/server rejections and transient SMTP rejections can retry with bounded backoff. Timeouts, interrupted delivery and partial email acceptance become `unknown` instead of automatically risking a duplicate. `retry DELIVERY_ID` requires an operator to check receipt first. `accepted` means destination acceptance, not human acknowledgement. A one-shot `scan --notify` reports remaining backlog and leaves rate-limited, retry-delayed and future-digest jobs pending; use `start` to drain them when due.

Acknowledgement applies to the current finding revision. Material changes create a new revision. Suppression requires a reason and expiry and remains active until that expiry. `explain FINDING_ID` shows the current policy decision together with acknowledgement and suppression controls, so policy eligibility can be distinguished from an active operator hold. Existing pending deliveries are superseded when the assessment or policy changes. Cosmetic article/model wording does not create a fresh alert. Rare new advisory aliases can change canonical finding identity; this alpha does not migrate historical identities automatically.

## Persistence and recovery

Use one local SQLite database per worker. A worker lock prevents concurrent scans; inspection and control commands can run alongside it. The database contains source evidence/checkpoints, assessment history, model caches and reservations, and notification state. It is operationally sensitive and has no automatic retention pruning in this alpha.

Database schema 4 adds indexed evidence lookup without discarding history. Stop an older worker and run `scan` or `start` to migrate before using read-only commands from this version. Back up before upgrading operational databases.

`health` checks a worker heartbeat no older than 90 seconds, a completed scan no older than twice the polling interval (at least two minutes), and actionable failed, uncertain or more-than-five-minutes-overdue delivery. A new worker has a two-minute first-scan grace period. Suppressed/acknowledged findings, canceled routes and a valid Slack retry timer are excluded from actionable delivery health. `health --scan-only` omits the worker requirement for externally scheduled scans. Neither command writes data or calls external services; unhealthy monitoring returns exit code 2. A healthy monitor can still have critical affected systems.

`explain` includes each cited source's modification and fetch timestamps. Cached conclusions during a source outage reflect historical evidence; degraded health does not imply those sources were refreshed. Source revisions more than five minutes in the future are rejected without advancing their checkpoint.

Use `backup --output PATH` for a consistent backup, rather than copying a live SQLite file without its write-ahead log. To restore, stop the worker, preserve the old database and its sidecars, put the verified backup at the configured database path with private permissions, and restart. An interrupted in-flight delivery becomes `unknown` on worker recovery. `unlock` removes stale informational metadata only after acquiring the SQLite worker lock; it never deletes the lock database or interrupts a running worker.
