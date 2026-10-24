# Configuration

Configuration is strict YAML or JSON: unknown fields and invalid values fail validation. The configuration file is limited to 1 MiB. `${VARIABLE}` substitution is supported in parsed string values; an undefined variable is an error. Credential settings contain the **name** of an environment variable, never its secret value. The CLI does not automatically load `.env` files.

`inventory` and `database` resolve relative to the configuration file. Inventory `lockfile` paths resolve relative to the inventory file. Configuration is read once per process; restart the worker after changing it. Inventory is loaded again on each scheduled scan. In the supplied Docker Compose setup, use `inventory: /config/systems.yaml`, `database: /data/watch.db`, and a root-level `.env` file copied from `.env.example`. Set `SECURITY_WATCH_UID`/`SECURITY_WATCH_GID` to your host user/group IDs; this preserves mode-0600 configuration/inventory access without widening host permissions. Compose initializes ownership of its `watch-data` named volume before starting the application. SQLite remains on Docker's native filesystem, while the VM must have access to the read-only configuration/inventory bind mounts. Retain the named volume when recreating containers.

## Minimal setup

```yaml
version: 1
inventory: ./systems.yaml
database: ./data/watch.db
poll_interval_minutes: 15
inventory_stale_days: 7
digest_interval_hours: 24

sources:
  osv: true
  github: true
  github_token_env: GITHUB_TOKEN
  kev: true
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

| Setting                    | Default and behavior                                                                                              |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `sources.osv`              | `true`; query exact npm name/version pairs, fetch full advisory records and revisit previously tracked advisories |
| `sources.github`           | `true`; collect both reviewed and malware npm advisories, tracking modifications and withdrawals                  |
| `sources.github_token_env` | `GITHUB_TOKEN`; optional authentication for the GitHub API                                                        |
| `sources.kev`              | `true`; enrich matching CVEs with CISA known-exploitation evidence; KEV alone does not invent a product finding   |
| `sources.feeds`            | `[]`; up to 30 selected public HTTPS RSS 2.0/Atom URLs, without URL credentials                                   |

Feeds supply titles and summaries/content present in the feed. The bot does not crawl linked articles, search the web, execute page scripts or obtain paywalled content. Choose feed URLs deliberately. Public destinations, DNS results, redirects, response sizes and request durations are checked; a failing source retains its previous checkpoint and cached evidence and produces degraded status.

GitHub's first collection looks back seven days of modifications; later scans use checkpoint overlap. OSV exact-version queries supply existing advisory matches for the declared npm inventory. GitHub-only operation is not a full historical vulnerability scan. Pagination and collection have explicit caps; reaching a cap reports an incomplete source rather than an all-clear.

References: [OSV batch queries](https://google.github.io/osv.dev/post-v1-querybatch/), [GitHub global advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories), [CISA KEV data](https://github.com/cisagov/kev-data).

## Model configuration

No model is enabled by default. Set an exact model ID supported by the selected provider; no model names, prices or capabilities are guessed. The model must return the expected structured JSON within the configured limit.

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

The `verification` entry is optional. It runs for source-critical, exploited, unknown/conflicting findings or when the first model proposes critical priority. It receives the evidence independently. Disagreement is preserved as uncertainty; two agreeing models are not proof of safety. Verification failure, exhausted budget or disagreement retains the highest validated proposed priority with an explicit unavailable/conflicting state. `scan --dry-run` disables models and does not spend model budget. Use a normal `scan` without `--notify` to test actual model behavior while persisting budget reservations and findings.

| `ModelSpec` field                                 | Meaning                                                                                                            |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `provider`                                        | `openai`, `anthropic`, or `openai-compatible`                                                                      |
| `model`                                           | Required exact model ID                                                                                            |
| `api_key_env`                                     | Required environment-variable name; no literal API key                                                             |
| `endpoint`                                        | Optional full API endpoint override; required for `openai-compatible`                                              |
| `allow_private_endpoint`                          | `false` by default; explicitly permits an operator-selected private address and HTTP for a local compatible server |
| `input_usd_per_million`, `output_usd_per_million` | Optional operator-supplied model prices, each between 0 and 10,000                                                 |

`openai` uses the Responses API; `anthropic` uses the Messages API; `openai-compatible` expects a Chat Completions endpoint supporting `response_format` JSON schema. Supply the complete endpoint path rather than a base URL. Local compatible endpoints may omit the actual key when `allow_private_endpoint: true`; `api_key_env` still names the optional variable. Private-endpoint permission applies only to the configured model request, not feeds or article links.

References: [OpenAI Responses API](https://platform.openai.com/docs/api-reference/responses), [Anthropic Messages API](https://docs.anthropic.com/en/api/messages). `doctor` validates configuration; only a real analysis validates the selected model's compatibility. Unsupported structured output is a degraded analysis, not silent success.

Set `daily_budget_usd` only after configuring both prices for **every** selected model. Without prices, dollar cost is unknown; request and token allowances still apply. Model calls reserve conservative input/output allowances before the request. Reservations are not provider invoices, are not refunded after a timeout or malformed response, and include verification calls. Daily counters use UTC days. Adding a dollar cap after unpriced calls prevents further billed requests for that UTC day because the prior spend is unknown. There are no automatic model retries or provider fallbacks. Cache hits reuse validated results without a new request reservation. Provider usage and billing remain authoritative.

The analysis includes relevant components/products/keywords from the matched system and its deployment context, with up to six bounded evidence excerpts. Authoritative and urgent evidence is prioritized, and omitted/truncated context is explicit. Selection is capped at 20 components and 20 products; excess or oversized context fails with an explicit model-context health finding. Partial context or stale inventory cannot support an AI-only irrelevance conclusion; unknown relevance enters review. Models receive no tool definitions or notification credentials. Evidence IDs and verbatim supporting quotes are validated; this verifies attribution, not the truth of model reasoning.

## Policy and scheduling

Each `library`, `product` and `news` rule has `levels`, `basis` and `channels`. Malware uses the library rule's destinations. Category defaults select critical libraries and high/critical products/news, but all channel arrays default to empty. A referenced channel requires matching notification configuration.

- `basis: source_severity` filters on source severity. `basis: priority` filters on the higher of source severity and contextual priority. Levels are explicit memberships, not numeric minimums: use `[high, critical]` for both.
- Source severity cannot be lowered by AI. Known exploitation raises contextual priority to at least high; a high advisory affecting an internet-exposed, business-critical system also receives critical contextual priority.
- `urgent_unknown: true` sends potentially critical unknown/conflicting findings immediately, even before affectedness can be established. Other uncertain findings go to a review digest, including uncertainty below the category's immediate levels.
- `exploited_override: true` and `malware_override: true` notify immediately even without a matching severity level. They do not override an empty channel list or a supported `not_affected` decision.
- Confirmed exclusions and all-source withdrawals are retained without new vulnerability notifications. Withdrawal alone does not prove a system safe. Withdrawal disagreement remains conflicting.
- AI may reject noncritical standalone news relevance; it cannot suppress source-critical news, an enabled exploitation override or deterministic library/product urgency by declaring it irrelevant. Advisory-linked package news uses library policy. Multi-advisory articles retain unmatched CVE/GHSA subjects separately until authoritative alias evidence joins them.
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
