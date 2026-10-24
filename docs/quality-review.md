# Release review

Review date: 2026-10-24. Package: `@shieldaai/security-watch`, `0.1.0-alpha.0`.

The alpha supports small installations with library inventories across 12 ecosystems, cve.now/OSV advisories, security and vendor news, optional model analysis, and Slack/SMTP delivery from one host. The checks below cover that scope. Product backports, runtime reachability, large fleets and distributed workers are outside it.

## Changes covered

### Sources and assessment

- New configurations use cve.now and The Hacker News. OSV, GitHub, CISA KEV and RSS/Atom adapters remain optional. Official Node.js, Python and PHP feeds can be selected explicitly; article extraction stays within fixed vendor hosts and content limits.
- Library lists accept ecosystem aliases and optional exact versions across npm, PyPI, Packagist, Go, Maven, crates.io, RubyGems, NuGet, Hex, Pub, Hackage and SwiftURL. Only npm has range ordering/exclusion support; other ecosystems need exact positive OSV or listed-version evidence. Missing versions and unsupported constraints remain uncertain. Library checks do not require a model.
- cve.now uses original descriptions and structured affected ranges. Its model-generated summaries are excluded from evidence. Separate exact npm queries preserve matches that the provider would deduplicate in a combined request.
- cve.now requests start at least 1.1 seconds apart. A supplied `Retry-After` on HTTP 403/429 delays later requests, with a one-hour cap. Isolated detail failures preserve other records; batch and failure limits bound collection. An incomplete source keeps its previous checkpoint and reports degraded health.
- Malformed source items are isolated across feeds, GitHub, KEV, cve.now and OSV. Valid neighboring records survive, incomplete checkpoints stay unchanged, and cancellation still stops collection.
- Relevant tracked CVEs and identifiers found in news are refreshed. Recent-entry collection does not establish exhaustive historical coverage for every product.
- Multi-CVE articles keep unmatched subjects as separate review candidates until advisory aliases establish that they describe the same vulnerability.
- OSV event ordering and independent limit events follow the [OSV schema algorithm](https://ossf.github.io/osv-schema/).
- News text comes from an inert HTML parser, excluding scripts, styles, templates, comments and attributes. Parsing and traversal have input, depth and node limits. An article needs an explicit closing wrapper to be considered complete; malformed or over-limit pages retain the feed excerpt.
- Newer source revisions take precedence. Future timestamps fail collection, and unchanged KEV records retain their content revision when the catalog changes.
- The scan interval and news discovery window are independent. RSS/Atom and The Hacker News filter new stories by publication or modification time before fetching articles. Successful checkpoints allow catch-up after downtime; tracked findings and authoritative package matches remain in scope. Undated entries produce a health warning, and unchanged undated content does not create duplicate revisions or model calls.

### Model analysis

- A shared catalog defines 22 provider profiles: 17 cloud services, four local/gateway profiles and a generic Chat Completions adapter. Provider-specific authentication, request formats, output limits and response validation cover six protocol families. The CLI can list the catalog without configuration or network access. Models select source excerpt IDs; the application resolves them to exact quotations and rejects unsupported claims. Installed-version constraints apply to fresh responses and cached results.
- Structured output defaults follow each provider's API, including native JSON Schema for OpenAI and Anthropic, with explicit overrides for model-specific capabilities. Incomplete, refused, asynchronous and unexpected tool/code responses are rejected. Model failures do not silently switch providers or weaken evidence validation.
- System news has separate classifications for new vulnerabilities, known-vulnerability updates, general coverage and uncertainty. Claimed system impact is recorded separately from deterministic package applicability.
- Product identity, installed versions, supporting quotes, article completeness and evidence freshness constrain impact conclusions. Linked CVEs preserve product-news analysis without weakening package matching.
- Both affected and excluded impact claims must cite the configured product name. Search keywords, including a shared vendor name, cannot establish product identity. An exclusion quoted for another product remains uncertain and goes to review. The analysis version changed so stored conclusions are reassessed.
- Critical-source severity and configured exploitation overrides survive model dismissals. Missing, truncated or stale context leaves the assessment uncertain.
- Failed or conflicting verification retains the highest validated priority proposal and records the failure or disagreement.
- General coverage remains historical when its article, inventory and model settings are unchanged. Current affected or excluded impact claims require fresh evidence.
- `evaluate:models` runs source-derived synthetic scenarios through the production analyzer. Reports separate acceptance, coverage, reference-label agreement, false exclusions and disagreements. The corpus labels remain `pending_human_review`; this is not an independently labeled production benchmark. Live provider calls require explicit opt-in, credentials, model IDs and bounded request settings.

### Setup and operations

- `init` accepts common-system templates or a library list, provider/model selection, vendor feeds, external heartbeat setup and independent scan/news timing. The default generated schedule is 30 minutes with a 40-minute news window. Templates do not invent installed versions or deployment details.
- `--credentials-file` explicitly loads dotenv data with existing environment values taking precedence. Reads are bounded to 128 KiB; Unix permissions, file type and runtime-variable checks happen before environment changes. The flag avoids Node’s startup handling of `--env-file`.
- Inventory exclusions, withdrawals, removed components and changed routes are reconciled before delivery. Dispatch checks the current policy again before sending.
- Notification setup supports explicit Slack/email routes, and doctor reports disabled routing. Known preconnection failures retry with bounded backoff. Slack digests split within the message limit; malformed queued messages do not block healthy jobs. Genuine database claim failures still stop delivery.
- Immediate alerts take priority over old digests. Pending messages receive updated wording and citations without resetting their schedule or attempt count.
- Early delivery failures appear in the final one-shot scan result and return exit code 2. Invalid command/flag combinations fail before activity.
- Database and worker-lock file checks reject links and insecure permissions without opening and closing existing SQLite files. This preserves SQLite’s process locks during concurrent inspection and repeated lock attempts. Backups are published atomically without replacing an existing destination.
- Shutdown cancels source/model requests and active Slack/SMTP sends, closes SMTP sockets, and leaves queued messages untouched. An interrupted send keeps an unknown receipt and is not retried automatically. Worker heartbeat, scan freshness and actionable delivery failures are available through a read-only health command.
- External heartbeat pings are opt-in and withheld until monitoring is healthy. The receiver must alert on missing pings; local health and external heartbeat state are separate.
- Opt-in retention has a read-only preview and atomic batches that count dependent history rows. Active, affected or uncertain findings and unresolved deliveries stay protected; inventory removal alone does not authorize deletion.
- Backups are restored and migrated only in a private temporary copy, then checked for SQLite integrity, relationships, schema and readable saved JSON. Automatic rotation and retention follow successful verification. Verification establishes structural restorability, not the semantic accuracy of saved security claims.
- Builds clean `dist` before compiling. Package checks install the tarball in a fresh consumer and verify the CLI version, public types and runtime exports.

## Validation

All **639 tests** pass on Node 26.12.0 and Node 24.22.1 in the Linux Docker test stage. They cover news windows, source recovery, package identity/version boundaries, model evidence validation, notification retries, concurrent SQLite readers and worker-lock contention. Maintenance tests cover read-only previews, bounded atomic pruning, protected records, migration, temporary restore verification and damaged-backup rejection. Provider protocol tests use real loopback HTTP with simulated responses; they do not establish hosted-model accuracy. `npm run check` also passes formatting, strict compilation and clean-package consumer checks.

Hosted CI for the release branch must pass at its final commit before merge. The repository requires an independent approval and passing checks.

The runtime image passes checks with a non-root user, a read-only root filesystem, disabled network access, private configuration and a native SQLite volume. Repeated scans, deduplication, monitoring health and verified backup pass. The packed CLI, public types and exports also pass on the minimum supported Node 24.0.0. The production dependency audit reports no known vulnerabilities at review time.

A local SQLite load check used 10 deployments, 1,000 components, 100 advisories and 1,000 findings. Three scans took 355, 197 and 191 ms with about 184 MiB peak process RSS and no duplicate revisions. Network requests, model calls and delivery were excluded; this was not an endurance test.

Earlier live source checks on 2026-10-24 included:

- An exact query for `lodash@4.17.20` returned eight advisories without source errors, including five historical package matches.
- A broad 24-hour scan initially hit HTTP 403 during detail collection. After pacing was added, a new scan of the 24-system sample completed all 157 public requests successfully: eight complete news articles and 143 advisories (134 published in the window and nine older records cited by news), with no source errors. The window was 2026-10-23 15:55 UTC through 2026-10-24 15:55 UTC. These are records returned by the configured sources, not a claim of exhaustive CVE coverage.
- After the HTML parser change, a fresh live check completed nine public requests and returned the same eight complete article extracts. All eight text bodies were identical to the model evaluation sample. A further check after the recovery changes again completed nine requests and read eight full articles without source errors.
- Against one live feed snapshot, a 40-minute news window returned zero stories and a one-day window returned eight. All eight fell within that window. Public requests still occur in dry-run mode; models and notifications do not.

Earlier live model checks on 2026-10-24 used a fictional security bulletin through the production analyzer and HTTP client:

| Provider  | Model              | Result                                         | Requests | Duration     |
| --------- | ------------------ | ---------------------------------------------- | -------- | ------------ |
| OpenAI    | `gpt-6-luna`       | HTTP 200; schema and evidence quotes validated | 1        | 10.0 seconds |
| Anthropic | `claude-haiku-5-5` | HTTP 200; schema and evidence quotes validated | 1        | 4.8 seconds  |

Each request had a 2,048-output-token cap and a 60-second timeout. No private inventory, tools, verification calls or notifications were involved. Both model IDs were checked against the providers' current documentation: [OpenAI](https://developers.openai.com/api/docs/models/gpt-6-luna) and [Anthropic](https://platform.claude.com/docs/en/models/haiku-5-5/overview). These checks establish compatibility for the tested models and credentials at review time, not general model accuracy. The remaining 20 provider profiles have simulated transport coverage only. No real Slack/email messages were sent.

### Expanded source checks, 2026-10-24

A public sample with exact versions from all 12 ecosystems, plus name-only Python and PHP entries, completed 129 OSV requests and retained 128 advisory records without coverage errors. Every exact-version sample returned at least one advisory. Both name-only samples produced candidates with unknown applicability and no affected or unaffected conclusions. Advisory aliases can refer to the same underlying vulnerability, so these record counts are not unique CVE counts.

Live checks exposed OSV spelling differences for Rust, NuGet and Swift that simulated responses had missed. Queries now preserve the published spelling and use bounded equivalent alternatives. A legitimate Swift host/path entry in a mixed Go/Swift advisory is also accepted. Regression tests cover each case; arbitrary package spelling is still not a discovery guarantee.

The official Node.js, Python and PHP feeds completed 11 requests over a seven-day window and returned eight full article extracts with no source errors: one Node.js article, one Python article and six PHP articles. PHP's historical feed needs its own bounded entry allowance. Updated vendor articles can be shorter than an older feed excerpt; the extractor verifies the complete article wrapper, title and body instead of treating length alone as completeness.

### Expanded model evaluation, 2026-10-24

A later run of `evaluate:models` made 20 requests against the source-derived synthetic corpus. OpenAI `gpt-6-luna` produced accepted output for all ten cases and matched both provisional classification and impact labels in seven; the other three answers were more uncertain. No false exclusions were recorded against those reference labels.

All ten Anthropic `claude-haiku-5-5` requests returned HTTP 401 with the credentials supplied for this run. That is an authentication failure, not a model-quality result, and it does not invalidate the earlier successful compatibility smoke check. A new comparison requires working credentials.

The corpus labels are still `pending_human_review`. These figures describe a small synthetic exercise, not production accuracy or an independently reviewed benchmark.

## Before deployment

A real-article evaluation used the sample inventory of 24 common systems with no installed versions. The initial run completed only two of 19 assessments. The final test used the same 19 target/event pairs from the successful paced source scan, with native JSON Schema output from OpenAI and Anthropic. Nine assessments completed, seven had conflicting classifications, and three were rejected for unsupported extracted claims. All 36 API requests returned HTTP 200; there were no JSON-format or quotation-reference failures. The clock was fixed at the source capture time for this evaluation. This is a small operational sample, not an accuracy benchmark.

These results support using model analysis as a review aid. They do not establish reliable automatic classification across arbitrary articles. Disagreement, failed validation and missing installed versions remain visible and cannot establish that a system is safe. No real notifications were sent.

- Obtain passing hosted checks and the required independent approval for the final commit before publishing.
- Repeat the synthetic live check when selecting other model IDs or provider accounts, and validate notification destinations separately. Mocked protocol tests do not cover hosted model behavior or destination credentials.
- Observe scheduled operation, source outages and delivery failures in a representative deployment before relying on the monitor operationally.
- Plan storage and retention before increasing the installation size. Retention is opt-in, and protected unresolved records can continue growing. Current evidence and findings are loaded into memory during a scan.
- Treat cached conclusions during source outages as historical. New advisory aliases can change a finding's canonical identity; this alpha does not migrate those identities automatically.

Schema 5 adds cache timestamps and evidence/finding age metadata for retention. Unknown legacy cache ages start at migration time so they are not immediately deleted. Before upgrading an operational database, take a backup and stop the old worker. Run `scan` or `start` to migrate, then use the read-only commands from the new version.
