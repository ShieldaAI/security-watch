# Security policy and boundaries

Security Watch is an experimental monitoring tool without an independent security audit or a patch-response SLA. Validate findings against your deployment before using them to make remediation decisions.

## Report a vulnerability

Use [GitHub's private vulnerability reporting form](https://github.com/ShieldaAI/security-watch/security/advisories/new). If that option is unavailable, ask a maintainer for a private reporting channel without posting exploit details, credentials, private inventory or affected customer data publicly. Do not send real secrets in examples. There is no dedicated security reporting address yet.

Include the relevant commit/version, Node version, a minimal synthetic reproduction, expected versus observed behavior, and which trust boundary is crossed. Reports involving lost alerts, false safety conclusions, credential disclosure, unsafe network access or duplicate/incorrect delivery are particularly useful.

## Trust model

Trusted inputs are the operator's configuration, inventory, chosen model/SMTP endpoints, environment, local filesystem and installed application/dependencies. Feed bodies, article text, advisory text and model output are untrusted evidence. The application does not protect against a malicious local administrator, compromised dependency, hostile model endpoint explicitly trusted by the operator, or altered system clock.

Implemented boundaries include:

- Strict configuration/inventory parsing, bounded input sizes and metadata-only lockfile import. No package installation or lifecycle-script execution occurs during monitoring.
- Public HTTPS fetching with checks on the addresses used by the connection, bounded redirects/timeouts/response sizes, and removal of authentication headers on cross-origin redirects. Model and external-heartbeat endpoints may explicitly opt into private addressing; SMTP endpoints are operator-selected.
- Models receive no shell, browser, filesystem or notification tools. Output is schema-checked, evidence IDs must exist, and supporting quotes must appear in the supplied evidence.
- The Hacker News article requests are restricted to its publication hosts and have size limits. Article links to other sites are not crawled. Missing, excerpted, stale or truncated evidence cannot support a new decisive AI impact conclusion. Historical general-news classifications are retained; current affected/excluded claims require fresh evidence.
- Deterministic package matching and source-severity floors govern library/product decisions. AI cannot rewrite recipients, authoritative version constraints or dependency applicability.
- AI news classification and claimed system impact are stored separately from authoritative applicability. Evidence-backed general news or an AI-reported exclusion can suppress noncritical news alerts, but cannot override source-critical or enabled known-exploitation safeguards.
- Slack destinations come only from operator configuration and are restricted to standard `hooks.slack.com` incoming webhooks. SMTP requires TLS. Notification content is rendered as text and cannot enable attachments, filesystem reads or URL-fetching features in the email transport.
- Findings and their delivery jobs are committed together. Ambiguous delivery is visible and requires a manual receipt check before retrying.

Models can misinterpret sources, feeds can omit important facts, and advisories can be wrong or delayed. Check source failures and uncertain findings during operational review. The bot does not provide a general prompt-injection detector or execution sandbox.

## Data handling

cve.now stack requests reveal deduplicated npm package names and exact versions through URL query parameters; lockfiles and system/deployment metadata are not uploaded. The Hacker News feed and article servers receive normal HTTP request metadata. Optional OSV requests reveal library ecosystem, package name and the installed version when supplied. Official vendor feeds receive normal request metadata. Other enabled advisory/feed servers receive normal request metadata, and GitHub may receive the configured API token. The configured AI provider receives selected relevant inventory entries and deployment context from the matched system plus selected evidence. Notifications disclose finding context and source links to Slack or the configured email recipients. There is no automatic application telemetry. An optional, operator-configured heartbeat endpoint receives bodyless success pings and normal request metadata. It receives no inventory, finding content or logs.

Credential values are read from environment variables, not placed in model prompts or intentionally persisted in SQLite. Do not insert keys into model names, feed URLs, inventory text or configuration substitutions. Use your service manager or secret manager to supply credentials; the CLI does not automatically load `.env` files. Do not commit configuration, database files, backups or `.env` files to source control.

SQLite stores evidence, finding revisions, model analysis excerpts, caches, budgets and delivery state. Database files use private permissions but are not application-encrypted. Use appropriate host access controls and encrypted storage. Retention and scheduled backups are disabled until configured. Cleanup preserves active or unresolved findings, unresolved delivery audit, source checkpoints and budgets; it is bounded and has a read-only preview. Scheduled backup rotation removes only managed snapshots after a new snapshot verifies successfully. Backups can contain the same sensitive material as the live database. Verification copies a standalone snapshot into a private temporary directory and checks structural restoration, including migrations, without replacing live state. This is not validation of every stored security claim; plan disk capacity and protect backup destinations.

## Coverage limitations

- Library inventory supports 12 ecosystems. Only npm uses supported version-range evaluation and exclusions. Other ecosystems require a positive exact OSV query or an explicitly listed affected version; a missing version, unmatched result or unsupported range stays unknown. Lockfile entries include dependencies that may not be present in production.
- Generic products, operating systems and SaaS services have name/keyword candidate matching plus optional AI news/impact analysis. AI impact is an evidence-backed opinion, not a deterministic product-version result. Vendor backports, enabled features and exploit reachability are not automatically established.
- Missing versions, unknown constraints and stale inventory remain uncertain. An empty advisory search does not establish that a system has no vulnerabilities.
- CVSS v3.0/v3.1 calculation and supplied source labels/scores are supported; CVSS v4 vectors are not calculated in this alpha.
- Source requests and model inputs have size and request limits. Incomplete collection or analysis reports degraded monitoring and requires review.
- Recent cve.now entry collection, tracked/news-cited refreshes and exact npm stack queries do not establish exhaustive historical coverage for every product. The Hacker News may block article access; the feed excerpt remains available for review without a confident impact conclusion.
- There is no general SBOM ingestion, authenticated web crawling, automatic remediation, distributed lock, multi-host worker or independent penetration-test certification.
- Notifications are not exactly-once delivery. A timeout can occur after a destination accepts a message. Verify receipt before retrying an `unknown` job.

Review `status`, `deliveries`, source-health findings and service logs. Optional external success pings stop when monitoring is unhealthy, but the receiving service must be configured to detect missing pings. Loss of the host or every delivery channel cannot be reported through that same failed infrastructure.
