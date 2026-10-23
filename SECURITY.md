# Security policy and boundaries

Security Watch is an experimental monitoring tool. It has not received an independent security audit and does not certify that a system is secure, affected, reachable or remediated. The initial alpha has no production support or patch-response SLA.

## Report a vulnerability

If the hosting repository enables private vulnerability reporting, use **Security → Advisories → Report a vulnerability**. If that option is unavailable, ask a maintainer for a private reporting channel without posting exploit details, credentials, private inventory or affected customer data publicly. Do not send real secrets in examples. A dedicated reporting address has not been established in this checkout.

Include the relevant commit/version, Node version, a minimal synthetic reproduction, expected versus observed behavior, and which trust boundary is crossed. Reports involving lost alerts, false safety conclusions, credential disclosure, unsafe network access or duplicate/incorrect delivery are particularly useful.

## Trust model

Trusted inputs are the operator's configuration, inventory, chosen model/SMTP endpoints, environment, local filesystem and installed application/dependencies. Feed bodies, advisory text and model output are untrusted evidence. The application does not protect against a malicious local administrator, compromised dependency, hostile model endpoint explicitly trusted by the operator, or altered system clock.

Implemented boundaries include:

- Strict configuration/inventory parsing, bounded input sizes and metadata-only lockfile import. No package installation or lifecycle-script execution occurs during monitoring.
- Public HTTPS fetching with checks on the addresses used by the connection, bounded redirects/timeouts/response sizes, and removal of authentication headers on cross-origin redirects. Model endpoints may explicitly opt into private addressing; SMTP endpoints are operator-selected.
- Models receive no shell, browser, filesystem or notification tools. Output is schema-checked, evidence IDs must exist, and supporting quotes must appear in the supplied evidence.
- Deterministic package matching and source-severity floors govern library/product decisions. AI cannot rewrite recipients, authoritative version constraints or dependency applicability.
- Slack destinations come only from operator configuration and are restricted to standard `hooks.slack.com` incoming webhooks. SMTP requires TLS. Notification content is rendered as text and cannot enable attachments, filesystem reads or URL-fetching features in the email transport.
- Findings and their delivery jobs are committed together. Ambiguous delivery is visible and requires a manual receipt check before retrying.

These controls reduce risks; they are not a general prompt-injection detector or sandbox. A model can still misinterpret a quoted source. A feed can omit important facts. A valid advisory may be wrong, withdrawn or delayed. Source failures and uncertain applicability must remain visible in operational review.

## Data handling

OSV requests reveal npm package names and exact versions. Other advisory/feed servers receive normal request metadata, and GitHub may receive the configured API token. The configured AI provider receives selected relevant inventory entries and deployment context from the matched system plus selected evidence. Notifications disclose finding context and source links to Slack or the configured email recipients. There is no application telemetry.

Credential values are read from environment variables, not placed in model prompts or intentionally persisted in SQLite. Do not insert keys into model names, feed URLs, inventory text or configuration substitutions. Use your service manager or secret manager to supply credentials; the CLI does not automatically load `.env` files. Do not commit configuration, database files, backups or `.env` files to source control.

SQLite stores evidence, finding revisions, model analysis excerpts, caches, budgets and delivery state. Database files use private permissions but are not application-encrypted. Use appropriate host access controls and encrypted storage. Retention and backup disposal are operator responsibilities. Backups can contain the same sensitive material as the live database.

## Coverage limitations

- Exact vulnerability matching is limited to supported npm identity/version evidence. Lockfile entries include dependencies that may not be present in production.
- Generic products, operating systems and SaaS services have name/keyword relevance only. Vendor backports, enabled features and exploit reachability are not automatically established.
- Missing versions, unknown constraints and stale inventory remain uncertain. No returned advisory does not mean no vulnerability exists.
- CVSS v3.0/v3.1 calculation and supplied source labels/scores are supported; CVSS v4 vectors are not calculated in this alpha.
- Sources and model contexts are bounded. Incomplete collection or analysis is degraded monitoring, not successful clearance.
- There is no general SBOM ingestion, authenticated web crawling, automatic remediation, distributed lock, multi-host worker or independent penetration-test certification.
- Notifications are not exactly-once delivery. A timeout can occur after a destination accepts a message. Verify receipt before retrying an `unknown` job.

Review `status`, `deliveries`, source-health findings and service logs. Loss of every delivery channel or loss of the host cannot be reported through that same failed infrastructure; use external service monitoring where required.
