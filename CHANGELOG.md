# Changelog

Versions follow [semantic versioning](https://semver.org/). What counts as a compatible change is defined in the [compatibility policy](docs/compatibility.md).

## 1.0.0-rc.1

Release candidate, published under the `next` tag. Not yet published at the time of writing.

### Upgrading from 0.1.0-alpha.0

1. Use Node.js 24.10.0 or newer (the alpha accepted 24.0).
2. Stop the old worker and take a backup: `security-watch backup --output PATH`.
3. Install the new version, then run `security-watch scan` or `security-watch start` once. This migrates the database to schema 7. Read-only commands refuse to run until that has happened. There is no downgrade path other than restoring the backup with the old version.
4. Run `security-watch doctor`. It now reports an SMTP address it cannot use and a verification model identical to the analysis model.

Behaviour that changes for an existing installation:

- **AI dismissals are reviewed by default.** News that a model classifies as general news or as not affecting you goes to a local review queue and the digest instead of being recorded silently. Set `policy.ai_dismissals: record` to keep the old behaviour.
- **Models receive less.** Each model defaults to the `minimal` disclosure profile: package and product names and versions only.
- **`models.verification` must differ from `models.analysis`.** An identical pair is rejected at start-up.
- **`models.daily_token_limit` defaults to 1,000,000** (was 100,000), and a request now reserves one token per three bytes instead of one per byte. The old defaults allowed about four requests a day.
- **Plain `http://` model endpoints** are accepted only for local or private hosts, even with `allow_private_endpoint: true`.
- **The first cve.now scan looks back one day** (was seven). A week meant about 4,500 detail requests and 80 to 90 minutes before the first result. Exact npm package matches still cover all of history.
- **Recipient domains are compared in lower case.** Email to `Ops@Example.ORG` was delivered but recorded as uncertain.

### Added

- **Notes that say where to look.** Systems, libraries and products accept a `note`; library list lines accept `# note`. Every notification carries `Where to look:` and `Affected item:` lines with the system name, owner and notes. Notes are never sent to sources or models.
- CycloneDX 1.4 to 1.6 import, per-source coverage receipts, inventory drift, declared artifact and remediation evidence.
- CVSS v4 base-vector scoring for OSV and GitHub records.
- Local review queue for AI dismissals (`reviews`, `review`).
- Offline rehearsal (`rehearse`) and pilot measurement commands (`pilot-report`, `pilot-cases`, `pilot-score`, `pilot-recall`, `pilot-response-template`).
- `acknowledge --revision N` refuses to acknowledge a revision newer than the one that was read.
- Library exports: `safeHttp`, `acquireLock`, `notificationText`, `sendEmail`, `smtpProblem`, `attachLocation`, `SCHEMA_VERSION`, and the types `HealthReport`, `ExternalHeartbeat`, `MaintenanceRun`, `EmailSender`, `EmailMessage`, `EmailReceipt`, `DeliveryOptions`, `FindingLocation`. `deliverPending` accepts an options object.

### Fixed: alerts that were wrong or lost

- A validated AI "affected" verdict on a news finding could be recorded silently while an uncertain one alerted. It is now never quieter than the uncertain route.
- A news finding matched by keyword or package name disappeared when an advisory record without package claims arrived for the same CVE. It now stays and takes on the advisory's severity and exploitation status.
- While a source was incomplete, an excluded finding flipped between "not affected" and "unknown" on every scan and sent a new alert each time.
- CISA KEV evidence was not attached to news about a CVE that had no advisory record yet, so the known-exploitation override did not fire.
- npm ranges using grammar that advisory sources do not use (`^`, `~`, hyphen ranges, `> 1.2`) could produce a false "not affected". They now give "unknown".

### Fixed: sources that stalled

- The set of stored cve.now records re-read at every scan grew without bound and eventually failed the source. Records without a package match now take turns, 200 per scan.
- A backlog larger than one scan reads (cve.now, GitHub) was never drained. Collection now resumes from the last record processed.
- One package name that could not be normalised discarded the whole advisory and held back the checkpoint.
- A stored OSV record that no longer exists stopped the refresh of the records after it.
- Feed entries that appeared after their own timestamp were dropped silently.
- cve.now changed its response formats: the package lookup is now a JSON Feed and the listing pages with `next_cursor`. Both the earlier and the current formats are read; before, the package lookup failed and only the first listing page was read.
- A cve.now record stamped later than the scan's start time (for example one updated while a long first scan was still running) made the whole source incomplete. Such a record is now collected with its earlier timestamp; only a record with no usable time is refused.
- Everyday words that are also package names (`send`, `buffer`, `request`) matched unrelated advisory and news text.
- Comparing a large inventory with a large evidence store blocked the process for many seconds.

### Fixed: delivery, storage and import

- An SMTP address with an unencoded `%` was recorded as an uncertain receipt; TLS and sign-in failures before the message is handed over are now retried instead of being marked uncertain.
- `backup --output` left a file at the destination when verification failed.
- Two processes opening an old database at the same moment could leave it unopenable.
- A job superseded while it was being sent stayed `pending` after a failed attempt.
- A send displaced by a second database handle stopped the worker.
- A legacy npm name (`JSONStream`) or one unreadable lockfile or SBOM entry rejected the whole inventory; CycloneDX documents without `dependsOn`, with an unencoded npm scope, or with `v`-prefixed Go versions were rejected.
- A one-character version citation satisfied model validation; news evidence without a content status was treated as a fully read article.
- `doctor` printed feed addresses after variable substitution.
- A setup without an AI model reported every scan as degraded: exit code 2, a standing health finding and alert, and withheld external heartbeat pings. "AI is disabled" is now a `notices` entry in the scan report.

### Changed

- The published `Store` type no longer declares the worker's internal methods (`claimDue`, `completeJob`, `recoverSending`, `setMeta`, `reserveBudget` and others). They still exist at run time and are not part of the public API.
- Types are exported by name instead of `export *`.
- Dependency: `fast-xml-parser` 5.12.1 (GHSA-474x-hrwr-fgx4).

### Not verified in this release candidate

- No human-labelled evaluation: the prepared 120-case pilot has not been reviewed.
- No representative deployment period, and no real Slack or email message has been sent.
- Hosted CI has not run on this commit; tests ran on macOS with Node 26.12.0. Windows is untested.
- Only OpenAI and Anthropic were ever checked against live APIs, on 2026-10-24; the other provider profiles are covered by simulated responses.

## 0.1.0-alpha.0

First public alpha: inventories for 12 ecosystems, cve.now, OSV, GitHub, KEV and feed sources, optional model analysis, Slack and SMTP delivery from one host.
