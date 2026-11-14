# Changelog

Versions follow [semantic versioning](https://semver.org/). What counts as a compatible change is defined in the [compatibility policy](docs/compatibility.md).

## 1.0.0-rc.1

Release candidate, published under the `next` tag. Not yet published at the time of writing.

### Upgrading from 0.1.0-alpha.0

1. Use Node.js 24.10.0 or newer (the alpha accepted 24.0).
2. Stop the old worker and take a backup: `security-watch backup --output PATH`.
3. Install the new version, then run `security-watch scan` or `security-watch start` once. This migrates the database to schema 7. Read-only commands refuse to run until that has happened. There is no downgrade path other than restoring the backup with the old version. Findings that did not change keep their revision, their delivered alerts and their acknowledgements: the upgrade does not send them again.
4. Run `security-watch doctor`. It now reports an SMTP address it cannot use, a verification model identical to the analysis model, and inventory entries that were left out (`import_warnings`) and npm names that may be a typing mistake (`name_notices`). It exits with status 2 whenever it prints `ok: false`.

Behaviour that changes for an existing installation:

- **AI dismissals are reviewed by default.** News that a model classifies as general news or as not affecting you goes to a local review queue and the digest instead of being recorded silently. Set `policy.ai_dismissals: record` to keep the old behaviour.
- **Models receive less.** Each model defaults to the `minimal` disclosure profile: package and product names and versions only.
- **`models.verification` must differ from `models.analysis`.** A pair that reaches the same model at the same address is rejected at start-up, however each one is written (a spelled-out default endpoint, a trailing slash, different letter case, a compatible-endpoint profile pointing at the same service).
- **`models.daily_token_limit` defaults to 1,000,000** (was 100,000), and a request now reserves one token per three bytes instead of one per byte. The old defaults allowed about four requests a day.
- **Plain `http://` endpoints** (models and the external heartbeat) are accepted only for local or private hosts, even with `allow_private_endpoint: true`. An address is judged by its range; addresses that wrap a public IPv4 address (NAT64, 6to4) count as public. A name is accepted when it has no public form (`ollama`, `ollama.ml-tools`, `*.internal`, `*.ts.net`, `*.test`, `*.home` and similar), and the request is refused if the name resolves to a public address.
- **Inventory text is one line.** System `id`, `name`, `owner`, `environment`, keywords, product names and every `note` are rejected when they contain a control character (tabs and line breaks included) or a Unicode line separator. These values are printed in notifications.
- **A capitalised npm name typed by hand is pointed out.** `npm:Lodash` is accepted, because some packages from before 2017 keep their capitals (`MD5`, `CSSselect`), but it matches only advisories for exactly that spelling. `doctor` lists such entries under `name_notices` and every scan report carries them in `notices`. A notice is not a fault: the scan is not degraded, no health alert is sent, and the heartbeat is not withheld. Names imported from a lockfile or SBOM, and `JSONStream`, `Base64`, `JSONPath` and `JSONSelect`, are taken as published.
- **cve.now reads one week past its checkpoint** on every scan (about 45 listing requests at the current rate of some 600 records a day, under a minute) to find records the service ingested after their publication date.
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
- A news finding matched by keyword or package name disappeared when an advisory record arrived for the same CVE without a package claim this application can use (no claims at all, an ecosystem it does not know such as GitHub Actions or Debian, or a name it cannot normalise). It now stays and takes on the advisory's severity and exploitation status.
- While a source was incomplete, an excluded finding flipped between "not affected" and "unknown" on every scan and sent a new alert each time. Only the advisory source that supplied the excluding version range counts: a linked news article that could not be read no longer turns an exclusion into an urgent "unknown".
- After the monitor had been stopped for longer than two poll intervals, the first scan briefly stored excluded findings as "unknown" and queued urgent alerts for them before refreshing the evidence. Stored evidence is now judged as of the last collection until it has been refreshed.
- With a model enabled, editing a note (or the owner) created new revisions, a new review beside a dismissed one, and a second digest or immediate alert. Notes, the owner and the `Where to look` text are now left out of everything that decides revisions, reviews, analysis reuse and alerts.
- Upgrading from 0.1.0-alpha.0 gave every active finding a new revision and a new alert and dropped acknowledgements, because the stored fingerprint gained fields. A finding unchanged in what the earlier release compared keeps its revision.
- CISA KEV evidence was not attached to news about a CVE that had no advisory record yet, so the known-exploitation override did not fire.
- npm ranges using grammar that advisory sources do not use (`^`, `~`, hyphen ranges, `> 1.2`) could produce a false "not affected". They now give "unknown".

### Fixed: sources that stalled

- The set of stored cve.now records re-read at every scan grew without bound and eventually failed the source. Records without a package match now take turns, 200 per scan.
- A backlog larger than one scan reads (cve.now, GitHub) was never drained. Collection now resumes from the last record processed.
- One package name that could not be normalised discarded the whole advisory and held back the checkpoint.
- A stored OSV record that no longer exists stopped the refresh of the records after it.
- Feed entries that appeared after their own timestamp were dropped silently.
- cve.now changed its response formats: the package lookup is now a JSON Feed and the listing pages with `next_cursor`. Both the earlier and the current formats are read; before, the package lookup failed and only the first listing page was read.
- A cve.now record stamped later than the scan's start time (for example one updated while a long first scan was still running) made the whole source incomplete. Such a record is now collected with its earlier timestamp; only a record with no usable time is refused. A listing record with a publication date ahead of the clock is collected and never ends paging.
- cve.now records ingested after their publication date were never collected: the listing is ordered by publication date, so they appear below the checkpoint. The listing is now read one week past the checkpoint and a record counts as new when it was first seen inside the window. A record ingested more than a week late is found only through an exact npm match or a news citation.
- One cve.now record could stop the source for good: a stored record the service no longer serves (HTTP 404) failed every scan, and a record that cannot be parsed held back the resume point of a backlog. A new record that cannot be read keeps the checkpoint where it is, so it is asked for again, but only for a limited time: one day when the service answers with a refusal or with content that cannot be used (this includes a listing entry with no usable identifier or date), three days when the request itself fails. After that it is reported and passed over. A stored record the service no longer serves, or serves in a form that cannot be used, keeps its last known content and counts as checked, so a result that rests on it does not turn into `unknown`. A bad item in the package lookup is reported and no longer holds the listing checkpoint.
- After a long stop, cve.now could list more than one scan pages through, and every later scan failed with "pagination limit reached". One scan now pages through about 60,000 records (some three months); beyond that it reads what was listed, reports the period it could not read, and moves on.
- CVEs cited by stored news were re-read from cve.now at every scan without limit. Once stored they take turns with the other tracked records. Requests left out by the 5,000-per-scan limit are reported as incomplete coverage instead of being dropped silently.
- Everyday words that are also package names (`send`, `buffer`, `request`) matched unrelated advisory and news text. They now need a story about packages or a named release (`Next.js`, `Requests 2.32.0`, `send@0.19.0`, `debug v4.4`); a bare decimal after the word ("send 1.5 million requests") is not a release. Well-known software named with an everyday word (`express`, `react`, `flask`, `rails`) also counts when it is written as a name: "a flaw in Express", "Rails releases patches", but not "researchers express concern". Any other name (`axios`, `django`, `webpack`) matches wherever it appears.
- Comparing a large inventory with a large evidence store blocked the process for many seconds.

### Fixed: delivery, storage and import

- An SMTP address with an unencoded `%` was recorded as an uncertain receipt. Failures that provably happen before the message is handed over (connection, TLS, greeting, a dropped session before `MAIL FROM`) are retried instead of being marked uncertain. A rejected sign-in (response code 535) is a configuration fault and fails at once; a temporary refusal (4xx) is retried. Once `MAIL FROM` has been written, a dropped connection or timeout is recorded as uncertain and never retried automatically.
- Text from an advisory (title, fixed version), a model or the inventory could contain a line break and so add forged `Rule:`, `Finding:` or `Where to look:` lines to a notification. Every value is now placed on one line.
- `backup --output` left a file at the destination when verification failed.
- Two processes opening an old database at the same moment could leave it unopenable.
- A job superseded while it was being sent stayed `pending` after a failed attempt.
- A send displaced by a second database handle stopped the worker.
- A legacy npm name (`JSONStream`) or one unreadable lockfile or SBOM entry rejected the whole inventory; CycloneDX documents without `dependsOn`, with an unencoded npm scope, with `v`-prefixed Go versions, with an empty `version`, with an upper-case package type (`pkg:NPM/…`), or with a Python version written two equal ways (`1.0` and `1.0.0`) were rejected. A component with an unreadable package URL or a non-text version is left out with a warning. Two genuinely different versions for one component, duplicate references and malformed hashes still reject the document.
- A version citation that only matched a digit inside another number (`4` inside `4.2` or a CVE number) satisfied model validation; news evidence without a content status was treated as a fully read article.
- `doctor` printed feed addresses after variable substitution, and exited with status 0 while reporting an unusable SMTP address.
- With `models` left out of the configuration, `daily_token_limit` defaulted to 100,000 instead of the documented 1,000,000.
- A setup without an AI model reported every scan as degraded: exit code 2, a standing health finding and alert, and withheld external heartbeat pings. "AI is disabled" is now a `notices` entry in the scan report.

### Changed

- The published `Store` type no longer declares the worker's internal methods (`claimDue`, `completeJob`, `recoverSending`, `setMeta`, `reserveBudget` and others). They still exist at run time and are not part of the public API. `ModelAnalyzer` accepts the published `Store`, or a caller's own state described by the exported type `ModelState`.
- A replacement `emailSender` can no longer signal "nothing was sent" through an error's `code` or `command`: such labels do not prove it. Its failures are retried only on an SMTP 4xx response code and are otherwise recorded as uncertain.
- Publishing goes through `npm run release`, which chooses the tag from the version. A bare `npm publish` is refused, because `npm publish --tag latest` cannot be told apart from it inside a lifecycle script.
- Types are exported by name instead of `export *`.
- Dependency: `fast-xml-parser` 5.12.1 (GHSA-474x-hrwr-fgx4).

### Not verified in this release candidate

- No human-labelled evaluation: the prepared 120-case pilot has not been reviewed.
- No representative deployment period, and no real Slack or email message has been sent.
- Hosted CI has not run on this commit; tests ran on macOS with Node 26.12.0. Windows is untested.
- Only OpenAI and Anthropic were ever checked against live APIs, on 2026-10-24; the other provider profiles are covered by simulated responses.
- The cve.now listing order (publication date, newest first) and its `limit` parameter were checked against the live service on 2026-11-14 with a handful of requests. How often the service ingests a record more than a week after its publication date is not known.
- `npm run release` has not been run, with or without `--dry-run`.

## 0.1.0-alpha.0

First public alpha: inventories for 12 ecosystems, cve.now, OSV, GitHub, KEV and feed sources, optional model analysis, Slack and SMTP delivery from one host.
