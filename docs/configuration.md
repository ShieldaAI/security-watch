# Configuration

Configuration is strict YAML or JSON: unknown fields and invalid values fail validation. The configuration file is limited to 1 MiB. `${VARIABLE}` substitution is supported in parsed string values; an undefined variable is an error. Credential settings contain the **name** of an environment variable, never its secret value.

Pass `--credentials-file ./watch/.env` to load credentials and configuration variables from a dotenv file. It is read as data, with no shell commands or variable expansion. Existing environment values take precedence. The file must be a regular file of at most 128 KiB; symlinks are rejected. On Unix, run `chmod 600` first. Shell, Node.js and TLS runtime settings belong in the service manager and are rejected in this file. Without this flag, the CLI uses only its environment and does not search for `.env` files.

`inventory` and `database` resolve relative to the configuration file. Inventory `lockfile` paths resolve relative to the inventory file. Configuration is read once per process; restart the worker after changing it. Inventory is loaded again on each scheduled scan. In the supplied Docker Compose setup, use `inventory: /config/systems.yaml`, `database: /data/watch.db`, and a root-level `.env` file copied from `.env.example`. Set `SECURITY_WATCH_UID`/`SECURITY_WATCH_GID` to your host user/group IDs; this preserves mode-0600 configuration/inventory access without widening host permissions. Compose initializes ownership of its `watch-data` named volume before starting the application. SQLite remains on Docker's native filesystem, while the VM must have access to the read-only configuration/inventory bind mounts. Retain the named volume when recreating containers.

## Minimal setup

`security-watch init --directory ./watch --systems nodejs,python --yes` creates a starter configuration, private inventory and `.env.example`. It selects a 30-minute polling interval and a 40-minute news window. Add `--provider NAME --model ID` to configure analysis, or use interactive `init` to choose a provider and notification routes. `--poll-minutes` and `--lookback-minutes` set timing during setup. Run `security-watch templates` for system names and `security-watch providers` for provider IDs. Selected systems have no assumed installed version; edit the inventory before assessing deployment impact.

Add `--notifications slack` to configure Slack routes, or `--notifications email --email-from alerts@example.com --email-to security@example.com` for email. Both channels can be selected with `--notifications slack,email`; email recipients are comma-separated. Setup writes credential variable names to `.env.example` and enables the selected channels for library, product, news and monitoring-health findings. It sends nothing. Without a notification choice, routes remain disabled. `doctor` reports the routes so this is visible before starting the worker.

For an existing monitor, edit the category `channels` and `health_channels` below and add the matching destination settings. After loading the private credentials file, run `test-notification --channel slack` or `test-notification --channel email` with your `--config` and `--credentials-file` paths. This attempts one test, reports its status and failure reason, and does not write to the monitor database or retry automatically.

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

The 10-minute overlap in this example re-reads recent stories, and stable evidence and finding IDs prevent the overlap from creating duplicate notifications. A feed can also list a story after the time it is stamped with, for example when it publishes with a delay or stamps entries with a date only. The monitor remembers which entries each feed listed at the previous scan, so an entry that appears for the first time is collected even when its stamp is older than the window, up to seven days before the last successful scan. An entry that was already listed and left out as too old stays out. The first scan of a new installation uses the window alone. After downtime or a source failure, discovery reaches back to the last successful checkpoint, with up to five minutes of additional overlap. Catch-up can therefore cover more than 40 minutes. Feed history and existing collection limits still constrain what can be recovered.

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

`SMTP_URL` must name an `smtp:` or `smtps:` endpoint, for example `smtps://alerts:PASSWORD@mail.example.com`. STARTTLS/TLS is required, certificates are verified, and URL query options are rejected. A user name or password that contains `%`, `@`, `:` or `/` must be percent-encoded; write a literal `%` as `%25`. `doctor` reports an address it cannot use, and such an address is recorded as a failed delivery, never as an uncertain one. Recipient addresses are compared with the domain in lower case, so `Ops@Example.ORG` and `Ops@example.org` are the same recipient. SMTP destinations are operator-selected and may be internal. Up to 20 recipients are supported. Partial acceptance produces `unknown`, since automatically repeating the whole message could duplicate delivery to accepted recipients.

## System inventory

```yaml
systems:
  - id: production-api
    name: Production API
    environment: production
    owner: platform
    note: runs on cluster eu-1, namespace api; on-call rota "platform"
    exposure: internet
    criticality: critical
    updated_at: '2026-10-24T12:00:00Z'
    components:
      - id: parser
        ecosystem: npm
        name: example-parser
        version: 1.2.0
        note: request parsing in services/api, file package.json
    lockfile: ./api/package-lock.json
    products:
      - name: PostgreSQL
        version: '16.4'
        keywords: [Postgres]
        note: managed database "api-prod", owned by the data team
    keywords: [our-runtime-name]
```

Replace the example names and timestamp with verified deployment information. `updated_at` is required; use an ISO timestamp with a timezone. Inventory freshness comes from this value, not file modification time. `id` and `name` are required; other lists default to empty, `environment` defaults to `unknown`, and exposure/criticality default to `unknown`.

| Field                                 | Meaning                                                                                                |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| System `id`                           | Stable, unique deployment identity; keep it unchanged when upgrading a package                         |
| `environment`, `owner`                | Inventory context; the owner is shown in notifications and does not route them                         |
| `note` (system, component, product)   | Your own pointer to where the item lives or who to ask; shown in notifications, see below              |
| `exposure`                            | `internet`, `internal` or `unknown`                                                                    |
| `criticality`                         | `unknown`, `low`, `medium`, `high` or `critical`; business importance, separate from advisory severity |
| Component `id`                        | Unique within its system; keep stable across upgrades                                                  |
| Component `ecosystem`                 | One of the 12 supported ecosystems or a recognized alias                                               |
| Component `name`                      | Registry package identity; npm scopes and Maven coordinates are significant                            |
| Component `version`                   | Optional exact installed version; omit unknown versions rather than supplying constraints              |
| Product `name`, `version`, `keywords` | Product context and matching terms; not a supported vendor version/backport decision                   |
| System `keywords`                     | Explicit terms for news matching                                                                       |

### Notes: telling readers where to look

A finding names a system and a library. The person who receives the alert usually needs one more fact: where that library is used and who can check it. Put that in a `note`:

- on a **system**: where it runs and who owns it, for example `runs on cluster eu-1, namespace shop`;
- on a **component** or library: where it is declared or used, for example `checkout API, repository acme/checkout, file package.json`;
- on a **product**: which instance is meant, for example `managed database "shop-prod"`.

Every notification then carries two extra lines built from your inventory:

```text
Where to look: Web shop (owner: Dana, platform team) - runs on cluster eu-1, namespace shop
Affected item: npm alpha 1.0.0 - checkout API, repository acme/checkout, file package.json
```

Both lines appear even without notes, with the system's name and the item in plain words. A note is one line of at most 500 characters. Editing a note, or the owner, updates messages that are still waiting to be sent and does not create a new alert, a new review or a new model request. Names, the owner, keywords and notes may not contain control characters (tabs and line breaks included) or Unicode line separators, because each is printed on one line of a notification. Notes are stored in the local database and sent to your notification destinations. They are not sent to advisory sources, and they are not included in requests to AI models under either disclosure profile. They are your own text, not evidence: a note never changes whether a finding applies or how it is routed.

Lockfiles must be package-lock v2/v3 with a `packages` map. An entry whose name or version cannot be read is skipped with a monitoring warning instead of rejecting the file; npm names registered before 2017 with capital letters, such as `JSONStream`, are accepted as published. npm names are case-sensitive and current names are lower case, so a capitalised name **typed by hand** (`npm:Lodash`) matches only advisories for exactly that spelling: it is kept, `doctor` lists it under `name_notices`, and every scan report carries it in `notices`. The same is done for RubyGems, Hex and Pub names with capitals; at most 200 notices are listed, with a count of the rest. A notice does not degrade the scan or raise a health alert, because some packages from before 2017 really are published with capitals (`MD5`, `CSSselect`); write the name in lower case unless yours is one of them. Names that come from a lockfile or SBOM, and the known legacy names `JSONStream`, `Base64`, `JSONPath` and `JSONSelect`, are not mentioned. Imports include transitive, development and optional entries and skip workspace links. They read metadata only. Import IDs follow `lock:node_modules/…` paths. Imported and manual component IDs must be unique. The inventory is bounded to 2 MiB, individual lockfiles to 20 MiB, and each system to 20,000 components. Duplicate system IDs or product names within a system are rejected; YAML aliases are rejected.

Use longer explicit keywords for short product names: matching ignores terms shorter than three characters. Whole-name matching reduces substring/scope collisions but cannot disambiguate every product name. Inventory changes trigger reassessment of stored evidence. A removed finding becomes inactive; disappearance is not proof of remediation.

### Library lists and ecosystem groups

Library matching does not require AI. Enable `sources.osv` to query the supported registry ecosystems: npm, PyPI, Packagist, Go, Maven, crates.io, RubyGems, NuGet, Hex, Pub, Hackage and SwiftURL. `security-watch ecosystems` lists these names. Aliases include `nodejs`, `python`, `php`, `java`, `rust`, `ruby`, `dotnet`, `elixir`, `dart`, `haskell` and `swift`.

A system can have a grouped `libraries` field instead of manually assigned component IDs:

```yaml
libraries:
  npm:
    - express
    - '@types/node'
  python:
    - requests
    - name: urllib3
      version: '2.2.3'
  php:
    - symfony/http-foundation
  maven:
    - org.apache.logging.log4j:log4j-core
```

The versions above illustrate syntax; use your installed versions. Arrays also accept explicit prefixes, such as `libraries: [python:requests, npm:express]`. Empty lines and lines that start with `#` are ignored in text lists.

To say where a library is used, add a note. In a text list, write it after `#` at the end of the line. In YAML, either quote the whole entry or use the object form:

```yaml
libraries:
  - 'npm:express@4.21.2   # checkout API, repository acme/checkout, file package.json'
  - { ecosystem: python, name: requests, version: '2.32.3', note: 'billing worker, services/billing' }
```

Without the quotes YAML treats everything after `#` as a comment of its own and the note is lost. The same library listed more than once keeps each distinct note, joined with `|`. Entries can be `python:requests`, `python:requests==2.32.3`, `npm:express@4.21.2`, or a package name followed by one exact version separated by whitespace. `latest`, wildcards and dependency constraints are rejected. Names without versions still produce advisory candidates, with applicability unknown.

```sh
security-watch normalize-libraries --input examples/libraries.example.txt
security-watch normalize-libraries --input php-libraries.txt --ecosystem php --output components.json
security-watch init --directory ./watch --yes --libraries examples/libraries.example.txt
```

Normalization is local and does not install packages, call providers or overwrite an existing output file. Its output is a component array suitable for an inventory's `components` field. Setup creates one application system and enables OSV; it cannot combine `--libraries` with `--systems`. Lists are capped at 2 MiB and 20,000 entries. Generated library IDs include ecosystem, package and version; use explicit component IDs when you need the same identity across upgrades. See the [grouped example](../examples/libraries.example.yaml) and [library-only configuration](../examples/library-watch.example.yaml).

npm affected ranges and a documented PyPI final-release subset are evaluated locally. For other ecosystems and unsupported PyPI forms, an exact positive OSV query or an explicitly listed affected version establishes a match; unsupported ranges and empty search results do not establish exclusion. OSV receives the ecosystem, name and optional version. Use the registry's published package spelling, especially for NuGet; arbitrary casing is not a discovery guarantee. A language/runtime product name is not a library package.

## Sources and coverage

| Setting                    | Default and behavior                                                                                                                                             |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sources.cve_now`          | `true`; collect recent CVE entries, revisit inventory-relevant tracked/news-cited IDs and query exact npm package/version pairs through cve.now's stack endpoint |
| `sources.hacker_news`      | `true`; collect The Hacker News security feed and bounded article text for system news analysis                                                                  |
| `sources.osv`              | `false`; optional package queries across supported ecosystems, with or without versions, full advisory records and tracked-advisory refreshes                    |
| `sources.github`           | `false`; optional reviewed and malware advisories, tracking modifications and withdrawals; local range evaluation remains npm-only                               |
| `sources.github_token_env` | `GITHUB_TOKEN`; optional authentication for the GitHub API                                                                                                       |
| `sources.kev`              | `false`; optional matching-CVE enrichment with CISA known-exploitation evidence; KEV alone does not invent a product finding                                     |
| `sources.vendor_feeds`     | `[]`; opt-in official Node.js, Python and PHP feeds with bounded article extraction                                                                              |
| `sources.feeds`            | `[]`; up to 30 selected public HTTPS RSS 2.0/Atom URLs, without URL credentials                                                                                  |

Collection is designed to keep making progress. cve.now records that match a package on your list are re-read at every scan; records kept only because a declared product or keyword appears in their text, or because a stored news story cites them, are re-read in turn, 200 per scan, longest unread first. When cve.now or GitHub lists more new records than one scan reads (5,000), the oldest are collected, the scan is reported as incomplete, and the next scan continues from where this one stopped; any request left out by that limit is reported the same way. A package name in a source record that this application cannot normalise is kept as published and matches nothing; it no longer discards the rest of the record. A stored OSV record that the service no longer serves is skipped. A stored cve.now record that the service no longer serves keeps its last known content and counts as checked at that scan; nothing is reported, and a finding that rests on it stays as it was. A stored record that the service serves in a form that cannot be used (a status this application does not know, such as a supersession) is reported as a failed request when it concerns one of your packages, and exclusions drawn from cve.now then become `unknown`; any other stored record keeps its last content. A new cve.now record whose request fails is not lost and cannot hold the source back. On the scan in which it first fails, the scan is reported as incomplete and its checkpoint stays where it was, as for any failed collection, unless that scan listed more than 200 new records (a first scan, or a catch-up after downtime): then the checkpoint moves at once, so that the next scan does not read the same records again. From then on the record is remembered by its identifier and the checkpoint moves on; the record is asked for again on every scan, after all the others. Records left unasked because a scan ended early are remembered the same way. Up to 2,000 records are remembered, the oldest first; when there are more, the checkpoint stops just before the first one that is not, and the next scan finds it in the listing. It is given up on, with a report, one day after its first failure when the service answers with a refusal (such as HTTP 404) or with content that cannot be used, and three days after when the request itself fails (a transport error, HTTP 5xx or "too many requests"). Nothing is given up on while a scan is cut short without a single record read: that is an outage, not a bad record. A listing entry with no usable identifier cannot be asked for by name: it holds the checkpoint for at most one day from when it was first seen and is reported during that time. A checkpoint that lies ahead of the clock (the clock was set back) is treated like a new installation's: the scan looks back one day. A CVE that a stored news story cites and cve.now does not have is asked for again once a day; when it is published it also appears in the listing.

An incomplete cve.now scan does not by itself withdraw version exclusions. When the package lookup, every record it named and every stored record with a package match were read (also on a scan whose listing request failed, and whatever happened to records kept only for a product, a keyword or a citation), the coverage receipt carries `package_results: complete` and a finding that is `not_affected` because of a version range stays so. The gap is still reported and the scan is still degraded. When a record for one of your packages could not be read, exclusions drawn from cve.now become `unknown` until it can.

One scan pages through at most 600 listing pages, about 60,000 records or three months at the current publication rate. If the worker was stopped for longer, the scan reads what was listed, reports the period it could not read, and continues; exact npm package matches still cover all of history.

The cve.now listing is ordered by publication date, newest first. A record the service ingests late keeps its old publication date and so appears below newer records. Each scan therefore reads the listing one week past its checkpoint (about 45 requests at some 600 records a day) and treats a record as new when it was published or first seen inside the window. A record ingested more than a week after its publication date is found only through an exact npm match or a news story that cites it.

A package named only in the text of a news story is matched by how much its name shows by itself:

- **A name that is not an English word** (`axios`, `lodash`, `django`, `webpack`, `left-pad`, `@acme/sdk`) is the package wherever it is written.
- **A name that is an English word** (`entities`, `scheduler`, `immediate`, `express`, `react`, `rails`), a term of security writing (`xss`, `cors`, `rollup`) or a given name (`jason`, `morgan`) is used in its ordinary sense far more often than it names the package. It matches when it is named as a package: followed by "package", "library", "module", "dependency", "gem", "crate" or "plugin" ("the request package", "the requests library"); after a registry and the kind ("the npm package next"); after "called" or "named" ("a dependency called which"); in an install command or with a registry prefix ("npm install send", "pip install requests", "npm:debug"); in a short list before or after a registry and the plural ("Chalk and Debug npm Packages", "the npm libraries colors and faker"); or after the ecosystem's language and what the software is ("the Python framework Tornado"). The word "package" elsewhere in the sentence is not enough: "the packages, which deliver a loader" and "a buffer overflow in the C library" are about other things; when the story names a release (`send@0.19.0`, `debug v4.4`, `Requests 2.32.0`, `Rails 7.2`, `Next.js`, `ExpressJS`), or when it is written as a name: with a capital straight after a lower-case word and not followed by another capitalised word ("a flaw in Express lets"). 63 well-known library names (`express`, `react`, `flask`, `rails`, `electron`, `spring` and others) also count when a capitalised word follows ("a flaw in React Server Components"), when they open a sentence that continues in lower case ("Rails releases patches"), and as the second word of such a sentence ("Critical Rails flaw", "The React team").
- **The commonest words of security prose** (`send`, `buffer`, `request`, `next`, `address`, `config`, `which`, `three`; about 1,700 are built in) match in the same two ways, named as a package or with a release (`send@0.19.0`, `Requests 2.32.0`, `Salt 3007.1`, `Next.js`), but never when they are merely written with a capital.

Some things are deliberately not a match. A bare decimal is not a release ("send 1.5 million requests", "the next 2.5 weeks", "Address 9.8 CVSS bug"), nor is an IP address. A lower-case `config.js` or `server.js` is a file, not a library (`validator.js`, a word that is not among the commonest, is the library). The word "module" is not package context: kernel, PAM and web-server modules are not packages. A capital inside a headline in title case shows nothing. "Salt Typhoon", "Tornado Cash" and "Windows Task Scheduler" are other names. The English words come from a built-in filter of about 197,000 dictionary words and given names (Webster's Second International and the BSD name list); about one name in a hundred that is not a word is taken for one (two or three in a hundred for names ending in -s, -er or -ing), and so are library names that happen to be old dictionary entries (`koa`, `chai`, `pug`); such a name then needs the same context as a word.

Known limits: a name of two characters (`ws`, `qs`, `ip`) matches only as `name@version` or right next to the word "package", "library" or "module"; a scoped or namespaced package is matched by its full name only (`@angular/core`, not "Angular"; `org.apache.logging.log4j:log4j-core`, not "Log4j"), a headline in title case that names an English-word package without a version or a registry ("React, Vue and Angular Apps Exposed") does not match; and a story about a product that shares a package's name (a hosted service called like its client library) does match. Advisories are not affected by any of this: they are matched by their structured package claims. Use a system `keywords` entry when you want a word matched everywhere. A news story is linked to the first 100 advisory identifiers it cites.

`hacker_news` means **The Hacker News** at `thehackernews.com`, the cybersecurity publication, not Y Combinator's Hacker News. Its feed is [The Hacker News RSS](https://feeds.feedburner.com/TheHackersNews). The bot fetches bounded article text only from allowed The Hacker News hosts, without executing scripts: at most 50 articles per scan, four concurrently, with a 2 MB HTML response cap and 16,000 characters of extracted text per article. Evidence records whether full article content, a feed excerpt or unavailable content was used. A failed or capped article fetch retains the feed excerpt and cannot support a new confident AI-only dismissal. Incomplete articles relevant to the inventory create a `hacker_news:articles` monitoring-health finding; the successful RSS collection and its checkpoint are still retained.

Set `sources.vendor_feeds: [nodejs, python, php]`, or choose those names with `init --vendor-feeds`, to enable the official Node.js vulnerability feed, Python release blog and PHP announcements. Each adapter fetches at most 20 eligible articles per scan from its fixed vendor origin, with bounded HTML parsing and 16,000-character text limits. Unsupported links or failed extraction retain an excerpt; relevant incomplete articles produce a health warning. PHP announcements are extracted by their feed anchor so unrelated releases do not become one article. Vendor release dates and later advisory-index publication dates do not prove first vulnerability disclosure.

Additional `feeds` supply titles and summaries/content present in their RSS/Atom response; their article links are not fetched. The bot does not search the web or obtain paywalled content. Choose feed URLs deliberately. Public destinations, DNS results, redirects, response sizes and request durations are checked; a failing source retains its previous checkpoint and cached evidence and produces degraded status.

Malformed individual records are skipped while valid neighboring records continue through collection and assessment. Incomplete collection keeps the previous checkpoint, including when valid records have already been saved. Authentication failures, rate limits, invalid pagination and request bounds can stop the affected source; other sources and notification delivery continue. Cancellation stops further requests.

cve.now's first recent-entry collection looks back one day (about 800 records and 17 minutes when measured on 2026-11-13); later scans use one hour of checkpoint overlap. Exact npm package queries are not limited by this window. Collection is bounded to 600 listing pages and 5,000 advisory records per scan. Historical refreshes are limited to cached records relevant to the current inventory and CVE/GHSA IDs in relevant cached/current news, so unrelated global history does not expand the refresh set forever.

The stack endpoint is queried separately for each deduplicated exact npm package/version pair, at most 1,000 pairs per scan and four requests concurrently. Separate requests preserve matches that cve.now would deduplicate in a multi-package request. Only those pairs are sent, not a lockfile or system/deployment metadata. Limits and request failures report incomplete collection and retain the previous checkpoint. Valid cve.now records collected before a failure are still assessed, and the records named by the exact-package lookup are read even when the listing request fails, so a failed listing request does not discard exact-package matches. Recent-entry pagination cannot guarantee discovery of every update to an older, previously unseen CVE. Structured affected ranges and original advisory descriptions are used as evidence; generated summaries do not establish affectedness. Unsupported statuses, including supersession without verified withdrawal semantics, fail visibly instead of being treated as a resolved vulnerability. This is not exhaustive historical product coverage.

Optional GitHub collection first looks back seven days of modifications; later scans use checkpoint overlap. Optional OSV queries supply existing advisory matches for the declared library inventory. Versionless queries discover candidates but cannot establish installed-version impact. The per-scan limit is 10,000 unique ecosystem/package/version queries. GitHub-only operation is not a full historical vulnerability scan. Pagination and collection have explicit caps; reaching a cap reports an incomplete source rather than an all-clear.

OSV and GitHub CVSS 4.0 vectors contribute validated base severity alongside existing severity labels and numeric scores. Optional threat/environment metrics are preserved for inspection but excluded from the calculated base score; they do not establish exploitation or local deployment facts. `explain` includes bounded `cvss_v4` score/unsupported diagnostics beside source timestamps. See [supported CVSS v4 semantics and limits](cvss-v4-support.md).

For an existing installation, configuration fields set to `true` stay enabled. To switch to cve.now and The Hacker News only, add the two new fields as shown above, explicitly set `osv`, `github` and `kev` to `false`, clear any unneeded additional feeds, and restart the worker. Omitting the old fields now defaults them to `false`; omitting the new fields defaults them to `true`. To run without any network sources, explicitly disable all five source switches and keep both `feeds: []` and `vendor_feeds: []`. Existing cached evidence and history are retained.

References: [cve.now machine-readable API guide](https://cve.now/llms.txt), [The Hacker News](https://thehackernews.com/), [OSV batch queries](https://google.github.io/osv.dev/post-v1-querybatch/), [GitHub global advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories), [CISA KEV data](https://github.com/cisagov/kev-data).

## Model configuration

Before enabling real delivery, [offline rehearsal](offline-rehearsal.md) can replay a bounded sequence of normalized evidence and optional inventory snapshots through the existing policy, queue and simulated delivery transports. It preserves configured channel selection while replacing destinations with in-process sinks, forces models/sources off, and verifies a temporary SQLite backup/restore. The command does not load credentials or open the configured database. Its private report omits raw identifiers, source text and destinations; it does not measure live coverage or model/analyst quality.

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
  daily_token_limit: 1000000
  max_input_chars: 12000
  max_output_tokens: 1500
  timeout_seconds: 45
```

The `verification` entry is optional and must name a different model from `analysis` (another provider, model ID or endpoint): an identical model would only repeat the first answer, so that configuration is rejected. Two entries are identical when they reach the same model ID, compared without regard to letter case, a `models/` prefix or a `:latest` suffix, at the same address in its common spellings: a spelled-out default endpoint, a trailing slash, any way of writing this machine (`localhost`, `127.0.0.1`, `[::1]`) or the `openai-compatible` profile pointed at the same URL does not make them different. It runs for every news analysis, source-critical, exploited, unknown/conflicting findings or when the first model proposes critical priority. It receives the evidence independently; disagreement leaves the result uncertain. Verification failure, exhausted budget or disagreement retains the highest validated proposed priority with an explicit unavailable/conflicting state. `scan --dry-run` disables models and does not spend model budget. Use a normal `scan` without `--notify` to test actual model behavior while persisting budget reservations and findings.

For matched system news, analysis records two distinct conclusions:

- News classification: `new_vulnerability`, `known_vulnerability_update`, `general_news` or `unknown`. A report about an existing CVE, exploitation or a patch is distinct from a newly reported vulnerability; a product announcement or a passing mention is general news.
- Claimed impact on the declared system: `affected`, `not_affected`, `unknown` or `not_applicable`, with cited evidence and an explanation. This is the model's contextual conclusion, separate from authoritative version-range `applicability`; it does not certify the system safe or establish general product-version support.

The model also records affected product names, affected versions and prerequisites from its supporting article quotes. A decisive `affected` or `not_affected` claim requires a known installed target version and source product/version evidence; missing deployment details stay uncertain. The quoted product must match the configured product name. Keywords help find candidate articles but cannot establish product identity, even when two products share a vendor.

For noncritical system news, a validated complete analysis of general news/no applicable vulnerability or no claimed system impact records the article without a vulnerability notification. Generic product findings retain this news analysis even when a cited CVE has been collected; deterministic library applicability remains separate. A new vulnerability or known-vulnerability update with claimed impact follows the configured news/product severity policy. Unknown, conflicting, disabled or unavailable analysis goes to review. Incomplete article/context evidence and stale inventory cannot support a new confident AI-only dismissal. Initial news candidates are held for analysis before notification routing; source-critical and enabled exploitation safeguards still apply.

Completed `general_news`/`not_applicable` classifications remain in history after an article leaves RSS. Changes to the article, inventory, models, prompt or input settings trigger reassessment. This retention rule applies only to general news; `affected` and `not_affected` impact claims still require fresh evidence.

| `ModelSpec` field                                 | Meaning                                                                                                                   |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `provider`                                        | One of the profiles below; use the same fields for analysis and verification                                              |
| `disclosure_profile`                              | `minimal` by default; `deployment-context` explicitly adds the limited deployment fields below, separately for each model |
| `model`                                           | Required model ID available to your account, or an Azure deployment name; there is no default                             |
| `api_key_env`                                     | Optional environment-variable name; defaults to the profile's key variable, never a literal API key                       |
| `endpoint`                                        | Complete API request URL; required for Azure, generic compatible endpoints and local profiles                             |
| `output_format`                                   | `auto` by default; choose `json_schema`, `json_object` or `prompt` when supported                                         |
| `allow_private_endpoint`                          | `false` by default; permits private destinations, and plain HTTP to a private or local host, for the model request        |
| `input_usd_per_million`, `output_usd_per_million` | Optional operator-supplied prices, each between 0 and 10,000                                                              |

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

Plain `http://` is accepted only for a host on this machine or a private network, and only with `allow_private_endpoint: true`. An IP address must be loopback, private (RFC 1918), carrier-grade NAT, link-local, IPv6 unique-local or the unspecified address (`0.0.0.0`, `::`, which reach this machine); an IPv6 address that wraps a public IPv4 address (NAT64, 6to4) is public. A name is accepted when it has no public form: a single label such as `ollama`, a name whose last label cannot be a public domain such as `ollama.ml-tools`, or a name ending in `.localhost`, `.local`, `.internal`, `.intranet`, `.private`, `.corp`, `.lan`, `.home`, `.home.arpa`, `.test`, `.svc`, `.cluster.local` or `.ts.net`. Any other name needs HTTPS. Because a name cannot be resolved when the configuration is read, the request itself is also refused if the name resolves to a public address.

See the [provider registry](https://github.com/ShieldaAI/security-watch/blob/main/src/providers.ts) for endpoint defaults and official API references. `doctor` validates configuration; a live analysis is needed to check account access and the selected model's compatibility. From a source checkout, `node scripts/check-models.mjs --help` describes a bounded synthetic test with separate passed, failed and skipped results. A missing key or model is a skip, never a successful live test.

Set `daily_budget_usd` only after configuring both prices for **every** selected model. Without prices, dollar cost is unknown; request and token allowances still apply. Model calls reserve an allowance before the request: one token per three bytes of the request plus 512, plus the full `max_output_tokens`. The default `daily_token_limit` of 1,000,000 covers the default 100 daily requests at the largest default request size; lower it to cap spending more tightly. Reservations are not provider invoices, are not refunded after a timeout or malformed response, and include verification calls. Daily counters use UTC days. Adding a dollar cap after unpriced calls prevents further billed requests for that UTC day because the prior spend is unknown. There are no automatic model retries or provider fallbacks. Cache hits reuse validated results without a new request reservation. Provider usage and billing remain authoritative.

### Data sent to models

Each analysis and verification model has its own `disclosure_profile`. The default is `minimal`, including when the setting is omitted in existing configurations. A verifier never inherits the first model's disclosure permission. Both use explicit field projections so adding inventory fields cannot expand a provider request.

| Profile              | Inventory fields in the request                                                                                                                                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `minimal`            | Relevant package ecosystem, name and known exact version; relevant product name and known version; request-local opaque component/product IDs; current/stale inventory status; whether the exact target has a known installed version |
| `deployment-context` | All minimal fields plus system environment, exposure and criticality, and only system/product keywords mentioned in the selected evidence, capped at 30 per list                                                                      |

Neither profile sends original system/component IDs, system name, owner, inventory update timestamp, arbitrary configuration, repository/source URLs or revisions, origin, digest, package URLs, SBOM references or graph, provenance, observations, signature/attestation declarations, remediation records or operator identities. These remain available to local assessment and audit. `deployment-context` is an explicit opt-in to the listed fields, including free-text environment and matching keywords. It does not grant access to other inventory metadata. Choose it separately for a trusted local model if cloud providers should receive only minimal inventory.

```yaml
models:
  enabled: true
  analysis:
    provider: openai
    model: your-model-id
    disclosure_profile: minimal
  verification:
    provider: anthropic
    model: your-model-id
    disclosure_profile: minimal
```

Both profiles also send the target event/category and verified aliases, selected evidence identifiers and source labels, titles and bounded source excerpts, explicit package claims, severity/exploitation/withdrawal signals, source dates and context coverage. Evidence text is required for cited analysis and is untrusted data. This policy selects fields, not secrets embedded in permitted package/product names or source text. Review private feeds before enabling cloud analysis. If those fields cannot be disclosed, keep models disabled or select an approved local endpoint. Missing deployment fields mean unknown context and cannot establish that a vulnerability prerequisite is absent.

Up to six evidence records are selected, with authoritative and urgent evidence prioritized. Omitted/truncated context is explicit. Selection is capped at 20 components and 20 products; excess or oversized context fails with an explicit model-context health finding. Partial context or stale inventory cannot support an AI dismissal; unknown relevance enters review. Models receive no tools or notification credentials. The adapter checks that evidence IDs exist and quotes match source text, but these checks cannot establish whether the model interpreted the source correctly.

The `security-watch-10` prompt/cache revision invalidates older analyses. Each cache key includes the normalized disclosure profile and exact projected context; changing a profile or visible installed version cannot reuse the other contract's cached result. Deterministic matching and local priority rules still use the full local inventory when models are off or receive minimal context. The default now omits deployment details that older versions sent, so contextual model judgments may differ. There is no need to opt in to preserve deterministic vulnerability findings.

This setting controls AI requests only. Public cve.now lookups receive npm names/exact versions, optional OSV lookups receive ecosystem/name/version, and notification destinations receive formatted finding context and links under their own configuration. See [the separate disclosure boundaries](../SECURITY.md#data-handling).

## Policy and scheduling

Each `library`, `product` and `news` rule has `levels`, `basis` and `channels`. Malware uses the library rule's destinations. Category defaults select critical libraries and high/critical products/news, but all channel arrays default to empty. A referenced channel requires matching notification configuration.

- `basis: source_severity` filters on source severity. `basis: priority` filters on the higher of source severity and contextual priority. Levels are explicit memberships, not numeric minimums: use `[high, critical]` for both.
- Source severity cannot be lowered by AI. Known exploitation raises contextual priority to at least high; a high advisory affecting an internet-exposed, business-critical system also receives critical contextual priority.
- `urgent_unknown: true` sends potentially critical unknown/conflicting findings immediately, even before affectedness can be established. Other uncertain findings go to a review digest, including uncertainty below the category's immediate levels.
- `exploited_override: true` and `malware_override: true` notify immediately even without a matching severity level. They do not override an empty channel list or a supported `not_affected` decision.
- Confirmed exclusions and all-source withdrawals are retained without new vulnerability notifications. Withdrawal alone does not prove a system safe. Withdrawal disagreement remains conflicting.
- AI distinguishes noncritical system news from vulnerability reports and evaluates claimed system impact before routing; general news and supported AI-only exclusions enter a durable local review queue by default, with a digest when channels are configured. Generic product reports with linked CVEs use this analysis too. Uncertain analysis goes to review. AI cannot suppress source-critical news, an enabled exploitation override or deterministic package urgency by declaring it irrelevant. Advisory-linked package news uses library policy. Multi-advisory articles retain unmatched CVE/GHSA subjects separately until authoritative alias evidence joins them.
- `policy.ai_dismissals: review` is the default. Both complete `general_news/not_applicable` and model-only `not_affected` conclusions require local review, including legacy AI-only irrelevant news. `record` is an explicit opt-out. Deterministic package exclusions, source-critical and enabled exploitation overrides take precedence. See the local review workflow below.
- `health_channels` routes monitoring failures independently from vulnerability thresholds. If every destination fails, inspect local status/logs; the bot cannot notify through an unavailable channel.

`poll_interval_minutes` is an integer from 1 to 1,440, default 15. `inventory_stale_days` is 1–365, default 7; timestamps more than five minutes in the future are also invalid for assessment. `digest_interval_hours` is an integer from 1 to 168, default 24. Digest boundaries are aligned to the Unix epoch in UTC, not a user's timezone. Each Slack/email digest contains at most five findings; additional groups are sent separately.

A notification is one Slack section of at most 2,900 characters, and the same text by email. Every value is on one line behind its label. When a finding has more to say than fits, whole lines are left out from the end of the body (reasons first, then the model's analysis) and the message says `(Message shortened; run explain for the full finding.)`; the fix, the rule that sent the message, the assessment time and up to three source links always close the message, whole. A source link longer than 320 characters is left out, never cut.

`notifications.max_attempts` is 1–10, default 3. Explicit Slack rate-limit/server rejections, transient SMTP rejections and DNS/connection failures known to occur before sending retry with bounded backoff. A Slack timeout after connecting, an interrupted delivery and partial email acceptance become `unknown` instead of automatically risking a duplicate. An SMTP session that ends before the client has written `MAIL FROM` (a silent or dropped greeting, a failed TLS handshake) is retried, because nothing was handed over. `retry DELIVERY_ID` requires an operator to check receipt first. `accepted` means destination acceptance, not human acknowledgement. A one-shot `scan --notify` reports remaining backlog and leaves rate-limited, retry-delayed and future-digest jobs pending; use `start` to drain them when due.

Slack digest groups also respect the message size limit. Entries that do not fit wait for another batch without consuming a send attempt. A malformed saved notification is marked failed while healthy queued work continues. A failed destination does not block another destination. Database errors that prevent reliable queue updates remain fatal; the worker must not claim successful delivery without durable state.

Acknowledgement applies to the current finding revision. Material changes create a new revision. Pass the revision you read, `security-watch acknowledge FINDING_ID --revision N`, to have the command refuse when a newer revision has appeared in the meantime; without `--revision` the current revision is acknowledged and its number is printed. Suppression requires a reason and expiry and remains active until that expiry. `explain FINDING_ID` shows the current policy decision together with acknowledgement and suppression controls, so policy eligibility can be distinguished from an active operator hold. Existing pending deliveries are superseded when the assessment or policy changes. Ordinary alerts keep semantic deduplication. AI dismissal reviews additionally bind the exact reviewed conclusion, evidence content and inventory/model context; changes to that basis create a new review revision. Scan timestamps, unchanged evidence refreshes and JSON object key order do not reopen a review. Rare new advisory aliases can change canonical finding identity; this release does not migrate historical identities automatically.

### Reviewing AI dismissals locally

```yaml
policy:
  ai_dismissals: review
```

This changes the old omitted-setting behavior from quiet recording to review. Existing `review_before_news_suppression: false` is accepted as an explicit legacy alias for `ai_dismissals: record`; `true` maps to `review` and now covers both quiet paths. Conflicting old/new values are rejected. `init` writes the normalized policy. Replace the legacy key with `ai_dismissals` when editing an existing configuration. `status` reports the effective policy. Existing saved findings are enrolled or superseded on the next scan; changing YAML does not rewrite historical verdicts by itself.

```sh
security-watch reviews --limit 100
security-watch reviews --limit 100 --after CURSOR_FROM_PREVIOUS_PAGE
security-watch review FINDING_ID --revision 2 --disposition investigate --reviewer local-operator --reason 'Check the cited version and prerequisites'
security-watch review FINDING_ID --revision 2 --disposition dismiss --reviewer local-operator --reason 'Inspected the article and installed version'
security-watch reviews --all
```

Listing returns the exact finding revision, saved assessment, source IDs/content hashes, queue state and declared reviewer disposition. Pages contain at most 1,000 items, default 100; use the returned cursor for the next page. `status` and `reviews` include pending/investigation counts and the age of the oldest open item. A digest reaching Slack or email never counts as human review. An empty channel list still creates a local queue item. General `acknowledge` or temporary `suppress` controls do not adjudicate the review.

`investigate` records the operator's reason and keeps the item actionable. `dismiss` closes that exact review and acknowledges only its current finding revision, canceling any pending digest for it. These commands send no messages and invoke no model. An already in-flight delivery may still complete. A changed conclusion, source content, installed context or configured model creates a new review revision; a stale verdict is rejected inside a SQLite transaction. Evidence is rechecked at adjudication even if a scan has fetched new source content but has not yet finished reassessment. Source withdrawal, authoritative exclusion, inventory removal or a changed review policy supersedes open obsolete reviews during the scan. No verdict establishes authoritative package safety.

The reviewer is a local operator label, not a separately authenticated account. Access is controlled by OS permissions on the private database and the existing worker/store controls. The label and reason stay in the local database and backups; they are not added to AI provider requests. Schema 6 is applied by `scan` or `start`; read-only and adjudication commands ask for migration first on older stores. Backup verification checks the review table and relationships. Generic retention protects review-bearing finding history and associated evidence, including resolved reviews; it does not yet expire review records. Account for that retained audit data in backup capacity and local access policy.

## Persistence and recovery

Use one local SQLite database per worker. A worker lock prevents concurrent scans; inspection and control commands can run alongside it. The database contains source evidence/checkpoints, assessment history, model caches and reservations, and notification state. It is operationally sensitive. Retention and scheduled backups are disabled until configured.

Keep the database in a trusted local data directory. Database, SQLite sidecar and worker-lock database files must be regular files without links. On Unix systems, they must have no group or other permissions. New files are created privately. If a permission check fails, stop the worker and correct the named file’s permissions before restarting; the application does not change permissions on an active SQLite file.

Database schema 5 adds timestamps and current-evidence hashes for retention without deleting existing data. Legacy cache ages begin at migration time because their original write times are unknown. Stop an older worker and run `scan` or `start` to migrate before using read-only commands from this version. Back up before upgrading operational databases.

`health` checks a worker heartbeat no older than 90 seconds, a completed scan no older than twice the polling interval (at least two minutes), and actionable failed, uncertain or more-than-five-minutes-overdue delivery. A new worker has a two-minute first-scan grace period. Suppressed/acknowledged findings, canceled routes and a valid Slack retry timer are excluded from actionable delivery health. `health --scan-only` omits the worker requirement for externally scheduled scans. Neither command writes data or calls external services; unhealthy monitoring returns exit code 2. A healthy monitor can still have critical affected systems.

`explain` includes each cited source's modification and fetch timestamps. Cached conclusions during a source outage reflect historical evidence; degraded health does not imply those sources were refreshed. Source revisions more than five minutes in the future are rejected without advancing their checkpoint.

Use `backup --output PATH` for a consistent backup at a new destination; the command also verifies a temporary restored copy. Use `verify-backup --input PATH` to inspect an existing standalone snapshot without loading monitor configuration. Do not copy a live SQLite file without its write-ahead log. To restore, stop the worker, preserve the old database and its sidecars, put the verified backup at the configured database path with private permissions, and restart. An interrupted in-flight delivery becomes `unknown` on worker recovery. `unlock` removes stale informational metadata only after acquiring the SQLite worker lock; it never deletes the lock database or interrupts a running worker.

## External heartbeat

```yaml
monitoring:
  heartbeat_url_env: HEARTBEAT_URL
  interval_seconds: 60
  allow_private_endpoint: false
```

This is optional; `init --heartbeat` adds the default environment-variable name to the configuration. Store the endpoint URL in the private credentials file, and configure its service to alert on missed pings. The worker sends a bodyless GET only after a completed scan and while local monitoring health is healthy. Unhealthy scans, delivery problems and maintenance failures withhold success pings; a startup grace period is not a successful scan. The receiver gets request metadata, but no inventory, findings or logs.

Intervals may be 30–3,600 seconds. Requests have a five-second timeout, no redirects and a 4 KiB response cap. Public HTTPS is required unless `allow_private_endpoint: true` explicitly permits a trusted private/local HTTP(S) destination; plain HTTP to an address that is not private or local is refused even then. The URL is not included in recorded status or errors. `status` exposes the last external-heartbeat outcome independently of the local worker heartbeat. An external ping cannot itself notify you that it was never sent; the receiving service must detect that absence.

## Retention and verified backups

Nothing is pruned or backed up automatically unless `maintenance` is configured. For example:

```yaml
maintenance:
  interval_hours: 24
  retention:
    analysis_cache_days: 30
    evidence_history_days: 180
    finding_history_days: 180
    accepted_delivery_days: 180
    inactive_findings_days: 365
    unreferenced_evidence_days: 365
    batch_size: 1000
  backup:
    directory: ./backups
    keep: 7
    max_bytes: 536870912
```

Choose periods for your deployment rather than copying this policy blindly. Omit individual retention fields to leave that category untouched; omit `retention` or `backup` to disable it. Retention periods are 1–3,650 days. `interval_hours` is 1–168, default 24. Once configured, `start` performs scheduled maintenance, including retention; preview the policy before restarting the worker:

```sh
security-watch prune --config ./watch/security-watch.yaml
security-watch prune --config ./watch/security-watch.yaml --apply
```

The first command opens the database read-only and reports a plan. `--apply` recomputes eligibility and deletes one batch atomically. Every deleted row, including dependent history and assessment-basis metadata, counts toward `batch_size` (1–10,000, default 1,000). `more_available` indicates further eligible work. Pruning does not compact the database file; freed pages remain available for SQLite reuse.

Analysis-cache age is measured from its last write. Current evidence revisions are retained unless old evidence is explicitly eligible for unreferenced-evidence cleanup. Active findings, affected or uncertain inactive findings, and pending, sending, unknown or failed delivery records protect their associated history and evidence. Source checkpoints and budget records are never pruned. An inactive finding expires only after supported exclusion, withdrawal or confirmed general-news classification, and only when its audit dependencies are also eligible. Removing a component from inventory alone does not make its finding resolved. These protections can leave data older than the configured periods.

Backup paths are relative to the configuration file. The destination directory must be private. Scheduled backups are verified before older managed snapshots are rotated, and before retention runs when both are enabled. `keep` defaults to 7 and allows 1–365 snapshots. Rotation leaves files outside the application's backup filename pattern untouched. A failed backup or verification prevents cleanup during that maintenance attempt and is recorded as a monitoring problem.

Verification copies a standalone snapshot into a private temporary directory in a separate process. It checks SQLite integrity, supported schema and migrations, foreign-key relationships, saved JSON and scan metadata, then deletes the temporary copy. It never overwrites the source or restores over a live database. It rejects live sidecars, links, oversized inputs and unsupported schemas. This checks structural restorability, not the truth or semantic correctness of saved vulnerability assessments.

The default verification size limit is 512 MiB. Configured backup verification permits up to 20 GiB through `max_bytes`; standalone `verify-backup` uses the default. Verification has a 60-second process limit and needs writable temporary space as well as room for the new backup. For a container with a read-only root filesystem, provide a writable `/tmp` tmpfs with enough capacity. Protect backups as carefully as the live database. Before an actual restore, stop the worker, retain the old database and sidecars, and place a verified snapshot at the configured path with private permissions.

## Model evaluation

From a source checkout, `npm run evaluate:models -- --help` lists the available options. Without `--live`, the script makes no network requests and reports skipped cases; exit code 3 means no cases were attempted. A live run requires provider credentials and exact `SECURITY_WATCH_EVAL_<PROVIDER>_MODEL` environment variables. EVAL settings can fall back to matching SMOKE settings; there is no default model.

The default cap is 20 total requests, 45 seconds per request and 2,048 output tokens. Select cases/providers to fit the cap. Optional verification uses up to two requests per case. Provider charges may apply; a token/request cap is not a dollar budget. Evaluation sends no notifications and uses fictional inventory against source-derived synthetic text.

The versioned corpus includes source references, but its labels remain `pending_human_review`. Reports separate accepted output, attempted coverage, reference-label agreement, false exclusions, rejected outputs and conflicting results. Acceptance measures the production schema/evidence checks, not accuracy. Treat label agreement as a comparison with provisional references; it does not establish production performance. Rejected, skipped and conflicting cases remain visible rather than disappearing from the report.

## Agent deployment evidence, SBOMs and drift

Existing inventory/configuration files continue to work. Systems and components may add
`origin`, `digest` (`sha256:`, `sha384:` or `sha512:` plus lowercase hex),
`provenance: {source, reference?, recorded_at?}` and
`observation: {observed_at, method, reference?}`. Timestamps use ISO 8601 with a timezone.
These fields record operator-supplied evidence; they do not verify a signature, registry,
running process or attestation. System `configuration` accepts up to 100 scalar observations.
Record security settings only, never credentials. Inventory snapshots are persisted in the
private, unencrypted SQLite database and backups.

Optional artifact metadata includes `artifact_kind` (`application`, `library`, `mcp_server`,
`mcp_client`, `plugin`, `skill`, `model`, `container` or `other`), `purl`, `source_url`,
`source_revision`, `sbom_ref` and `dependencies: [{ref, component_id?}]`. A generic model,
MCP server or plugin can be a system with no package components; its kind does not invent
a package ecosystem or version match. Source URLs must be HTTPS without credentials,
query or fragment. References are data and are never fetched. Package URL metadata does
not override the component's declared ecosystem/name/version used by deterministic assessment.

`signature_verification` and `attestation_verification` each accept
`{status: verified|failed|unknown, reference, recorded_at, recorded_by?}`. These are results
recorded by an operator or external verifier, not verification performed by Security Watch.
The importer never turns an SBOM signature into a `verified` status. Component findings
show the component's own verification declaration, not a system signature inherited as
proof for every dependency.

`remediation_evidence` contains at most 100 records per system or component:
`{event_id, stage: proposed|changed|deployed, verification: supported|failed|unknown,
reference, recorded_at, recorded_by?}`. Findings include records matching their event ID
or a known advisory alias under `remediation.operator_records`. They also retain declared
signature/attestation evidence. None of these fields changes deterministic applicability,
closes a finding or asserts a deployment is safe. Retain separate records for proposal,
change, deployment and verification evidence. Required references and dates make a declaration
traceable; they do not authenticate its author. Do not place credentials or secrets in them.

```yaml
systems:
  - id: flow-service
    name: Flow service
    updated_at: '2026-10-28T12:00:00Z'
    sbom: ./deployment.cdx.json
    provenance:
      source: deployment-pipeline
      reference: build-123
    observation:
      observed_at: '2026-10-28T12:00:00Z'
      method: operator runtime inventory
    configuration:
      LANGFLOW_WEBHOOK_AUTH_ENABLE: true
```

`sbom` imports a local CycloneDX JSON 1.4, 1.5 or 1.6 file. The importer is bounded to
20 MiB, 20,000 components and 32 nesting levels. Supported package URLs determine package
identity and exact version; conflicting versions, duplicate references and invalid SHA-256
hashes fail import. SHA-256 component hashes and the input-file digest are retained.
Original package URLs and component references are preserved. Dependency graphs are bounded
to 20,000 source entries, 1,000 targets per entry and 100,000 total edges. The import report's
`dependencies` and inventory system's `sbom_dependencies` retain `{ref, depends_on}` entries.
Imported components also have `dependencies` links with `component_id` when the target can
be resolved. Missing or unsupported targets remain unresolved references with warnings;
relationships from an unknown source are retained with a warning. A declared CycloneDX metadata
root retains its outgoing edges without being treated as a missing package. Duplicate or malformed
references fail import. Dependency edges are declarations, not verified reachability or
transitive affectedness. Explicit `library`, `application`, `container` and machine-learning-model
component types populate artifact kind; names do not establish MCP/plugin trust.
References, scripts, vulnerabilities and remote artifacts in the SBOM are never fetched or
executed. Unsupported ecosystems and missing package URLs are reported as incomplete
inventory, never silently treated as safe. SBOM timestamps do not establish deployment freshness.

Preview without configuration or network access:

```sh
security-watch import-sbom --input ./deployment.cdx.json --output ./import-report.json
security-watch coverage --config ./security-watch.yaml
security-watch inventory-drift --config ./security-watch.yaml
```

The import command creates a new private report file (never overwrites); warnings give exit
code 2. `loadInventory` imports via `sbom` and scans emit monitoring-health findings for import
warnings. Exported APIs include `importCycloneDx`, `compareInventories` and `refreshCoverage`.

Each completed scan compares the inventory with the previous completed scan. Drift reports
additions, removals and changes in identity, version, digest, origin, provenance, environment,
exposure, configuration, artifact/source identity, dependency relationships, declared signature/attestation
results and remediation evidence. `updated_at` and deployment-observation timestamps alone do not create drift. The first scan establishes
a baseline; `inventory-drift` shows the most recent comparison. This compares declarations,
not live processes. Removing a dependency does not establish remediation.

Each configured source produces a coverage receipt containing attempt/last-success times,
expiry, complete/partial/failed collection, evidence count, sanitized errors and collection
scope. `coverage` and `status` recalculate freshness when read. A complete empty query means
that bounded request succeeded, not that the deployment is vulnerability-free. Fixtures
produce no live-source receipts. Stale evidence cannot establish a new version exclusion;
positive historical matches remain visible. Incomplete source coverage also prevents a
current exclusion for findings using that source.

Findings expose `remediation` with cited guidance, relevant configuration observations,
artifact/observation evidence and a review state. An observed version exclusion is still an
operator declaration, not a verified fix. Configuration-dependent guidance is currently
curated for [Langflow webhook authentication](https://github.com/langflow-ai/langflow/security/advisories/GHSA-cf6m-vc3m-7cgm)
and [LangGraph namespace isolation](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-47pj-3jcm-6whg),
plus MCP Python [token audience](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-w4fh-qvv9-3v23),
[redirect handling](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-5h93-6whr-6q8j),
[schema references](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-rwrf-2pqf-9j8j)
and [OpenHands sandbox exposure](https://www.vulncheck.com/advisories/openhands-software-agent-sdk-unauthenticated-sandbox-agent-server-rce),
reviewed on 2026-10-28. These findings remain `review_required`; updating a version or
recording a setting cannot automatically close them. The source-derived fixtures in
`examples/agent-advisories-2026.json` contain selected affected example versions and fixed
capture timestamps, not a complete vulnerability database or live safety assessment.

`examples/agent-advisory-cases-2026.json` separates vulnerable example releases,
vendor-fixed releases with declared good or bad settings, missing versions and
unsupported PyPI ordering. Final release versions within the supported subset can
establish version exclusion; unsupported forms remain `unknown`. Version exclusion
never establishes configuration remediation. MCP audience checks also require verifier output and settings, beyond
the version update. OpenHands remains a product-level finding because the CNA names
the GitHub SDK, not a verified registry package. Declared port/authentication
settings remain review evidence rather than tested deployment security.

### Python version range coverage

PyPI range evaluation uses the pinned, maintained
[`@renovatebot/pep440`](https://github.com/renovatebot/pep440) library, independently
of npm semantics. The supported subset is final numeric releases (for example
`1.29.1`) and comma-separated `==`, `!=`, `<`, `<=`, `>`, `>=` constraints over final
numeric releases. PEP 440 zero-padding equivalence is respected. Input bounds limit
range length, component count and integer size; failures remain `unknown`.

Prerelease, development, postrelease, local and epoch versions, wildcard and
compatible-release constraints, arbitrary equality and invalid/unsupported syntax
remain `unknown` unless an exact positive source match establishes that the installed
version is affected. An unsupported constraint alongside a supported one cannot
establish exclusion. Empty or partial version lists do not establish exclusion either.
Stale inventory, stale evidence and incomplete source coverage retain their existing
uncertainty rules. This is intentionally a supported subset, not full PEP 440 coverage.

The dependency requires Node **24.10.0 or newer**, now the minimum supported runtime.
The lockfile pins version 6.0.0 and its registry integrity digest. No Python runtime
or subprocess is required to evaluate advisories.
