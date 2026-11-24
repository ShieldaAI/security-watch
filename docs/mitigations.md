# Temporary mitigations: shields, policies and VEX

A fix takes time to test and roll out. In the meantime a temporary mitigation can block the attack: a runtime shield that blocks one code path ([Shirudo](shirudo.md)), an eBPF policy (Tetragon, KubeArmor), a firewall rule in front of the service, or a live kernel patch. Security Watch does not write, sign or load any of these. It runs nothing on your machines and needs no privileges there, and a mitigation that blocks the wrong thing can take production down. It helps in three ways:

1. **`shield-candidates`** lists the findings worth a mitigation, with what is known for writing one and what is missing.
2. **Mitigation status** shows, in alerts and reports, how many of the hosts running an affected system are covered, read from a file your mitigation tool writes.
3. **`vex`** writes an OpenVEX document so that other scanners know what Security Watch knows.

A mitigation is temporary. Security Watch never closes a finding because of one: the finding stays open until the fix is deployed and the next inventory shows the fixed version.

## What a mitigation needs

A shield or a narrow policy blocks one code path or one kind of request, so someone has to find it first. These help, best first:

1. **The fix itself**: a fix commit or patch link. Its diff shows the vulnerable function.
2. **The package, the installed version and the fixed version.** The difference between the two releases contains the fix, with more noise.
3. **Public exploit code**, to test that the mitigation stops the attack and nothing else.
4. **The weakness type** (CWE) and the conditions for exploitation, to keep it narrow.

A news story that says something is being exploited usually has none of the first three. News alone is therefore never enough: such a finding is listed as `news_only`, with "wait for an advisory".

Security Watch keeps these inputs from the sources it already reads: links with their type from OSV and GitHub advisories (code changes such as commits, pull requests and patches are marked `fix`), fix commits from OSV, CWE identifiers from OSV and GitHub, and Exploit-DB, Metasploit, Nuclei and GitHub proof-of-concept entries from cve.now. Only https links without credentials are kept, at most 40 links, 20 commits and 20 weaknesses per advisory. A link to an advisory database (GitHub's, PyPA's, RustSec, the Go and CVE lists) is never a fix. They are not sent to models and are not part of an advisory's revision, so upgrading creates no new revisions, alerts or analyses. OSV advisories gain them at the next scan; GitHub and cve.now advisories when the source next sends them. `explain` shows them per advisory.

## Shield candidates

```sh
security-watch shield-candidates --config ./watch/security-watch.yaml
```

The command reads the database and changes nothing. By default it lists active findings that are critical, or known or reported to be exploited, and leaves out suppressed ones. A malicious package is never listed: it is removed, not mitigated.

| Option              | Does                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------ |
| `--all`             | Every finding that may affect you, suppressed ones included.                               |
| `--unmitigated`     | Leaves out findings that a current (not out-of-date) status shows mitigated on every host. |
| `--omit-location`   | Leaves out what identifies your systems; use it before handing the list to anyone outside. |
| `--output NEW.json` | Writes the list to a new private file; never replaces one.                                 |

Each candidate has a `readiness`, most ready first:

| Readiness             | Means                                                                                                |
| --------------------- | ---------------------------------------------------------------------------------------------------- |
| `fix_known`           | The installed version is affected, and an advisory links the fix commit or patch.                    |
| `fixed_version_known` | The installed version is affected and a fixed version is published, but no fix link.                 |
| `advisory_only`       | An advisory exists, but the installed version is not confirmed affected (no version, product match). |
| `news_only`           | Only news so far. Wait for an advisory or a vendor bulletin.                                         |

`missing` lists in plain words what is not known yet, for example that no public exploit code is reported, so the mitigation has to be tested against the fix instead. A candidate also carries its identifiers, the package with its installed and fixed versions, `fix_links`, `fix_commits`, other `references`, `weaknesses`, `public_exploit`, EPSS, the advisories it rests on, its `mitigations` status and where to look.

```json
{
  "finding_id": "1e35fbcd…",
  "readiness": "fix_known",
  "missing": [
    "No public exploit code reported by the sources read, so a shield cannot be tested against a real attack; test it against the fix instead."
  ],
  "identifiers": ["CVE-2026-20001", "GHSA-aaaa-bbbb-cccc"],
  "package": { "ecosystem": "Maven", "name": "org.example:parser", "installed": "2.4.1", "fixed": "2.4.2" },
  "fix_links": ["https://github.com/example/parser/commit/abcdef1234"],
  "weaknesses": ["CWE-502"],
  "exploited": true,
  "mitigations": [{ "source": "Shirudo", "summary": "Shirudo: mitigated on 0 of 4 hosts; 4 not mitigated." }]
}
```

**Before you hand the list to an agent or a service outside your network**, add `--omit-location`. Without it the list includes system IDs, names, owners and the notes from your inventory, package URLs with their qualifiers (which can name a private registry), and links to news articles (a feed can be internal). With it, those are left out and a candidate is known by its `finding_id`; advisory identifiers, package names and versions stay, because a mitigation is written from them.

When the inventory cannot be read, a package and its installed version are shown only where an advisory matched exactly one package by version.

## Mitigation status

Each mitigation tool writes a [JSON Lines](https://jsonlines.org/) file on a timer (one JSON object per line), and Security Watch reads it at every scan. Up to ten sources:

```yaml
# watch/security-watch.yaml
mitigations:
  - format: shirudo # Shirudo's node_vulns export; see the Shirudo guide
    file: ./shirudo/node-vulns.jsonl # relative to this file
  - format: generic # anything else
    name: Edge WAF # shown in alerts; default Shirudo or Mitigations; each source needs its own
    file: ./waf/mitigations.jsonl
    max_age_minutes: 60 # 5 to 10080, default 120: an older file is reported, and its status marked out of date
    systems: # optional: the file's system key -> Security Watch system ID
      shop-frontend: web-shop # without an entry, the key is the system ID
```

The generic format has one row per host and finding, and one `none` row for a host with nothing to report, so that it is counted:

```json
{"system_id": "web-shop", "host": "web-1", "identifier": "CVE-2026-20001", "package": "org.example:parser", "status": "mitigated", "mitigation": "waf-rule-42", "expires_at": "2026-12-01T00:00:00Z"}
{"system_id": "web-shop", "host": "web-2", "identifier": "CVE-2026-20001", "package": "org.example:parser", "status": "unmitigated"}
{"system_id": "web-shop", "host": "web-3", "status": "none"}
```

| Field        | Required      | Meaning                                                                                                                                                                                                                                                                                                       |
| ------------ | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `system_id`  | yes           | The system, or a key that `systems` maps to one.                                                                                                                                                                                                                                                              |
| `host`       | yes           | A host, node or instance. The same name in two systems is two hosts.                                                                                                                                                                                                                                          |
| `identifier` | unless `none` | The CVE, GHSA or other advisory identifier.                                                                                                                                                                                                                                                                   |
| `package`    | no            | Needed for a library finding: the package name as Security Watch writes it (Maven `group:artifact`); compared without case, and for PyPI also without `-`, `_`, `.` differences. One CVE can name several packages, so a row without a package applies only to findings without one (products, news, kernel). |
| `kernel`     | no            | `true` for a kernel row: it matches by identifier alone.                                                                                                                                                                                                                                                      |
| `status`     | yes           | `mitigated`, `pending`, `failed`, `excluded`, `withdrawn`, `expired`, `unmitigated`, `unknown` or `none`. Any other value is `unknown`.                                                                                                                                                                       |
| `mitigation` | no            | The rule, policy, shield or patch, named in alerts while it is in place or waiting to load.                                                                                                                                                                                                                   |
| `expires_at` | no            | An ISO time. A `mitigated` or `pending` row past it counts as `expired`.                                                                                                                                                                                                                                      |

Write the file under a temporary name and rename it into place (`mv`), so that a scan never reads half of it: its modification time is the export time.

At each scan, rows are matched to findings by system, by identifier (the finding's own, or a CVE or GHSA alias of one of its current advisories, not one a news article cites) and, for a library, by package name. A status or exposure value this release does not know is read as `unknown` and reported, in case the tool added one. Each host counts once, by its worst row (not mitigated, expired, withdrawn, excluded, failed, unknown, pending, mitigated). Alerts and digests show up to three sources, and `explain`, `findings` and `shield-candidates` show all:

```text
Edge WAF: mitigated on 3 of 4 hosts; 1 not mitigated. (export 2026-11-24 11:55 UTC; a mitigation is temporary and does not close the finding) In place: waf-rule-42
```

When the hosts of a system have no row for a finding, the status says the source lists no such finding there, so nothing is linked to it. That is the most useful line for whoever runs the tool: Security Watch knows of a problem the tool does not.

**The status is shown only.** It does not change applicability, priority or routing. A change in it creates no new revision, re-sends nothing and asks no model for a new analysis. A missing, unreadable or empty file is a monitoring-health error, as a failed source is, and findings then show no status from it rather than an old one. A file older than `max_age_minutes`, or dated in the future, is reported the same way, and its status is marked out of date. Lines that cannot be read are skipped, counted and reported; the rest are used. `doctor` reads every file and names system keys that match no system. Rehearsal (`rehearse`) never reads these files.

Files are limited to 64 MiB and 500,000 rows. Fields are single-line text of at most 512 characters.

## VEX for other tools

```sh
security-watch vex --config ./watch/security-watch.yaml --output security-watch.vex.json
```

`vex` writes an [OpenVEX](https://github.com/openvex/spec) 0.2.0 document for library findings that name an exact package version, so that scanners which read VEX (Trivy, Grype, Docker Scout) and the people reading their reports know what Security Watch knows. It reads the database and the inventory and changes nothing.

| Finding                                             | Statement                                                                                                                                                                      |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Affected                                            | `affected`, with the action: update to the fixed version, or follow the advisory; plus, when a current source shows hosts mitigated, how many, by which source and as of when. |
| Malicious package                                   | `affected`, action: remove it.                                                                                                                                                 |
| Unknown or conflicting                              | `under_investigation`.                                                                                                                                                         |
| Not affected (version outside the published ranges) | Only with `--include-not-affected`: `not_affected`, `vulnerable_code_not_present`.                                                                                             |

A scanner that reads `not_affected` hides the vulnerability from its own report. Security Watch reaches that conclusion from published version ranges, which can be wrong, so it is left out unless you ask for it.

The product is the package URL from your inventory, published with only descriptive qualifiers (`classifier`, `type`, `arch`, `distro`, `os`, `epoch`; others, such as `repository_url`, can name a private registry) and the component's version, or one built from the ecosystem, name and version when the inventory's cannot be read. A package URL whose version is not the component's is left out. The mitigation part of an action names your tool and host counts; `--omit-mitigations` leaves it out. News, product and health findings have no package to point at and are left out; with `--output`, the command says how many were left out and why. `--system ID` limits the document to one system, `--author TEXT` names who stands behind it (default `Security Watch`). The document identifier depends only on the statements, so an unchanged state gives the same identifier on every run. A mitigation never changes a status: a mitigated finding is still `affected`. Checked with Trivy 0.71.2: `trivy sbom --vex security-watch.vex.json your.cdx.json` hides the `not_affected` vulnerabilities and keeps the others.

Statuses are saved at each scan and judged again whenever they are read: `findings`, `explain`, `shield-candidates` and `vex` mark a status out of date (`stale_reason`) when its export is now older than `max_age_minutes`, its source is no longer configured, or a mitigation it counted has expired, so an old status is never shown as current after scans stop.
