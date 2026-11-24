# Temporary runtime shields with Shirudo

A fix takes time to test and roll out. A runtime shield blocks the vulnerable code path on running machines in the meantime, without a restart. [Shirudo](https://shirudo.dev), an open-source project from OpenAI and Cisco announced in November 2026, does this on Linux with signed eBPF programs it calls upatches. Its documented shield types are for the kernel and for Java (JVM) applications. It is pre-release, and production machines need its kernel patches and a TPM 2.0.

Security Watch and Shirudo do different jobs:

- **Security Watch** finds out early that something you run is affected: advisories, the known-exploited catalog, news before a CVE exists, and who has to act.
- **Shirudo** knows which machines run which image, and whether a shield covers them.

Security Watch does not write, sign or load shields. It runs nothing on your machines and needs no privileges there, and a shield that blocks the wrong code path can take production down. Writing a shield is a job for a person or an agent, and approving it is the operator's, with Shirudo's own signing and trial-run steps.

```text
Advisories, news, KEV, EPSS ──┐
                              ├──► Security Watch ──► alert to the owner (Slack, email)
Your SBOMs (CI, image store) ─┘          │
                                         ▼
                      shield-candidates: critical or exploited findings,
                      with what is known for writing a shield
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
   Person or agent writes and tests a shield         The real fix, started at once
                 ▼                                               │
   Approval, signing, Shirudo trial run, then block              ▼
                 │                                       Fix deployed, new SBOM
                 └──► Shirudo status back in alerts ◄────────────┘
                      (shielded, waiting, exposed)        finding gone, shield withdrawn
```

## What a shield needs

A shield blocks one code path, so someone has to find that code path first. These help, best first:

1. **The fix itself**: a fix commit or patch link. Its diff shows the vulnerable function.
2. **The package, the installed version and the fixed version.** The difference between the two releases contains the fix, with more noise.
3. **Public exploit code**, to test that the shield stops the attack and nothing else.
4. **The weakness type** (CWE) and the conditions for exploitation, to keep the shield narrow.

A news story that says something is being exploited usually has none of the first three. News alone is therefore never enough: such a finding is listed as `news_only`, with "wait for an advisory".

Security Watch keeps these inputs from the sources it already reads: links with their type from OSV and GitHub advisories, fix commits from OSV, CWE identifiers from OSV and GitHub, and Exploit-DB, Metasploit, Nuclei and GitHub proof-of-concept entries from cve.now. Only https links without credentials are kept. They are not sent to models, and they are not part of an advisory's revision, so upgrading creates no new revisions, alerts or analyses. OSV advisories gain them at the next scan; GitHub and cve.now advisories when the source next sends them.

## 1. Give Security Watch your images' SBOMs

Shirudo's backend keeps one CycloneDX SBOM per image in an SBOM store, at `<image_id>/<image_version>/<root>/sbom.cdx.json`. Copy the newest version of each into the [SBOM folder](sbom.md#the-sbom-folder) under the image ID, so that the system ID is the image ID:

```sh
# A file:// store; for an s3:// store, first run: aws s3 sync s3://fleet-sboms ./sbom-store
STORE=./sbom-store
DEST=./watch/sboms
for image in "$STORE"/*/; do
  id=$(basename "$image")
  version=$(ls "$image" | sort -V | tail -n 1)
  for sbom in "$image$version"/*/sbom.cdx.json; do
    cp "$sbom" "$DEST/$id.cdx.json.tmp" && mv "$DEST/$id.cdx.json.tmp" "$DEST/$id.cdx.json"
    break
  done
done
```

Security Watch reads CycloneDX 1.4 to 1.6. It does not match operating-system packages (deb, rpm, apk); Shirudo's own scan covers those. What it adds for an image is the application libraries inside it, such as the JARs of a Java service, which are also what Shirudo's JVM shields protect.

The layout above is taken from Shirudo's documentation of November 2026. Check it against your store.

## 2. List the shield candidates

```sh
security-watch shield-candidates --config ./watch/security-watch.yaml
```

The command reads the database and changes nothing. By default it lists active findings that are critical, or known or reported to be exploited, and leaves out suppressed ones; `--all` lists every finding that may affect you. A malicious package is never listed: it is removed, not shielded. `--output NEW.json` writes the list to a new private file and never replaces one.

Each candidate has a `readiness`, most ready first:

| Readiness             | Means                                                                                                |
| --------------------- | ---------------------------------------------------------------------------------------------------- |
| `fix_known`           | The installed version is affected, and an advisory links the fix commit or patch.                    |
| `fixed_version_known` | The installed version is affected and a fixed version is published, but no fix link.                 |
| `advisory_only`       | An advisory exists, but the installed version is not confirmed affected (no version, product match). |
| `news_only`           | Only news so far. Wait for an advisory or a vendor bulletin.                                         |

`missing` lists in plain words what is not known yet, for example that no public exploit code is reported, so the shield has to be tested against the fix instead. A candidate also carries its identifiers, the package with its installed and fixed versions, `fix_links`, `fix_commits`, other `references`, `weaknesses`, `public_exploit`, EPSS, the advisories it rests on, the Shirudo status (below), and where to look.

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
  "runtime_shield": { "summary": "Shirudo: shielded on 0 of 4 nodes; 4 exposed with no shield." }
}
```

**Before you hand the list to an agent or a service outside your network**, add `--omit-location`. Without it the list includes system IDs, names, owners and the notes from your inventory, package URLs with their qualifiers, and links to news articles. With it, those are left out (a candidate is then known by its `finding_id`); advisory identifiers, package names and versions stay, because they are what a shield is written from.

## 3. Show Shirudo's status in Security Watch

Shirudo's backend keeps a `shirudo.node_vulns` table in ClickHouse: one row per machine and finding, with an `exposure` value. Security Watch does not connect to ClickHouse. Export the table to a file on a timer instead, and point Security Watch at the file:

```sh
# Every 5 to 15 minutes, from cron or a systemd timer, with the credentials you already use.
clickhouse-client --query "
  SELECT node_id, host_name, image_id, image_version, toString(source) AS source,
         vuln_id, package, installed, fixed, toString(exposure) AS exposure, upatch_id
  FROM shirudo.node_vulns
  FORMAT JSONEachRow" > ./watch/shirudo/node-vulns.jsonl.tmp \
  && mv ./watch/shirudo/node-vulns.jsonl.tmp ./watch/shirudo/node-vulns.jsonl
```

```yaml
# watch/security-watch.yaml
shirudo:
  exposure_file: ./shirudo/node-vulns.jsonl # relative to this file
  max_age_minutes: 120 # an older file is reported to monitoring health; default 120
  image_systems: # optional: Shirudo image ID -> Security Watch system ID
    fleet-os: web-shop # without an entry, the image ID is the system ID
```

The file's modification time is the export time, so write it with the temporary name and `mv` shown above. At each scan Security Watch matches the rows to findings by image (the system), by advisory ID (the finding's identifier or any CVE or GHSA alias of its advisories) and, for a library, by package name. A kernel row matches by identifier alone. Each machine counts once, by its worst row. Alerts, digests, `explain`, `findings` and `shield-candidates` then show, for example:

```text
Shirudo: shielded on 3 of 4 nodes; 1 exposed with no shield. (export 2026-11-24 11:55 UTC; a shield is temporary and does not close the finding) Shield: parser-deser-guard
```

| Shirudo `exposure`     | Shown as                           |
| ---------------------- | ---------------------------------- |
| `shielded`             | shielded                           |
| `shield_pending`       | shield waiting to load             |
| `shield_module_absent` | shield cannot load (module absent) |
| `shield_excludes_node` | shield excludes the node           |
| `shield_withdrawn`     | shield withdrawn                   |
| `exposed_no_shield`    | exposed with no shield             |
| anything else          | status unknown                     |

`Shield:` names up to three shields that are in place or waiting to load; a withdrawn one is not named. When the machines running a system have no row for a finding at all, the status says that Shirudo lists no such finding there, so no shield is linked. That is common for findings Security Watch learned from news or an advisory that Shirudo's scanner does not have yet. Link a shield to it in Shirudo's `upatch_fixes` table, or add the kernel advisory to `kernel_vulns`, as its documentation describes.

**The status is shown only.** It does not change applicability, priority or routing. A change in it creates no new revision, re-sends nothing and asks no model for a new analysis. A shielded finding stays open until the fix is deployed and the next SBOM shows the fixed version. A missing, unreadable or empty export is a monitoring-health error, as a failed source is, and findings then show no status rather than an old one. An export older than `max_age_minutes` is reported the same way, and its status is marked out of date. Lines that cannot be read are skipped, counted and reported; the rest are used.

## Limits

- Built from Shirudo's documentation of November 2026 and tested against files in that format, not against a running Shirudo deployment. Shirudo is pre-release and its tables may change.
- Rows are matched to library findings by package name, so Shirudo's `package` column must use the names Security Watch uses (Maven `group:artifact`, as Trivy reports them). A name written differently makes the status say that Shirudo lists no such finding.
- Security Watch does not fill Shirudo's `kernel_vulns`: it has no kernel version-range matching.
- Fix links and exploit entries are only as complete as the advisories. Many have neither.
- `readiness` describes the information available, not whether a shield is possible or safe.
