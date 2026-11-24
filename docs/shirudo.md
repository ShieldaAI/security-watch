# Security Watch with Shirudo

[Shirudo](https://shirudo.dev), an open-source project from OpenAI and Cisco announced in November 2026, blocks one vulnerable code path on running Linux machines with signed eBPF programs it calls upatches (shields), without a restart, while the real fix is prepared. Its documented shield types are for the kernel and for Java (JVM) applications. It is pre-release, and production machines need its kernel patches and a TPM 2.0.

The two do different jobs:

- **Security Watch** finds out early that something you run is affected: advisories, the known-exploited catalog, news before a CVE exists, and who has to act.
- **Shirudo** knows which machines run which image, and whether a shield covers them.

```text
Advisories, news, KEV, EPSS ──┐
                              ├──► Security Watch ──► alert to the owner (Slack, email)
Shirudo's SBOM store ─────────┘          │      ▲
     (shirudo-sboms)                     │      └── Shirudo's node_vulns export (mitigations)
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
                 └──► status back in alerts ◄────────────────────┘
                      (mitigated, waiting, exposed)       finding gone, shield withdrawn
```

Security Watch does not write, sign or load shields, and does not connect to Shirudo: it reads files. Setup takes three steps.

## 1. Watch your images: `shirudo-sboms`

Shirudo's backend keeps one CycloneDX SBOM per image build in an SBOM store, at `<image_id>/<image_version>/<root>/sbom.cdx.json`. `shirudo-sboms` copies them into Security Watch's [SBOM folder](sbom.md#the-sbom-folder), one file per image:

```sh
# For an s3:// store, first copy it to a folder: aws s3 sync s3://fleet-sboms ./sbom-store
security-watch shirudo-sboms --store ./sbom-store --directory ./watch/sboms --running ./watch/shirudo/node-vulns.jsonl
security-watch shirudo-sboms --store ./sbom-store --directory ./watch/sboms --running ./watch/shirudo/node-vulns.jsonl --config ./watch/security-watch.yaml --apply
```

The first command prints what it would do and writes nothing; `--apply` writes it. Run the second on the same timer as the export below.

- **The system ID is the image ID**, so it stays the same when a new version rolls out, and a finding is not reported again for every version.
- **With `--running`** (the export of step 3), only images that machines run are watched, with the versions they run. When several versions run at once (a rolling upgrade, a canary), their SBOMs are merged into one, so the old version stays watched until no machine runs it. The note on the system says which versions run on how many hosts. A running version whose SBOM is not in the store yet is named in the plan; the other versions are still watched.
- **Without `--running`**, the newest version of every image in the store is taken (natural order: 2026.11.10 is newer than 2026.11.9).
- **The file's time is the time of the sync**, refreshed at least daily even when nothing changed: the store (and the export) confirm the list is current, so a stable image does not turn stale seven days after it was built. Run the sync on a timer.
- **When a version has several builds** (roots), the most recently stored one is used, and the plan says so.
- **It writes only its own files.** Each file it writes is marked with a property; a file of the same name that it did not write is never replaced, and is reported. An image whose ID another SBOM in the folder already uses as its system ID is not written; with `--config`, the systems described by hand in the inventory are checked too. Files are written compactly under a hidden temporary name and renamed into place, so a scan never reads half of one, and one that would be larger than the 20 MiB a scan reads is not written.
- **It removes a file only when its image is gone**: no machine in a complete export runs it, or, without an export, it is no longer in the store. When an image's SBOMs cannot be read, the store holds no image (not mounted, a failed copy), the export is empty, or a row of the export is unusable, every file is kept as it was, so a scan never loses a system because the sync could not see it. When a running version's SBOM is missing or unreadable, an earlier list is kept rather than replaced by one without that version. A run that would remove more than half of the images it watches removes nothing unless `--allow-removals` is given. Rows of machines bound to no image are skipped without a problem.
- Links (symbolic links) in the store are not followed (an image replaced by one keeps its file), names that are not Shirudo image IDs are ignored, an image ID too long for a file name is reported, and the SBOM folder and the store must be separate folders, neither inside the other. The plan's `problems` list everything left out or kept, and the command then exits with code 2.

Security Watch does not match operating-system packages (deb, rpm, apk); Shirudo's own scan covers those. What it adds for an image is the application libraries inside it, such as the JARs of a Java service, which are also what Shirudo's JVM shields protect. Add owners and notes for these systems by hand if you want them in alerts, in `systems.yaml` beside the folder.

## 2. List the shield candidates

```sh
security-watch shield-candidates --config ./watch/security-watch.yaml --unmitigated --omit-location
```

The list, its readiness levels and the privacy options are described in [shield candidates](mitigations.md#shield-candidates). `fix_known` candidates carry the fix commit, the best input for writing a shield, by hand or with an agent such as Codex. A shield still goes through Shirudo's approval, signing and trial run.

## 3. Show Shirudo's status in Security Watch

Shirudo's backend keeps a `shirudo.node_vulns` table in ClickHouse: one row per machine and finding, with an `exposure` value. Export it to a file on a timer, with the credentials you already use:

```sh
# Every 5 to 15 minutes, from cron or a systemd timer.
clickhouse-client --query "
  SELECT node_id, host_name, toString(status) AS status, image_id, image_version, toString(source) AS source,
         vuln_id, package, installed, fixed, toString(exposure) AS exposure, upatch_id
  FROM shirudo.node_vulns
  FORMAT JSONEachRow" > ./watch/shirudo/node-vulns.jsonl.tmp \
  && mv ./watch/shirudo/node-vulns.jsonl.tmp ./watch/shirudo/node-vulns.jsonl
```

```yaml
# watch/security-watch.yaml
mitigations:
  - format: shirudo
    file: ./shirudo/node-vulns.jsonl # relative to this file
    # max_age_minutes: 120             (default)
    # systems: { fleet-os: web-shop }  (only if an image is watched under another system ID)
```

The same export feeds `shirudo-sboms --running`. Shirudo's words are shown in the shared [mitigation status](mitigations.md#mitigation-status) words:

| Shirudo `exposure`     | Shown as                                             |
| ---------------------- | ---------------------------------------------------- |
| `shielded`             | mitigated                                            |
| `shield_pending`       | mitigation waiting to load                           |
| `shield_module_absent` | mitigation failed to load                            |
| `shield_excludes_node` | mitigation excludes the host                         |
| `shield_withdrawn`     | mitigation withdrawn                                 |
| `exposed_no_shield`    | not mitigated                                        |
| `none`                 | (a machine with no finding, counted among the hosts) |
| anything else          | status unknown                                       |

```text
Shirudo: mitigated on 3 of 4 hosts; 1 not mitigated. (export 2026-11-24 11:55 UTC; a mitigation is temporary and does not close the finding) In place: parser-deser-guard
```

A machine whose `status` is `stale` (it stopped reporting) proves nothing about its shields: its rows count as status unknown. Rows of machines bound to no image (an empty `image_id`) belong to no system and are left out without a warning. When the machines running an image have no row for a finding at all, the status says that Shirudo lists no such finding there. That is common for findings Security Watch learned from news or from an advisory that Shirudo's scanner does not have yet. Link a shield to it in Shirudo's `upatch_fixes` table, or add the kernel advisory to `kernel_vulns`, as its documentation describes.

`doctor` checks the export: that it can be read, how old it is, and which image IDs match no system.

## Limits

- Built from Shirudo's documentation of November 2026 and tested against files in that format, not against a running Shirudo deployment. Shirudo is pre-release and its tables and store layout may change.
- `shirudo-sboms` reads a store in a folder (`file://`); copy an `s3://` store first. It does not read `image.json`, whose fields are not documented.
- Rows are matched to library findings by package name, so Shirudo's `package` column must use the names Security Watch uses (Maven `group:artifact`, as Trivy reports them). A name written differently makes the status say that Shirudo lists no such finding.
- Security Watch does not fill Shirudo's `kernel_vulns` or `upatch_fixes`: it has no kernel version-range matching, and those tables are Shirudo's to change.
- Fix links and exploit entries are only as complete as the advisories. Many have neither.
- `readiness` describes the information available, not whether a shield is possible or safe.
