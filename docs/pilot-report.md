# Read pilot activity from a monitor database

Run `pilot-report` after an opted-in pilot has collected data. Choose the existing database and a period of 1–31 complete UTC days. The report counts retained policy decisions, review workload and model reservations during that period. A separate snapshot shows the queue and latest stored monitor health when the report was read. The command runs locally without loading monitor configuration, inventory or credentials.

```sh
security-watch pilot-report --database ./state/watch.db \
  --from 2026-10-20 --until 2026-11-03 --output ./pilot-report.json
```

This example includes October 20 through November 2. Each window starts at midnight UTC on `--from` and excludes midnight on `--until`. Choose today’s UTC date as the end to include all of yesterday. Omitting `--output` prints the same aggregate JSON. File output requires a new `.json` path in an existing directory and publishes a complete private file without replacing an existing file or symbolic link.

Use `--database` for a monitor database. All queries share a single read transaction, so the report sees one consistent state while a worker is committing findings and delivery jobs. It uses SQLite’s read-only mode and runs no migrations or monitor actions. SQLite may create or update its `-wal` and `-shm` coordination files when reading a live **or stopped** WAL database. Leave those files under SQLite’s control.

Use **`--backup` for a standalone backup**. The command verifies a bounded temporary copy, reads that copy and removes it. The original remains a standalone backup suitable for subsequent verification and recovery.

```sh
security-watch pilot-report --backup ./backups/watch.db \
  --from 2026-10-20 --until 2026-11-03 --output ./backup-pilot-report.json
```

Live databases require schema 7. For a schema 6 backup, the reader upgrades its private working copy. Earlier backups lack the full review history required for pilot reporting. Both paths require a private regular file and safe SQLite sidecars where applicable. On Unix, group and other users must have no file permissions. The backup reader rejects sidecars, links and files over 512 MiB. Report generation never loads a credentials file or contacts an advisory source, model, notification destination or heartbeat endpoint.

## Reading a report

| Field                                                | What it measures                                                                                                                                                                                                                                                                |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `activity.finding_revisions` and `distinct_findings` | Retained changes in finding state during the window and the number of distinct finding IDs that changed. An unchanged rescan adds no revision. Health findings and withdrawn or retired revisions count when retained.                                                          |
| `activity.decisions` and `daily`                     | Revision counts by the stored policy action (`notify`, `digest`, `record`). Each day also counts distinct retained evidence revisions by their first recorded fetch time. Zero rows mean the store had no retained revisions for that day.                                      |
| `activity.delivery_states_for_revisions`             | The state when read of each retained per-channel job tied to a finding revision from the window. A later acceptance, failure, retry or ambiguous receipt can change this count. A digest send can cover several jobs.                                                           |
| `activity.reviews`                                   | Reviews opened in the window and review rows whose latest stored operator response occurred in it. The p95 is the nearest-rank duration from review creation to that latest response. It includes a sample count, excludes invalid clock intervals and is null without samples. |
| `activity.model_reservations`                        | Reserved requests, tokens and estimated cost for the selected UTC budget days. An unpriced reservation sets `reserved_usd` to null and leaves the known subtotal and unpriced count visible. Billing records are needed to establish actual spend.                              |
| `snapshot.delivery_states`                           | All retained jobs by their state when read, including jobs for revisions outside the window. Investigate `unknown` receipts locally before retrying.                                                                                                                            |
| `snapshot.reviews`                                   | Counts of pending and under-investigation reviews and, for a monitor database, the age of the oldest open review.                                                                                                                                                               |
| `snapshot.source_coverage` and `last_scan`           | Counts from the latest saved source receipts and the last scan’s available age, duration and degraded status. Freshness is recalculated against report read time for monitor databases. Missing metadata yields null.                                                           |

`snapshot.source` distinguishes a monitor database from a verified backup. A backup holds the last state saved in that copy. Its capture time and later worker activity are unknown, so the backup report leaves oldest-open age, last-scan age and source freshness null. Its retained statuses, scan duration and degraded flag can still be inspected.

Retention may have pruned history. Migrated revisions with timestamp zero are omitted from historical counts. `days_with_retained_revisions` counts days with evidence or finding revisions. Continuous monitoring requires separate historical coverage evidence. An operator may investigate a review and later dismiss it, replacing its previous response timestamp. Consequently the response metric measures the retained latest action for each review revision. The report leaves urgent recall, false-alert rate, source-to-triage p95, monitored days and actual spend explicitly unmeasured. For independently labeled routing metrics from retained revisions, use the [pilot case workflow](pilot-cases.md).

## Privacy and bounds

The report includes aggregate counts, fixed outcome names, requested dates, read time and durations. Raw source text, finding IDs, evidence IDs, names, URLs, review notes, reviewer identities, destination credentials and model prompts stay out of the report and error messages. Counts can still reveal operational volume.

The reader limits each window to 100,000 retained finding revisions and 100,000 retained evidence revisions. Current backlog and receipt queries accept at most 100,000 review rows and 100,000 notification rows across the database. It accepts at most 128 stored source receipts, 1 MiB each of coverage or last-scan metadata and 16 KiB per retained policy decision in the window. Exceeding a limit fails the report and publishes no partial totals.

```js
import { readPilotReport, readPilotBackupReport } from '@shieldaai/security-watch';

const window = { from: '2026-10-20', until: '2026-11-03' };
const monitor = readPilotReport('./state/watch.db', window);
const backup = await readPilotBackupReport('./backups/watch.db', window);
```
