# Review policy decisions from a pilot backup

Use a private standalone Security Watch backup to compare the monitor’s saved decisions with independent analysts’ judgments. A case is one retained, active, non-withdrawn library, product, malware or news finding revision in the chosen window. The same finding can change several times and contribute several cases.

## Prepare the cases

Agree on the window, the expected routing criteria and one canonical reviewer handle per person before looking at results. Retain the original backup, an authoritative snapshot of the deployment inventory and the advisory evidence available during that period. Create a local lookup packet in a private directory.

```sh
security-watch pilot-cases --backup ./backups/watch.db \
  --from 2026-10-20 --until 2026-11-03 --output ./review/cases.json
```

Windows span 1–31 completed UTC days, with an exclusive end date. The command verifies a private temporary copy of the original backup. It includes every eligible retained revision and reports the number of health, retired or withdrawn revisions excluded. Unknown migration timestamps (zero) fall outside the cohort. Empty windows are allowed. A window with over 1,000 total revisions, 32 MiB of retained finding payloads, 256 KiB for one payload or 16 KiB for one decision fails before producing a packet. Use a shorter period when needed. A missing or pruned finding cannot enter the cohort.

**Keep the packet local to authorized analysts.** Each case gives a snapshot-specific opaque case ID, recorded time and the event, system, component and source-evidence identifiers needed for research. These identifiers can reveal private infrastructure. The command requires a new private `.json` output file. It omits model conclusions, assessment prose, policy actions, delivery states, operator verdicts and credentials.

Have two people work separately from the lookup packet, the contemporaneous inventory and the original evidence. Look up the deployment and source content as of the case’s recorded time. A bare evidence ID can belong to several sources or revisions. An empty list is possible. If the analyst cannot verify the relevant historical version or context, choose `abstain`. Keep each analyst blind to the monitor’s decision and to the other analyst’s response until both submit. Keep the source material and each analyst’s rationale in the controlled review system.

## Score the feedback

Copy `packet_id` and the corresponding `case_id` from the packet. Combine the submitted labels into a private UTF-8 JSON file with mode `0600` on Unix. The following schematic shows the accepted fields.

```json
{
  "version": 1,
  "packet_id": "<packet_id>",
  "reviews": [
    { "case_id": "<case_id>", "reviewer": "analyst-a", "blinded": true, "label": "urgent" },
    { "case_id": "<case_id>", "reviewer": "analyst-b", "blinded": true, "label": "must_review" }
  ],
  "adjudications": [{ "case_id": "<case_id>", "adjudicator": "analyst-c", "label": "urgent" }]
}
```

Use `urgent` for an immediate notification, `must_review` for a case that should reach a person, `benign` for one that does not warrant an immediate notification, and `abstain` when evidence is insufficient. A third person can resolve a disagreement after two distinct blinded votes. Agreement needs no adjudication. Enroll one lowercase ASCII handle per person, beginning with a letter and using letters, digits, underscores or hyphens up to 64 characters. The coordinator verifies the people behind those handles and their independence. The scorer validates their declarations, rejects repeated or conflicting identity roles per case and rejects duplicate JSON keys, including alternate escaped spellings.

```sh
security-watch pilot-score --backup ./backups/watch.db \
  --from 2026-10-20 --until 2026-11-03 --input ./review/labels.json \
  --output ./review/aggregate.json
```

The score uses the original backup and dates. IDs bind the exact original file bytes, window and finding revision. Copying the backup byte for byte is supported. Regenerating or modifying the backup requires a fresh packet and new feedback. Input labels are limited to 1 MiB on disk. The command checks that the input is a stable private regular file with a single link. Omit `--output` to print the aggregate JSON. Each file output publishes a complete new private file. Both commands operate locally without configuration, notifications or model requests.

## Interpret a score

`coverage` accounts for every eligible revision across `scored`, `unreviewed`, `single_review`, `unresolved_conflicts` and `abstained`. Agreement, disagreement and adjudication counts add context and overlap those totals. Each policy metric describes **only the scored revisions**, including the numerator, denominator and ratio. A zero denominator yields null.

| Metric                  | Numerator                                                                                                                    | Denominator                             |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `urgent_immediate`      | Urgent revisions whose saved policy selected immediate notification on at least one channel                                  | Scored urgent revisions                 |
| `quiet_risk`            | Urgent or must-review revisions whose policy selected neither a destination for digest/immediate delivery nor a local review | Scored urgent and must-review revisions |
| `unnecessary_immediate` | Benign revisions whose policy selected immediate notification on at least one channel                                        | Scored benign revisions                 |

An urgent revision directed to a digest can miss immediate routing while remaining visible. Counts use the policy decision stored for that revision. Acknowledgments, suppression, retries and destination failures can affect delivery after the decision. Use the [pilot report](pilot-report.md) for retained receipt states and workload. The aggregate score includes dates and counters only. Population urgent recall and delivered false-alert rate remain null. Use [pilot-recall](pilot-recall.md) to include an independently enumerated list of urgent incidents, including events with no matching retained finding. Selective labeling, correlated revisions, retained-history gaps and a small sample all affect how the ratios can be interpreted.

The package also exports `createPilotCasePacket(backup, {from, until})` and `scorePilotCases(backup, {from, until}, feedback)`. Both return promises and use the same verified-copy and grading paths as the CLI.
