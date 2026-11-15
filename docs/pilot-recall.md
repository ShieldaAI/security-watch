# Measure urgent incident recall on a frozen backup

Use `pilot-recall` to measure how often Security Watch observed an independently listed urgent incident, selected immediate notification, and received an acknowledgement from Slack or the SMTP relay before the incident’s deadline. Each rate uses every listed incident as its denominator, including incidents without a retained finding.

## Prepare the reference independently

Before consulting Security Watch findings or alerts, choose a completed UTC date window, the deployments under review, the inclusion criteria for urgent incidents and the expected response interval. Have an independent curator assemble and freeze the complete list for those criteria from incident tickets, dated vendor advisories and contemporaneous deployment inventory. Resolve duplicate events and confirm affected targets, publication or availability times and equivalent identifiers. Keep the source records, manifest and criteria privately for audit. The importer checks the curator’s declaration and relies on the coordinator to verify the curator's independence and the evidence.

Each incident represents one urgent event on one system and optional component. Use a different incident ID for each affected target. A null component matches system-level findings exactly. Include only confirmed equivalent advisory or source event IDs in `event_refs`. Security Watch gives a GHSA priority over a CVE when it groups advisory aliases, so include both when the reference establishes equivalence. CVE and GHSA IDs use the collector’s case normalization. Other IDs and deployment identifiers compare exactly. Finding titles, shared evidence IDs, model text and news mentions never supply event equivalence.

For example, save this synthetic incident reference in a private regular file.

```json
{
  "version": 1,
  "window": { "from": "2026-10-20", "until": "2026-10-21" },
  "curator": "pilot-curator",
  "selected_independently": true,
  "incidents": [
    {
      "incident_id": "reference-001",
      "event_refs": ["CVE-2026-99999", "GHSA-xxxx-yyyy-zzzz"],
      "system_ref": "example-service",
      "component_ref": "example-library",
      "available_at": "2026-10-20T10:00:00.000Z",
      "deadline_at": "2026-10-20T12:00:00.000Z"
    }
  ]
}
```

Use a standalone private backup captured after the window ends. Confirm separately that it belongs to the intended pilot, the monitor was active and retention covers the period. The current schema cannot establish continuous collection, the backup capture time, or the scope of pruned history. Record these checks alongside the source list when interpreting misses.

```sh
security-watch pilot-recall --backup ./backups/watch.db \
  --from 2026-10-20 --until 2026-10-21 \
  --input ./review/urgent-incidents.json --output ./review/recall.json
```

The command verifies a private temporary copy and leaves the standalone backup available for restore. Both window arguments must match the reference. Windows cover 1–31 complete UTC calendar days. Specify canonical ISO UTC instants with milliseconds. Every incident’s response interval must fit inside the window. A revision exactly at `available_at` counts as on time. A revision exactly at `deadline_at` counts as late within the window. The exclusive midnight at `until` falls outside the query. Choosing the window and deadlines before examining results avoids giving missed cases extra time.

## Read the results

`metrics.on_time_observed` counts incidents with at least one qualifying active finding revision recorded within their response interval. `metrics.on_time_immediate` adds the requirement of an in-interval saved `notify` policy decision with an enabled destination. Revisions across different aliases, times and channels earn at most one credit per incident. Multiple records for the same deployment with overlapping event references are rejected. A zero denominator produces a null rate.

| Outcome             | What the backup retained for that target in the requested window               |
| ------------------- | ------------------------------------------------------------------------------ |
| `on_time_immediate` | At least one immediate-policy revision in the response interval                |
| `on_time_other`     | At least one in-interval revision, with other routing throughout that interval |
| `prior_only`        | Matching revisions only before the independently declared availability         |
| `late_only`         | Matching revisions only at or after the deadline                               |
| `prior_and_late`    | Revisions on both sides of the response interval, with none inside it          |
| `no_retained_match` | Zero qualifying revisions with the enrolled event and exact system/component   |

These six counts partition the entire reference. Health, inactive and withdrawn revisions are excluded. A finding first recorded before availability can still earn timely credit from a new in-interval revision. A quiet finding with no change during that interval contributes to `prior_only` if the earlier revision is retained in the query window. A missing match can indicate an unobserved incident, an identifier mismatch, inactive monitoring or incomplete history. Consult the private source material before assigning a cause. The [retained pilot score](pilot-cases.md) measures unnecessary immediate routing on independently labeled benign cases.

### Provider acceptance

`provider_acceptance.on_time` counts each incident once when at least one matching notification receives a qualifying provider response at or after `available_at` and strictly before `deadline_at`. Both immediate alerts and digests qualify. `on_time_immediate` counts only immediate alerts. For example, a digest queued the previous evening and accepted at 10:03 for a 10:00–12:00 incident earns on-time provider credit even if the routing section has zero in-window revisions.

The worker records its local wall clock after Slack returns its expected success response or the SMTP server accepts all configured recipients. A digest batch shares the response time for its included jobs. Partial SMTP acceptance and interrupted sends have an unknown outcome. An acknowledgement records what the service accepted. A separate read receipt or operator record would be needed to measure when a person received, read or acted on a message. `unmeasured.delivered_alert_recall`, population recall and continuous monitoring remain unmeasured.

The scorer joins jobs to their exact finding revision and verifies the saved message identifies the same finding, event, system and optional component. A conflicting target stops the report. It examines every retained job for eligible revisions recorded during the study window. For earlier revisions it includes only jobs with a dated acceptance inside that window. A receipt at or after the exclusive window end still provides evidence of a late acceptance for an in-window revision. `without_retained_job` counts incidents with no job under these selection rules. A previous-day pending job, a pruned job or an earlier revision with an undated acceptance may therefore leave an incident in this group. Interpret the on-time fractions as the share of the full reference with retained confirmation. Missing evidence prevents a conclusion about what the destination actually received for the remaining incidents.

`incidents_with` counts incidents with each kind of retained evidence. One incident may appear in multiple counts when revisions or channels have different outcomes. `before_availability`, `on_time` and `at_or_after_deadline` use the provider acknowledgement clock. `accepted_time_unknown` covers accepted jobs with no timestamp or a clock reading earlier than their own revision. For schema-6 backups the scorer migrates an isolated copy and preserves every original byte. Historical accepted jobs keep their unknown time. `pending`, `sending`, `failed` and `unknown` describe the job state retained at backup time. A later retry can change that state.

`first_acceptance_after_availability` summarizes the delay in milliseconds from external availability to the first dated, retained provider acknowledgement at or after it. The count includes incidents with a late acceptance, and each qualifying incident contributes one delay. An even-sized sample averages its middle pair for the median. The 95th percentile uses nearest rank. Both timings are null for an empty sample. An on-time rate with a zero incident denominator is also null.

## Measure human acknowledgement and triage

For a human-response study, have a reviewer examine independent, timestamped ticket, pager or response records for each enrolled deployment. Agree in advance on the systems of record, the observation cutoff and what counts as human action. An **acknowledgement** is an explicit human acceptance of responsibility for the incident. **Triage** is a human assessment that records an impact determination or next action. Automated ticket creation, delivery acknowledgements and the current state of an AI review queue cannot establish either stage. A person may triage before a formal acknowledgement or arrive through another source.

Generate a private worksheet with the original incident IDs already filled and both stages marked `unreviewed`. The command requires a new output file.

```sh
security-watch pilot-response-template --backup ./backups/watch.db \
  --from 2026-10-20 --until 2026-10-21 --input ./review/urgent-incidents.json \
  --output ./review/responses.json
```

Choose a reviewer separate from the reference curator. Keep the evidence and the mapping from local record handles to original records with the pilot owner. The reviewer fills in their opaque `reviewer` handle, the observation cutoff, and `reviewed_independently: true` after completing their review. The software checks the handle, declaration, timestamps and frozen evaluation ID. The pilot owner verifies who performed the review and whether the sources support each answer. For each stage use the first supported action at or after the incident’s `available_at`. Human activity before availability falls outside this measure. The common, inclusive `reviewed_through` must reach the study window’s exclusive end and cannot be in the future. Use `unresolved` for a stage where source coverage through the cutoff is insufficient.

Fill the stages separately in the private response register. For example, this row records a human acknowledgement and a completed search for triage evidence.

```json
{
  "incident_id": "reference-001",
  "acknowledgement": {
    "status": "observed",
    "at": "2026-10-20T10:12:30.000Z",
    "evidence_ref": "pager-export-row-212"
  },
  "triage": { "status": "no_record", "at": null, "evidence_ref": "triage-ledger-search-014" }
}
```

| Stage status | What the reviewer supplies                                                                                                  |
| ------------ | --------------------------------------------------------------------------------------------------------------------------- |
| `observed`   | The first qualifying UTC timestamp with milliseconds and a private handle for the supporting record.                        |
| `no_record`  | A null timestamp and a private handle for a completed search of the agreed sources through the cutoff.                      |
| `unresolved` | Null timestamp and handle. The reviewer examined this stage but could not establish an outcome.                             |
| `unreviewed` | Null timestamp and handle. The reviewer has yet to examine this stage. An omitted incident has this status for both stages. |

Use a local opaque handle of 1–128 letters, digits, dots, hyphens or underscores starting with a letter or digit. Keep ticket URLs, analyst identities, notes and raw messages in the private source system. A record can support both stages for one incident. For a source covering multiple incidents, identify each target-specific entry with its own handle. A search record may support multiple `no_record` answers.

```sh
security-watch pilot-recall --backup ./backups/watch.db \
  --from 2026-10-20 --until 2026-10-21 --input ./review/urgent-incidents.json \
  --responses ./review/responses.json --output ./review/human-response-score.json
```

For each stage, `on_time` gives the fraction of **all reference incidents** with confirmed action before their deadline. An action exactly at the deadline is late. `reviewed` includes unresolved cases. `resolved` counts observed actions and completed searches that found no record. The five outcome counts partition the reference. A missing record establishes what the reviewer found within the declared source scope. The `first_response_after_availability` median and 95th percentile use only observed timestamps, including late actions, and report their own sample size.

`paired_with_on_time_provider` counts timely provider and human evidence on the same incident. `both` can include human action before the provider response. `provider_only_confirmed` includes incidents where human evidence is unresolved or unreviewed. `human_only_confirmed` and `neither_confirmed` likewise describe evidence available here. These counts establish neither message readership, chronological sequence, nor the role of Security Watch in prompting action.

The `pilot_responses` report includes aggregate counts, timing summaries, window, cutoff, the original recall ID and its own evaluation ID. The latter binds the normalized register to the frozen recall score. A different backup or incident reference requires its own register. Use at most 1,000 response rows in a private file of up to 2 MiB. The programmatic entry point is `scorePilotResponses(backupPath, window, reference, register)`, with exported types `PilotResponseRegister` and `PilotResponseScore`.

## Privacy and limits

The printed report contains the window, aggregate outcomes, denominators and an opaque evaluation ID. This ID binds the normalized external reference and the exact backup and window. Reordering incidents or aliases preserves the ID. Changing input content or choosing a different backup can change it. Keep the reference file private because it contains deployment and incident lookup identifiers. Omit `--output` to print the aggregate JSON or supply a new `.json` file to create an exclusive private report. The scorer runs locally without loading inventory, model credentials or notification settings.

Use up to 1,000 listed incidents, 16 event identifiers per target, and a 1 MiB private JSON input. Use a lowercase ASCII curator handle beginning with a letter, up to 64 characters including digits, underscores and hyphens. The existing [pilot case limits](pilot-cases.md) apply to the combined set of in-window revisions and earlier revisions selected by receipt time. The scorer checks up to 2,000 in-window dated receipts and two jobs per eligible revision. Each examined job payload is limited to 512 KiB, with a 64 MiB combined limit. Oversized inputs, sparse or ambiguous references and duplicate JSON members fail without publishing partial results.

The installed package exports `scorePilotRecall(backupPath, {from, until}, reference)`, `PilotIncidentReference` and `PilotRecallScore`.
