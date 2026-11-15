# Rehearse policy and delivery locally

`security-watch rehearse` runs the normal scan, assessment, SQLite outbox and delivery implementation against a bounded sequence of local evidence snapshots. It uses a new private temporary database and in-process simulated Slack/email sinks. Sources and models are always disabled; it neither opens the configured live database nor loads credentials. This is preparation for a staged pilot, not a production-readiness or model-quality score.

From a checkout after `npm run build`:

```sh
node dist/cli.js init --directory .rehearsal --yes --notifications slack
node dist/cli.js rehearse --config .rehearsal/security-watch.yaml --input examples/rehearsal.json --sink disabled --output rehearsal-disabled.json
node dist/cli.js rehearse --config .rehearsal/security-watch.yaml --input examples/rehearsal.json --sink accepted --output rehearsal-accepted.json
node dist/cli.js rehearse --config .rehearsal/security-watch.yaml --input examples/rehearsal.json --sink unknown --output rehearsal-unknown.json
```

The packaged [example](../examples/rehearsal.json) supplies a fictional inventory in its first frame and repeats one critical advisory. The accepted run produces one simulated accepted Slack delivery; the unknown run keeps one ambiguous receipt with one attempt. Repeating an unchanged scan does not enqueue another delivery. No actual Slack or SMTP connection is made, including during the restore probe. Installed packages expose the same command as `security-watch rehearse`; locate the included example under the installed package's `examples` directory.

The default `--sink disabled` leaves jobs pending. `accepted`, `failed` and `unknown` select a fixed simulated response from both in-process transports. Existing production URL validation, policy checks, digest timing, rate limits and outbox transitions still run. The implementation supplies synthetic credentials through an explicit private map; it does not read or modify environment credentials. `--credentials-file`, `--notify`, remote sinks and arbitrary destinations are not accepted. Original configured policy channels are preserved, so a policy with no channels creates no delivery.

## Scenario contract and bounds

The JSON document is `{ "version": 1, "frames": [...] }`. Every frame has an ISO `at` timestamp and an `evidence` array of normalized evidence objects. An optional `inventory` replaces the preceding inventory snapshot for that and later frames; otherwise the initial inventory comes from configuration. Frame inventories contain materialized systems/components and cannot import a lockfile, libraries file or SBOM. The normal configured inventory loader may read its explicitly configured local imports before rehearsal starts.

Times must increase, stay on or after the Unix epoch and span at most 31 days. The clock advances only to supplied frame times. Rehearsal does not make stale evidence fresh, silently drain a future digest, or infer source completeness from fixture data. Previously retained evidence persists between frames; use an updated withdrawn record to exercise withdrawal. Cross-source collisions on the same evidence ID are rejected. Unknown fields, including model-like replies in evidence, are rejected. CVSS v4 metadata must match its validated base-vector calculation.

Limits are 8 MiB for input and report, 12 frames, 1,000 supplied evidence records in total, 20 systems and 500 component/product/system targets per frame. Each evidence description is at most 16,000 characters; package claims, versions, aliases and other strings are separately bounded. A conservative 100,000 work-unit limit accounts for retained records, package claims and explicit versions against every later frame's targets. Storage stops at 2,000 findings, 4,000 delivery records and 1,000 retained evidence records. Invalid or over-limit inputs fail with content-free errors. Input symbolic links and non-regular files are rejected.

The public API exports `readRehearsal(path)` and `runRehearsal({ config, inventory, scenario, sink })`, plus their scenario/report types. Direct API objects receive the same validation and bounds. Inputs are not mutated. No live-source or AI-shadow mode is available in this command; use the separate offline outcome evaluator for simulated model comparisons.

## Report and recovery evidence

The report exports only fixed field names, enum outcomes, counters, durations and per-run HMAC references. It omits inventory/package names, raw IDs, titles, descriptions, prompts, URLs, addresses, credentials, review notes and filesystem paths. The random HMAC key is never exported and is cleared when the run finishes, so references cannot be joined across runs or guessed by hashing a public package name. Counts, ages and outcomes can still reveal operational patterns; control distribution of the report.

Each frame links fixture ingestion to evidence, findings/revisions, policy decisions and delivery receipts. `retained: false` identifies received older evidence that did not replace the stored revision. All received references remain represented, while finding evidence links point to retained records. `scan_ms` measures only the scan; evidence ages and digest schedules use the supplied scenario clock. Final summary counts describe the last frame, not unique incidents across all frames. Source coverage, AI shadow, urgent recall, false-alert rates and analyst latency are explicitly `null`, since this rehearsal does not measure them.

After the frames, rehearsal closes/reopens the database, takes a real SQLite backup, runs the existing backup verifier, restores a separate copy, and compares evidence, findings/history, review state, controls, budgets and receipts. Opening/restoring never dispatches. With a simulated sink enabled, a separate explicit dispatcher probe checks that accepted, failed and unknown receipts are not retried. Any eligible pending work sent by this probe is counted separately in `recovery.probe_sink_calls`; it does not change the last-frame summary. Disabled delivery skips that probe. This validates fixture recovery, not a backup of the operator's production database.

The temporary database and backup contain local raw inputs while running, use private permissions, and are removed on success or failure; this is cleanup, not a secure-erasure guarantee. The exported report uses private permissions and a new output file, refusing existing files and symlinks. Omitting `--output` prints the same sanitized JSON. No findings or raw delivery bodies are printed on errors.

Before a real rollout, collect independently adjudicated labels, choose a nonproduction inventory, run a separately authorized source/model shadow period, test an approved destination, review representative workload and ambiguous receipts, and obtain analyst sign-off. Those operational gates remain open.

## Recorded validation, 5 November 2026

The complete `npm run check` passed all 746 tests with zero skips on Node 26.12.0, formatting and the clean installed-package check. The package check exercises the installed rehearsal CLI with model-enabled configuration, private canaries, a live-database marker, accepted/unknown sinks, duplicate frames and protected report output. All 72 selected rehearsal, delivery, engine and CVSS tests also passed on Node 24.22.1.

Running the example command above produced an [accepted report](validation/rehearsal-accepted-2026-11-05.json) and an [unknown-receipt report](validation/rehearsal-unknown-2026-11-05.json). Each records two frames, one finding and one simulated send. Repetition and the explicit restored dispatcher produced no additional send. Both reports record successful reopen, backup verification and restore, with zero external requests or deliveries. CI now runs the example and retains its redacted report for seven days.
