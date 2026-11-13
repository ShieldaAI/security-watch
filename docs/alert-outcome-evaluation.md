# Evaluating alert outcomes

Run the offline regression evaluation from a checkout:

```sh
npm run evaluate:outcomes -- --output alert-evaluation.json
```

It creates a JSON report and exits nonzero on an unsafe or incomplete regression run. No credentials, live provider, source collection or notification delivery are used. CI runs this full command and retains the report for seven days. The regular `npm run check` also tests the grader, negative controls, human-feedback validation and both unsafe routing paths.

## What runs

The [versioned corpus](https://github.com/ShieldaAI/security-watch/blob/main/evals/alert-outcomes/corpus.json) contains 12 original fictional cases across ten advisory families. It includes vulnerable and fixed packages, benign releases, incomplete articles, a provider outage, malicious article instructions, wrong model exclusions, disagreements, critical source evidence and an older flaw with newly observed exploitation. The six reserved cases have later dates and separate families from development cases. They are visible regression fixtures, not a sealed or independently labeled holdout.

Each case runs through production `assess`, optional `ModelAnalyzer`, `decide` and a new in-memory SQLite `Store`. The grader inspects real pending outbox records and local review items. A synthetic Slack route makes notification eligibility observable; no sender is invoked and no webhook is read. The three modes use identical inventory/evidence:

- `deterministic`: normal matching and policy with models disabled.
- `single-model`: the production analyzer receives a bounded, deterministic synthetic model reply.
- `verifier`: the same analyzer runs the configured verifier when production policy requires it, including disagreement and outage behavior.

The default runs two repetitions per case and mode: 72 trials, not 72 independent cases. Each trial resets matching/model cache/outbox/review state. Reports include unique cases/families, repeated outcome consistency, request counts, abstentions, model dispositions and local p95 latency. Synthetic transport cost is zero. Production cost per useful finding, false alerts per inventory/week and population confidence bounds remain unmeasured.

## Reading the scores

| Metric                               | Meaning                                                                                                                    |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `model_false_exclusions`             | A risk case received a model `not_affected` or `not_applicable` opinion. The application may still require review.         |
| `false_dismissals`                   | A must-review or urgent case has no eligible notification and no local review item. This measures the final quiet outcome. |
| `unnecessary_immediate_alert_trials` | A reference-benign case produced at least one immediate outbox notification.                                               |
| `nonactionable_digest_notifications` | Digest records for reference-benign cases. These are reported even when required by the conservative review policy.        |
| `nonactionable_total_notifications`  | Immediate plus digest records for reference-benign cases.                                                                  |
| `urgent_missed_immediate`            | An urgent source sentinel was not immediately delivery-eligible. A later digest is insufficient.                           |
| `review_workload_trials`             | Trials creating a digest or local review item; a trial with both is counted once.                                          |
| `local_review_items`                 | Number of revision-bound AI dismissal review entries. This is separate from digest jobs.                                   |

Rates name their scored denominators. Coverage, incomplete risk counts and all-case safe visibility keep evaluation failures visible; missing rows cannot turn a full gate green. A finding that stays in the digest or local review queue is not a quiet dismissal. Neither an eligible queue record nor a successful evaluation proves actual notification delivery.

The synthetic regression gate requires every corpus case in all three modes for every requested repetition, zero false quiet dismissals, zero unnecessary immediate pages and complete immediate eligibility for urgent sentinels. The always-record control must miss risk cases; the always-alert control must page benign cases. Duplicate, missing, unknown, malformed or altered case/result identities cannot pass. Tests also inject valid structured wrong model answers: false positive answers must actually reach the outbox and fail the gate, while false exclusions become quiet failures when the dismissal-review policy is explicitly disabled.

Benign digest and review burden is reported, with no invented operational threshold. Teams need to calibrate that tradeoff against representative analyst workload. This gate validates deterministic safety/routing behavior; it does not certify model quality or production promotion.

```sh
# Focused diagnostics write a report but exit 1 because the full gate is incomplete.
npm run evaluate:outcomes -- --cases elm-false-exclusion --output focused.json
npm run evaluate:outcomes -- --modes single-model --output focused.json
# Repeats are bounded to 1–5. Increasing them does not add independent evidence.
npm run evaluate:outcomes -- --repeats 3 --output repeated.json
```

Exit codes: `0` full regression pass; `1` unsafe or incomplete matrix; `2` invalid options, input or output destination. Reports omit raw provider payloads and transport errors.

## Independent analyst feedback

Reference labels currently say `agent_authored_pending_human_review`. The importer accepts local analyst declarations bound to the exact corpus and case content. It cannot authenticate analysts or prove they worked independently. Arrange separate blind labeling before preparing the file; do not ask reviewers to copy the seed answers.

Give each analyst an input-only packet containing inventory and evidence, without seed reference labels, replayed model answers, evaluation scores or the other analyst's choices. For example, after building:

```sh
node --input-type=module <<'JS'
import { writeFileSync } from 'node:fs';
import { randomInt, randomUUID } from 'node:crypto';
import { ALERT_CORPUS, alertFixture, digest } from './scripts/evaluate-alerts.mjs';
const packet = { version: 1, cases: [] };
const mapping = { version: 1, corpus_sha256: digest(ALERT_CORPUS), cases: [] };
for (const item of ALERT_CORPUS.cases) {
  const review_id = randomUUID();
  const { inventory, evidence } = alertFixture(item);
  evidence.id = `review-evidence:${review_id}`;
  packet.cases.push({ review_id, inventory, evidence: [evidence] });
  mapping.cases.push({ review_id, case_id: item.id, case_sha256: digest(item) });
}
// Avoid revealing the corpus order as another hint to its semantic case names.
for (let i = packet.cases.length - 1; i > 0; i--) {
  const j = randomInt(i + 1);
  [packet.cases[i], packet.cases[j]] = [packet.cases[j], packet.cases[i]];
}
writeFileSync('private-review-inputs.json', JSON.stringify(packet, null, 2), {
  mode: 0o600, flag: 'wx',
});
writeFileSync('coordinator-only-review-map.json', JSON.stringify(mapping, null, 2), {
  mode: 0o600, flag: 'wx',
});
JS
```

Give analysts only `private-review-inputs.json` and ask them to identify responses by the opaque `review_id`. Keep `coordinator-only-review-map.json` private to the coordinator; semantic case names such as `comet-fixed` and original evidence IDs can reveal the intended label. Collect the two responses separately before comparing them. The coordinator then uses the private map to restore `case_id`, `case_sha256` and the corpus hash when assembling the feedback import below. Never distribute the map or populated import file to analysts before their independent labeling is complete. The repository's source and seed references remain accessible to maintainers, so the importer cannot prove that a reviewer only used this packet.

For each case, two distinct reviewers label authoritative applicability, news classification, expected route, evidence support and risk, with a rationale. Matching categorical choices form a reference. Disagreements remain unresolved until a third distinct analyst supplies an adjudication. IDs are normalized to reject cosmetic duplicates. Unknown cases, changed hashes, invalid labels, conflicting risk/route fields and duplicate records are rejected before evaluation. A single reviewer does not count as a resolved reference.

The file shape below is a template, not submitted human evidence. Replace placeholders with the exact `digest(ALERT_CORPUS)` and `digest(case)` exports from [evaluate-alerts.mjs](https://github.com/ShieldaAI/security-watch/blob/main/scripts/evaluate-alerts.mjs), along with real local reviewer declarations:

```json
{
  "version": 1,
  "corpus_sha256": "<corpus digest>",
  "reviews": [
    {
      "case_id": "parser-vulnerable",
      "case_sha256": "<case digest>",
      "reviewer": "<first analyst>",
      "blinded": true,
      "reviewed_at": "2026-11-05",
      "rationale": "<independent explanation>",
      "label": {
        "risk": "urgent",
        "authoritative_applicability": "affected",
        "classification": "not_applicable",
        "expected_route": "notify",
        "evidence_support": "supported",
        "reason": "<reference explanation>"
      }
    }
  ],
  "adjudications": []
}
```

Add a second review with a distinct reviewer. For a disagreement, add an adjudication with `case_id`, `case_sha256`, `adjudicator`, `reviewed_at`, `rationale` and `label`; the adjudicator must differ from both reviewers. Supported risks are `benign`, `must_review`, `urgent`; their routes must respectively be `no_immediate_alert`, `review_or_notify`, `notify`. Evidence-support values are `supported`, `unsupported`, `uncertain` or `synthetic_source`. Review/adjudication dates use `YYYY-MM-DD`.

```sh
npm run evaluate:outcomes -- --feedback private-feedback.json --output reviewed-evaluation.json
```

Feedback remains local. Reports contain categorical references, feedback/corpus/case hashes, aggregate agreement and label source. Analyst names, free-text rationales and reference notes are omitted. Protect the feedback file itself; it contains that local attribution and reasoning. Partially resolved feedback leaves other cases explicitly agent-authored. Human labels can change grading and make the regression fail; they do not change model responses or runtime policy.

Production readiness is a separate, deliberately false field. The plan still requires at least 100 independently reviewed held-out cases, including 60 risk cases, meaningful separation from development, representative inventory-time exposure and calibrated workload/cost targets. This 12-case seed and replay repetitions do not meet those requirements. Expand and review the corpus before claiming an operational false-dismissal or false-alert rate.

## Reviewing a private package advisory cohort

The checkout includes a [private advisory review driver](https://github.com/ShieldaAI/security-watch/blob/main/scripts/review-advisory-holdout.mjs) for a separate deterministic study. Give it a frozen roster of advisory and deployment pairs, the archived GitHub and OSV records, per-version registry evidence and a review policy. It replays the saved GitHub responses through source ingestion, installed-version matching, routing and a private SQLite outbox. A deployment where no finding was produced stays in the cohort. Each analyst reviews the deployment facts and sources independently before seeing the replay results.

```sh
npm run build
node scripts/review-advisory-holdout.mjs prepare /private/study /private/new-review
node scripts/review-advisory-holdout.mjs score /private/study /private/new-review REVIEWED_ENROLLMENT_SHA256
```

Save the enrollment digest separately when preparing the study. Give reviewers only the evidence, instructions and their respective blank ballots. Collect both completed ballots into a private working copy of the prepared directory for scoring. The scorer checks the original backup, roster, policy, source files and runtime against the enrollment. A third independent person can resolve disagreements using an optional adjudication file supplied after the digest. An unresolved review or incomplete risk sample cannot pass. A passing score establishes the routing result for this cohort. News classification, production model behavior and weekly operator workload require separate samples.

## Existing live model evaluation

`npm run evaluate:models` retains its explicit `--live` opt-in and request/token limits. It now runs each returned assessment through production policy and a fresh local outbox with a synthetic route. Its report separates final false dismissals, unnecessary immediate alerts and benign digest workload. It sends no notifications.

Its exit behavior is stricter: accepted JSON with wrong reference labels or unsafe final outcomes fails. Rejected/conflicting results, request-cap skips and filtered/partial corpus runs cannot return a successful full-corpus gate. Exit `3` means no case was attempted. Its ten historical source-derived reference labels remain pending human review; the live gate is a regression check against those references, not a measured production accuracy claim. This offline milestone did not perform any paid model run.

## Recorded validation

On 5 November 2026, `npm run check` passed formatting, all 723 tests with zero skips and the installed-package consumer checks on Node 26.12.0. All 19 evaluation tests also passed on Node 24.22.1. The exact analyst-packet example was executed in a disposable directory and checked for semantic case IDs and reference/replay leakage.

The full npm command produced the [72-trial report](validation/alert-outcome-evaluation-2026-11-05.json). It records zero final quiet dismissals among 48 risk trials, zero unnecessary immediate alerts among 24 benign trials, and immediate eligibility for all 18 urgent trials. Twelve wrong model exclusion opinions stayed visible through policy/review. The workload remains explicit: 18 benign digest notifications, 44 trials requiring digest or local review, and 16 local review entries. Those categories overlap and must not be added as distinct analyst tasks. All 36 case/mode groups produced consistent outcomes across their two repetitions. These are synthetic observations, not operational accuracy estimates.
