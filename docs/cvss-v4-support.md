# CVSS v4 source severity

Security Watch now derives **CVSS-B (base) severity** from CVSS 4.0 vectors in OSV and GitHub advisories. This closes a reproduced routing miss: an OSV-confirmed affected package with only the vector below previously had unknown severity and stayed in history under a critical-only library policy. Its base score is 9.3, so it now reaches the configured immediate notification outbox. Tests use synthetic inventory and never deliver the notification.

```text
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

The change applies to OSV top-level and affected-package `severity` entries and GitHub `cvss.vector_string` / `cvss_severities.cvss_v4.vector_string`. Existing source severity labels and numeric scores remain independent floors: the highest supported severity wins. A low vector, invalid vector, or source-supplied threat adjustment cannot lower an explicit critical source rating. Existing CVSS 3.0/3.1 behavior is retained. New scoring is local, with no service request or runtime dependency.

## Supported semantics

The parser validates the entire supplied vector against FIRST's CVSS 4.0 metric table: exact case, fixed metric order, all eleven required base metrics, known metric names and values, and no duplicates. V4 candidates with version/type disagreement are unsupported, including OSV `CVSS_V3` paired with a 4.0 vector and `CVSS_V4` paired with a 3.x vector. Legacy untyped entries remain accepted when the vector itself identifies its version.

Valid threat, environmental and supplemental metrics are retained for inspection but removed before scoring. The calculated score is explicitly **CVSS-B**, even when the supplied vector describes CVSS-BT, CVSS-BE or CVSS-BTE. This avoids treating a publisher's deployment assumptions as observations about the operator's installation. In particular, `E:A` does not set known exploitation, and `E:U` does not lower the base severity. CVSS scoring defaults describe the score calculation; they do not establish a real-world incident or local exposure. Security Watch does not calculate contextual v4 scores.

Scores 0.1–3.9 map to low, 4.0–6.9 medium, 7.0–8.9 high and 9.0–10.0 critical. CVSS's zero/none rating stays `unknown` in Security Watch's existing severity vocabulary; the exact score 0 is retained. Neither zero nor an unsupported vector establishes that a package is unaffected. Package identity/version, withdrawal, source conflicts, inventory age and evidence freshness still determine applicability independently. A stale positive match remains historical affected evidence with a warning; stale exclusion evidence cannot establish `not_affected`.

## Inspection and bounds

Normalized `Evidence.cvss_v4` and `security-watch explain FINDING_ID` expose:

- `base_scores`: distinct validated source vectors, their exact `base_vector`, computed `score`, and `context_removed` flag.
- `unsupported_vectors`: number of rejected v4 candidates in that advisory, including declared-type mismatches. Rejected raw values are not copied into diagnostics.
- The existing `modified_at` and `fetched_at` evidence timestamps, displayed beside these diagnostics, establish source age separately from scoring.

Each vector is capped at 1,024 characters and 32 metrics. An advisory may contain at most 32 v4 candidates, counting repeats and malformed candidates across top-level and package-specific entries. Exceeding that cap rejects the advisory, reports incomplete collection and retains the prior source checkpoint. The collector does not truncate the list and silently discard a possible higher severity. Valid neighboring advisories still continue through the normal incomplete-source behavior.

This metadata is local evidence. It does not expand the model disclosure allowlist. Existing source/enrollment limits still apply: the adapter does not add product backports, reachability, supplier VEX, EPSS or historical coverage.

## Reference, licensing and validation

CVSS is owned by FIRST and used by permission. The reference implementation comes from [FIRST's calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator/tree/c5b0d409ae9f57c44264c6ce5f27d89298e1d32a), pinned to commit `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a`. Original source hashes and adaptations are in [the provenance manifest](vendor/cvss-v4-provenance.json). The [BSD-2-Clause license](vendor/cvss-v4-LICENSE.txt) is retained in both distributed documentation and the compiled vendored module. The project license does not replace this third-party license.

The vendored change concatenates the five calculator/data files, gives browser globals function-local declarations, adds module exports and applies formatting. Scoring equations and lookup data are unchanged. The small wrapper performs validation and explicit base projection. Tests compare fourteen independently published [FIRST examples](https://www.first.org/cvss/v4.0/examples), 512 deterministic vectors scored by the unmodified pinned browser reference, malformed vectors, optional context, boundaries, and ingestion through assessment/policy into a local outbox. Nearby fixed, withdrawn, conflicting, stale and missing-version cases exercise the existing safety rules. These are regression checks, not a representative production accuracy measurement.

The [recorded exhaustive adaptation check](validation/cvss-v4-reference-parity-2026-11-05.json) matched all 104,976 possible base vectors. To repeat it after building, put the original pinned files from the provenance manifest in a directory and run `node scripts/verify-cvss-v4.mjs /path/to/reference-files`. The script verifies every original hash before executing the reference in an isolated JavaScript context, compares every base combination and emits a JSON report with source and executed-module hashes. It makes no network requests. This parity check catches module adaptation mistakes; the separately asserted published examples remain an independent numerical check.

Validation on 5 November 2026: `npm run check` passed all 733 tests with zero skips on Node 26.12.0, formatting and the installed-package consumer. The package check carries v4 evidence through collection, assessment and policy into a local notification outbox. All 74 focused CVSS/source/assessment tests also passed on Node 24.22.1. Neither run sends a notification or invokes a model.

To update the pinned reference, review the upstream diff and license, retrieve the exact pinned files listed in the manifest, verify their hashes, apply only the documented module adaptations, regenerate the reference sample fixture from the unmodified files, and rerun the published examples, full base-vector parity and package checks. Do not regenerate expected scores from the adapted implementation. Review any changed scores against the [FIRST specification](https://www.first.org/cvss/v4.0/specification-document) before accepting them.
