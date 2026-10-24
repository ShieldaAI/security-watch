# Security Watch quality review

Reviewed on 2026-10-24 against the hardening changes on `audit/reliability-hardening`.

**Assessment: 9.0/10 for the documented small-installation alpha implementation.** This is an engineering judgment based on reproduced defects, fixes and verification, not a certification, measured probability of safety, or production-readiness guarantee. The score applies to supported npm inventory, selected advisory/feed sources, optional model analysis and single-host Slack/SMTP monitoring. It does not apply to comprehensive enterprise vulnerability coverage.

## Review rubric

| Area                              | Weight | Score | Evidence and limits                                                                                                                                                                              |
| --------------------------------- | ------ | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Matching and decision correctness | 30%    | 9.2   | OSV range boundaries, multi-advisory grouping, criticality floors, source revision ordering and inventory transitions have outcome regressions. Generic product applicability remains uncertain. |
| Security boundaries               | 25%    | 9.0   | Socket-level destination checks, bounded/cancelable requests, untrusted model context, quote validation, private database files and atomic backups. No independent penetration test.             |
| Reliability and operations        | 20%    | 9.2   | Durable outbox, current-policy dispatch, immediate-alert priority, honest uncertain receipt, shutdown cancellation, heartbeat/freshness/delivery health. No extended production soak.            |
| Installation and maintainability  | 15%    | 9.2   | Clean builds, strict TypeScript, consistent formatting, packaged consumer checks, non-root Linux image and documented recovery/migration.                                                        |
| Deployment validation             | 10%    | 7.8   | Local Node and Linux matrices pass. Hosted CI is blocked by GitHub account billing; real paid providers and real notification destinations were not exercised.                                   |

Weighted result: 9.01, reported as **9.0/10**. Broad production readiness is not rated 9/10 while the deployment-validation gaps below remain.

## Material fixes made during this review

- Pending alerts could outlive inventory exclusions, withdrawals, removals or routing changes. The engine reconciles known changes before yielding to network/AI work, and dispatch checks current policy before external I/O.
- A partly matched multi-CVE article could lose its remaining subjects. Unmatched subjects now remain review candidates until authoritative alias evidence joins them.
- AI irrelevance could suppress urgent news, and truncated/stale context could appear complete. Critical news and configured exploitation overrides survive AI irrelevance; incomplete context remains uncertain.
- A first critical AI proposal could disappear when verification failed or disagreed. The highest validated proposal is retained with explicit unavailable/conflicting status.
- Valid unsorted OSV events and independent limit events could fail collection. Evaluation now follows the [OSV schema algorithm](https://ossf.github.io/osv-schema/).
- Duplicate or far-future source revisions could poison cached state. Newest valid revisions win, future timestamps fail visibly, and unchanged KEV entries no longer create history revisions just because the catalog changed.
- Old digests could delay immediate alerts; pending wording/citations could remain stale. Immediate jobs take priority, and unsent payload updates preserve their schedule and attempt count.
- Linked database files and backup destination races could modify unintended files. File checks reject links; backups publish atomically without replacing an existing destination.
- Early delivery failures were omitted from a one-shot command's final result. Cumulative failures now produce exit code 2.
- Cross-command flags such as `test-notification --dry-run` could be silently ignored. Invalid combinations fail before activity.
- Shutdown could wait through a long source/model scan. Cancellation reaches native HTTP and stops subsequent requests/analysis. Worker and delivery health can be inspected without network calls or state writes.
- Generated build residue could enter a later package. Builds now clean `dist`; package checks verify CLI version, public types, runtime imports, documented files and installation in a fresh consumer.

The review used separate matching/source, HTTP/model, persistence/delivery and orchestration passes. Automated tests support these conclusions; their count alone is not the quality criterion.

## Verification performed

- **222 tests passed** on Node 26.12.0 and Node 24.22.1 locally.
- **222 tests passed** in the Linux Docker test stage on Node 24.22.1.
- `npm run check` passed: formatting, strict compilation, tests, packed CLI installation, public TypeScript declarations and runtime exports.
- The runtime image passed checks with a non-root user, read-only root, network disabled, private configuration, native SQLite volume, repeated scans, monitoring health and backup.
- `npm audit` reported **zero known vulnerabilities** in the dependency graph at review time. This is a registry snapshot, not proof that dependencies are vulnerability-free.
- A persistent-SQLite synthetic load check used 10 deployments, 1,000 declared components, 100 advisories and 1,000 findings. Three scans took 355, 197 and 191 ms locally, with about 184 MiB peak process RSS and no duplicate revisions. This excludes network, model and delivery latency and is not a fleet-scale or endurance benchmark.
- No real Slack/email messages were sent and no paid model calls were made.

## Remaining release and deployment gates

1. Resolve the GitHub account billing lock and obtain successful hosted CI on the reviewed commit. Local checks do not turn an unstarted hosted job into a passing job.
2. Validate the chosen real model IDs and actual notification destinations using synthetic inventory. Model IDs, provider response behavior and destination credentials are deployment-specific.
3. Observe a representative deployment through source outages, recipient failures and multiple scheduled cycles before relying on it operationally.
4. Keep the stated coverage limits: npm evidence does not prove deployment/reachability; products/backports lack authoritative adapters; aliases may change canonical identity; cached conclusions during outages are historical.
5. Plan retention and pagination before increasing scale. Evidence, finding history and model caches are retained; this alpha has no automatic pruning or distributed worker coordination.

Database schema is now 4. Back up an operational database, stop the old worker, and use `scan` or `start` to migrate before running read-only commands with this version. This review does not publish the npm package or merge a release.
