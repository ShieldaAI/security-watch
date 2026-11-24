---
name: security-watch-setup
description: Sets up continuous vulnerability monitoring with Security Watch, so new advisories and security news about the software a team runs arrive on Slack or email. Use when asked to monitor dependencies over time, get alerts for new CVEs, add an SBOM step to CI, or run the Security Watch monitor with Docker.
license: Apache-2.0
---

# Security Watch: set up monitoring

A one-time check answers "is this affected today". The Security Watch monitor answers "tell me when
something new affects it": it keeps reading advisories (OSV, GitHub, CISA KEV) and security news,
compares them with the systems a team runs, and alerts the owner on Slack or email with where to
look. It runs on the team's own server; their list of systems stays there.

Ask the user before you start: where it should run (a small always-on server, or their laptop to
try it), who should be alerted (Slack webhook or email), and which projects to watch. Credentials
(Slack webhook, SMTP URL, API keys) are the user's to enter: never paste them into files you
commit, and never ask for them in chat. They go in a private `.env` file the user fills in.

## Try it on one project (laptop, no alerts)

```sh
repo="$(git rev-parse --show-toplevel)"
(cd "$(mktemp -d)" && npx --yes @shieldaai/security-watch@1.4.1 init --directory "$HOME/security-watch" --yes --project "$repo")
```

It prints the next commands: `doctor`, then `scan --dry-run`, which shows what it would alert on
without sending anything (run them with the same `npx` prefix, or install the package globally). Add `--notifications slack` (or `email` with `--email-from` and `--email-to`) to `init`
for alerts, and tell the user which variable to set in `~/security-watch/.env`.

## Run it on a server with Docker

The image is `ghcr.io/shieldaai/security-watch:1.4.1` (linux/amd64 and linux/arm64, with signed build provenance). The
repository's `compose.yaml` runs it read-only, without capabilities, with the database in a
volume. Point the user at the README section "Run with Docker" rather than writing your own
compose file: it explains the user and group IDs the volume needs. `docker compose up -d` pulls
the image; `gh attestation verify oci://ghcr.io/shieldaai/security-watch:1.4.1 --repo
ShieldaAI/security-watch` checks first that this repository's release workflow built it.

## Keep the list of systems current from CI

Add the GitHub Action to the project's workflow so every merge sends a fresh SBOM:

```yaml
- uses: ShieldaAI/security-watch@v1.4.1
  with:
    system-id: my-app
    owner: Dana, platform team
    note: runs on cluster eu-1, namespace shop
    upload-url: https://watch.example.com:8787
    upload-token: ${{ secrets.SECURITY_WATCH_INTAKE_TOKEN }}
```

Without `upload-url` the Action only writes the SBOM and keeps it as a workflow artifact. The
receiver and its tokens are set up on the monitor's side (the `intake` section of its
configuration; see `docs/sbom.md` in the repository). Ask the user for the real owner and note:
alerts repeat them, so that whoever receives one knows where to look. Pipelines other than GitHub
Actions run `npx --yes @shieldaai/security-watch@1.4.1 sbom --system-id my-app --upload URL`
with `SECURITY_WATCH_INTAKE_TOKEN` set.

## Do not

- Do not enable model providers, extra news feeds or vendor feeds unless the user asks: each
  sends data to another service. The README section "Boundaries and privacy" lists what goes where.
- Do not run `security-watch start` in the user's terminal as a background job: it is a
  long-running service. Use Docker or the user's process manager.
