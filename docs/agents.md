# Security Watch for AI agents and one-off checks

The monitor tells you when something new affects software you run. Sometimes you need the answer
now, in the project you have open: is anything in here vulnerable, did my upgrade bring something
in, does this CVE concern us, is this package safe to add. `security-watch check` and the MCP
server answer those questions with the monitor's own engine, on an in-memory database: no
configuration, nothing stored.

## What it checks against

- **OSV** (api.osv.dev): every package version is looked up, transitive dependencies included, in
  the 12 ecosystems Security Watch reads. OSV aggregates GitHub's advisory database, PyPA, RustSec,
  the Go vulnerability database and others, and its `MAL-` records name malicious packages.
- **CISA's Known Exploited Vulnerabilities catalog**: findings it lists are marked and sorted first.
- **FIRST EPSS**, only when asked (`--epss`, or `epss: true` in the MCP tools): the estimated
  probability of exploitation in the next 30 days.

News, cve.now, vendor feeds and AI models are monitor features; the one-off checks do not use them.

**What is sent:** package ecosystems, names and versions to OSV, advisory IDs to OSV, and CVE IDs to
FIRST when EPSS is asked for. The KEV catalog is a public file that is downloaded. File contents,
paths and notes never leave the machine.

## On the command line

```sh
npx --yes @shieldaai/security-watch@1.4.1 check                       # the current folder
npx --yes @shieldaai/security-watch@1.4.1 check ./services/api --production
npx --yes @shieldaai/security-watch@1.4.1 check --base origin/main... # only what this branch changed
npx --yes @shieldaai/security-watch@1.4.1 check --package npm:lodash@4.17.21 --package pypi:requests@2.32.4
npx --yes @shieldaai/security-watch@1.4.1 check --advisory CVE-2021-44906
npx --yes @shieldaai/security-watch@1.4.1 check --sbom image.cdx.json   # Trivy, Syft, cdxgen, GitHub
```

- `--json` prints the whole report for scripts.
- `--fail-on critical|high|medium|low|none` sets when the exit code is 1 (default `high`): an
  installed version is affected at or above that level. Malware and known-exploited findings always
  count, except with `none`. An advisory without a severity (common for Go and some Python records)
  counts as medium; it is shown by default and the summary says how many there are. A package
  without an exact version ("check by hand") never fails the check.
- Exit code 2 means the check is incomplete: a source failed, or a dependency file could not be
  read (it is named at the top of the output). A pipeline should treat 2 as a failure too.
- `--base REF` reads the dependency files at that commit straight from git, without checking
  anything out, and reports what the working tree added and what it fixed. `--base REF...` (three
  dots, as in `git diff`) compares with the point where the current branch left REF, so a branch
  that is behind main is not blamed for upgrades made on main since. Both sides are the files git
  knows: submodules, nested repositories and ignored folders are left out. The project must be a
  git checkout that has the commit (fetch it first in CI).
- A package with several findings gets one line with the version that fixes them all.

In CI, `check --base origin/main... --fail-on high` fails a pull request that brings in a high or
critical vulnerability, without blocking on ones that were already there.

## The MCP server

```sh
npx --yes @shieldaai/security-watch@1.4.1 mcp /path/to/project
```

It speaks MCP over stdio (protocol versions 2024-11-05 to 2025-11-25). The project is the
argument, else `CLAUDE_PROJECT_DIR`, else the working folder. If that is a filesystem root or your
home folder (where some hosts start servers), the server asks the client for its roots and uses
the first project folder it names. Every tool's `path` must stay inside the project; links that
lead out are refused.

| Tool                            | What it does                                                                                                                                                                                                                          | Network  | Writes |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ------ |
| `check_project_vulnerabilities` | Every known vulnerability and malicious package in the installed versions, most urgent first, with the fixed version and the file, or the packages of an `sbom` file inside the project. `path`, `minSeverity`, `production`, `epss`. | OSV, KEV | no     |
| `check_dependency_change`       | Compares dependency files at `base` (a git ref) with the working tree: what the change brings in, what it fixes, which packages were added, removed or changed.                                                                       | OSV, KEV | no     |
| `check_package`                 | Up to 50 `packages` (`ecosystem`, `name`, optional `version`) before you add or upgrade them; flags OSV malicious-package records.                                                                                                    | OSV, KEV | no     |
| `check_advisory`                | Looks up a CVE, GHSA, PYSEC, RUSTSEC, GO or MAL identifier, follows its aliases to the records that name packages, and says whether the project is affected, has the package at a safe version, or does not use it.                   | OSV, KEV | no     |
| `list_dependencies`             | Files read, packages per ecosystem, packages without an exact version, files that could not be read; `includePackages` lists them all.                                                                                                | none     | no     |
| `write_sbom`                    | A CycloneDX 1.6 SBOM at `output` inside the project, with optional name, owner, environment, note and exposure. Replaces an existing file only with `overwrite: true` and only if it is an SBOM; never writes into hidden folders.    | none     | yes    |
| `list_watch_findings`           | Open findings of your running monitor: priority, system, owner, fix. Listed only when `SECURITY_WATCH_CONFIG` names its configuration. Reads its database, changes nothing.                                                           | none     | no     |

Results are plain text written for the agent to read and quote. Findings from one session share a
15-minute cache of the KEV catalog and OSV records, so repeated checks are fast; package queries
are always asked again.

Nothing in the server runs project code, installs packages, or changes the monitor's state.
Acknowledging, suppressing and reviewing findings stay in the command line, with a person deciding.

### In Claude Code, Codex, Antigravity and the desktop apps

Install the plugin from [plugins/security-watch](https://github.com/ShieldaAI/security-watch/tree/main/plugins/security-watch): it adds the
server and two skills that tell the agent when to check (before adding a package, after changing
dependency files, when a CVE is in the news) and how to fix findings without hiding them.

### In any other MCP client

```json
{
  "mcpServers": {
    "security-watch": {
      "command": "npx",
      "args": ["--yes", "@shieldaai/security-watch@1.4.1", "mcp", "/path/to/project"]
    }
  }
}
```

Or the container image (with signed build provenance), with the project mounted read-only:

```json
{
  "mcpServers": {
    "security-watch": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v",
        "/path/to/project:/project:ro",
        "ghcr.io/shieldaai/security-watch:1.4.1",
        "mcp",
        "/project"
      ]
    }
  }
}
```

The image has no git, so `check_dependency_change` needs the npm form; `write_sbom` needs the
mount to be writable. It is listed in the MCP Registry as `io.github.ShieldaAI/security-watch`.

Starting npx inside the project lets the project's `.npmrc` choose the registry the checker comes
from. The plugin's launcher avoids that by starting npx elsewhere; in your own configuration, give
the project as an argument (as above) and keep the client's working folder outside it if you can.

## Limits

- A clean result means no OSV advisory matches these exact versions today. It says nothing about
  code that has no advisory yet, and nothing about whether a vulnerable function is reachable.
- Without a lockfile, versions are unknown and findings are listed as "check by hand".
- Operating-system packages in a container SBOM, products and SaaS are not matched by the
  one-off checks: the monitor's news and product matching, or your image scanner, cover those.
- OSV can lag a new advisory by hours. For "is this morning's CVE in our stack", `check_advisory`
  says so when OSV has no record yet.
