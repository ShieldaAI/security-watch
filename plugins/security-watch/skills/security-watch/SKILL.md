---
name: security-watch
description: Checks a project's dependencies for known vulnerabilities and malicious packages with Security Watch (OSV and CISA KEV). Use before adding or upgrading a package, after changing package.json, requirements, go.mod, Cargo.toml or any lockfile, when reviewing a dependency pull request, when asked whether a CVE or GHSA affects the project, or when asked for an SBOM.
license: Apache-2.0
---

# Security Watch: dependency checks

Security Watch reads a project's lockfiles and manifests (npm, Python, Go, Rust, PHP, Ruby, Java,
.NET, Dart, Elixir, Swift, Haskell) or a CycloneDX/SPDX SBOM, and checks the exact versions against
OSV, marking entries in CISA's Known Exploited Vulnerabilities catalog. Each finding names the
package, the installed version, the fixed version and the file it came from.

It sends package names and versions to OSV (api.osv.dev) and nothing else from the project. It
does not run project code. Only `write_sbom` writes a file.

## Use the MCP tools if you have them

| Task                                                            | Tool                                                                                                                            |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Before adding or upgrading a dependency                         | `check_package` with the ecosystem, name and the version you plan to install                                                    |
| After changing dependency files, before handing the change back | `check_dependency_change` with `base: "HEAD"`; on a branch, the branch it merges into with three dots, such as `origin/main...` |
| Overview of the whole project                                   | `check_project_vulnerabilities` (optional `path`, `minSeverity`, `production`)                                                  |
| "Does CVE-X / GHSA-Y affect us?"                                | `check_advisory` with `id`                                                                                                      |
| What the project depends on, and what could not be read         | `list_dependencies`                                                                                                             |
| An SBOM for a customer, compliance or another scanner           | `write_sbom` with `output`, such as `sbom.cdx.json`                                                                             |
| Open findings of a running Security Watch monitor               | `list_watch_findings` (only listed when the user configured one)                                                                |

## Adding or upgrading a dependency

1. Before installing, call `check_package` with the exact version you intend to use. If it reports
   a vulnerability, pick the lowest version at or above the fixed version it gives, and check that
   one too.
2. If it reports **MALWARE** (an OSV `MAL-` record), do not install the package. Tell the user. If
   it is already installed, say so plainly: it should be removed, and any credentials the machine
   or CI could reach should be treated as exposed.
3. Install with the project's own package manager so the lockfile records the exact version.
4. Call `check_dependency_change` with `base: "HEAD"` (after committing, `HEAD~1` or
   `origin/main...`). Report anything it says the change brings in.

A package name you are not sure exists upstream is a risk of its own: look it up in the registry
before installing rather than trusting the name.

## Fixing what a check finds

- Work from the top of the list: malware, then known exploited (CISA KEV), then critical and high.
- Prefer upgrading to the fixed version the finding gives. For a transitive dependency, upgrade the
  direct dependency that pulls it in, or use the ecosystem's override (`overrides` in npm,
  `resolutions` in Yarn, a constraint in pip-tools or Poetry), and say which you used.
- After changing anything, regenerate the lockfile with the package manager, run the project's
  tests, and call `check_dependency_change` again.
- If no fixed version exists, say so, and say what the finding's advisory suggests instead. Do not
  claim a finding is not exploitable unless the user confirms how the package is used.
- Never delete a lockfile to make findings disappear: without it versions are unknown and
  findings move to "check by hand", they are not fixed.

## Reading the result

- `[critical]`, `[high]` ... is the priority: the advisory's severity, raised for known
  exploitation or malware. `[unknown]` with "the advisory gives no severity" is not low: many Go
  and Python advisories carry no score. Treat it like medium and read the advisory.
- "no exact version: check by hand" means the project has a manifest without its lockfile, so the
  installed version is unknown. Suggest committing the lockfile. `check_advisory` reports such a
  package as "MAY be affected", not as affected.
- "INCOMPLETE" at the top means a source failed or a dependency file could not be read, so
  findings may be missing. Say so and name the file; do not report the project as clean.
- "Upgrades that fix several at once" gives one version per package that fixes all its findings
  on that release line (5.2.17, or a later 5.2.x). Prefer it to upgrading one finding at a time.
  Moving to a newer line (6.0) is not checked by that line: check the version you pick with
  `check_package` first.

## Without the MCP tools

Use the command line (Node.js 24.10 or newer). Start it from a folder outside the project and pass
the project's path, so the project's own `.npmrc` or `node_modules` cannot change which tool runs.
The parentheses keep your shell where it was:

```sh
repo="$(git rev-parse --show-toplevel)"
(cd "$(mktemp -d)" && npx --yes @shieldaai/security-watch@1.4.1 check "$repo")
```

- `--base HEAD`: only what the working tree changed compared with that commit;
  `--base origin/main...` compares with the point where the branch left main.
- `--package npm:lodash@4.17.21` (repeat it for several), instead of a project path.
- `--advisory CVE-2021-44906`: does that advisory affect the project.
- `--json` for machine-readable output; `--production` to leave out development dependencies.
- Exit code 1: an installed version affected at or above `--fail-on` (high by default; malware
  and known-exploited always count, an advisory without a severity counts as medium). 2: the check
  is incomplete (a source failed or a dependency file could not be read); never report that as clean.

For an SBOM (the output path is absolute, because the command runs in a temporary folder):
`(cd "$(mktemp -d)" && npx --yes @shieldaai/security-watch@1.4.1 sbom --project "$repo" --output "$repo/sbom.cdx.json")`.

The first run downloads the package from npm, and every check calls api.osv.dev. If your sandbox
blocks network access, ask the user to allow it or to run the command themselves.
