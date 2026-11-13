# Compatibility policy

This page says what you can rely on between releases of `@shieldaai/security-watch` 1.x, and what may change. Versions follow [semantic versioning](https://semver.org/): a major version may break what is listed here, a minor version adds without breaking, a patch version only fixes.

Release candidates (`1.0.0-rc.N`, published under the `next` tag) can still change anything on this page. The policy binds from `1.0.0`.

## What stays stable in 1.x

| Area                   | Stable                                                                                                                                                                         | Not covered                                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| **Configuration file** | Every documented setting of `version: 1` keeps its name, meaning and accepted values. New settings are optional with a default that keeps existing behaviour.                  | Undocumented settings. Validation may reject a value that never worked.                                                       |
| **Inventory file**     | The documented system, component, library and product fields, including `note`, and the library line syntax.                                                                   | The generated `library:` and `sbom:` component IDs.                                                                           |
| **Command line**       | Command names, documented flags, and exit codes: 0 success, 1 error, 2 completed with a degraded or failed part.                                                               | The wording of human-readable messages and help text.                                                                         |
| **JSON output**        | Existing fields of commands that print JSON keep their names and types. Fields may be added.                                                                                   | Field order; fields documented as diagnostic.                                                                                 |
| **Database**           | A database written by any 1.x version opens in every later 1.x version; `scan` or `start` migrates it.                                                                         | Downgrading: restore a backup taken before the upgrade. Reading the SQLite file directly.                                     |
| **Library API**        | The names listed in `scripts/public-api.json` and their published TypeScript declarations.                                                                                     | Anything marked `@internal`, anything imported from a path other than the package root, and the exact text of error messages. |
| **Notifications**      | The `Finding:`, `Delivery:`, `Where to look:` and `Affected item:` lines keep their labels.                                                                                    | Other wording and line order. Do not parse messages; use `findings` or `explain` for data.                                    |
| **Runtime**            | Node.js 24.10 or newer on Linux and macOS. The minimum Node.js version rises only in a minor release, and only to a version that has been in long-term support for six months. | Windows: the private-file permission checks are skipped there and it is not tested.                                           |

## Security decisions are not frozen

Whether a finding applies, how urgent it is and which evidence is accepted will keep improving. A fix that turns a wrong "not affected" into "unknown", or that alerts where an earlier version stayed silent, can arrive in a patch release. Changes that make the monitor quieter by default are announced in the changelog and arrive in a minor release at the earliest.

Model prompts, the prompt version and cached analyses are internal. A release may invalidate cached analyses, which causes findings to be analysed again within the configured budget.

## Deprecations

A setting, flag or export is deprecated in a minor release with a changelog entry and, where possible, a warning from `doctor`. It keeps working until the next major version. Currently deprecated: `policy.review_before_news_suppression` (use `policy.ai_dismissals`), and the positional form of `deliverPending` (pass an options object).

## How this is enforced

- `test/public-api.test.mjs` fails when the exported names differ from `scripts/public-api.json`, when a worker-internal method appears in the published `Store` type, or when the version in `package.json`, the lockfile, `compose.yaml` and `CHANGELOG.md` disagree.
- `scripts/check-package.mjs` installs the packed tarball into an empty project and exercises the CLI, the types and the exports from there.
- Database migrations from every earlier schema are covered by the store and backup tests.
