# Watch a project from its dependency files

You do not have to write an inventory by hand. Security Watch can read the lockfiles and manifests already in your repository, write them as a CycloneDX SBOM (software bill of materials), and watch every package in it. A pipeline can refresh that SBOM on every build.

- [Start from a project](#start-from-a-project)
- [What is read](#what-is-read)
- [Make or refresh an SBOM](#make-or-refresh-an-sbom)
- [The SBOM folder](#the-sbom-folder)
- [From a CI pipeline](#from-a-ci-pipeline)
- [Receive SBOMs from pipelines](#receive-sboms-from-pipelines)
- [SBOMs from other tools](#sboms-from-other-tools)
- [Use it from code](#use-it-from-code)
- [Limits](#limits)

## Start from a project

```sh
npx @shieldaai/security-watch init --directory ./watch --yes --project ../checkout-api --notifications slack
```

This reads `../checkout-api`, writes `watch/sboms/checkout-api.cdx.json`, and creates a monitor whose inventory is that folder of SBOMs. Repeat `--project` for more projects; each becomes one system. If any package is not an npm package, OSV is turned on, because it is the advisory source that covers the other ecosystems.

Then add the Slack address and start, as in the [README](../README.md#get-started-in-four-steps).

## What is read

| Ecosystem         | Files with exact versions                                                                                | Files with names (and versions where pinned)                   |
| ----------------- | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| npm               | `package-lock.json` (v1 to v3), `npm-shrinkwrap.json`, `yarn.lock` (1 and 2+), `pnpm-lock.yaml` (5 to 9) | `package.json`                                                 |
| Python (PyPI)     | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`, `requirements*.txt` (pinned with `==`)             | `pyproject.toml` (PEP 621, dependency groups, Poetry)          |
| Go                | `go.mod` (with `replace` directives)                                                                     |                                                                |
| Rust (crates.io)  | `Cargo.lock`                                                                                             |                                                                |
| PHP (Packagist)   | `composer.lock`                                                                                          | `composer.json`                                                |
| Ruby (RubyGems)   | `Gemfile.lock`                                                                                           | `Gemfile`                                                      |
| Java (Maven)      | `gradle.lockfile`, `pom.xml` (versions written in the file or its properties)                            |                                                                |
| .NET (NuGet)      | `packages.lock.json`                                                                                     | `*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Packages.props` |
| Dart (Pub)        | `pubspec.lock`                                                                                           | `pubspec.yaml`                                                 |
| Elixir (Hex)      | `mix.lock`                                                                                               |                                                                |
| Swift             | `Package.resolved` (v1 to v3)                                                                            | `Package.swift`                                                |
| Haskell (Hackage) | `cabal.project.freeze`                                                                                   |                                                                |

The whole folder is searched, up to 12 levels deep. Folders that hold installed or generated copies (`node_modules`, `vendor`, `.venv`, `target`, `dist`, `build` and similar), test data (`fixtures`, `testdata`) and hidden folders are skipped. Symbolic links are not followed.

Where a lockfile and a manifest of the same ecosystem sit in one folder, only the lockfile is read. A manifest below a folder with a lockfile (a workspace member) adds only packages the lockfile does not already have. A package that is known only by name is watched by name: Security Watch can find advisories for it, but cannot say whether your version is affected. Commit lockfiles for exact versions.

Development-only dependencies are included and marked `scope: optional`, because a malicious build tool reaches your pipeline even if it never ships. Add `--production` to leave them out where the file says which they are: `package-lock.json`, `package.json`, `pnpm-lock.yaml` 5 and 6, `poetry.lock` (older `category = "dev"`), Poetry dev groups and PEP 735 dependency groups in `pyproject.toml`, `Pipfile.lock`, `composer.lock`, `composer.json`, `pubspec.lock`, `pubspec.yaml`, Maven `test` scope and Gradle test configurations.

Entries that come from Git, a local path or a URL are not on a public registry, so no advisory can name them. They are counted and reported, not watched.

## Make or refresh an SBOM

```sh
security-watch sbom --project ../checkout-api --output ./watch/sboms/checkout-api.cdx.json
```

Without `--output` the SBOM is printed. A summary and any warnings go to the error stream:

```text
checkout-api: 412 packages (PyPI, npm) from 3 files: package-lock.json, services/billing/requirements.txt, services/billing/pyproject.toml.
Wrote /srv/watch/sboms/checkout-api.cdx.json.
```

The command exits with status 1 when it finds no packages, so a pipeline that points at the wrong folder fails instead of publishing an empty SBOM. `--output` replaces an existing file in one step; a monitor reading the folder at that moment sees the old file or the new one, never half of one.

Describe the system with these options. They are written into the SBOM and shown in alerts:

| Option                  | Shown as                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| `--system-id ID`        | The system's ID. Keep it stable: one ID is one monitored system. Default: from the name.    |
| `--name NAME`           | System name. Default: the name in `package.json` or `pyproject.toml`, else the folder name. |
| `--owner TEXT`          | `owner` in the `Where to look` line.                                                        |
| `--note TEXT`           | The system note in the `Where to look` line. In CI the default is `repository OWNER/REPO`.  |
| `--environment TEXT`    | Environment, such as `production`.                                                          |
| `--exposure VALUE`      | `internet`, `internal` or `unknown`.                                                        |
| `--criticality VALUE`   | `low`, `medium`, `high` or `critical`.                                                      |
| `--source-url URL`      | Repository address (HTTPS). Read from GitHub Actions and GitLab CI when not given.          |
| `--source-revision REV` | Commit. Read from GitHub Actions and GitLab CI when not given.                              |

Each package records the files it was found in. An alert says where to look:

```text
Where to look: Checkout API (owner: Dana, platform team) - repository acme/checkout-api
Affected item: npm express 4.21.2 - found in package-lock.json
```

Nothing is installed, executed or downloaded, and no network request is made. The SBOM is a plain file; it leaves your machine only if you send it somewhere.

## The SBOM folder

An inventory can name a folder of SBOMs. Every `.json` file in it is one system:

```yaml
# systems.yaml
sbom_directory: ./sboms # relative to this file
systems: [] # systems you describe by hand can sit beside them
```

- **Each file is read at every scan.** Copy a new SBOM in and the next scan watches it. Remove it and the system is removed (`inventory-drift` shows the change).
- **The SBOM's creation time is the system's `updated_at`.** An SBOM that is no longer refreshed is reported as stale after `inventory_stale_days` (7 by default), exactly like a hand-written list. A file without a timestamp uses the file's modification time.
- **The system ID** comes from the SBOM (`security-watch:system-id`), else from the file name (`checkout-api.cdx.json` is `checkout-api`). An ID already used by another system is reported and that file is not watched.
- **Name, owner, note, environment, exposure and criticality** come from the SBOM properties that `security-watch sbom` writes. For an SBOM from another tool the name is the SBOM's own and the note is the file name.
- **An empty folder** is how a monitor fed by pipelines starts: `doctor` says that nothing is watched yet, and scans report an empty inventory until the first SBOM arrives.
- **A file that cannot be read** is reported as an import warning (`doctor`, and a monitoring-health finding at scan time) and left out; the other systems are still watched.
- **Operating-system packages** (deb, rpm, apk and similar, found in container-image SBOMs) are not matched against advisories. They are listed once as a notice, which does not degrade monitoring. Use your image scanner for them.

CycloneDX JSON 1.4 to 1.6 and SPDX JSON 2.2 and 2.3 are accepted, including GitHub's REST response (`{"sbom": {...}}`). Each file is bounded to 20 MiB and 20,000 packages, and the folder to 1,000 files. For Docker, mount the folder read-only beside the inventory, for example `--mount type=bind,src="$(pwd)/watch/sboms",dst=/config/sboms,readonly`.

## From a CI pipeline

A pipeline makes the SBOM where the code is and sends it to the monitor, which [receives it](#receive-sboms-from-pipelines) into its SBOM folder. The upload is checked exactly as the scanner will read it, so the job fails at once if the SBOM is unusable or the token is wrong. Use the same `--system-id` (or `system-id`) on every run, so each build replaces the previous SBOM of that system.

### GitHub Actions

```yaml
# .github/workflows/sbom.yml
name: SBOM
on:
  push:
    branches: [main]
  schedule:
    - cron: '17 5 * * *' # daily, so a quiet repository is not reported as stale
permissions:
  contents: read
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - id: sbom
        uses: ShieldaAI/security-watch@v1.2.0
        with:
          system-id: checkout-api
          owner: Dana, platform team
          environment: production
          exposure: internet
          upload-url: https://watch.example.com:8787
          upload-token: ${{ secrets.SECURITY_WATCH_INTAKE_TOKEN }}
```

The action writes `security-watch.cdx.json`, sends it to `upload-url`, uploads it as the `security-watch-sbom` artifact, and sets the outputs `sbom-file` and `packages`. Without `upload-url` it only makes and keeps the SBOM, for [delivery another way](#other-ways-to-deliver). It runs Node.js 24 (installing it only if the runner has an older version) and `npx @shieldaai/security-watch`. Pin it to a release tag or a commit. All inputs are listed in [`action.yml`](https://github.com/ShieldaAI/security-watch/blob/main/action.yml).

To use an SBOM made by another tool, pass it as `sbom-file`; the action checks that Security Watch can read it and uploads it:

```yaml
- run: trivy image --format cyclonedx --output image.cdx.json "$IMAGE"
- uses: ShieldaAI/security-watch@v1.2.0
  with:
    sbom-file: image.cdx.json
    system-id: checkout-image
    upload-url: https://watch.example.com:8787
    upload-token: ${{ secrets.SECURITY_WATCH_INTAKE_TOKEN }}
```

### GitLab CI and other pipelines

Any job with Node.js 24.10 or newer can run the command:

```yaml
# .gitlab-ci.yml; SECURITY_WATCH_INTAKE_TOKEN is a masked CI/CD variable
security-watch-sbom:
  image: node:24-slim
  script:
    - npx --yes @shieldaai/security-watch@1.2.0 sbom --system-id checkout-api --output security-watch.cdx.json --upload https://watch.example.com:8787
  artifacts:
    paths: [security-watch.cdx.json]
```

`sbom --upload URL` sends what it made; `security-watch upload --input FILE --url URL` sends an SBOM made by anything else. Both read the token from `SECURITY_WATCH_INTAKE_TOKEN` (or the variable `--token-env` names), retry network errors and busy answers, and exit 1 with the monitor's reason when it refuses. They send to HTTPS addresses only, or plain HTTP to the same machine; `--allow-http` permits plain HTTP elsewhere, which exposes the token to the network in between. Run the pipeline on a schedule as well as on merges (daily is plenty), so that a repository nobody touched for a week is not reported as stale.

## Receive SBOMs from pipelines

Add an `intake` section to `security-watch.yaml`, and `start` receives uploads while it watches:

```yaml
intake:
  listen: 0.0.0.0:8787 # default 127.0.0.1:8787, this machine only
  tls_cert_file: ./tls/cert.pem # relative to this file
  tls_key_file: ./tls/key.pem
  tokens:
    - token_env: SECURITY_WATCH_INTAKE_TOKEN # may upload any system
    - token_env: PAYMENTS_TEAM_INTAKE_TOKEN
      systems: [checkout-api, 'billing-*'] # exact IDs, or a prefix ending in *
```

Create each token with `openssl rand -hex 32` and put it in the credentials file (`.env`) and in the pipeline's secret store. Tokens must be at least 32 characters; `start` refuses to begin without them, and `doctor` reports a missing one. `security-watch intake` runs the receiver alone, for example in its own container beside the monitor.

The receiver accepts `PUT /v1/sboms/SYSTEM_ID` with `Authorization: Bearer TOKEN` and the SBOM as the body. It writes the file as `SYSTEM_ID.cdx.json` (or `.spdx.json`) into the SBOM folder in one step, replacing the system's previous SBOM, and the next scan watches it. `GET /healthz` answers without a token, for load balancers.

| Answer | Meaning                                                                                                                                                                          |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 200    | Stored. The answer lists the packages that will be watched and how many entries were not usable, with examples.                                                                  |
| 400    | The system ID is not 1 to 100 lower-case letters, digits, dots, hyphens or underscores, or the body is empty.                                                                    |
| 401    | No token, or a wrong one. After twenty failures from one address in a minute, further wrong tokens are answered 429 for the rest of that minute; a valid token is always served. |
| 403    | The token may not upload that system.                                                                                                                                            |
| 409    | The SBOM names another system ID, the system is written by hand in `systems.yaml`, or another file in the folder already describes it.                                           |
| 413    | Larger than 20 MiB.                                                                                                                                                              |
| 422    | Not a CycloneDX or SPDX JSON SBOM, or it has no package Security Watch can watch.                                                                                                |
| 503    | Four uploads are already being processed; the client retries.                                                                                                                    |

Every upload and refusal is logged as one JSON line, naming the token's variable and never the token.

**Exposing it.** Listening beyond this machine needs TLS: either the certificate and key above, or `allow_plain_http: true` when a TLS proxy in front of it is the only way in (for example Caddy: `watch.example.com { reverse_proxy 127.0.0.1:8787 }`, with `listen: 127.0.0.1:8787` needing neither). For a certificate from a private authority, give pipelines its root with `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`. Open the port to your CI runners only where you can; the token is the authentication, the network rule keeps everyone else from trying. In Docker, publish the port (`-p 8787:8787`), mount the SBOM folder writable (`--mount type=bind,src="$(pwd)/watch/sboms",dst=/config/sboms`) and pass the token in the environment.

What an upload can change: the SBOM for one system ID the token allows, including the owner and note that alerts show for it. It cannot touch systems written in `systems.yaml`, other files, or the configuration.

### Other ways to deliver

Without the receiver, copy the SBOM into the folder with what you already have:

- **Object storage.** The pipeline uploads, the monitor host syncs every few minutes:

  ```sh
  # in the pipeline
  aws s3 cp security-watch.cdx.json s3://acme-sboms/checkout-api.cdx.json
  # on the monitor host, from cron or a systemd timer
  aws s3 sync --delete s3://acme-sboms ./watch/sboms
  ```

- **A Git repository.** The pipeline commits its SBOM to an `sboms` repository; the monitor host runs `git -C ./watch/sboms pull --ff-only` on a timer.
- **Copy over SSH.** `scp security-watch.cdx.json monitor:/srv/watch/sboms/checkout-api.cdx.json` with a key that may write only there.
- **The same host.** A self-hosted runner writes straight into the folder.
- **Workflow artifacts.** The monitor host fetches the newest artifact: `gh run download --repo acme/checkout-api --name security-watch-sbom --dir ./watch/sboms`.

However it arrives, an SBOM that stops arriving is reported as stale, so a broken pipeline does not look like a quiet week.

## SBOMs from other tools

The importer reads CycloneDX and SPDX JSON as other tools write them; no conversion is needed. Use one when the built-in reader does not see what you run:

| Need                                              | Command                                                                                                                               |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| A container image                                 | `trivy image --format cyclonedx --output app.cdx.json registry/app:1.4` or `syft registry/app:1.4 -o cyclonedx-json=app.cdx.json`     |
| A folder, with Trivy's own lockfile readers       | `trivy fs --format cyclonedx --output app.cdx.json .`                                                                                 |
| Maven versions that come from a parent POM or BOM | `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom` (writes `target/bom.json`)                                                |
| Gradle without dependency locking                 | The CycloneDX Gradle plugin (`cyclonedxBom` task)                                                                                     |
| No tooling at all                                 | GitHub, repository **Insights → Dependency graph → Export SBOM**, or `gh api repos/OWNER/REPO/dependency-graph/sbom > repo.spdx.json` |

Check any SBOM before you rely on it:

```sh
security-watch import-sbom --input app.cdx.json
```

It prints the packages Security Watch will watch and a warning for each one it cannot (exit status 2 when there are warnings).

## Use it from code

```js
import { writeFileSync } from 'node:fs';
import { generateSbom, importSbom } from '@shieldaai/security-watch';

const result = generateSbom({ project: '.', systemId: 'checkout-api', owner: 'Dana' });
writeFileSync('security-watch.cdx.json', JSON.stringify(result.bom, null, 2));
console.log(result.packages, result.ecosystems, result.warnings);

const imported = importSbom('security-watch.cdx.json'); // CycloneDX or SPDX
```

`DEPENDENCY_FILES` lists the files that are read, by ecosystem.

## Limits

- Lockfiles say what a build resolved, not what is deployed or reachable. Generate the SBOM from the commit you deploy.
- Maven versions inherited from a parent POM or an imported BOM are not resolved; those packages are watched by name. `build.gradle` files are not read (use dependency locking or the CycloneDX plugin). `Package.swift` and `pubspec.yaml` without their lockfiles give version ranges only.
- Vendored code, packages copied into the repository, operating-system packages and binaries are not found by the built-in reader; use an image scanner's SBOM for those.
- A project with more than 20,000 packages must be split, for example one SBOM per service with `--project`.
