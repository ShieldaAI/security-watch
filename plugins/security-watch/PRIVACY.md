# Security Watch plugin: privacy

Last updated: 24 November 2026. Applies to the Security Watch plugin and the
`@shieldaai/security-watch` package it runs.

Shielda receives nothing from this plugin. It has no account, sends no usage data and keeps no
record of what it checked.

- **What it reads:** dependency files (lockfiles and manifests such as `package-lock.json`,
  `requirements.txt`, `go.mod`, `Cargo.lock`, `pom.xml`) in the project you have open, git objects
  of those files when it compares your changes with a commit, and an SBOM file when you point it
  at one. With `SECURITY_WATCH_CONFIG` set, it also reads your Security Watch monitor's
  configuration and database. It reads nothing else.
- **What it sends, and to whom:**
  - **OSV** (`api.osv.dev`, run by Google's open-source security team): the ecosystem, name and
    version of each package it checks, and the advisory IDs it looks up. This is how it knows
    which advisories apply. OSV's own terms cover that request.
  - **CISA's Known Exploited Vulnerabilities catalog**, a public file downloaded from
    `raw.githubusercontent.com`. Nothing about your project is sent.
  - **FIRST** (`api.first.org`), only when the agent asks for EPSS scores: CVE IDs.
  - Every request carries what any HTTPS request carries (your IP address, a user agent).
  - File contents, file paths, system names, owners, notes and your monitor's findings are never
    sent.
- **Network to start it:** npm downloads the pinned package from the npm registry in your npm
  settings (`registry.npmjs.org` by default), under the registry's own privacy terms.
- **What it writes:** only an SBOM file, when the `write_sbom` tool is called, at the path given,
  inside the project. Nothing is stored between sessions except npm's own package cache.
- **Your agent's model provider:** results returned to your agent become part of your session,
  which your agent host handles under its own terms, like any other tool output.
- **Personal data and children:** this is a developer tool. It does not set out to process
  personal data; a dependency file may happen to contain some (an author's name in a manifest),
  and that stays on your computer. It is not directed at people under 18.

The self-hosted monitor (`security-watch start`) has options that reach other services (news
feeds, AI model providers, Slack, email). The plugin does not use them.

Questions: [GitHub issues](https://github.com/ShieldaAI/security-watch/issues) or
support@shielda.ai.
