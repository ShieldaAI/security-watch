// The npm distribution tag a version must be published under, and the check that it will be.
//
// npm passes a command-line option to lifecycle scripts only when it differs from the default, so
// `npm publish --tag latest` looks to `prepublishOnly` exactly like `npm publish` while npm itself
// lets the option override `publishConfig.tag`. The check therefore does not try to read the option.
// The supported command, `npm run release`, passes the right tag explicitly and says so in
// SECURITY_WATCH_RELEASE_TAG; a bare `npm publish` carries no such statement and is refused.

/** Stable versions go to `latest`; a prerelease must never replace it. */
export function releaseTag(version) {
  return version.includes('-') ? 'next' : 'latest';
}

/** Returns nothing when the publish may go ahead, and the reason when it may not. */
export function releaseProblem(manifest, env) {
  const expected = releaseTag(manifest.version);
  if (manifest.publishConfig?.tag !== expected)
    return `package.json publishConfig.tag must be ${expected} for version ${manifest.version}.`;
  const stated = env.SECURITY_WATCH_RELEASE_TAG;
  if (!stated)
    return 'Publish with `npm run release`, which passes the right tag for this version. A bare `npm publish` is refused because its --tag option cannot be checked here.';
  if (stated !== expected)
    return `Version ${manifest.version} must be published under the ${expected} tag, not ${stated}.`;
  // A tag option that does reach this script must agree as well.
  if (env.npm_config_tag && env.npm_config_tag !== expected)
    return `Version ${manifest.version} must be published under the ${expected} tag, not ${env.npm_config_tag}.`;
  return undefined;
}

/**
 * The options `npm run release` passes on to `npm publish`. Anything else is refused: `--tag` would
 * override the tag chosen here, `--ignore-scripts` would skip the release checks, and `--registry`
 * would publish somewhere else.
 */
export function releaseOptions(extra) {
  for (const option of extra)
    if (option !== '--dry-run' && !/^--otp=\d{6,8}$/.test(option))
      throw new Error(
        `npm run release accepts only --dry-run and --otp=CODE, not ${option}. The tag is chosen from the version; do not pass --tag.`,
      );
  return [...extra];
}

/**
 * Why this environment must not start a publish, or nothing. An npm option typed before the `--`
 * (`npm run release --ignore-scripts`), or set in `.npmrc` or the environment, never reaches
 * `releaseOptions`: npm keeps it and hands it to the publish it starts. With scripts ignored the
 * publish would skip every release check and the build; with another registry it would go elsewhere.
 */
export function releaseEnvironmentProblem(env) {
  const setting = (name) =>
    Object.entries(env).find(([key]) => key.toLowerCase() === `npm_config_${name}`)?.[1];
  if (!['', 'false', undefined].includes(setting('ignore_scripts')))
    return 'npm is set to ignore scripts (--ignore-scripts or ignore-scripts=true), which would skip the release checks and the build. Remove that setting.';
  const registry = setting('registry');
  if (
    registry !== undefined &&
    registry !== '' &&
    registry.replace(/\/$/, '') !== 'https://registry.npmjs.org'
  )
    return `npm is set to publish to ${registry}; releases go to https://registry.npmjs.org/. Remove that setting.`;
  return undefined;
}

/**
 * Why npm's configured registries must not receive this package, or nothing. `registry` and
 * `scoped` are what `npm config get registry` and `npm config get @shieldaai:registry` print. A
 * scoped registry (a line `@shieldaai:registry=…` in an `.npmrc`) sets no environment variable,
 * so it is read from npm itself.
 */
export function registryProblem({ registry, scoped }) {
  const official = (value) =>
    value === undefined ||
    ['', 'undefined', 'null'].includes(value.trim()) ||
    value.trim().replace(/\/$/, '') === 'https://registry.npmjs.org';
  if (!official(scoped))
    return `npm is set to publish @shieldaai packages to ${scoped.trim()}; releases go to https://registry.npmjs.org/. Remove that setting.`;
  if (!official(registry))
    return `npm is set to publish to ${registry.trim()}; releases go to https://registry.npmjs.org/. Remove that setting.`;
  return undefined;
}

/** The environment for the publish: the tag is stated, and no tag setting is inherited. */
export function releaseEnvironment(env, tag) {
  const next = { ...env, SECURITY_WATCH_RELEASE_TAG: tag };
  for (const key of Object.keys(next)) if (key.toLowerCase() === 'npm_config_tag') delete next[key];
  return next;
}

/**
 * Packed files that are not in version control. `files` in package.json names whole directories, so
 * a git-ignored file left in `docs/` or `examples/` would be published. Build output is the one
 * part of the package that is not tracked.
 */
export function untrackedPackedFiles(packed, tracked) {
  const known = new Set(tracked);
  return packed.filter((path) => !path.startsWith('dist/') && !known.has(path));
}
