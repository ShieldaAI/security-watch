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
