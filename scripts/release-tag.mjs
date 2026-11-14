// The npm distribution tag a version must be published under, and the check that it will be.
//
// npm passes a command-line option to lifecycle scripts only when it differs from the default, so
// `npm publish --tag latest` looks to `prepublishOnly` exactly like `npm publish` while npm itself
// lets the option override `publishConfig.tag`. The check therefore does not try to read the option.
// The supported command, `npm run release`, passes the right tag explicitly and says so in
// SECURITY_WATCH_RELEASE_TAG; a bare `npm publish` carries no such statement and is refused.

/** Stable versions go to `latest`; a prerelease must never replace it. */
export function releaseTag(version) {
  // A hyphen in build metadata ("1.0.0+build-5") does not make a prerelease.
  return version.split('+')[0].includes('-') ? 'next' : 'latest';
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

/**
 * The checks `npm publish` runs before it packs (`prepublishOnly`). `run(command, args, options)`
 * runs a program in the package directory and returns its output; it throws when the program fails.
 * Throws the reason the publish must stop.
 */
export function releaseChecks({ root, env, manifest, run }) {
  const clean = () =>
    !run('git', ['status', '--porcelain', '--untracked-files=all'], { encoding: 'utf8' }).trim();
  if (!clean()) throw new Error('Publish only from a clean committed checkout.');
  if (!env.npm_execpath) throw new Error('Run through npm run release.');
  const npm = (args, options = {}) =>
    run(process.execPath, [env.npm_execpath, ...args], { encoding: 'utf8', ...options });
  // What npm itself is configured with, as the publish it starts would see it.
  const configured = (key) => npm(['config', 'get', key]).trim();
  const problem =
    releaseEnvironmentProblem(env) ??
    registryProblem({ registry: configured('registry'), scoped: configured('@shieldaai:registry') }) ??
    releaseProblem(manifest, env);
  if (problem) throw new Error(problem);
  // The publish command's own options reach this script as npm_config_* variables and would be
  // inherited by every npm command the checks run: under `--dry-run` the package check's `npm pack`
  // would write no tarball. The checks run as they do from a plain `npm run check`.
  const checkEnvironment = { ...env };
  for (const key of Object.keys(checkEnvironment))
    if (['npm_config_dry_run', 'npm_config_tag', 'npm_config_otp'].includes(key.toLowerCase()))
      delete checkEnvironment[key];
  npm(['run', 'check'], { stdio: 'inherit', env: checkEnvironment, encoding: undefined });
  // Everything packed apart from the build output must be a tracked file: an ignored file left in a
  // published directory does not show in `git status`.
  const [packed] = JSON.parse(
    npm(['pack', '--dry-run', '--json', '--ignore-scripts'], { env: checkEnvironment }),
  );
  const tracked = run('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0');
  const stray = untrackedPackedFiles(
    packed.files.map((file) => file.path),
    tracked,
  );
  if (stray.length)
    throw new Error(`The package would include files that are not in git: ${stray.join(', ')}`);
  if (!clean()) throw new Error('Release checks changed source.');
  return root;
}
