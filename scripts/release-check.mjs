import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  registryProblem,
  releaseEnvironmentProblem,
  releaseProblem,
  untrackedPackedFiles,
} from './release-tag.mjs';
const root = fileURLToPath(new URL('../', import.meta.url));
if (
  execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], {
    cwd: root,
    encoding: 'utf8',
  }).trim()
)
  throw new Error('Publish only from a clean committed checkout.');
// A stable version goes to the default tag; a prerelease must never replace it.
const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
if (!process.env.npm_execpath) throw new Error('Run through npm run release.');
/** What npm itself is configured with, as the publish it starts would see it. */
const configured = (key) =>
  execFileSync(process.execPath, [process.env.npm_execpath, 'config', 'get', key], {
    cwd: root,
    encoding: 'utf8',
  }).trim();
const problem =
  releaseEnvironmentProblem(process.env) ??
  registryProblem({ registry: configured('registry'), scoped: configured('@shieldaai:registry') }) ??
  releaseProblem(manifest, process.env);
if (problem) throw new Error(problem);
// The publish command's own options reach this script as npm_config_* variables and would be
// inherited by every npm command the checks run: under `--dry-run` the package check's `npm pack`
// would write no tarball. The checks run as they do from a plain `npm run check`.
const checkEnvironment = { ...process.env };
for (const key of Object.keys(checkEnvironment))
  if (['npm_config_dry_run', 'npm_config_tag', 'npm_config_otp'].includes(key.toLowerCase()))
    delete checkEnvironment[key];
execFileSync(process.execPath, [process.env.npm_execpath, 'run', 'check'], {
  cwd: root,
  stdio: 'inherit',
  env: checkEnvironment,
});
// Everything packed apart from the build output must be a tracked file: an ignored file left in a
// published directory does not show in `git status`.
const [packed] = JSON.parse(
  execFileSync(
    process.execPath,
    [process.env.npm_execpath, 'pack', '--dry-run', '--json', '--ignore-scripts'],
    {
      cwd: root,
      encoding: 'utf8',
      env: checkEnvironment,
    },
  ),
);
const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0');
const stray = untrackedPackedFiles(
  packed.files.map((file) => file.path),
  tracked,
);
if (stray.length) throw new Error(`The package would include files that are not in git: ${stray.join(', ')}`);
if (
  execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], {
    cwd: root,
    encoding: 'utf8',
  }).trim()
)
  throw new Error('Release checks changed source.');
