// The one supported way to publish: `npm run release` (add `-- --dry-run` to rehearse).
// It chooses the distribution tag from the version and passes it to npm explicitly, so no option
// typed by hand can send a release candidate to `latest` or a stable release to `next`. It guards
// against mistakes. It cannot stop a maintainer who runs `npm publish --ignore-scripts` on purpose.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  releaseEnvironment,
  releaseEnvironmentProblem,
  releaseOptions,
  releaseProblem,
  releaseTag,
  registryProblem,
} from './release-tag.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const tag = releaseTag(manifest.version);
const options = releaseOptions(process.argv.slice(2));
const env = releaseEnvironment(process.env, tag);
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
  releaseProblem(manifest, env);
if (problem) throw new Error(problem);
// `prepublishOnly` runs the release checks (clean checkout, tracked files only, `npm run check`).
execFileSync(process.execPath, [process.env.npm_execpath, 'publish', '--tag', tag, ...options], {
  cwd: root,
  stdio: 'inherit',
  env,
});
