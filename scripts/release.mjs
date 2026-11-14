// The one supported way to publish: `npm run release` (add `-- --dry-run` to rehearse).
// It chooses the distribution tag from the version and passes it to npm explicitly, so no option
// typed by hand can send a release candidate to `latest` or a stable release to `next`. It guards
// against mistakes. It cannot stop a maintainer who runs `npm publish --ignore-scripts` on purpose.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { releaseEnvironment, releaseOptions, releaseProblem, releaseTag } from './release-tag.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const tag = releaseTag(manifest.version);
const options = releaseOptions(process.argv.slice(2));
const env = releaseEnvironment(process.env, tag);
const problem = releaseProblem(manifest, env);
if (problem) throw new Error(problem);
if (!process.env.npm_execpath) throw new Error('Run through npm run release.');
// `prepublishOnly` runs the release checks (clean checkout, tracked files only, `npm run check`).
execFileSync(process.execPath, [process.env.npm_execpath, 'publish', '--tag', tag, ...options], {
  cwd: root,
  stdio: 'inherit',
  env,
});
