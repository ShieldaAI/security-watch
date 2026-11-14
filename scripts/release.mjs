// The one supported way to publish: `npm run release` (add `-- --dry-run` to rehearse).
// It chooses the distribution tag from the version and passes it to npm explicitly, so no option
// typed by hand can send a release candidate to `latest` or a stable release to `next`.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { releaseProblem, releaseTag } from './release-tag.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const tag = releaseTag(manifest.version);
const extra = process.argv.slice(2);
if (extra.some((argument) => argument === '--tag' || argument.startsWith('--tag=')))
  throw new Error(`The tag is chosen from the version (${tag}); do not pass --tag.`);
const env = { ...process.env, SECURITY_WATCH_RELEASE_TAG: tag };
delete env.npm_config_tag;
const problem = releaseProblem(manifest, env);
if (problem) throw new Error(problem);
if (!process.env.npm_execpath) throw new Error('Run through npm run release.');
execFileSync(process.execPath, [process.env.npm_execpath, 'publish', '--tag', tag, ...extra], {
  cwd: root,
  stdio: 'inherit',
  env,
});
