import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { releaseProblem } from './release-tag.mjs';
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
const problem = releaseProblem(manifest, process.env);
if (problem) throw new Error(problem);
execFileSync(process.execPath, [process.env.npm_execpath, 'run', 'check'], { cwd: root, stdio: 'inherit' });
if (
  execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], {
    cwd: root,
    encoding: 'utf8',
  }).trim()
)
  throw new Error('Release checks changed source.');
