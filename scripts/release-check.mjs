import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { releaseProblem, untrackedPackedFiles } from './release-tag.mjs';
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
// Everything packed apart from the build output must be a tracked file: an ignored file left in a
// published directory does not show in `git status`.
const [packed] = JSON.parse(
  execFileSync(
    process.execPath,
    [process.env.npm_execpath, 'pack', '--dry-run', '--json', '--ignore-scripts'],
    {
      cwd: root,
      encoding: 'utf8',
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
