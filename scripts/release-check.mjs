import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
if (
  execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], {
    cwd: root,
    encoding: 'utf8',
  }).trim()
)
  throw new Error('Publish only from a clean committed checkout.');
execFileSync(process.execPath, [process.env.npm_execpath, 'run', 'check'], { cwd: root, stdio: 'inherit' });
if (
  execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], {
    cwd: root,
    encoding: 'utf8',
  }).trim()
)
  throw new Error('Release checks changed source.');
