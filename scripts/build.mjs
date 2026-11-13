import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 24 || (major === 24 && minor < 10))
  throw new Error('Security Watch requires Node.js 24.10 or newer.');
// Remove stale build outputs before packaging.
rmSync(join(root, 'dist'), { recursive: true, force: true });
execFileSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json'], {
  cwd: root,
  stdio: 'inherit',
});
