import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
if (Number(process.versions.node.split('.')[0]) < 24)
  throw new Error('Security Watch requires Node.js 24 or newer.');
// dist is generated and ignored. Never include obsolete outputs from an earlier build in a release.
rmSync(join(root, 'dist'), { recursive: true, force: true });
execFileSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json'], {
  cwd: root,
  stdio: 'inherit',
});
