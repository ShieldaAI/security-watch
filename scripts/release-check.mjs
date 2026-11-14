import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { releaseChecks } from './release-tag.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
releaseChecks({
  root,
  env: process.env,
  manifest: JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')),
  run: (command, args, options) => execFileSync(command, args, { cwd: root, ...options }),
});
