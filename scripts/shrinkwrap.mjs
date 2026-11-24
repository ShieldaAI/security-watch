// Writes npm-shrinkwrap.json for the published package from package-lock.json, runtime packages
// only, so that `npx @shieldaai/security-watch@X` (the agent plugin, the MCP Registry entry) installs
// exactly the dependency tree this release was tested with, sub-dependencies included. Without it
// npm resolves the ranges inside dependencies (fast-xml-parser, parse5) again on every install.
// `npm pack` and `npm publish` run it as prepack; `--remove` (postpack) deletes the file again.
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const target = `${root}npm-shrinkwrap.json`;

export function shrinkwrap(lock) {
  const packages = {};
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === '') {
      const { devDependencies: _dev, ...rest } = entry;
      packages[path] = rest;
    } else if (!entry.dev) packages[path] = entry;
  }
  return { ...lock, packages };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes('--remove')) rmSync(target, { force: true });
  else {
    const lock = JSON.parse(readFileSync(`${root}package-lock.json`, 'utf8'));
    writeFileSync(target, `${JSON.stringify(shrinkwrap(lock), null, 2)}\n`);
  }
}
