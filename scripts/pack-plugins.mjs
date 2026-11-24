// Builds the upload archives for plugin directories that take a ZIP instead of reading GitHub.
//
//   node scripts/pack-plugins.mjs          -> artifacts/plugins/*.zip
//
// One plugin folder (plugins/security-watch) serves every host: Claude Code reads
// .claude-plugin/ and .mcp.json, Codex and ChatGPT read plugin.json and mcp.json, Antigravity reads
// .antigravity-plugin/ and mcp_config.json. The Claude and Antigravity directories read the folder
// from GitHub, so only OpenAI's portal needs archives:
//
//   - openai-skills: the skills only, for a public "Skills only" submission. No MCP server, no
//     scripts. plugin.json keeps requires_local_executor (the skills run npx on the user's machine).
//   - openai-local-mcp: the skills plus the local MCP server, for organizations OpenAI has
//     allowlisted for local MCP plugins. It cannot be added later to a skills-only listing.

import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const PLUGIN = 'plugins/security-watch';

function walk(dir, base = dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path, base));
    else out.push(relative(base, path).split(sep).join('/'));
  }
  return out.sort();
}

const SHARED = (path) =>
  path === 'plugin.json' ||
  path === 'README.md' ||
  path === 'LICENSE' ||
  path === 'PRIVACY.md' ||
  path.startsWith('skills/') ||
  path.startsWith('assets/');

/** The archives to build and the plugin files each one holds, relative to the plugin folder. */
export function archives(root = ROOT) {
  const files = walk(join(root, PLUGIN));
  return [
    { kind: 'openai-skills', files: files.filter(SHARED) },
    {
      kind: 'openai-local-mcp',
      files: files.filter((path) => SHARED(path) || path === 'mcp.json' || path.startsWith('scripts/')),
    },
  ];
}

const MCP_BLOCK = /<!-- mcp:start -->\n[\s\S]*?<!-- mcp:end -->\n/;
const SKILLS_BLOCK = /<!-- skills-only:\n([\s\S]*?)-->\n/;

/**
 * The README for one archive. The plugin README describes the MCP server between
 * `<!-- mcp:start -->` and `<!-- mcp:end -->`, and keeps the skills-only wording in a
 * `<!-- skills-only: ... -->` comment, so each archive documents exactly what it holds.
 */
export function readmeFor(kind, text) {
  if (!MCP_BLOCK.test(text) || !SKILLS_BLOCK.test(text))
    throw new Error('README is missing its mcp or skills-only block');
  if (kind === 'openai-skills') return text.replace(MCP_BLOCK, '').replace(SKILLS_BLOCK, '$1');
  return text.replace(SKILLS_BLOCK, '').replace(/<!-- mcp:(start|end) -->\n/g, '');
}

function main() {
  const { version } = JSON.parse(readFileSync(join(ROOT, PLUGIN, 'plugin.json'), 'utf8'));
  const outDir = join(ROOT, 'artifacts', 'plugins');
  mkdirSync(outDir, { recursive: true });
  for (const { kind, files } of archives()) {
    const stage = mkdtempSync(join(tmpdir(), 'security-watch-plugin-'));
    try {
      for (const file of files) {
        mkdirSync(join(stage, file, '..'), { recursive: true });
        if (file === 'README.md')
          writeFileSync(join(stage, file), readmeFor(kind, readFileSync(join(ROOT, PLUGIN, file), 'utf8')));
        else cpSync(join(ROOT, PLUGIN, file), join(stage, file));
      }
      const zip = join(outDir, `security-watch-${version}-${kind}.zip`);
      if (existsSync(zip)) rmSync(zip);
      // -X leaves out extra file attributes; -D leaves out directory entries.
      const result = spawnSync('zip', ['-X', '-D', '-q', zip, ...files], { cwd: stage, stdio: 'inherit' });
      if (result.error || result.status !== 0) throw new Error(`zip failed for ${kind}`);
      console.log(`${relative(ROOT, zip)}  ${files.length} files, ${statSync(zip).size} bytes`);
      for (const file of files) console.log(`  ${file}`);
    } finally {
      rmSync(stage, { recursive: true, force: true });
    }
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
