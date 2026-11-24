// The Security Watch plugin folder and its listings: every manifest agrees, every pinned version
// moves with the package, and the folder meets the rules each directory checks on submission
// (Anthropic's plugin directory, OpenAI's plugin portal, Antigravity's marketplace, the MCP
// Registry, GitHub Container Registry).

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { archives, PLUGIN, readmeFor } from '../scripts/pack-plugins.mjs';
import { shrinkwrap } from '../scripts/shrinkwrap.mjs';
import {
  MIN_NODE,
  npxArgs,
  npxCli,
  npxEnv,
  PACKAGE,
  projectRoot,
  VERSION as LAUNCHER_VERSION,
} from '../plugins/security-watch/scripts/start-mcp-server.mjs';
import { TOOLS } from '../dist/mcp-server.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const DIR = join(ROOT, PLUGIN);
const read = (path) => readFileSync(join(ROOT, path), 'utf8');
const json = (path) => JSON.parse(read(path));
const pkg = json('package.json');
const version = pkg.version;
const repoPath = resolve('/work/repo');

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}
const files = walk(DIR).map((path) => relative(DIR, path).split(sep).join('/'));

const claude = json(`${PLUGIN}/.claude-plugin/plugin.json`);
const portable = json(`${PLUGIN}/plugin.json`);
const openai = portable.extensions['com.openai'];
const antigravity = json(`${PLUGIN}/.antigravity-plugin/plugin.json`);
const SKILLS = ['security-watch', 'security-watch-setup'];
const skills = Object.fromEntries(
  SKILLS.map((name) => {
    const text = read(`${PLUGIN}/skills/${name}/SKILL.md`);
    return [name, { text, front: parseYaml(text.split('---')[1]) }];
  }),
);
const server = json('server.json');

function pngSize(path) {
  const bytes = readFileSync(join(DIR, path));
  assert.equal(bytes.subarray(1, 4).toString('latin1'), 'PNG', `${path} is not a PNG`);
  return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20), colorType: bytes[25] };
}

function contrast(hex, against) {
  const lum = (value) => {
    const [r, g, b] = [1, 3, 5].map((i) => parseInt(value.slice(i, i + 2), 16) / 255);
    const lin = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  };
  const [a, b] = [lum(hex), lum(against)].sort((x, y) => y - x);
  return (a + 0.05) / (b + 0.05);
}

test('every manifest names the same plugin, version and description', () => {
  for (const manifest of [claude, portable, antigravity]) {
    assert.equal(manifest.name, 'security-watch');
    assert.equal(manifest.version, version, 'plugin versions move with @shieldaai/security-watch');
    assert.equal(manifest.description, claude.description);
    assert.equal(manifest.license, 'Apache-2.0');
  }
  assert.equal(claude.displayName, 'Security Watch');
  assert.equal(antigravity.displayName, claude.displayName);
  assert.equal(openai.interface.displayName, claude.displayName);
});

test('every pinned version matches the package', () => {
  assert.equal(LAUNCHER_VERSION, version, 'scripts/start-mcp-server.mjs VERSION');
  assert.equal(PACKAGE, '@shieldaai/security-watch');
  assert.deepEqual(
    MIN_NODE,
    pkg.engines.node
      .match(/(\d+)\.(\d+)/)
      .slice(1, 3)
      .map(Number),
  );
  for (const path of [
    `${PLUGIN}/skills/security-watch/SKILL.md`,
    `${PLUGIN}/skills/security-watch-setup/SKILL.md`,
    `${PLUGIN}/README.md`,
    'docs/agents.md',
  ]) {
    const text = read(path);
    const pins = [
      ...text.matchAll(/@shieldaai\/security-watch@(\d+\.\d+\.\d+[\w.-]*)/g),
      ...text.matchAll(/ghcr\.io\/shieldaai\/security-watch:(\d+\.\d+\.\d+[\w.-]*)/g),
      ...text.matchAll(/ShieldaAI\/security-watch@v(\d+\.\d+\.\d+[\w.-]*)/g),
    ].map((match) => match[1]);
    assert.ok(pins.length > 0, `${path} pins no version`);
    for (const pin of pins) assert.equal(pin, version, `${path} pins ${pin}`);
  }
  assert.equal(server.version, version);
  assert.equal(server.packages[0].version, version);
  assert.equal(server.packages[1].identifier, `ghcr.io/shieldaai/security-watch:${version}`);
});

test('the marketplaces list the plugin folder', () => {
  const claudeMarket = json('.claude-plugin/marketplace.json');
  assert.equal(
    claudeMarket.name,
    'shielda-security-watch',
    'not "shielda": Agent Guard’s marketplace has it',
  );
  assert.equal(claudeMarket.plugins[0].name, claude.name);
  assert.equal(claudeMarket.plugins[0].source, `./${PLUGIN}`);
  assert.equal(claudeMarket.plugins[0].description, claude.description);
  const codexMarket = json('.agents/plugins/marketplace.json');
  assert.equal(codexMarket.name, claudeMarket.name);
  assert.equal(codexMarket.plugins[0].name, claude.name);
  assert.deepEqual(codexMarket.plugins[0].source, { source: 'local', path: `./${PLUGIN}` });
  // The README tells people to install it from this marketplace.
  assert.match(read(`${PLUGIN}/README.md`), /\/plugin install security-watch@shielda-security-watch/);
});

test('Claude directory: layout, size and file rules', () => {
  assert.match(claude.name, /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/);
  for (const key of ['description', 'author', 'version', 'license', 'homepage', 'repository'])
    assert.ok(claude[key], key);
  assert.ok(existsSync(join(DIR, claude.icon)), 'icon file exists');
  for (const key of ['documentationUrl', 'supportUrl', 'privacyPolicyUrl', 'termsOfServiceUrl'])
    assert.match(claude[key], /^https:\/\//, key);
  const prose = read(`${PLUGIN}/README.md`).replace(/```[\s\S]*?```/g, ' ');
  assert.ok(prose.split(/\s+/).filter(Boolean).length >= 40);
  assert.ok(existsSync(join(DIR, 'LICENSE')));
  assert.equal(read(`${PLUGIN}/LICENSE`), read('LICENSE'));
  assert.ok(files.length <= 512);
  for (const file of files) {
    const path = join(DIR, file);
    assert.ok(!lstatSync(path).isSymbolicLink(), `${file} is a link`);
    assert.ok(!/(^|\/)(\.DS_Store|Thumbs\.db|desktop\.ini|__MACOSX)$/.test(file), `${file} is a system file`);
    assert.ok(
      !/(^|\/)(\.npmrc|\.yarnrc|\.yarnrc\.yml|bunfig\.toml|uv\.toml|pip\.conf)$/.test(file),
      `${file} sets a package source`,
    );
    assert.ok(!/(^|\/)\.gitattributes$/.test(file), `${file} can rewrite file contents`);
    assert.ok(/\.(png|svg)$/.test(file) || statSync(path).size < 256 * 1024, `${file} is over 256 KiB`);
    assert.ok(/^[A-Za-z0-9._/-]+$/.test(file), `${file} has a name some systems refuse`);
  }
  assert.ok(!existsSync(join(ROOT, '.gitattributes')), 'a root .gitattributes stops the directory validator');
  const lower = files.map((file) => file.toLowerCase());
  assert.equal(new Set(lower).size, lower.length, 'names that differ only in case');
  assert.ok(!files.some((file) => file.startsWith('bin/')));
  assert.ok(!files.includes('package.json') && !files.includes('package-lock.json'));
});

test('MCP configs start the bundled launcher by a path inside the plugin', () => {
  const configs = {
    '.mcp.json': '${CLAUDE_PLUGIN_ROOT}',
    'mcp.json': '${PLUGIN_ROOT}',
    'mcp_config.json': '${PLUGIN_ROOT}',
  };
  for (const [file, variable] of Object.entries(configs)) {
    const servers = json(`${PLUGIN}/${file}`).mcpServers;
    assert.deepEqual(Object.keys(servers), ['security-watch'], file);
    const entry = servers['security-watch'];
    assert.equal(entry.command, 'node', file);
    assert.deepEqual(entry.args, [`${variable}/scripts/start-mcp-server.mjs`], file);
    assert.equal(entry.cwd, undefined, file);
    assert.equal(entry.env, undefined, file);
  }
  assert.equal(json(`${PLUGIN}/mcp.json`).mcpServers['security-watch'].type, 'stdio');
});

test('skills: front matter every host accepts, provider-neutral, and they name real tools', () => {
  const toolNames = [...TOOLS.map((tool) => tool.name), 'list_watch_findings'];
  for (const [name, { text, front }] of Object.entries(skills)) {
    assert.equal(front.name, name);
    assert.match(front.name, /^[a-z0-9-]{1,64}$/);
    assert.ok(front.description.length >= 1 && front.description.length <= 1024);
    assert.doesNotMatch(text, /\b(Claude|ChatGPT|Gemini|Codex),? (should|must|will)\b/);
    for (const [, tool] of text.matchAll(/`((?:check|list|write)_[a-z_]+)`/g))
      assert.ok(toolNames.includes(tool), `${name} names ${tool}, which is not a tool`);
  }
  for (const tool of toolNames) assert.match(skills['security-watch'].text, new RegExp(`\`${tool}\``));
  // No credential is ever to be pasted into a committed file or into chat.
  assert.match(skills['security-watch-setup'].text, /never paste them into files you\s+commit/);
});

test('OpenAI portal: interface limits, icons and colors', () => {
  const ui = openai.interface;
  assert.equal(openai.requires_local_executor, true);
  assert.ok(ui.displayName.length <= 30);
  assert.ok(ui.shortDescription.length <= 30);
  assert.ok(ui.longDescription.length <= 4000);
  assert.ok(ui.developerName.length <= 80);
  assert.deepEqual(ui.capabilities, ['Read', 'Write'], 'write_sbom writes; everything else reads');
  assert.ok(ui.defaultPrompt.length <= 3 && new Set(ui.defaultPrompt).size === ui.defaultPrompt.length);
  for (const prompt of ui.defaultPrompt) assert.ok(prompt.length <= 128 && !prompt.includes('@'), prompt);
  for (const key of ['websiteURL', 'supportURL', 'privacyPolicyURL', 'termsOfServiceURL'])
    assert.match(ui[key], /^https:\/\/.{1,1000}$/, key);
  assert.match(ui.brandColor, /^#[0-9A-F]{6}$/i);
  assert.ok(contrast(ui.brandColor, '#FFFFFF') >= 3, 'brandColor contrast against white');
  for (const key of ['composerIcon', 'logo']) {
    assert.match(ui[key], /^\.\//);
    const { width, height, colorType } = pngSize(ui[key]);
    assert.equal(width, height, `${key} is square`);
    assert.ok(width >= 48 && width <= 4096, `${key} size`);
    assert.equal(colorType, 6, `${key} has an alpha channel`);
  }
  assert.ok(!files.some((file) => file.startsWith('hooks/')) && !files.includes('.app.json'));
  assert.equal(openai.hooks, undefined);
  assert.equal(openai.apps, undefined);
});

test('OpenAI archives: skills-only leaves out the MCP server, local-MCP adds it', () => {
  const [skillsOnly, local] = archives();
  assert.equal(skillsOnly.kind, 'openai-skills');
  for (const name of SKILLS) assert.ok(skillsOnly.files.includes(`skills/${name}/SKILL.md`));
  assert.ok(skillsOnly.files.includes('plugin.json'));
  assert.ok(!skillsOnly.files.some((file) => /mcp|^scripts\//.test(file)), 'no MCP config or launcher');
  assert.ok(!skillsOnly.files.some((file) => file.startsWith('.')), 'no other hosts’ manifests');
  assert.deepEqual(
    local.files.filter((file) => !skillsOnly.files.includes(file)),
    ['mcp.json', 'scripts/start-mcp-server.mjs'],
  );
  for (const archive of [skillsOnly, local])
    for (const file of [openai.interface.logo, openai.interface.composerIcon])
      assert.ok(archive.files.includes(file.slice(2)), `${archive.kind} has ${file}`);
});

test('Antigravity marketplace: required fields and limits', () => {
  assert.match(antigravity.name, /^[a-z0-9-]+$/);
  for (const key of ['displayName', 'description', 'version', 'logo', 'suggestedPrompts', 'author'])
    assert.ok(antigravity[key], key);
  assert.ok(antigravity.description.length >= 120 && antigravity.description.length <= 160);
  assert.ok(antigravity.suggestedPrompts.length <= 3);
  assert.deepEqual(antigravity.suggestedPrompts, openai.interface.defaultPrompt);
  assert.ok(existsSync(join(DIR, antigravity.logo)));
  assert.match(antigravity.author.url, /^https:\/\//);
});

test('MCP Registry: server.json matches the npm package and the image', () => {
  assert.equal(server.name, pkg.mcpName, 'mcpName proves npm ownership');
  assert.match(server.name, /^io\.github\.ShieldaAI\/[a-zA-Z0-9._-]+$/);
  assert.ok(server.description.length <= 100);
  const [npm, oci] = server.packages;
  assert.equal(npm.registryType, 'npm');
  assert.equal(npm.registryBaseUrl, 'https://registry.npmjs.org');
  assert.equal(npm.identifier, pkg.name);
  assert.equal(npm.transport.type, 'stdio');
  assert.equal(npm.packageArguments[0].value, 'mcp', 'mcp must be the first argument');
  assert.ok(!pkg.files.includes('server.json'), 'server.json is registry metadata, not package content');
  assert.equal(oci.registryType, 'oci');
  assert.equal(oci.transport.type, 'stdio');
  assert.deepEqual(
    oci.packageArguments.map((argument) => argument.value),
    ['mcp', '/project'],
  );
  // The registry checks this label on the image; the Dockerfile sets it.
  assert.match(read('Dockerfile'), new RegExp(`io\\.modelcontextprotocol\\.server\\.name="${server.name}"`));
  assert.match(
    read('Dockerfile'),
    /org\.opencontainers\.image\.source="https:\/\/github\.com\/ShieldaAI\/security-watch"/,
  );
});

test('the image workflow uses only GitHub’s own actions, pinned, and tests before it tags', () => {
  const workflow = read('.github/workflows/image.yml');
  // The repository allows only GitHub-owned actions, pinned to a full commit: anything else makes the
  // run fail at startup (it did for v1.4.0 with docker/* and sigstore/* actions).
  for (const [, ref] of workflow.matchAll(/uses: ([^\s]+)/g)) {
    assert.match(ref, /^(actions|github)\//, `${ref} is not a GitHub-owned action`);
    assert.match(ref, /@[0-9a-f]{40}$/, ref);
  }
  const order = [
    '--target test',
    'check-docker.mjs',
    'docker login ghcr.io',
    'docker buildx build',
    'Run the pushed image',
    'imagetools create --tag "$IMAGE:$VERSION"',
    'attest-build-provenance',
    'Move the release-line and latest tags',
  ];
  const positions = order.map((needle) => workflow.indexOf(needle));
  assert.ok(
    positions.every((position) => position >= 0),
    `every step is there: ${order.filter((_, i) => positions[i] < 0)}`,
  );
  assert.deepEqual(
    [...positions].sort((a, b) => a - b),
    positions,
    'in this order',
  );
  // Both architectures are built and run on their own hardware.
  assert.match(workflow, /platform: linux\/amd64\n\s+runner: ubuntu-latest/);
  assert.match(workflow, /platform: linux\/arm64\n\s+runner: ubuntu-24\.04-arm/);
  assert.match(workflow, /--provenance=mode=max/);
  assert.match(workflow, /--sbom=true/);
  assert.match(workflow, /push-by-digest=true/);
  assert.match(workflow, /^permissions:\n {2}contents: read$/m);
  assert.match(workflow, /^run-name: Container image \$\{\{ inputs\.tag \|\| github\.ref_name \}\}$/m);
});

test('launcher: picks the open project and refuses to read itself', () => {
  const plugin = DIR;
  const repo = resolve('/work/repo');
  assert.equal(
    projectRoot({ argv: [repo], env: { CLAUDE_PROJECT_DIR: resolve('/x') }, cwd: resolve('/y'), plugin }),
    repo,
  );
  assert.equal(projectRoot({ env: { CLAUDE_PROJECT_DIR: repo }, cwd: resolve('/y'), plugin }), repo);
  assert.equal(projectRoot({ env: {}, cwd: repo, plugin }), repo);
  assert.equal(projectRoot({ env: {}, cwd: plugin, plugin }), undefined);
  assert.equal(projectRoot({ env: {}, cwd: join(plugin, 'scripts'), plugin }), undefined);
  assert.equal(projectRoot({ env: {}, cwd: ROOT, plugin }), resolve(ROOT));
});

test('launcher: runs npm’s own npx with the pinned package, and asks the client when the project is unknown', () => {
  const cellar = resolve('/opt/homebrew/Cellar/node/26/bin');
  const linked = resolve('/opt/homebrew/lib/node_modules/npm/bin/npx-cli.js');
  const fs = (present) => ({
    exists: (path) => present.includes(path),
    realpath: (path) => {
      if (path === join(cellar, 'npx')) return linked;
      throw new Error('ENOENT');
    },
  });
  assert.equal(npxCli(join(cellar, 'node'), fs([linked])), linked);
  assert.equal(npxCli(resolve('/nowhere/bin/node'), fs([])), undefined);
  const evil = resolve('/tmp/evil/npx');
  assert.equal(
    npxCli(resolve('/opt/x/bin/node'), { exists: (path) => path === evil, realpath: () => evil }),
    undefined,
  );
  assert.deepEqual(npxArgs('npx-cli.js', repoPath), [
    'npx-cli.js',
    '--yes',
    `--package=@shieldaai/security-watch@${version}`,
    '--',
    'security-watch-mcp',
    repoPath,
  ]);
  assert.deepEqual(npxArgs('npx-cli.js', undefined).slice(-2), ['security-watch-mcp', '--client-roots']);
});

test('launcher: refuses the filesystem root and the home folder, strips npm and Node settings', () => {
  const home = resolve('/Users/someone');
  const args = { env: {}, plugin: DIR, home };
  assert.equal(projectRoot({ ...args, cwd: resolve('/') }), undefined);
  assert.equal(projectRoot({ ...args, cwd: home }), undefined);
  assert.equal(projectRoot({ ...args, cwd: join(home, 'code', 'app') }), join(home, 'code', 'app'));
  const env = npxEnv({
    PATH: '/usr/bin',
    HOME: home,
    SECURITY_WATCH_CONFIG: '/srv/watch/security-watch.yaml',
    npm_config_registry: 'http://127.0.0.1:9/',
    NPM_CONFIG_CACHE: '/repo/cache',
    NODE_OPTIONS: '--require /repo/x.js',
    NODE_PATH: '/repo/lib',
  });
  assert.equal(env.PATH, '/usr/bin');
  assert.equal(
    env.SECURITY_WATCH_CONFIG,
    '/srv/watch/security-watch.yaml',
    'the monitor setting reaches the server',
  );
  for (const key of ['npm_config_registry', 'NPM_CONFIG_CACHE', 'NODE_OPTIONS', 'NODE_PATH'])
    assert.equal(env[key], undefined, key);
});

test('each archive documents what it holds, and local links resolve', () => {
  const readme = read(`${PLUGIN}/README.md`);
  const skillsOnly = readmeFor('openai-skills', readme);
  const local = readmeFor('openai-local-mcp', readme);
  assert.doesNotMatch(skillsOnly, /<!--|check_project_vulnerabilities|start-mcp-server|MCP server/);
  assert.match(skillsOnly, /## Install/);
  assert.doesNotMatch(local, /<!--/);
  assert.match(local, /start-mcp-server\.mjs/);
  assert.equal(readmeFor('claude', readme), local);
  for (const tool of [...TOOLS.map((item) => item.name), 'list_watch_findings'])
    assert.match(local, new RegExp(`\`${tool}\``), `README documents ${tool}`);
  for (const path of [`${PLUGIN}/README.md`, `${PLUGIN}/PRIVACY.md`, 'docs/agents.md'])
    for (const [, target] of read(path).matchAll(/\]\((?!https?:|mailto:|#)([^)#\s]+)/g))
      assert.ok(existsSync(join(ROOT, path, '..', target)), `${path} links to ${target}`);
});

test('the published package fixes its whole dependency tree', () => {
  const lock = json('package-lock.json');
  const wrapped = shrinkwrap(lock);
  assert.equal(wrapped.lockfileVersion, lock.lockfileVersion);
  assert.equal(wrapped.packages[''].devDependencies, undefined);
  assert.deepEqual(wrapped.packages[''].dependencies, pkg.dependencies);
  const runtime = Object.entries(lock.packages).filter(([path, entry]) => path && !entry.dev);
  assert.equal(Object.keys(wrapped.packages).length - 1, runtime.length);
  for (const [path, entry] of runtime) assert.equal(wrapped.packages[path].version, entry.version, path);
  // Direct dependencies are exact versions too.
  for (const [name, range] of Object.entries(pkg.dependencies)) assert.match(range, /^\d+\.\d+\.\d+$/, name);
  assert.ok(pkg.files.includes('npm-shrinkwrap.json'));
  assert.equal(pkg.scripts.prepack, 'npm run build && node scripts/shrinkwrap.mjs');
});

test('the logo files are the same picture: the SVG renders the PNGs', () => {
  const svg = read(`${PLUGIN}/assets/logo.svg`);
  assert.match(svg, /viewBox="0 0 400 400"/);
  assert.deepEqual([pngSize('assets/logo.png').width, pngSize('assets/icon.png').width], [400, 128]);
});
