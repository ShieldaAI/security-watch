import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const excluded = manifest.files.filter((entry) => entry.startsWith('!')).map((entry) => entry.slice(1));
const included = manifest.files.filter((entry) => !entry.startsWith('!'));
/** Whether a repository path is part of the published npm package. */
const published = (path) =>
  path === 'package.json' ||
  (included.some((entry) => path === entry || path.startsWith(`${entry}/`)) &&
    !excluded.some((entry) => path === entry || path.startsWith(`${entry}/`)));
const markdown = [
  ...readdirSync(root).filter((name) => name.endsWith('.md')),
  ...readdirSync(join(root, 'docs'))
    .filter((name) => name.endsWith('.md'))
    .map((name) => `docs/${name}`),
];
const slug = (heading) =>
  heading
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .trim()
    .replace(/\s/g, '-');
const anchors = (file) =>
  new Set(
    readFileSync(join(root, file), 'utf8')
      .split('\n')
      .filter((line) => /^#{1,6}\s/.test(line))
      .map((line) => slug(line.replace(/^#{1,6}\s+/, ''))),
  );

test('relative links in the documentation resolve, including their section anchors', () => {
  const problems = [];
  for (const file of markdown) {
    const text = readFileSync(join(root, file), 'utf8').replace(/```[\s\S]*?```/g, '');
    for (const [, target] of text.matchAll(/\]\(([^)\s]+)\)/g)) {
      if (/^(?:https?:|mailto:)/.test(target)) continue;
      const [path, anchor] = target.split('#');
      const resolved = path
        ? normalize(join(dirname(file), path))
            .split(sep)
            .join('/')
        : file;
      if (!existsSync(join(root, resolved))) problems.push(`${file}: ${target} does not exist`);
      else if (anchor && resolved.endsWith('.md') && !anchors(resolved).has(anchor))
        problems.push(`${file}: ${target} has no such section`);
      else if (published(file) && !published(resolved))
        problems.push(`${file}: ${target} is not in the published package`);
    }
  }
  assert.deepEqual(problems, []);
});

test('documents shipped in the package describe the current version, not the alpha', () => {
  for (const file of markdown.filter(published)) {
    if (file === 'CHANGELOG.md') continue;
    const text = readFileSync(join(root, file), 'utf8');
    assert.ok(!text.includes('0.1.0-alpha'), `${file} still names the alpha version`);
    assert.ok(!/@shieldaai\/security-watch@alpha\b/.test(text), `${file} installs the alpha tag`);
    assert.ok(!/\b(?:this|experimental) alpha\b/i.test(text), `${file} still calls the release an alpha`);
  }
});
