// Regressions from the ninth review of collection and matching: package lookups that take turns
// over many polls, a failing lookup going to the back, and technology named as what something is
// built with.
import test from 'node:test';
import assert from 'node:assert/strict';
import { packageMentioned } from '../dist/matching.js';
import { collectSources } from '../dist/sources.js';

const HOUR = 3_600_000;
const NOW = Date.parse('2026-10-24T12:00:00Z');
const iso = (time) => new Date(time).toISOString();
const json = (value) => ({ status: 200, headers: {}, body: JSON.stringify(value) });
const sources = {
  news_lookback_minutes: 40,
  poll_interval_minutes: 30,
  inventory_stale_days: 30,
  policy: {},
  sources: {
    cve_now: true,
    hacker_news: false,
    osv: false,
    github: false,
    github_token_env: 'NINTH_COLLECTION_UNUSED',
    kev: false,
    feeds: [],
  },
};
const inventory = (count) => ({
  systems: [
    {
      id: 'prod',
      name: 'prod',
      updated_at: iso(NOW),
      products: [],
      keywords: [],
      components: Array.from({ length: count }, (_, index) => ({
        id: `c:${index}`,
        ecosystem: 'npm',
        name: `pkg-${String(index).padStart(5, '0')}`,
        version: '1.0.0',
      })),
    },
  ],
});

async function polls(count, times, fail = () => false) {
  const inv = inventory(count);
  let checkpoints = { cve_now: iso(NOW - HOUR) };
  const rounds = [];
  for (let poll = 0; poll < times; poll++) {
    const asked = [];
    const now = NOW + poll * 30 * 60_000;
    const http = async (url) => {
      const { pathname, searchParams } = new URL(url);
      if (pathname === '/stack') {
        const key = searchParams.get('p');
        asked.push(key);
        return fail(key, poll) ? { status: 500, headers: {}, body: '' } : json({ packages: 1, entries: [] });
      }
      if (pathname === '/api/v1/entries') return json({ entries: [] });
      return { status: 404, headers: {}, body: '' };
    };
    const result = await collectSources(inv, sources, checkpoints, http, now, []);
    checkpoints = result.checkpoints;
    rounds.push({ asked, result });
  }
  return rounds;
}

test('with 2,500 package versions every one is looked up within three polls, and again in turn', async () => {
  const rounds = await polls(2_500, 6);
  for (const { asked } of rounds) assert.equal(asked.length, 1_000);
  const firstCycle = new Set(rounds.slice(0, 3).flatMap(({ asked }) => asked));
  assert.equal(firstCycle.size, 2_500, 'all versions in the first three polls');
  assert.ok(firstCycle.has('npm:pkg-02499@1.0.0'), 'the last one by name is reached');
  // Poll 2 looks up the last 500 and starts the next round with the first 500; poll 3 goes on with
  // what was looked up longest ago.
  assert.equal(rounds[2].asked[500], 'npm:pkg-00000@1.0.0');
  assert.equal(rounds[3].asked[0], 'npm:pkg-00500@1.0.0');
  const seen = new Map();
  rounds.forEach(({ asked }, poll) =>
    asked.forEach((key) => (seen.get(key) ?? seen.set(key, []).get(key)).push(poll)),
  );
  for (const [key, list] of seen)
    for (let index = 1; index < list.length; index++)
      assert.ok(list[index] - list[index - 1] <= 3, `${key} waits at most three polls`);
});

test('a lookup that keeps failing goes to the back and does not keep the others from their turn', async () => {
  // The four versions first by name fail on every poll; a failed batch ends the lookups of a poll.
  const broken = new Set([
    'npm:pkg-00000@1.0.0',
    'npm:pkg-00001@1.0.0',
    'npm:pkg-00002@1.0.0',
    'npm:pkg-00003@1.0.0',
  ]);
  const rounds = await polls(1_200, 4, (key) => broken.has(key));
  assert.equal(rounds[0].asked.length, 4, 'the first poll stops at them');
  // From then on they are tried last, so every other version is looked up.
  const later = new Set(rounds.slice(1).flatMap(({ asked }) => asked));
  assert.equal([...later].filter((key) => !broken.has(key)).length, 1_196);
  assert.match(
    rounds[1].result.errors[0]?.message ?? '',
    /package lookup request\(s\) failed or were not sent/,
  );
});

test('technology named as what something is built with is not the package', () => {
  const mentioned = (name, text) => packageMentioned(text, { ecosystem: 'npm', name });
  for (const [name, text] of [
    ['react', 'Phishing pages built with React imitate the bank login.'],
    ['typescript', 'The stealer is written in Python or TypeScript and steals cookies.'],
    ['electron', 'Attackers target Electron apps that bundle a TypeScript loader.'],
    ['typescript', 'The campaign drops a fake CAPTCHA and a TypeScript loader.'],
  ])
    assert.equal(mentioned(name, text), false, `${name}: ${text}`);
  for (const [name, text] of [
    ['react', 'A flaw in React Server Components allows remote code execution.'],
    ['electron', 'Electron fixes a sandbox escape in the renderer.'],
    ['typescript', 'A bug in TypeScript lets crafted declarations hang the compiler.'],
  ])
    assert.equal(mentioned(name, text), true, `${name}: ${text}`);
});
