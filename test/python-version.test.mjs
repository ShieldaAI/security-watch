import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pythonRangeStatus } from '../dist/python-version.js';
import { assess, parseConfig } from '../dist/index.js';

const fixtures = JSON.parse(
  readFileSync(new URL('./fixtures/pep440-final-releases.json', import.meta.url), 'utf8'),
);

test('supported PyPI final-release ranges agree with Python packaging reference fixtures', () => {
  for (const item of fixtures.cases)
    assert.equal(pythonRangeStatus(item.version, item.range), item.expected, JSON.stringify(item));
});

test('unsupported or unbounded PyPI syntax cannot establish exclusion', () => {
  for (const version of [
    '1.30.0rc1',
    '1.30.0.dev0',
    '1.30.0.post1',
    '1.30.0+local',
    '1!1.30.0',
    'v1.30.0',
    '9007199254740992',
    '1.'.repeat(30) + '1',
    'x',
    '1'.repeat(129),
  ]) {
    assert.equal(pythonRangeStatus(version, '<1.30.0'), 'unknown', version);
  }
  for (const range of [
    undefined,
    '',
    ' ',
    '*',
    '<1.0 || >2.0',
    '>=1 <2',
    '===1.0',
    '~=1.0',
    '==1.*',
    '<1.30.0rc1',
    '>1!1.30.0',
    '<1, garbage',
    '<1,,>=0',
    '<1,>=9007199254740992',
    '<1,>=1+local',
    '>0,'.repeat(33) + '<2',
    '<' + '1'.repeat(2048),
  ]) {
    assert.equal(pythonRangeStatus('1.30.0', range), 'unknown', String(range));
  }
});

test('PyPI assessment preserves exact positive evidence, range union, conflicts and freshness rules', () => {
  const now = Date.parse('2026-10-28T17:00:00Z');
  const config = parseConfig({ version: 1 });
  const system = {
    id: 'agent',
    name: 'agent',
    environment: 'production',
    exposure: 'internet',
    criticality: 'high',
    updated_at: new Date(now).toISOString(),
    components: [{ id: 'mcp', ecosystem: 'PyPI', name: 'mcp', version: '1.30.0' }],
    products: [],
    keywords: [],
  };
  const evidence = {
    id: 'fixture:GHSA-w4fh-qvv9-3v23',
    source: 'fixture',
    kind: 'advisory',
    title: 'MCP',
    url: 'https://github.com/advisories/GHSA-w4fh-qvv9-3v23',
    aliases: [],
    description: '',
    severity: 'high',
    fetched_at: new Date(now).toISOString(),
    packages: [
      { ecosystem: 'PyPI', name: 'mcp', range: '>=1.10.0,<1.30.0' },
      { ecosystem: 'PyPI', name: 'mcp', range: '>=2.0.0,<2.2.0' },
    ],
  };
  const run = (systems = [system], records = [evidence]) =>
    assess({ systems }, records, config, now)[0].applicability;
  assert.equal(run(), 'not_affected');
  assert.equal(run([{ ...system, components: [{ ...system.components[0], version: '2.1.0' }] }]), 'affected');
  assert.equal(run([{ ...system, updated_at: '2025-01-01T00:00:00Z' }]), 'unknown');
  assert.equal(run([system], [{ ...evidence, fetched_at: '2025-01-01T00:00:00Z' }]), 'unknown');
  assert.equal(
    run(
      [system],
      [
        {
          ...evidence,
          packages: [{ ...evidence.packages[0], range: undefined, fixed: '1.30.0', versions: ['1.29.1'] }],
        },
      ],
    ),
    'unknown',
  );
  assert.equal(
    run(
      [system],
      [{ ...evidence, packages: [evidence.packages[0], { ...evidence.packages[0], range: '<1.30.0rc1' }] }],
    ),
    'unknown',
  );
  assert.equal(
    run(
      [{ ...system, components: [{ ...system.components[0], version: '1.30.0rc1' }] }],
      [{ ...evidence, packages: [{ ...evidence.packages[0], versions: ['1.30.0rc1'] }] }],
    ),
    'affected',
  );
  assert.equal(
    run(
      [system],
      [
        evidence,
        {
          ...evidence,
          id: 'other',
          source: 'other',
          aliases: [evidence.id],
          packages: [{ ...evidence.packages[0], range: '<2' }],
        },
      ],
    ),
    'conflicting',
  );
});
