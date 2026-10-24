import test from 'node:test';
import assert from 'node:assert/strict';
import { assess, decide } from '../dist/assessment.js';

const now = Date.parse('2026-10-24T12:00:00Z');
const config = {
  models: { enabled: false },
  inventory_stale_days: 7,
  policy: {
    library: { levels: ['critical'], basis: 'priority', channels: ['slack', 'email'] },
    product: { levels: ['critical'], basis: 'priority', channels: ['slack'] },
    news: { levels: ['high', 'critical'], basis: 'priority', channels: ['slack'] },
    urgent_unknown: true,
    exploited_override: true,
    malware_override: true,
    health_channels: ['slack'],
  },
};
function system(id = 'production', version = '1.0.0', overrides = {}) {
  return {
    id,
    name: id,
    environment: id,
    exposure: 'internal',
    criticality: 'high',
    updated_at: new Date(now).toISOString(),
    components: [
      { id: 'dep', ecosystem: 'npm', name: '@org/dep', ...(version === undefined ? {} : { version }) },
    ],
    products: [],
    keywords: [],
    ...overrides,
  };
}
function advisory(overrides = {}) {
  return {
    id: 'osv:GHSA-aaaa-bbbb-cccc',
    source: 'osv',
    kind: 'advisory',
    title: 'Dependency vulnerability',
    url: 'https://example.com/advisory',
    description: '',
    aliases: ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-10001'],
    severity: 'critical',
    modified_at: '2026-10-23T12:00:00Z',
    fetched_at: new Date(now).toISOString(),
    packages: [{ ecosystem: 'npm', name: '@org/dep', range: '<2.0.0', fixed: '2.0.0' }],
    ...overrides,
  };
}

test('affected and excluded deployments receive separate decisions; source critical floor survives AI downgrade', () => {
  const findings = assess(
    { systems: [system('production'), system('staging', '2.0.0')] },
    [advisory()],
    config,
    now,
  );
  const production = findings.find((item) => item.system_id === 'production');
  const staging = findings.find((item) => item.system_id === 'staging');
  assert.equal(production.applicability, 'affected');
  assert.equal(staging.applicability, 'not_affected');
  assert.equal(decide({ ...production, priority: 'low' }, config).action, 'notify');
  assert.equal(decide(staging, config).action, 'record');
  assert.notEqual(production.id, staging.id);
});

test('exact ecosystem and scoped npm identity prevent substring and scope collisions', () => {
  const input = { systems: [system()] };
  for (const name of ['dep', '@other/dep', '@org/dependency']) {
    assert.deepEqual(
      assess(input, [advisory({ packages: [{ ecosystem: 'npm', name, range: '*' }] })], config, now),
      [],
    );
  }
  assert.deepEqual(
    assess(
      input,
      [advisory({ packages: [{ ecosystem: 'PyPI', name: '@org/dep', range: '*' }] })],
      config,
      now,
    ),
    [],
  );
});

test('missing versions, stale inventory and unproven OSV exclusions require urgent critical investigation', () => {
  const missing = system();
  delete missing.components[0].version;
  for (const input of [missing, system('production', '3.0.0', { updated_at: '2026-01-01T00:00:00Z' })]) {
    const finding = assess({ systems: [input] }, [advisory()], config, now)[0];
    assert.equal(finding.applicability, 'unknown');
    assert.equal(decide(finding, config).action, 'notify');
    assert.match(decide(finding, config).reason, /Investigation required/);
  }
  for (const claim of [
    { ecosystem: 'npm', name: '@org/dep', matched_versions: [] },
    { ecosystem: 'npm', name: '@org/dep', versions: ['0.9.0'] },
    { ecosystem: 'npm', name: '@org/dep', fixed: '0.9.0' },
  ]) {
    assert.equal(
      assess({ systems: [system()] }, [advisory({ packages: [claim] })], config, now)[0].applicability,
      'unknown',
    );
  }
  assert.deepEqual(assess({ systems: [system()] }, [], config, now), []);
});

test('verified OSV exact match proves affected; npm prerelease exclusion does not prove safety', () => {
  assert.equal(
    assess(
      { systems: [system()] },
      [advisory({ packages: [{ ecosystem: 'npm', name: '@org/dep', matched_versions: ['1.0.0'] }] })],
      config,
      now,
    )[0].applicability,
    'affected',
  );
  assert.equal(
    assess({ systems: [system('production', '1.0.0-beta.1')] }, [advisory()], config, now)[0].applicability,
    'unknown',
  );
  assert.equal(
    assess(
      { systems: [system()] },
      [advisory({ packages: [{ ecosystem: 'npm', name: '@org/dep', range: '>= 0.5.0, < 2.0.0' }] })],
      config,
      now,
    )[0].applicability,
    'affected',
  );
});

test('alias chains merge advisory origins, deduplicate revisions and preserve cross-source conflicts', () => {
  const old = advisory();
  const revised = advisory({
    modified_at: '2026-10-24T01:00:00Z',
    packages: [{ ecosystem: 'npm', name: '@org/dep', range: '<0.5.0' }],
  });
  const bridge = advisory({
    id: 'github:GHSA-xxxx-yyyy-zzzz',
    source: 'github',
    aliases: ['GHSA-xxxx-yyyy-zzzz', 'CVE-2026-10001'],
    packages: [{ ecosystem: 'npm', name: '@org/dep', range: '<0.5.0' }],
  });
  const third = advisory({
    id: 'vendor:CVE-2026-10002',
    source: 'vendor',
    aliases: ['CVE-2026-10002', 'GHSA-xxxx-yyyy-zzzz'],
  });
  const findings = assess({ systems: [system()] }, [old, revised, bridge, third, revised], config, now);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].applicability, 'conflicting');
  assert.equal(findings[0].evidence_ids.length, 3);
  assert.equal(decide(findings[0], config).action, 'notify');
  assert.equal(assess({ systems: [system()] }, [old, revised], config, now)[0].applicability, 'not_affected');
});

test('withdrawal updates are retained, and disagreement with another origin stays conflicting', () => {
  const withdrawn = advisory({ withdrawn: true, modified_at: '2026-10-24T01:00:00Z' });
  const findings = assess({ systems: [system()] }, [advisory(), withdrawn], config, now);
  assert.equal(findings[0].withdrawn, true);
  assert.equal(findings[0].applicability, 'unknown');
  assert.equal(decide(findings[0], config).action, 'record');
  const disputed = assess(
    { systems: [system()] },
    [withdrawn, advisory({ source: 'github', id: 'github:GHSA-aaaa-bbbb-cccc' })],
    config,
    now,
  )[0];
  assert.equal(disputed.applicability, 'conflicting');
  assert.equal(disputed.withdrawn, false);
});

test('a multi-CVE news article enriches separate findings without joining their identities or bypassing library rules', () => {
  const first = advisory({ severity: 'high' });
  const second = advisory({
    id: 'osv:GHSA-dddd-eeee-ffff',
    aliases: ['GHSA-dddd-eeee-ffff', 'CVE-2026-10002'],
    severity: 'high',
  });
  const news = advisory({
    id: 'feed:story',
    source: 'feed',
    kind: 'news',
    title: '@org/dep issues',
    aliases: ['CVE-2026-10001', 'CVE-2026-10002'],
    packages: [],
    severity: 'high',
  });
  const findings = assess({ systems: [system()] }, [first, second, news], config, now);
  assert.equal(findings.length, 2);
  assert.equal(new Set(findings.map((item) => item.event_id)).size, 2);
  for (const finding of findings) {
    assert.equal(finding.category, 'library');
    assert.equal(finding.evidence_ids.includes('feed:story'), true);
    assert.equal(decide(finding, config).action, 'record');
  }
});

test('KEV enriches only a matching advisory and enables exploitation override without generic duplicate findings', () => {
  const kev = advisory({
    id: 'kev:CVE-2026-10001',
    source: 'kev',
    kind: 'kev',
    aliases: ['CVE-2026-10001'],
    packages: [],
    severity: 'unknown',
    exploited: true,
  });
  assert.deepEqual(assess({ systems: [system()] }, [kev], config, now), []);
  const findings = assess({ systems: [system()] }, [advisory({ severity: 'low' }), kev], config, now);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].exploited, true);
  assert.equal(decide(findings[0], config).action, 'notify');
});

test('product version and apparent distro backport do not become unsupported safe decisions', () => {
  const inventory = {
    systems: [
      system('prod', '1.0.0', {
        components: [],
        products: [{ name: 'OpenSSL', version: '3.0.2-ubuntu42', keywords: [] }],
      }),
    ],
  };
  const finding = assess(inventory, [advisory({ title: 'OpenSSL flaw', packages: [] })], config, now)[0];
  assert.equal(finding.category, 'product');
  assert.equal(finding.applicability, 'unknown');
  assert.equal(decide({ ...finding, relevance: 'irrelevant' }, config).action, 'notify');
});

test('standalone news requires whole-name context and unclassified news enters review', () => {
  const inventory = { systems: [system('production', '1.0.0', { components: [], keywords: ['express'] })] };
  const story = advisory({
    id: 'feed:story',
    source: 'feed',
    kind: 'news',
    title: 'New regular expressions issue',
    aliases: [],
    packages: [],
    severity: 'high',
  });
  assert.deepEqual(assess(inventory, [story], config, now), []);
  const finding = assess(inventory, [{ ...story, title: 'Express security release' }], config, now)[0];
  assert.equal(finding.category, 'news');
  assert.equal(decide(finding, config).action, 'digest');
  assert.equal(decide({ ...finding, relevance: 'irrelevant' }, config).action, 'digest');
});

test('uncertain lower-severity findings enter a review digest, while unscored malware uses its explicit override', () => {
  const missing = system();
  delete missing.components[0].version;
  const unknown = assess({ systems: [missing] }, [advisory({ severity: 'medium' })], config, now)[0];
  assert.equal(decide(unknown, config).action, 'digest');
  const malware = assess(
    { systems: [system()] },
    [advisory({ severity: 'unknown', malware: true })],
    config,
    now,
  )[0];
  assert.equal(malware.category, 'malware');
  assert.equal(decide(malware, config).action, 'notify');
});

test('identified library news cannot use news thresholds before structured advisory evidence arrives', () => {
  const story = advisory({
    id: 'feed:story',
    source: 'feed',
    kind: 'news',
    title: '@org/dep advisory GHSA-aaaa-bbbb-cccc',
    aliases: ['GHSA-aaaa-bbbb-cccc'],
    packages: [],
    severity: 'high',
  });
  const initial = assess({ systems: [system()] }, [story], config, now);
  assert.equal(initial.length, 1);
  assert.equal(initial[0].category, 'library');
  assert.equal(initial[0].applicability, 'unknown');
  assert.equal(initial[0].component_id, 'dep');
  assert.equal(decide(initial[0], config).action, 'digest');
  const repeated = assess(
    { systems: [system()] },
    [story, { ...story, id: 'feed:second-story', title: 'Another report about @org/dep' }],
    config,
    now,
  );
  assert.equal(repeated.length, 1);
  assert.equal(repeated[0].evidence_ids.length, 2);
  const later = assess({ systems: [system()] }, [story, advisory({ severity: 'high' })], config, now);
  assert.equal(later.length, 1);
  assert.equal(later[0].id, initial[0].id);
  assert.equal(later[0].applicability, 'affected');
  assert.equal(decide(later[0], config).action, 'record');
  const unrelated = assess(
    { systems: [system()] },
    [{ ...story, title: '@other/dep advisory', aliases: ['CVE-2026-10001'] }],
    config,
    now,
  );
  assert.deepEqual(unrelated, []);
});

test('a partly matched multi-CVE story preserves the unstructured advisory candidate', () => {
  const known = advisory({ packages: [{ ecosystem: 'npm', name: 'other-package', range: '<2.0.0' }] });
  const story = advisory({
    id: 'feed:roundup',
    source: 'feed',
    kind: 'news',
    title: '@org/dep security roundup',
    aliases: ['CVE-2026-10001', 'CVE-2026-10002'],
    packages: [],
  });
  const findings = assess({ systems: [system()] }, [known, story], config, now);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].event_id, 'CVE-2026-10002');
  assert.equal(findings[0].category, 'library');
  assert.equal(findings[0].applicability, 'unknown');
  assert.equal(decide(findings[0], config).action, 'notify');
});

test('independent unstructured CVEs in one story do not lose their separate identities', () => {
  const story = advisory({
    id: 'feed:roundup',
    source: 'feed',
    kind: 'news',
    title: '@org/dep security roundup',
    aliases: ['CVE-2026-10001', 'CVE-2026-10002'],
    packages: [],
  });
  const findings = assess({ systems: [system()] }, [story], config, now);
  assert.deepEqual(findings.map((f) => f.event_id).sort(), ['CVE-2026-10001', 'CVE-2026-10002']);
  assert.ok(findings.every((f) => f.applicability === 'unknown'));
});

test('AI news irrelevance cannot suppress source-critical findings or enabled exploitation overrides', () => {
  const story = advisory({
    id: 'feed:story',
    source: 'feed',
    kind: 'news',
    title: 'Express security release',
    aliases: [],
    packages: [],
  });
  const inventory = { systems: [system('production', '1.0.0', { components: [], keywords: ['express'] })] };
  const critical = assess(inventory, [story], config, now)[0];
  assert.equal(decide({ ...critical, relevance: 'irrelevant' }, config).action, 'notify');
  assert.equal(
    decide({ ...critical, relevance: 'irrelevant', applicability: 'unknown' }, config).action,
    'notify',
  );
  const exploited = {
    ...critical,
    relevance: 'irrelevant',
    source_severity: 'low',
    priority: 'high',
    exploited: true,
  };
  assert.equal(decide(exploited, config).action, 'notify');
  assert.equal(
    decide(exploited, { ...config, policy: { ...config.policy, exploited_override: false } }).action,
    'digest',
  );
});
