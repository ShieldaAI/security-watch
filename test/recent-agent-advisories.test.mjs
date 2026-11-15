import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readFixture, assess, attachRemediation, parseConfig } from '../dist/index.js';

const evidence = readFixture(new URL('../examples/agent-advisories-2026.json', import.meta.url).pathname);
const scenarios = JSON.parse(
  readFileSync(new URL('../examples/agent-advisory-cases-2026.json', import.meta.url), 'utf8'),
);
const now = Date.parse(scenarios.source_checked_at);
const config = parseConfig({ version: 1, sources: { cve_now: false, hacker_news: false } });

for (const scenario of scenarios.cases) {
  test(`source-derived advisory case: ${scenario.id}`, () => {
    const advisory = evidence.find((item) => item.id === scenario.advisory_id);
    assert.ok(advisory);
    assert.ok(Date.parse(advisory.published_at) <= now);
    assert.ok(Date.parse(advisory.modified_at) <= now);
    const inventory = {
      systems: [
        {
          id: 'agent',
          name: 'Agent',
          environment: 'production',
          exposure: 'internet',
          criticality: 'high',
          updated_at: scenarios.source_checked_at,
          components: scenario.component ? [scenario.component] : [],
          products: scenario.product ? [scenario.product] : [],
          keywords: [],
          configuration: { ...scenario.configuration, unrelated_secret: 'DO_NOT_INCLUDE' },
        },
      ],
    };
    const findings = assess(inventory, [advisory], config, now);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].applicability, scenario.expected_applicability);
    const result = attachRemediation(findings[0], inventory, [advisory], config, now);
    assert.equal(result.remediation.status, scenario.expected_remediation);
    assert.deepEqual(result.remediation.configuration, scenario.configuration);
    assert.ok(result.remediation.requirements.length >= 2);
    assert.ok(result.remediation.source_urls.includes(advisory.url));
    assert.equal(JSON.stringify(result.remediation).includes('DO_NOT_INCLUDE'), false);
    if (scenario.vendor_fixed_release && scenario.component) {
      assert.ok(advisory.packages.some((claim) => claim.fixed === scenario.component.version));
      assert.equal(
        result.applicability,
        'not_affected',
        'Supported PEP 440 bounds establish version exclusion only',
      );
    }
    if (scenario.product) {
      assert.deepEqual(
        advisory.packages,
        [],
        'CNA identifies the GitHub SDK product, not a registry package',
      );
      assert.match(result.remediation.requirements.join(' '), /1\.52\.0/);
    }
  });
}

test('audience remediation requires both SDK settings and verifier output; a version bump never closes it', () => {
  const scenario = scenarios.cases.find((item) => item.id === 'mcp-audience-fixed-release-misconfigured');
  const advisory = evidence.find((item) => item.id === scenario.advisory_id);
  const inventory = {
    systems: [
      {
        id: 'agent',
        name: 'Agent',
        environment: 'production',
        exposure: 'internal',
        criticality: 'high',
        updated_at: scenarios.source_checked_at,
        components: [scenario.component],
        products: [],
        keywords: [],
        configuration: scenario.configuration,
      },
    ],
  };
  const finding = assess(inventory, [advisory], config, now)[0];
  const result = attachRemediation(
    { ...finding, applicability: 'not_affected' },
    inventory,
    [advisory],
    config,
    now,
  );
  assert.equal(result.remediation.status, 'review_required');
  const guidance = result.remediation.requirements.join(' ');
  for (const term of [
    'validate_token_resource',
    'resource_server_url',
    'AccessToken.resource',
    'TokenVerifier',
  ])
    assert.ok(guidance.includes(term));
  assert.equal(result.remediation.configuration.validate_token_resource, false);
});

test('source records retain both supported MCP release lines and distinct vulnerable lower bounds', () => {
  const expected = [
    ['GHSA-w4fh-qvv9-3v23', '1.10.0'],
    ['GHSA-5h93-6whr-6q8j', '1.8.0'],
    ['GHSA-rwrf-2pqf-9j8j', '1.10.0'],
  ];
  for (const [id, first] of expected) {
    const advisory = evidence.find((item) => item.id === id);
    assert.deepEqual(
      advisory.packages.map((claim) => [claim.ecosystem, claim.name, claim.range, claim.fixed]),
      [
        ['PyPI', 'mcp', `>= ${first}, < 1.30.0`, '1.30.0'],
        ['PyPI', 'mcp', '>= 2.0.0, < 2.2.0', '2.2.0'],
      ],
    );
  }
});
