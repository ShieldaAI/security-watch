import type { Assessment, Component, Config, Evidence, Inventory, InventoryDrift, System } from './types.js';
import { hash } from './util.js';

/** Compares declarations; a changed or removed declaration never proves deployed remediation. */
export function compareInventories(previous: Inventory | undefined, current: Inventory): InventoryDrift[] {
  if (!previous) return [];
  const changes: InventoryDrift[] = [];
  const compare = (
    before: System | Component | undefined,
    after: System | Component | undefined,
    system: string,
    component?: string,
  ) => {
    const fields = [
      'version',
      'ecosystem',
      'name',
      'origin',
      'digest',
      'provenance',
      'configuration',
      'environment',
      'exposure',
      'artifact_kind',
      'purl',
      'source_url',
      'source_revision',
      'sbom_ref',
      'dependencies',
      'sbom_dependencies',
      'signature_verification',
      'attestation_verification',
      'remediation_evidence',
    ];
    const changed = fields.filter(
      (key) =>
        hash((before as unknown as Record<string, unknown> | undefined)?.[key] ?? null) !==
        hash((after as unknown as Record<string, unknown> | undefined)?.[key] ?? null),
    );
    if (before && after && !changed.length) return;
    changes.push({
      system_id: system,
      ...(component ? { component_id: component } : {}),
      change: !before ? 'added' : !after ? 'removed' : 'changed',
      fields: changed,
      ...(before?.digest ? { before_digest: before.digest } : {}),
      ...(after?.digest ? { after_digest: after.digest } : {}),
    });
  };
  const oldSystems = new Map(previous.systems.map((system) => [system.id, system]));
  const newSystems = new Map(current.systems.map((system) => [system.id, system]));
  for (const id of new Set([...oldSystems.keys(), ...newSystems.keys()])) {
    const before = oldSystems.get(id),
      after = newSystems.get(id);
    compare(before, after, id);
    const oldComponents = new Map(before?.components.map((component) => [component.id, component]) ?? []);
    const newComponents = new Map(after?.components.map((component) => [component.id, component]) ?? []);
    for (const component of new Set([...oldComponents.keys(), ...newComponents.keys()]))
      compare(oldComponents.get(component), newComponents.get(component), id, component);
  }
  return changes;
}

const profiles = [
  {
    identifiers: ['CVE-2026-116684', 'GHSA-W4FH-QVV9-3V23'],
    keys: [
      'validate_token_resource',
      'resource_server_url_configured',
      'access_token_resource_populated',
      'token_verifier_checks_audience',
    ],
    requirements: [
      'Use a release containing the mcp 1.30.0 (1.x) or 2.2.0 (2.x) fix. Upgrading alone does not enable audience checking.',
      'Enable validate_token_resource, configure resource_server_url for this server, and return the token audience as AccessToken.resource; alternatively verify audience independently in TokenVerifier.',
      'Reject tokens issued for another resource server in a deployment test. Record both accepted intended-audience and rejected wrong-audience requests.',
    ],
    url: 'https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-w4fh-qvv9-3v23',
  },
  {
    identifiers: ['CVE-2026-116685', 'GHSA-5H93-6WHR-6Q8J'],
    keys: ['mcp_transport', 'custom_http_client_used', 'follow_redirects', 'cross_origin_redirect_override'],
    requirements: [
      'Use a release containing the mcp 1.30.0 (1.x) or 2.2.0 (2.x) redirect fix; check custom HTTP clients do not override its redirect policy.',
      'Verify cross-origin redirects cannot forward custom credentials or request bodies, including OAuth traffic. Configure the final endpoint directly when a cross-origin redirect is rejected.',
      'Before upgrading, disable redirect following in supported custom clients. Rotate custom credentials if an uncontrolled redirect destination may have received them.',
    ],
    url: 'https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-5h93-6whr-6q8j',
  },
  {
    identifiers: ['CVE-2026-116686', 'GHSA-RWRF-2PQF-9J8J'],
    keys: [
      'mcp_role',
      'calls_untrusted_mcp_tools',
      'external_schema_refs_blocked',
      'schema_validation_network_access',
    ],
    requirements: [
      'Use a release containing the mcp 1.30.0 (1.x) or 2.2.0 (2.x) schema-resolution fix on clients calling tools.',
      'Verify remote and file schema references are rejected without network or file access, while in-document references remain usable. Include a stalled-endpoint negative test.',
      'Until upgraded, restrict tool use to trusted servers; screening external references is only a partial stopgap.',
    ],
    url: 'https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-rwrf-2pqf-9j8j',
  },
  {
    identifiers: ['CVE-2026-112346', 'GHSA-RP7H-CRM7-H5QJ'],
    keys: [
      'sandbox_workspace_backend',
      'sandbox_bind_address',
      'sandbox_authentication_required',
      'sandbox_session_keys_configured',
      'sandbox_port_reachable_from_untrusted_network',
    ],
    requirements: [
      'Upgrade the OpenHands Software Agent SDK deployment to a release containing the 1.52.0 fix; verify the actual workspace launcher and container image.',
      'Inspect published Docker/Apptainer ports and authentication: wildcard bindings plus missing session keys can expose the sandbox to reachable callers.',
      'Test unauthenticated HTTP and WebSocket access from outside the trusted host. Verify mounted workspace and secret-store access, even when the declared version is patched.',
    ],
    url: 'https://www.vulncheck.com/advisories/openhands-software-agent-sdk-unauthenticated-sandbox-agent-server-rce',
  },
  {
    identifiers: ['CVE-2026-8505', 'GHSA-CF6M-VC3M-7CGM'],
    keys: ['LANGFLOW_WEBHOOK_AUTH_ENABLE'],
    requirements: [
      'Upgrade langflow to a release containing the 1.9.1 webhook authentication fix; verify the current vendor guidance.',
      'Verify LANGFLOW_WEBHOOK_AUTH_ENABLE is true in the running deployment; an explicit false setting can preserve unauthenticated webhook access after upgrading.',
      'Verify webhook authentication and flow ownership using an unauthenticated negative test.',
    ],
    url: 'https://github.com/langflow-ai/langflow/security/advisories/GHSA-cf6m-vc3m-7cgm',
  },
  {
    identifiers: ['CVE-2026-71433', 'GHSA-47PJ-3JCM-6WHG'],
    keys: ['namespace_used_as_tenant_boundary'],
    requirements: [
      'Upgrade affected langgraph-checkpoint-postgres/sqlite stores to a release containing the 3.1.1 fix; verify current vendor guidance.',
      'If namespaces isolate tenants, test sibling-prefix namespaces for cross-tenant reads and review application authorization separately.',
    ],
    url: 'https://github.com/langchain-ai/langgraph/security/advisories/GHSA-47pj-3jcm-6whg',
  },
];

/**
 * Copy the inventory's own names and notes onto a finding so a notification says where to look.
 * This is the operator's text, not evidence: it never changes applicability, priority or routing.
 */
export function attachLocation(finding: Assessment, inventory: Inventory): Assessment {
  if (finding.category === 'health') return finding;
  const system = inventory.systems.find((item) => item.id === finding.system_id);
  if (!system) return finding;
  const component = system.components.find((item) => item.id === finding.component_id);
  const product = finding.component_id?.startsWith('product:')
    ? system.products.find((item) => `product:${item.name.toLowerCase()}` === finding.component_id)
    : undefined;
  const label = component
    ? `${component.ecosystem} ${component.name}${component.version ? ` ${component.version}` : ''}`
    : product
      ? `${product.name}${product.version ? ` ${product.version}` : ''}`
      : undefined;
  const note = component?.note ?? product?.note;
  return {
    ...finding,
    location: {
      system: system.name,
      ...(system.owner ? { owner: system.owner } : {}),
      ...(system.note ? { system_note: system.note } : {}),
      ...(label ? { component: label } : {}),
      ...(note ? { component_note: note } : {}),
    },
  };
}

/** Cited guidance and operator observations, never an automatic closure or configuration attestation. */
export function attachRemediation(
  finding: Assessment,
  inventory: Inventory,
  evidence: Evidence[],
  config: Config,
  now: number,
): Assessment {
  if (finding.category === 'health') return finding;
  const system = inventory.systems.find((item) => item.id === finding.system_id);
  if (!system) return finding;
  const component = system.components.find((item) => item.id === finding.component_id);
  const matching = evidence.filter((item) => finding.evidence_ids.includes(item.id));
  const ids = new Set(
    [finding.event_id, ...matching.flatMap((item) => [item.id, ...item.aliases])].map((id) =>
      id.toUpperCase(),
    ),
  );
  const profile = profiles.find((item) => item.identifiers.some((id) => ids.has(id)));
  const observation = component?.observation ?? system.observation;
  const digest = component?.digest ?? system.digest;
  const observed = observation ? Date.parse(observation.observed_at) : NaN;
  const fresh =
    Number.isFinite(observed) &&
    observed <= now + 300_000 &&
    now - observed <= config.inventory_stale_days * 86_400_000;
  const excluded = finding.applicability === 'not_affected';
  const records = [...(system.remediation_evidence ?? []), ...(component?.remediation_evidence ?? [])].filter(
    (record) => ids.has(record.event_id.toUpperCase()),
  );
  const signature = component ? component.signature_verification : system.signature_verification;
  const attestation = component ? component.attestation_verification : system.attestation_verification;
  return {
    ...finding,
    remediation: {
      status:
        excluded && !profile
          ? fresh && digest
            ? 'observed_version_excluded'
            : 'version_excluded'
          : 'review_required',
      ...(observation ? { observed_at: observation.observed_at } : {}),
      ...(digest ? { artifact_digest: digest } : {}),
      ...(records.length ? { operator_records: records } : {}),
      ...(signature ? { signature_verification: signature } : {}),
      ...(attestation ? { attestation_verification: attestation } : {}),
      source_urls: [...new Set([...finding.urls, ...(profile ? [profile.url] : [])])],
      requirements: profile?.requirements ?? [
        'Confirm the running artifact and installed version, review the cited fix, and verify the affected behavior after deployment.',
      ],
      configuration: Object.fromEntries(
        (profile?.keys ?? [])
          .filter((key) => system.configuration?.[key] !== undefined)
          .map((key) => [key, system.configuration![key]!]),
      ),
      note: 'Inventory, signature/attestation results and lifecycle observations are operator-supplied evidence, not verified attestations. Security Watch performs no cryptographic verification. Declared changes, deployment or supported verification do not close a finding. Version exclusion does not establish reachability, configuration safety or complete remediation.',
    },
  };
}
