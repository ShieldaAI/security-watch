// Local preparation and scoring for a frozen GitHub advisory/deployment cohort.
// The transport below accepts only local replay records and never opens a socket.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assess, collectSources, decide, parseConfig, Store } from '../dist/index.js';
import { normalizeEventId } from '../dist/assessment.js';
import { gradePilotRoutes, loadPilotCohort } from '../dist/pilot-cases.js';
import { readPrivatePilotJson } from '../dist/pilot-input.js';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const binding = (...parts) => hash(JSON.stringify(parts));
const output = (path, value) =>
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
class StudyError extends Error {}
function check(ok, message) {
  if (!ok) throw new StudyError(message);
}
function sourceBytes(dir, path, expected, name) {
  check(path === 'sources/' + name, 'Invalid referenced source filename.');
  const bytes = readFileSync(join(dir, path));
  check(hash(bytes) === expected, 'Source bytes differ from the roster.');
  return bytes;
}
function validateGate(gate, total) {
  // This implementation accepts exactly the proposed protocol. A new gate requires a new enrollment.
  check(
    [gate.min_cases, gate.min_risk, gate.min_urgent, gate.min_benign].every(Number.isSafeInteger) &&
      gate.min_cases >= 100 &&
      gate.min_risk >= 60 &&
      gate.min_urgent >= 1 &&
      gate.min_benign >= 1 &&
      gate.min_cases <= total &&
      Math.max(gate.min_risk, gate.min_urgent) + gate.min_benign <= total &&
      gate.require_every_case_resolved === true &&
      gate.max_quiet_risk === 0 &&
      gate.require_all_urgent_immediate === true &&
      gate.max_unnecessary_immediate === 0,
    'Unsupported gate.',
  );
}
function loadStudy(dir) {
  const rosterBytes = readFileSync(join(dir, 'case-inputs.json'));
  const policyBytes = readFileSync(join(dir, 'review-policy.json'));
  const releaseBytes = readFileSync(join(dir, 'release-evidence.json'));
  const policy = JSON.parse(policyBytes),
    roster = JSON.parse(rosterBytes),
    releases = JSON.parse(releaseBytes);
  const registryBytes = readFileSync(join(dir, 'registry/index.json'));
  const registry = JSON.parse(registryBytes);
  const rosterHash = hash(rosterBytes);
  const cutoff = Date.parse(policy.replay_at);
  check(
    policy.version === 1 &&
      cutoff >= Date.parse(policy.window.from) &&
      cutoff < Date.parse(policy.window.until),
    'Replay time falls outside the agreed window.',
  );
  const byCase = (rows) => {
    check(
      Array.isArray(rows) && rows.length === roster.cases.length,
      'Missing or duplicate release evidence.',
    );
    const result = new Map(rows.map((row) => [row.case_id, row]));
    check(result.size === rows.length, 'Missing or duplicate release evidence.');
    return result;
  };
  check(
    registry.version === 1 &&
      releases.version === 1 &&
      releases.case_inputs_sha256 === rosterHash &&
      registry.case_inputs_sha256 === rosterHash,
    'Release evidence belongs to a different roster.',
  );
  const releaseByCase = byCase(releases.releases),
    registryByCase = byCase(registry.release_documents);
  const keys = new Set(),
    targets = new Set();
  check(
    roster.version === 1 &&
      Array.isArray(roster.cases) &&
      roster.cases.length > 0 &&
      roster.cases.length <= 1000,
    'Invalid cohort size.',
  );
  validateGate(policy.gate, roster.cases.length);
  const cases = roster.cases.map((row) => {
    const { case_id, advisory: a, deployment: d } = row;
    const target = JSON.stringify([a.id, d.system_id, d.component_id]);
    check(
      /^sw-[a-f0-9]{16}$/.test(case_id) && !keys.has(case_id) && !targets.has(target),
      'Invalid or duplicated roster target.',
    );
    keys.add(case_id);
    targets.add(target);
    check(/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(a.id), 'Invalid advisory ID.');
    const archived = JSON.parse(sourceBytes(dir, a.source_file, a.source_sha256, a.id + '.json'));
    const github = JSON.parse(sourceBytes(dir, a.github_file, a.github_sha256, a.id + '.github.json'));
    check(archived.id === a.id && github.ghsa_id === a.id, 'Unexpected archived advisory.');
    const aliases = (list) => [...(list ?? [])].map(normalizeEventId).sort().join('|');
    const githubIds = new Set((github.identifiers ?? []).map((item) => normalizeEventId(item.value)));
    check(
      aliases(archived.aliases) === aliases(a.aliases) &&
        a.aliases.every((alias) => githubIds.has(normalizeEventId(alias))),
      'Advisory aliases disagree.',
    );
    check(
      archived.published === a.published &&
        archived.modified === a.modified &&
        [a.published, a.modified, github.published_at, github.updated_at].every(
          (value) => Date.parse(value) <= cutoff,
        ),
      'Advisory dates violate the study cutoff.',
    );
    const release = releaseByCase.get(case_id),
      registryDoc = registryByCase.get(case_id);
    check(
      release &&
        registryDoc &&
        ['ecosystem', 'package_name', 'version'].every((key) => release[key] === d[key]) &&
        Date.parse(release.released_at) <= cutoff,
      'Release evidence does not match the reviewed deployment or cutoff.',
    );
    check(
      registryDoc.source_file === 'registry/' + case_id + '.json' &&
        hash(readFileSync(join(dir, registryDoc.source_file))) === registryDoc.source_sha256,
      'Registry source bytes differ from the enrolled release.',
    );

    return { case_id, advisory: a, deployment: d, github };
  });
  // A graph of core runtime code, checkout driver, and installed dependency versions defines this replay.
  const dist = fileURLToPath(new URL('../dist/', import.meta.url));
  const runtime = readdirSync(dist)
    .filter((name) => name.endsWith('.js'))
    .sort()
    .map((name) => [name, hash(readFileSync(join(dist, name)))]);
  runtime.push(
    ['driver', hash(readFileSync(fileURLToPath(import.meta.url)))],
    ['lock', hash(readFileSync(new URL('../package-lock.json', import.meta.url)))],
  );
  return {
    cases,
    policy,
    rosterHash: hash(rosterBytes),
    policyHash: hash(policyBytes),
    releasesHash: hash(releaseBytes),
    registryHash: hash(registryBytes),
    runtimeHash: binding(runtime),
  };
}

async function replay(study, backup) {
  const { policy, cases } = study;
  const config = parseConfig({
    version: 1,
    models: { enabled: false },
    sources: {
      github: true,
      github_token_env: 'WATCH_HOLDOUT_UNUSED_AUTH',
      cve_now: false,
      hacker_news: false,
    },
    policy: { library: policy.library_rule, urgent_unknown: policy.urgent_unknown },
    notifications: { slack: { webhook_url_env: 'WATCH_HOLDOUT_UNUSED_DESTINATION' } },
  });
  const now = Date.parse(policy.replay_at);
  const sourceEpoch = '1970-01-01T00:00:00.000Z';
  const store = new Store(':memory:');
  try {
    for (const row of cases) {
      const { deployment: d, github } = row;
      const inventory = {
        systems: [
          {
            id: d.system_id,
            name: d.system_id,
            environment: d.environment,
            exposure: d.exposure,
            criticality: d.criticality,
            updated_at: policy.replay_at,
            components: [
              { id: d.component_id, ecosystem: d.ecosystem, name: d.package_name, version: d.version },
            ],
            products: [],
            keywords: [],
          },
        ],
      };
      const transport = async (url) => {
        const u = new URL(url),
          type = u.searchParams.get('type');
        check(
          u.origin === 'https://api.github.com' &&
            u.pathname === '/advisories' &&
            ['reviewed', 'malware'].includes(type),
          'Unexpected replay request.',
        );
        return { status: 200, headers: {}, body: JSON.stringify(type === 'reviewed' ? [github] : []) };
      };
      const source = await collectSources(
        inventory,
        config,
        { 'github:reviewed': sourceEpoch, 'github:malware': sourceEpoch },
        transport,
        now,
      );
      check(
        !source.errors.length &&
          source.evidence.length === 1 &&
          source.evidence[0].id === 'github:' + row.advisory.id,
        'GitHub replay failed to parse a selected advisory.',
      );
      store.saveEvidence(source.evidence, {});
      const findings = assess(inventory, source.evidence, config, now);
      check(findings.length <= 1, 'Ambiguous findings for one enrolled target.');
      for (const f of findings)
        store.saveAssessment(f, decide(f, config), now, 86_400_000, 'archived-advisory-replay');
    }
    await store.backup(backup);
  } finally {
    store.close();
  }
}

function studyId(study, packetId) {
  return binding(
    'security-watch.external-advisory-review.v1',
    study.rosterHash,
    study.releasesHash,
    study.registryHash,
    study.policyHash,
    study.runtimeHash,
    packetId,
  );
}
export async function prepare(dir, destination) {
  const study = loadStudy(dir);
  mkdirSync(destination, { mode: 0o700 });
  try {
    const backup = join(destination, 'replay.db');
    await replay(study, backup);
    const { packet } = await loadPilotCohort(backup, study.policy.window);
    const enrollment = studyId(study, packet.packet_id);
    const ballot = {
      version: 1,
      enrollment_id: enrollment,
      reviewer: null,
      blinded: false,
      reviews: study.cases.map((row) => ({
        case_id: row.case_id,
        label: null,
        applicability: null,
        evidence_support: null,
        rationale: null,
      })),
    };
    for (const slot of ['a', 'b']) output(join(destination, 'ballot-' + slot + '.json'), { ...ballot, slot });
    const receipt = {
      version: 1,
      enrollment_id: enrollment,
      roster_sha256: study.rosterHash,
      releases_sha256: study.releasesHash,
      registry_sha256: study.registryHash,
      policy_sha256: study.policyHash,
      runtime_sha256: study.runtimeHash,
      backup_packet_id: packet.packet_id,
      case_count: study.cases.length,
      mode: 'offline_deterministic',
    };
    output(join(destination, 'enrollment.json'), receipt);
    return receipt;
  } catch (error) {
    rmSync(destination, { recursive: true, force: true });
    throw error;
  }
}
const handles = /^[a-z][a-z0-9_-]{0,63}$/;
function validateJudgment(row) {
  check(
    ['affected', 'not_affected', 'unknown', 'conflicting'].includes(row.applicability) &&
      ['supported', 'unsupported', 'uncertain'].includes(row.evidence_support) &&
      typeof row.rationale === 'string' &&
      row.rationale.trim().length > 0 &&
      row.rationale.length <= 2000,
    'An answered case requires an applicability judgment, evidence support and a private rationale.',
  );
}
function collectBallot(ballot, slot, enrollment, ids, reviews) {
  check(
    ballot.version === 1 &&
      ballot.slot === slot &&
      ballot.enrollment_id === enrollment &&
      Array.isArray(ballot.reviews) &&
      ballot.reviews.length === ids.size,
    'Wrong ballot, enrollment or case count.',
  );
  const seen = new Set(),
    judgments = new Map();
  for (const row of ballot.reviews) {
    check(ids.has(row.case_id) && !seen.has(row.case_id), 'Unexpected or repeated ballot case.');
    seen.add(row.case_id);
    if (row.label === null) {
      check(
        row.rationale === null && row.evidence_support === null && row.applicability === null,
        'A partially filled case requires a routing judgment or an abstention.',
      );
      continue;
    }
    validateJudgment(row);
    judgments.set(row.case_id, row);
    check(
      ballot.blinded === true && handles.test(ballot.reviewer) && typeof ballot.reviewer === 'string',
      'Review requires an independent human declaration.',
    );
    reviews.push({
      case_id: ids.get(row.case_id),
      reviewer: ballot.reviewer,
      blinded: true,
      label: row.label,
    });
  }
  return judgments;
}
export async function score(dir, prepared, pin, adjudicationFile) {
  const study = loadStudy(dir);
  const { packet, routes } = await loadPilotCohort(join(prepared, 'replay.db'), study.policy.window);
  const enrollment = studyId(study, packet.packet_id);
  check(
    enrollment === pin &&
      readPrivatePilotJson(join(prepared, 'enrollment.json'), 'labels').enrollment_id === pin,
    'Frozen inputs, runtime, backup or enrollment digest changed.',
  );
  const ids = new Map(study.cases.map((c) => [c.case_id, binding(enrollment, c.case_id)]));
  const target = (event, system, component) => JSON.stringify([normalizeEventId(event), system, component]);
  const retained = new Map(
    packet.cases.map((c) => [target(c.event_ref, c.system_ref, c.component_ref), c.case_id]),
  );
  check(
    retained.size === packet.cases.length && !packet.excluded_revisions,
    'Ambiguous or excluded replay revision.',
  );
  const joined = new Map();
  let missing = 0;
  for (const c of study.cases) {
    const key = target(c.advisory.id, c.deployment.system_id, c.deployment.component_id);
    const recorded = retained.get(key);
    if (!recorded) missing++;
    joined.set(ids.get(c.case_id), recorded ? routes.get(recorded) : { immediate: false, quiet: true });
    retained.delete(key);
  }
  check(!retained.size, 'The backup contains cases outside the enrolled roster.');
  const reviews = [],
    adjudications = [];
  const read = (path) => readPrivatePilotJson(path, 'labels');
  const a = read(join(prepared, 'ballot-a.json')),
    b = read(join(prepared, 'ballot-b.json'));
  const first = collectBallot(a, 'a', enrollment, ids, reviews);
  const second = collectBallot(b, 'b', enrollment, ids, reviews);
  const evidenceDisagreements = new Set();
  for (const [id, x] of first) {
    const y = second.get(id);
    if (y && (x.applicability !== y.applicability || x.evidence_support !== y.evidence_support))
      evidenceDisagreements.add(ids.get(id));
  }
  check(
    a.reviewer === null || b.reviewer === null || a.reviewer !== b.reviewer,
    'The two ballots require distinct reviewers.',
  );
  if (adjudicationFile) {
    const file = read(adjudicationFile);
    check(
      file.version === 1 && file.enrollment_id === pin && Array.isArray(file.adjudications),
      'Invalid adjudication file.',
    );
    for (const row of file.adjudications) {
      check(ids.has(row.case_id), 'Unexpected case in adjudication.');
      validateJudgment(row);
      adjudications.push({ adjudicator: row.adjudicator, label: row.label, case_id: ids.get(row.case_id) });
    }
  }
  const results = gradePilotRoutes(
    { packet_id: pin, window: packet.window, excluded_revisions: 0 },
    joined,
    {
      version: 1,
      packet_id: pin,
      reviews,
      adjudications,
    },
    evidenceDisagreements,
  );
  const { coverage, policy } = results,
    gate = study.policy.gate;
  const violation =
    policy.quiet_risk.numerator > 0 ||
    policy.urgent_immediate.numerator < policy.urgent_immediate.denominator ||
    policy.unnecessary_immediate.numerator > 0;
  const ready =
    coverage.scored === coverage.eligible &&
    coverage.eligible >= gate.min_cases &&
    policy.quiet_risk.denominator >= gate.min_risk &&
    policy.urgent_immediate.denominator >= gate.min_urgent &&
    policy.unnecessary_immediate.denominator >= gate.min_benign;
  return {
    version: 1,
    mode: 'offline_deterministic',
    enrollment_id: pin,
    roster_cases: coverage.eligible,
    cases_without_a_finding: missing,
    evidence_disagreements: evidenceDisagreements.size,
    coverage,
    policy,
    status: violation ? 'failed' : ready ? 'passed' : 'inconclusive',
  };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [command, dir, prepared, pin, adjudications, ...extra] = process.argv.slice(2);
    check(
      dir &&
        prepared &&
        !extra.length &&
        ((command === 'prepare' && !pin) || (command === 'score' && /^[a-f0-9]{64}$/.test(pin))),
      'Use prepare CASE_DIRECTORY NEW_DIRECTORY, or score CASE_DIRECTORY PREPARED_DIRECTORY ENROLLMENT_SHA256 [ADJUDICATIONS.json].',
    );
    const result =
      command === 'prepare' ? await prepare(dir, prepared) : await score(dir, prepared, pin, adjudications);
    console.log(JSON.stringify(result, null, 2));
    if (command === 'score' && result.status !== 'passed') process.exitCode = 1;
  } catch (error) {
    console.error(
      error instanceof StudyError
        ? error.message
        : 'Holdout operation failed. Check private inputs, ballot declarations, backup and output permissions.',
    );
    process.exitCode = 2;
  }
}
