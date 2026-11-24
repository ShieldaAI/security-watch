import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'security-watch-pack-'));
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error('Run through npm run check.');
function run(args, cwd = temp) {
  const result = spawnSync(process.execPath, args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || 'Package check failed');
  return result.stdout;
}
// The published package carries npm-shrinkwrap.json (prepack writes it); --ignore-scripts skips
// prepack, so it is written here the same way and removed afterwards.
run([join(root, 'scripts', 'shrinkwrap.mjs')], root);
try {
  const [packed] = JSON.parse(
    run([npmCli, 'pack', '--ignore-scripts', '--json', '--pack-destination', temp], root),
  );
  for (const file of packed.files)
    if (
      !/^(dist\/|examples\/|docs\/|package.json$|npm-shrinkwrap.json$|README.md$|CHANGELOG.md$|LICENSE$|SECURITY.md$|CONTRIBUTING.md$)/.test(
        file.path,
      )
    )
      throw new Error(`Unexpected packed file: ${file.path}`);
  for (const required of [
    'dist/cli.js',
    'dist/mcp-server.js',
    'dist/check.js',
    'npm-shrinkwrap.json',
    'dist/index.js',
    'dist/index.d.ts',
    'dist/sbom.js',
    'dist/manifests.js',
    'dist/intake.js',
    'dist/upload.js',
    'docs/sbom.md',
    'dist/coverage.js',
    'dist/inventory-evidence.js',
    'dist/python-version.js',
    'dist/cvss4.js',
    'dist/rehearsal.js',
    'dist/pilot-report.js',
    'dist/pilot-cases.js',
    'dist/pilot-recall.js',
    'dist/pilot-responses.js',
    'dist/vendor/cvss4-reference.js',
    'examples/agent-advisories-2026.json',
    'examples/agent-advisory-cases-2026.json',
    'examples/rehearsal.json',
    'README.md',
    'CHANGELOG.md',
    'SECURITY.md',
    'docs/configuration.md',
    'docs/compatibility.md',
    'dist/matching.js',
    'docs/cvss-v4-support.md',
    'docs/offline-rehearsal.md',
    'docs/pilot-report.md',
    'docs/pilot-cases.md',
    'docs/pilot-recall.md',
    'docs/vendor/cvss-v4-provenance.json',
    'docs/vendor/cvss-v4-LICENSE.txt',
    'LICENSE',
    'examples/advisories.json',
  ])
    if (!packed.files.some((file) => file.path === required))
      throw new Error(`Missing packed file: ${required}`);
  const consumer = join(temp, 'consumer');
  mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  run(
    [npmCli, 'install', '--ignore-scripts', '--no-audit', '--no-fund', join(temp, packed.filename)],
    consumer,
  );
  const cli = join(consumer, 'node_modules/@shieldaai/security-watch/dist/cli.js');
  if (run([cli, '--version'], consumer).trim() !== packed.version)
    throw new Error('CLI version does not match the packed package');
  // The shrinkwrap fixes every runtime package, sub-dependencies included, to the tested version.
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8')).packages;
  for (const [path, entry] of Object.entries(lock)) {
    if (!path || entry.dev) continue;
    const installed = join(consumer, 'node_modules', path.replace(/^node_modules\//, ''), 'package.json');
    const nested = join(consumer, 'node_modules/@shieldaai/security-watch', path, 'package.json');
    const file = existsSync(installed) ? installed : nested;
    if (!existsSync(file) || JSON.parse(readFileSync(file, 'utf8')).version !== entry.version)
      throw new Error(`Packed install did not use the shrinkwrapped ${path}@${entry.version}`);
  }
  const mcp = join(consumer, 'node_modules/@shieldaai/security-watch/dist/mcp-server.js');
  if (run([mcp, '--version'], consumer).trim() !== packed.version)
    throw new Error('MCP server version does not match the packed package');
  const providers = JSON.parse(run([cli, 'providers'], consumer));
  if (providers.length !== 22 || !providers.some((provider) => provider.id === 'anthropic'))
    throw new Error('Packed CLI provider catalog is incomplete');
  const templates = JSON.parse(run([cli, 'templates'], consumer));
  if (templates.length !== 24 || !templates.some((template) => template.id === 'python'))
    throw new Error('Packed CLI system templates are incomplete');
  const libraries = join(consumer, 'libraries.txt');
  writeFileSync(libraries, 'php:symfony/http-foundation@7.1.0\npython:Requests\n');
  const normalized = JSON.parse(run([cli, 'normalize-libraries', '--input', libraries], consumer));
  if (
    normalized.length !== 2 ||
    normalized[0].ecosystem !== 'Packagist' ||
    normalized[1].name !== 'requests' ||
    normalized[1].version !== undefined
  )
    throw new Error('Packed library normalization failed');
  const sbom = join(consumer, 'deployment.cdx.json');
  writeFileSync(
    sbom,
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [{ purl: 'pkg:pypi/langflow@1.9.0' }],
    }),
  );
  const imported = JSON.parse(run([cli, 'import-sbom', '--input', sbom], consumer));
  if (
    imported.components[0]?.name !== 'langflow' ||
    imported.components[0]?.ecosystem !== 'PyPI' ||
    imported.warnings.length
  )
    throw new Error('Packed SBOM import failed');
  // The packed CLI makes an SBOM from a project's lockfiles, and init builds a monitor from it.
  const project = join(consumer, 'project');
  mkdirSync(join(project, 'api'), { recursive: true });
  writeFileSync(join(project, 'requirements.txt'), 'requests==2.31.0\n');
  writeFileSync(
    join(project, 'api', 'go.mod'),
    'module example.com/api\n\nrequire github.com/gin-gonic/gin v1.9.1\n',
  );
  const projectSbom = JSON.parse(run([cli, 'sbom', '--project', project], consumer));
  if (
    projectSbom.bomFormat !== 'CycloneDX' ||
    projectSbom.components.map((component) => component.purl).join(' ') !==
      'pkg:golang/github.com/gin-gonic/gin@v1.9.1 pkg:pypi/requests@2.31.0'
  )
    throw new Error('Packed SBOM generation failed');
  const fromProject = join(consumer, 'from-project');
  run([cli, 'init', '--yes', '--directory', fromProject, '--project', project], consumer);
  const projectDoctor = JSON.parse(
    run([cli, 'doctor', '--config', join(fromProject, 'security-watch.yaml')], consumer),
  );
  if (
    !projectDoctor.ok ||
    projectDoctor.systems !== 1 ||
    projectDoctor.components !== 2 ||
    !projectDoctor.sources.osv
  )
    throw new Error('Packed init --project failed');
  const configured = join(consumer, 'configured');
  run(
    [
      cli,
      'init',
      '--yes',
      '--directory',
      configured,
      '--systems',
      'nodejs,python',
      '--notifications',
      'slack',
    ],
    consumer,
  );
  const credentials = join(configured, '.env');
  writeFileSync(credentials, 'SLACK_WEBHOOK_URL=https://hooks.slack.com/services/PACKAGE_TEST_ONLY\n', {
    mode: 0o600,
  });
  const doctor = JSON.parse(
    run(
      [cli, 'doctor', '--config', join(configured, 'security-watch.yaml'), '--credentials-file', credentials],
      consumer,
    ),
  );
  if (
    !doctor.ok ||
    doctor.systems !== 2 ||
    doctor.notification_channels.join(',') !== 'slack' ||
    doctor.poll_interval_minutes !== 30 ||
    doctor.news_lookback_minutes !== 40
  )
    throw new Error('Packed setup and credential loading failed');
  run([cli, 'init', '--yes'], consumer);
  const report = JSON.parse(
    run(
      [
        cli,
        'scan',
        '--dry-run',
        '--fixture',
        join(consumer, 'node_modules/@shieldaai/security-watch/examples/advisories.json'),
      ],
      consumer,
    ),
  );
  if (!report.findings.some((f) => f.applicability === 'affected'))
    throw new Error('Packed CLI did not match the fixture');
  writeFileSync(
    join(consumer, 'consumer.mts'),
    `import { ModelAnalyzer, safeHttp, deliverPending, attachLocation, type ModelState, type DeliveryOptions, type FindingLocation } from '@shieldaai/security-watch';
import { generateSbom, importSbom, DEPENDENCY_FILES, type GeneratedSbom, type SbomOptions, type DependencyFile } from '@shieldaai/security-watch';
import { startIntake, createIntakeHandler, uploadSbom, type IntakeUpload, type IntakeOptions, type RunningIntake, type UploadOptions } from '@shieldaai/security-watch';
const intakeStarter: (config: Parameters<typeof startIntake>[0], options?: IntakeOptions) => Promise<RunningIntake> = startIntake;
const uploader: (options: UploadOptions) => Promise<IntakeUpload> = uploadSbom;
if (typeof intakeStarter !== 'function' || typeof uploader !== 'function' || typeof createIntakeHandler !== 'function') throw new Error('Unexpected intake exports');
const sbomOptions: SbomOptions = { project: './project', production: true, exposure: 'internal' };
const generatedSbom: GeneratedSbom = generateSbom(sbomOptions);
const sbomFiles: DependencyFile[] = generatedSbom.files;
if (generatedSbom.packages !== 2 || sbomFiles.length !== 2 || !DEPENDENCY_FILES.npm.includes('package-lock.json') || typeof importSbom !== 'function') throw new Error('Unexpected SBOM exports');
import { assess, decide, collectSources, parseConfig, Store, PROVIDERS, providerDefinition, parseLibraryList, importCycloneDx, compareInventories, refreshCoverage, runRehearsal, readRehearsal, readPilotReport, readPilotBackupReport, createPilotCasePacket, scorePilotCases, scorePilotRecall, type PilotIncidentReference, type PilotRecallScore, type PilotCasePacket, type PilotFeedback, type PilotScore, type PilotReport, type RehearsalReport, type CoverageReceipt, type Ecosystem, type Assessment, type AiReview, type ModelProvider, type Inventory } from '@shieldaai/security-watch';
const recallScorer: (path: string, window: { from: string, until: string }, reference: PilotIncidentReference) => Promise<PilotRecallScore> = scorePilotRecall;
import { createPilotResponseTemplate, scorePilotResponses, type PilotResponseRegister, type PilotResponseScore } from '@shieldaai/security-watch';
const responseScorer: (path: string, window: { from: string, until: string }, incidents: PilotIncidentReference, register: PilotResponseRegister) => Promise<PilotResponseScore> = scorePilotResponses;
if (typeof responseScorer !== 'function' || typeof createPilotResponseTemplate !== 'function') throw new Error('Missing pilot response API');
if (typeof recallScorer !== 'function') throw new Error('Missing incident recall API');
const prepareCases: (path: string, window: { from: string, until: string }) => Promise<PilotCasePacket> = createPilotCasePacket;
const scoreCases: (path: string, window: { from: string, until: string }, feedback: PilotFeedback) => Promise<PilotScore> = scorePilotCases;
if (typeof prepareCases !== 'function' || typeof scoreCases !== 'function') throw new Error('Missing pilot scoring exports');
const pilotReader: (path: string, window: { from: string, until: string }) => PilotReport = readPilotReport;
const pilotBackupReader: (path: string, window: { from: string, until: string }) => Promise<PilotReport> = readPilotBackupReport;
if (typeof pilotReader !== 'function' || typeof pilotBackupReader !== 'function') throw new Error('Missing pilot report readers');
const rehearsalRunner: (...args: Parameters<typeof runRehearsal>) => Promise<RehearsalReport> = runRehearsal;
if (typeof rehearsalRunner !== 'function' || typeof readRehearsal !== 'function') throw new Error('Missing rehearsal exports');
const receipts: CoverageReceipt[] = refreshCoverage([]);
if (receipts.length || compareInventories(undefined, { systems: [] }).length || typeof importCycloneDx !== 'function') throw new Error('Unexpected inventory/coverage exports');
const ecosystem: Ecosystem = 'Packagist';
if (parseLibraryList('symfony/http-foundation', ecosystem)[0]?.ecosystem !== ecosystem) throw new Error('Unexpected ecosystem exports');
const provider: ModelProvider = 'anthropic';
const config = parseConfig({version: 1, poll_interval_minutes: 30, news_lookback_minutes: 40});
const now = Date.now();
const python = assess({systems:[{id:'python',name:'python',environment:'production',exposure:'internal',criticality:'high',updated_at:new Date(now).toISOString(),components:[{id:'mcp',ecosystem:'PyPI',name:'mcp',version:'1.30.0'}],products:[],keywords:[]}]},[{id:'fixture',source:'fixture',kind:'advisory',title:'MCP',url:'https://github.com/advisories/GHSA-w4fh-qvv9-3v23',description:'',aliases:[],severity:'high',modified_at:new Date(now).toISOString(),fetched_at:new Date(now).toISOString(),packages:[{ecosystem:'PyPI',name:'mcp',range:'>=1.10.0,<1.30.0'}]}],config,now);
if(python[0]?.applicability!=='not_affected') throw new Error('Packed PEP 440 evaluator failed');
const store = new Store(':memory:');
// The published types must compile together: the analyzer takes the published Store, or a caller's own state.
const analyzer = new ModelAnalyzer(config, store, safeHttp);
const ownState: ModelState = { getMeta: () => undefined, setMeta: () => undefined, reserveBudget: () => true };
if (typeof analyzer.analyze !== 'function' || typeof new ModelAnalyzer(config, ownState, safeHttp).analyze !== 'function') throw new Error('Missing analyzer');
const deliveryOptions: DeliveryOptions = { now };
const delivered = await deliverPending(store, config, safeHttp, deliveryOptions);
if (delivered.accepted || delivered.failed || delivered.unknown) throw new Error('Unexpected delivery from an empty store');
const where: FindingLocation | undefined = attachLocation({ id: 'f', event_id: 'e', system_id: 'none', category: 'library', applicability: 'unknown', source_severity: 'low', priority: 'low', title: 't', summary: 's', reasons: [], evidence_ids: [], urls: [], exploited: false, updated_at: new Date(now).toISOString() }, { systems: [] }).location;
if (where !== undefined) throw new Error('Unexpected location');
const findings: Assessment[] = store.findings();
const reviews: AiReview[] = store.reviews({ limit: 10 });
if (reviews.length || store.reviewSummary().pending || config.policy.ai_dismissals !== 'review') throw new Error('Unexpected review contract');
if (config.version !== 1 || findings.length) throw new Error('Unexpected exports');
if (config.news_lookback_minutes !== 40 || config.poll_interval_minutes !== 30) throw new Error('Unexpected timing configuration');
if (PROVIDERS.length !== 22 || providerDefinition(provider).apiKeyEnv !== 'ANTHROPIC_API_KEY') throw new Error('Unexpected provider exports');
store.close();
const cvssConfig = parseConfig({ version: 1,
  sources: { osv: true, github: false, cve_now: false, hacker_news: false, kev: false, feeds: [], vendor_feeds: [] },
  policy: { library: { levels: ['critical'], channels: ['slack'] } },
  notifications: { slack: { webhook_url_env: 'PACKED_EVIDENCE_NEVER_READ' } } });
const cvssInventory: Inventory = { systems: [{ id: 'packed-v4', name: 'Synthetic scoring fixture',
  environment: 'test', exposure: 'internal', criticality: 'low', updated_at: new Date(now).toISOString(),
  components: [{ id: 'alpha', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }], products: [], keywords: [] }] };
const vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
const advisoryId = 'GHSA-aaaa-bbbb-cccc';
const collected = await collectSources(cvssInventory, cvssConfig, {}, async url => {
  if (url.endsWith('/querybatch')) return { status: 200, headers: {}, body: JSON.stringify({ results: [{ vulns: [{ id: advisoryId }] }] }) };
  if (!url.endsWith('/vulns/' + advisoryId)) throw new Error('Unexpected packed evidence request');
  return { status: 200, headers: {}, body: JSON.stringify({ id: advisoryId,
    modified: new Date(now).toISOString(), summary: 'Synthetic CVSS 4 severity fixture', details: 'Affected alpha versions precede 2.0.0.',
    severity: [{ type: 'CVSS_V4', score: vector }],
    affected: [{ package: { ecosystem: 'npm', name: 'alpha' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] }) };
}, now);
const scored = collected.evidence[0];
if (collected.errors.length || collected.evidence.length !== 1 || scored?.severity !== 'critical' ||
    scored.cvss_v4?.base_scores[0]?.score !== 9.3 || scored.cvss_v4.unsupported_vectors !== 0)
  throw new Error('Packed CVSS 4 scorer or diagnostics missing');
const assessed = assess(cvssInventory, collected.evidence, cvssConfig, now)[0];
if (!assessed || assessed.applicability !== 'affected' || decide(assessed, cvssConfig).action !== 'notify')
  throw new Error('Packed CVSS 4 evidence did not preserve critical notification eligibility');
const evidenceStore = new Store(':memory:');
try {
  evidenceStore.saveEvidence(collected.evidence, {});
  evidenceStore.saveAssessment(assessed, decide(assessed, cvssConfig), now);
  if (evidenceStore.jobs().filter(job => job.status === 'pending' && JSON.parse(job.payload).mode === 'notify').length !== 1)
    throw new Error('Packed CVSS 4 result did not reach the local outbox');
} finally { evidenceStore.close(); }
`,
  );
  run(
    [
      join(root, 'node_modules/typescript/bin/tsc'),
      'consumer.mts',
      '--module',
      'NodeNext',
      '--moduleResolution',
      'NodeNext',
      '--target',
      'ES2023',
      '--strict',
      '--skipLibCheck',
      'false',
      '--types',
      'node',
      '--typeRoots',
      join(root, 'node_modules/@types'),
      '--outDir',
      'compiled',
    ],
    consumer,
  );
  run([join(consumer, 'compiled/consumer.mjs')], consumer);
  writeFileSync(
    join(consumer, 'review-config.json'),
    JSON.stringify({ version: 1, database: './review.db' }),
  );
  writeFileSync(
    join(consumer, 'review-fixture.mjs'),
    `import { Store, parseConfig, decide, deliverPending } from '@shieldaai/security-watch';
import { mock } from 'node:test';
const store = new Store('./review.db');
try {
  const assessment = { id: 'packed-review', event_id: 'synthetic-news', system_id: 'synthetic-system',
    category: 'news', news_candidate: true, applicability: 'relevant', source_severity: 'low', priority: 'low',
    title: 'Synthetic general news', summary: 'Offline package review fixture', reasons: [], evidence_ids: [], urls: [],
    exploited: false, updated_at: new Date().toISOString(),
    ai: { model: 'offline', provider: 'synthetic', prompt_version: 'fixture', status: 'complete' },
    news_analysis: { classification: 'general_news', impact: 'not_applicable', affected_products: [], affected_versions: [],
      prerequisites: [], rationale: 'Synthetic fixture', quotes: [] } };
  const config = parseConfig({ version: 1,
    policy: { news: { levels: ['critical'], basis: 'source_severity', channels: ['email'] } },
    notifications: { email: { smtp_url_env: 'PACK_TEST_SMTP', from: 'watch@example.org', to: ['ops@example.org'] } } });
  const at = Date.parse('2025-06-10T14:00:00Z'), due = at + 60_000;
  store.saveAssessment(assessment, decide(assessment, config), at, 60_000);
  let time = due;
  const clock = mock.method(Date, 'now', () => time);
  try {
    const result = await deliverPending(store, config, () => { throw new Error('Unexpected HTTP'); }, due,
      async ({ to }) => { time += 300; return { accepted: to, rejected: [] }; }, undefined,
      { PACK_TEST_SMTP: 'smtps://fixture.invalid' });
    if (result.accepted !== 1 || store.jobs()[0].accepted_at !== due + 300) throw new Error('Missing simulated SMTP acknowledgement');
  } finally { clock.mock.restore(); }
} finally { store.close(); }
`,
  );
  run([join(consumer, 'review-fixture.mjs')], consumer);
  const pendingReviews = JSON.parse(run([cli, 'reviews', '--config', 'review-config.json'], consumer));
  if (pendingReviews.reviews.length !== 1 || pendingReviews.summary.pending !== 1)
    throw new Error('Packed CLI did not retain the AI dismissal for review');
  const reviewed = JSON.parse(
    run(
      [
        cli,
        'review',
        'packed-review',
        '--config',
        'review-config.json',
        '--revision',
        String(pendingReviews.reviews[0].revision),
        '--disposition',
        'dismiss',
        '--reviewer',
        'packed-test-operator',
        '--reason',
        'Synthetic evidence checked',
      ],
      consumer,
    ),
  );
  if (reviewed.delivery_sent !== false)
    throw new Error('Packed local review must not dispatch notifications');
  const reviewHistory = JSON.parse(
    run([cli, 'reviews', '--all', '--config', 'review-config.json'], consumer),
  );
  if (reviewHistory.reviews[0]?.status !== 'dismissed' || reviewHistory.summary.pending !== 0)
    throw new Error('Packed CLI did not retain the operator verdict');
  const dbPath = join(consumer, 'review.db');
  const databaseBefore = readFileSync(dbPath);
  const pilotArgs = [
    cli,
    'pilot-report',
    '--database',
    dbPath,
    '--from',
    '2025-06-10',
    '--until',
    '2025-06-11',
  ];
  const serializedPilot = run(pilotArgs, consumer);
  const pilot = JSON.parse(serializedPilot);
  if (
    pilot.mode !== 'pilot_report' ||
    pilot.window.days !== 1 ||
    pilot.activity.finding_revisions !== 1 ||
    pilot.snapshot.reviews.pending !== 0 ||
    pilot.unmeasured.false_alert_rate !== null ||
    [
      'packed-review',
      'Synthetic general news',
      'packed-test-operator',
      'Synthetic evidence checked',
      dbPath,
    ].some((privateValue) => serializedPilot.includes(privateValue))
  )
    throw new Error('Packed pilot report lost its reporting window, current backlog, or privacy boundary');
  if (!readFileSync(dbPath).equals(databaseBefore))
    throw new Error('Packed pilot report changed the monitor database');
  const backupPath = join(consumer, 'pilot-backup.db');
  run([cli, 'backup', '--config', 'review-config.json', '--output', backupPath], consumer);
  const backupBefore = readFileSync(backupPath);
  const archivedPilot = JSON.parse(
    run(
      [cli, 'pilot-report', '--backup', backupPath, '--from', '2025-06-10', '--until', '2025-06-11'],
      consumer,
    ),
  );
  if (
    archivedPilot.activity.finding_revisions !== pilot.activity.finding_revisions ||
    !readFileSync(backupPath).equals(backupBefore) ||
    ['-wal', '-shm', '-journal'].some((suffix) => existsSync(backupPath + suffix))
  )
    throw new Error('Packed pilot report changed the standalone backup or lost the recorded finding');
  run([cli, 'verify-backup', '--input', backupPath], consumer);
  const windowArgs = ['--backup', backupPath, '--from', '2025-06-10', '--until', '2025-06-11'];
  const packetPath = join(consumer, 'analyst-packet.json');
  run([cli, 'pilot-cases', ...windowArgs, '--output', packetPath], consumer);
  const packetText = readFileSync(packetPath, 'utf8');
  const packet = JSON.parse(packetText);
  if (
    packet.cases.length !== 1 ||
    (process.platform !== 'win32' && (statSync(packetPath).mode & 0o077) !== 0) ||
    ['packed-test-operator', 'Synthetic evidence checked', 'ai_general_news'].some((value) =>
      packetText.includes(value),
    )
  )
    throw new Error('Packed pilot case export lost privacy or cases');
  const labelsPath = join(consumer, 'independent-labels.json');
  const reviews = ['analyst-one', 'analyst-two'].map((reviewer) => ({
    case_id: packet.cases[0].case_id,
    reviewer,
    blinded: true,
    label: 'benign',
  }));
  writeFileSync(
    labelsPath,
    JSON.stringify({ version: 1, packet_id: packet.packet_id, reviews, adjudications: [] }),
    { mode: 0o600 },
  );
  const scoreText = run([cli, 'pilot-score', ...windowArgs, '--input', labelsPath], consumer);
  const score = JSON.parse(scoreText);
  if (
    score.mode !== 'pilot_score' ||
    score.coverage.eligible !== 1 ||
    score.coverage.scored !== 1 ||
    score.policy.unnecessary_immediate.denominator !== 1 ||
    score.policy.unnecessary_immediate.numerator !== 0 ||
    [packet.cases[0].case_id, 'analyst-one', 'synthetic-system', labelsPath].some((value) =>
      scoreText.includes(value),
    )
  )
    throw new Error('Packed pilot scoring lost its labeled denominator or disclosed private details');
  if (
    !readFileSync(backupPath).equals(backupBefore) ||
    ['-wal', '-shm', '-journal'].some((suffix) => existsSync(backupPath + suffix))
  )
    throw new Error('Packed pilot scoring changed the standalone backup');
  const referencePath = join(consumer, 'urgent-incidents.json');
  const target = {
    system_ref: 'synthetic-system',
    component_ref: null,
    available_at: '2025-06-10T13:00:00.000Z',
    deadline_at: '2025-06-10T15:00:00.000Z',
  };
  writeFileSync(
    referencePath,
    JSON.stringify({
      version: 1,
      window: { from: '2025-06-10', until: '2025-06-11' },
      curator: 'analyst-one',
      selected_independently: true,
      incidents: [
        { ...target, incident_id: 'incident-one', event_refs: ['synthetic-news'] },
        { ...target, incident_id: 'incident-two', event_refs: ['unobserved-event'] },
      ],
    }),
    { mode: 0o600 },
  );
  const recallText = run([cli, 'pilot-recall', ...windowArgs, '--input', referencePath], consumer);
  const recall = JSON.parse(recallText);
  if (
    recall.mode !== 'pilot_recall' ||
    recall.reference_incidents !== 2 ||
    recall.metrics.on_time_observed.numerator !== 1 ||
    recall.metrics.on_time_observed.denominator !== 2 ||
    recall.metrics.on_time_immediate.numerator !== 0 ||
    recall.provider_acceptance.on_time.numerator !== 1 ||
    recall.provider_acceptance.on_time.denominator !== 2 ||
    recall.provider_acceptance.on_time_immediate.numerator !== 0 ||
    recall.provider_acceptance.without_retained_job !== 1 ||
    recall.outcomes.no_retained_match !== 1 ||
    [referencePath, 'analyst-one', 'unobserved-event', 'synthetic-system', 'incident-one'].some((value) =>
      recallText.includes(value),
    )
  )
    throw new Error('Packed pilot recall omitted an external incident or disclosed reference data');
  const worksheet = join(consumer, 'reviewer-worksheet.json');
  const templateArgs = [cli, 'pilot-response-template', ...windowArgs, '--input', referencePath];
  const noDestination = spawnSync(process.execPath, templateArgs, { cwd: consumer, encoding: 'utf8' });
  if (noDestination.status !== 1 || noDestination.stdout || noDestination.stderr.includes(referencePath))
    throw new Error('Packed pilot worksheet requires private file output');
  if (run([...templateArgs, '--output', worksheet], consumer))
    throw new Error('Packed pilot worksheet printed private incident IDs');
  const draftText = readFileSync(worksheet, 'utf8');
  const draft = JSON.parse(draftText);
  if (
    draft.recall_evaluation_id !== recall.evaluation_id ||
    draft.responses.map((row) => row.incident_id).join(',') !== 'incident-one,incident-two' ||
    draft.reviewer !== null ||
    draft.reviewed_independently !== false ||
    draft.responses.some(
      (row) => row.acknowledgement.status !== 'unreviewed' || row.triage.status !== 'unreviewed',
    ) ||
    ['synthetic-news', 'synthetic-system', 'analyst-one', 'provider_acceptance'].some((value) =>
      draftText.includes(value),
    ) ||
    (process.platform !== 'win32' && (statSync(worksheet).mode & 0o077) !== 0)
  )
    throw new Error('Packed pilot worksheet lost the frozen cohort, private permissions or blinding');
  const responseArgs = [
    cli,
    'pilot-recall',
    ...windowArgs,
    '--input',
    referencePath,
    '--responses',
    worksheet,
  ];
  const incomplete = spawnSync(process.execPath, responseArgs, { cwd: consumer, encoding: 'utf8' });
  if (incomplete.status !== 1 || incomplete.stdout)
    throw new Error('Packed CLI accepted a blank attestation');
  // A human can acknowledge an incident via another channel even when Watch had no matching finding.
  draft.reviewer = 'external-analyst';
  draft.reviewed_independently = true;
  draft.reviewed_through = '2025-06-11T00:00:00.000Z';
  draft.responses[1].acknowledgement = {
    status: 'observed',
    at: '2025-06-10T14:30:00.000Z',
    evidence_ref: 'case-event-123',
  };
  writeFileSync(worksheet, JSON.stringify(draft));
  const overwrite = spawnSync(process.execPath, [...templateArgs, '--output', worksheet], {
    cwd: consumer,
    encoding: 'utf8',
  });
  if (overwrite.status !== 1 || readFileSync(worksheet, 'utf8') !== JSON.stringify(draft))
    throw new Error('Packed pilot worksheet overwrote the independent analyst responses');
  const humanText = run(responseArgs, consumer),
    human = JSON.parse(humanText);
  if (
    human.mode !== 'pilot_responses' ||
    human.recall_evaluation_id !== recall.evaluation_id ||
    human.acknowledgement.on_time.numerator !== 1 ||
    human.acknowledgement.on_time.denominator !== 2 ||
    human.acknowledgement.outcomes.unreviewed !== 1 ||
    human.triage.outcomes.unreviewed !== 2 ||
    human.acknowledgement.paired_with_on_time_provider.both !== 0 ||
    human.acknowledgement.paired_with_on_time_provider.provider_only_confirmed !== 1 ||
    human.acknowledgement.paired_with_on_time_provider.human_only_confirmed !== 1 ||
    ['case-event-123', 'incident-two', 'external-analyst', 'synthetic-system', worksheet].some((value) =>
      humanText.includes(value),
    )
  )
    throw new Error(
      'Packed pilot response scoring lost independent human evidence, missing cases or redaction',
    );
  if (
    !readFileSync(backupPath).equals(backupBefore) ||
    ['-wal', '-shm', '-journal'].some((suffix) => existsSync(backupPath + suffix))
  )
    throw new Error('Packed pilot recall modified the original backup');
  const rehearsalNow = Date.now();
  const rehearsalAt = new Date(rehearsalNow).toISOString();
  const privateCanary = 'PACKED_REHEARSAL_PRIVATE_CANARY';
  const liveDatabase = join(consumer, 'rehearsal-live.db');
  writeFileSync(liveDatabase, privateCanary, { mode: 0o600 });
  writeFileSync(
    join(consumer, 'rehearsal-inventory.json'),
    JSON.stringify({
      systems: [
        {
          id: privateCanary,
          name: privateCanary,
          environment: 'test',
          exposure: 'internal',
          criticality: 'low',
          updated_at: rehearsalAt,
          components: [{ id: privateCanary, ecosystem: 'npm', name: 'alpha', version: '1.0.0' }],
          products: [],
          keywords: [],
        },
      ],
    }),
  );
  writeFileSync(
    join(consumer, 'rehearsal-config.json'),
    JSON.stringify({
      version: 1,
      database: liveDatabase,
      inventory: './rehearsal-inventory.json',
      models: {
        enabled: true,
        analysis: { provider: 'openai', model: privateCanary, api_key_env: 'REHEARSAL_PRIVATE_API_KEY' },
      },
      policy: { library: { levels: ['critical'], channels: ['slack'] } },
      notifications: { slack: { webhook_url_env: 'REHEARSAL_PRIVATE_WEBHOOK' } },
    }),
  );
  const rehearsalEvidence = {
    id: privateCanary,
    source: privateCanary,
    kind: 'advisory',
    severity: 'critical',
    title: privateCanary,
    description: privateCanary,
    url: 'https://private.example/' + privateCanary,
    aliases: ['CVE-2099-99999'],
    modified_at: rehearsalAt,
    fetched_at: rehearsalAt,
    packages: [{ ecosystem: 'npm', name: 'alpha', range: '<2.0.0' }],
  };
  writeFileSync(
    join(consumer, 'rehearsal-scenario.json'),
    JSON.stringify({
      version: 1,
      frames: [
        { at: rehearsalAt, evidence: [rehearsalEvidence] },
        { at: new Date(rehearsalNow + 60000).toISOString(), evidence: [rehearsalEvidence] },
      ],
    }),
  );
  for (const sink of ['accepted', 'unknown']) {
    const reportPath = join(consumer, `rehearsal-${sink}.json`);
    const args = [
      cli,
      'rehearse',
      '--config',
      'rehearsal-config.json',
      '--input',
      'rehearsal-scenario.json',
      '--sink',
      sink,
      '--output',
      reportPath,
    ];
    const stdout = run(args, consumer);
    const serialized = readFileSync(reportPath, 'utf8');
    const rehearsal = JSON.parse(serialized);
    if (
      rehearsal.mode !== 'offline_rehearsal' ||
      rehearsal.sink !== sink ||
      rehearsal.summary.delivery_states[sink] !== 1 ||
      rehearsal.summary.sink_calls !== 1 ||
      rehearsal.safety.network_requests !== 0 ||
      rehearsal.safety.external_deliveries !== 0 ||
      rehearsal.safety.live_database_opened !== false ||
      rehearsal.safety.credentials_loaded !== false ||
      rehearsal.recovery.backup_verified !== true ||
      rehearsal.recovery.restored !== true ||
      rehearsal.recovery.receipts_preserved !== true ||
      serialized.includes(privateCanary) ||
      stdout.includes(privateCanary)
    )
      throw new Error('Packed rehearsal did not preserve privacy, deduplication, receipts or recovery');
    if (process.platform !== 'win32' && (statSync(reportPath).mode & 0o077) !== 0)
      throw new Error('Packed rehearsal report permissions are not private');
    const repeated = spawnSync(process.execPath, args, { cwd: consumer, encoding: 'utf8' });
    if (repeated.status === 0 || readFileSync(reportPath, 'utf8') !== serialized)
      throw new Error('Packed rehearsal overwrote existing evidence');
  }
  if (
    readFileSync(liveDatabase, 'utf8') !== privateCanary ||
    existsSync(liveDatabase + '-wal') ||
    existsSync(liveDatabase + '-shm')
  )
    throw new Error('Packed rehearsal touched the configured live database');
  writeFileSync(
    join(consumer, 'offline-advisory-preview.mjs'),
    readFileSync(join(root, 'examples/offline-advisory-preview.mjs')),
  );
  run([join(consumer, 'offline-advisory-preview.mjs')], consumer);
  console.log(
    'Clean packed CLI, offline matching, CVSS 4 outbox, local AI review, independently labeled pilot scoring, external incident recall and analyst response timing, pilot report, isolated rehearsal/recovery, public types and exports passed.',
  );
} finally {
  rmSync(temp, { recursive: true, force: true });
  rmSync(join(root, 'npm-shrinkwrap.json'), { force: true });
}
