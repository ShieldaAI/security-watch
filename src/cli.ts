#!/usr/bin/env node
import { parseArgs } from 'node:util';
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, extname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { parse as parseYaml, stringify } from 'yaml';
import { z } from 'zod';
import { loadConfig, parseConfig, missingCredentials } from './config.js';
import { keepComponentIds, loadInventory } from './inventory.js';
import {
  checkAdvisory,
  checkChange,
  checkPackages,
  checkProject,
  formatAdvisoryReport,
  formatChangeReport,
  formatCheckReport,
  failsAt,
  type CheckFinding,
  type PackageQuery,
} from './check.js';
import { shieldCandidates } from './shield-candidates.js';
import { openVex } from './vex.js';
import { exportProblems, maxAges, readMitigationExport, withCurrentMitigations } from './mitigations.js';
import { syncShirudoSboms } from './shirudo-sboms.js';
import { importSbom } from './sbom.js';
import { DEPENDENCY_FILES, generateSbom, type GeneratedSbom, type SbomOptions } from './manifests.js';
import { intakeDirectory, startIntake } from './intake.js';
import { uploadSbom } from './upload.js';
import { refreshCoverage } from './coverage.js';
import { Store, readPilotReport } from './store.js';
import { PilotReportError } from './pilot-report.js';
import { runScan, readFixture, healthFinding } from './engine.js';
import { deliverPending, slackProblem, smtpProblem } from './delivery.js';
import { safeHttp, validateDestination } from './http.js';

/** The inventory as it is now, with the component identifiers the last scan gave its findings. */
function currentInventory(path: string, store: Store): Inventory {
  const baseline = store.getMeta('inventory:baseline');
  return keepComponentIds(loadInventory(path), baseline ? (JSON.parse(baseline) as Inventory) : undefined);
}

/** Whether the heartbeat would refuse this address. */
function heartbeatProblem(address: string, allowPrivate: boolean | undefined): boolean {
  try {
    const url = validateDestination(address, allowPrivate ?? false);
    return Boolean(url.username || url.password);
  } catch {
    return true;
  }
}
import { acquireLock, unlockStoppedWorker } from './lock.js';
import { decide } from './assessment.js';
import { catchingUpFrom, checkHealth } from './health.js';
import type { Assessment, Config, Inventory, Severity } from './types.js';
import { PROVIDERS, providerDefinition } from './providers.js';
import { loadEnvFile, starterSystems, SYSTEM_TEMPLATES } from './setup.js';
import { ECOSYSTEMS, parseLibraryList } from './ecosystems.js';
import { HeartbeatMonitor } from './heartbeat.js';
import { MaintenanceScheduler } from './operations.js';
import { createPilotCasePacket, readPilotFeedback, scorePilotCases } from './pilot-cases.js';
import { createPilotResponseTemplate, readPilotIncidentReference, scorePilotRecall } from './pilot-recall.js';
import { readPilotResponseRegister, scorePilotResponses } from './pilot-responses.js';
import { verifyBackup, readPilotBackupReport } from './maintenance.js';
import { readRehearsal, runRehearsal, type RehearsalSink } from './rehearsal.js';

const pilotCommands = new Set([
  'pilot-report',
  'pilot-cases',
  'pilot-score',
  'pilot-recall',
  'pilot-response-template',
]);
/**
 * The first scan of a new database reads a day of recent advisories at a polite pace.
 * Say so on the error stream, so a silent terminal is not mistaken for a hang.
 */
function firstScanNotice(config: Config, store: Store, offline: boolean): void {
  if (offline || !config.sources.cve_now || store.checkpoints().cve_now !== undefined) return;
  console.error(
    'First scan: reading the last day of advisories from cve.now, about one request a second. ' +
      'This can take 15 to 20 minutes; later scans usually take a minute or two. ' +
      'A dry run saves nothing, so the next scan starts from the beginning again.',
  );
}

/** The one place the version is defined is package.json, which ships beside the compiled files. */
const VERSION = (
  JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }
).version;
const help = `Shielda Security Watch ${VERSION}

  security-watch check [PROJECT] [--production] [--epss] [--fail-on high] [--json]
  security-watch check [PROJECT] --base REF        (only what a change since REF brings in)
  security-watch check --sbom FILE.json
  security-watch check --package npm:lodash@4.17.21 [--package pypi:requests@2.31.0 ...]
  security-watch check [PROJECT] --advisory CVE-2021-44906
  security-watch mcp [PROJECT]                     (MCP server on stdio, for AI agents)

  security-watch sbom [--project PATH] [--output FILE.cdx.json] [--name NAME] [--system-id ID]
    [--owner TEXT] [--environment TEXT] [--note TEXT] [--exposure internet|internal|unknown]
    [--criticality low|medium|high|critical] [--production] [--source-url URL] [--source-revision REV]
    [--upload URL [--token-env NAME] [--allow-http]]
  security-watch upload --input FILE.json --url URL [--system-id ID] [--token-env NAME] [--allow-http]
  security-watch intake [--config PATH] [--credentials-file PATH]
  security-watch init [--directory PATH] [--yes] [--project PATH ...] [--systems nodejs,python]
    [--libraries PATH --ecosystem php] [--vendor-feeds nodejs,python,php] [--heartbeat]
    [--provider NAME --model ID] [--endpoint URL] [--allow-private-endpoint]
    [--poll-minutes 30] [--lookback-minutes 40]
    [--notifications slack,email] [--email-from ADDRESS] [--email-to ADDRESS,ADDRESS]
  security-watch doctor [--config PATH] [--credentials-file PATH]
  security-watch providers
  security-watch templates
  security-watch ecosystems
  security-watch import-sbom --input PATH [--output PATH]   (CycloneDX or SPDX JSON)
  security-watch coverage | inventory-drift [--config PATH]
  security-watch normalize-libraries --input PATH [--ecosystem php] [--output PATH]
  security-watch scan [--dry-run] [--notify] [--fixture PATH] [--no-ai]
  security-watch rehearse --config PATH --input SCENARIO.json [--sink disabled|accepted|failed|unknown] [--output NEW.json]
  security-watch start [--config PATH]
  security-watch findings | status | deliveries | budget
  security-watch shield-candidates [--all] [--unmitigated] [--omit-location] [--output NEW.json]
  security-watch vex [--system ID] [--include-not-affected] [--omit-mitigations] [--author TEXT] [--output NEW.json]
  security-watch shirudo-sboms --store DIR --directory SBOM_DIR [--running EXPORT.jsonl] [--config PATH] [--apply] [--allow-removals]
  security-watch pilot-report (--database PATH | --backup PATH) --from YYYY-MM-DD --until YYYY-MM-DD [--output NEW.json]
  security-watch pilot-recall --backup PATH --from YYYY-MM-DD --until YYYY-MM-DD --input INCIDENTS.json [--responses RESPONSES.json] [--output NEW.json]
  security-watch pilot-cases --backup PATH --from YYYY-MM-DD --until YYYY-MM-DD --output NEW.json
  security-watch pilot-response-template --backup PATH --from YYYY-MM-DD --until YYYY-MM-DD --input INCIDENTS.json --output NEW.json
  security-watch pilot-score --backup PATH --from YYYY-MM-DD --until YYYY-MM-DD --input LABELS.json [--output NEW.json]
  security-watch health [--scan-only]
  security-watch explain FINDING_ID
  security-watch history FINDING_ID
  security-watch reviews [--all] [--limit 100] [--after CURSOR]
  security-watch review FINDING_ID --revision N --disposition dismiss|investigate --reviewer NAME --reason TEXT
  security-watch acknowledge FINDING_ID [--revision N]
  security-watch suppress FINDING_ID --hours 24 --reason TEXT
  security-watch retry DELIVERY_ID   (verify receipt before retrying unknown delivery)
  security-watch backup --output PATH
  security-watch verify-backup --input PATH
  security-watch prune [--apply]    (shows the retention plan unless --apply is given)
  security-watch unlock             (only removes a stopped worker's lock)
  security-watch test-notification --channel slack|email

check asks OSV about every package in a project now and marks CISA known-exploited entries; it
sends package names and versions (and, with --epss, CVE IDs to FIRST), stores nothing and needs no
configuration. Exit code 1: an installed version affected at or above --fail-on (high; malware and
known-exploited always count, an advisory without a severity counts as medium, a package without an
exact version never does; none never fails); 2: the check is incomplete (a source failed or a
dependency file could not be read). --base REF... compares with the point where the branch left REF.

sbom reads the lockfiles and manifests in a project (npm, Python, Go, Rust, PHP, Ruby, Java,
.NET, Dart, Elixir, Swift, Haskell) and writes a CycloneDX SBOM. It runs nothing and sends nothing.
init --project creates a monitor for that project in one step. With an intake section in the
configuration, start also receives SBOMs from CI (sbom --upload, upload); intake runs only that.
Upload tokens are read from SECURITY_WATCH_INTAKE_TOKEN unless --token-env names another variable.

shield-candidates lists critical and exploited findings with what is known for writing a temporary
runtime shield (fix links, versions, exploit code) and what is missing; vex writes OpenVEX for
other scanners; both change nothing. shirudo-sboms copies Shirudo's image SBOMs into the SBOM
folder, showing its plan unless --apply is given.

Default config: ./security-watch.yaml. scan records findings; --dry-run writes no state,
disables models and sends nothing. --notify sends due jobs. start runs the foreground scheduler and
configured notification routes. Model/feed requests can leave this machine; fixture
mode performs no source or model requests. No packages are installed or patched.
Monitor commands accept --credentials-file PATH; rehearse uses no credentials.
Existing environment values take precedence for monitor commands.
`;
function argumentsFromCommandLine() {
  return parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string' },
      database: { type: 'string' },
      backup: { type: 'string' },
      from: { type: 'string' },
      until: { type: 'string' },
      directory: { type: 'string' },
      systems: { type: 'string' },
      libraries: { type: 'string' },
      ecosystem: { type: 'string' },
      input: { type: 'string' },
      'vendor-feeds': { type: 'string' },
      heartbeat: { type: 'boolean' },
      apply: { type: 'boolean' },
      provider: { type: 'string' },
      model: { type: 'string' },
      endpoint: { type: 'string' },
      'allow-private-endpoint': { type: 'boolean' },
      'poll-minutes': { type: 'string' },
      'lookback-minutes': { type: 'string' },
      notifications: { type: 'string' },
      'email-from': { type: 'string' },
      'email-to': { type: 'string' },
      'credentials-file': { type: 'string' },
      yes: { type: 'boolean' },
      'dry-run': { type: 'boolean' },
      notify: { type: 'boolean' },
      fixture: { type: 'string' },
      'no-ai': { type: 'boolean' },
      hours: { type: 'string' },
      reason: { type: 'string' },
      revision: { type: 'string' },
      disposition: { type: 'string' },
      reviewer: { type: 'string' },
      all: { type: 'boolean' },
      limit: { type: 'string' },
      after: { type: 'string' },
      output: { type: 'string' },
      responses: { type: 'string' },
      channel: { type: 'string' },
      sink: { type: 'string' },
      help: { type: 'boolean' },
      version: { type: 'boolean' },
      'scan-only': { type: 'boolean' },
      project: { type: 'string', multiple: true },
      name: { type: 'string' },
      'system-id': { type: 'string' },
      owner: { type: 'string' },
      environment: { type: 'string' },
      note: { type: 'string' },
      exposure: { type: 'string' },
      criticality: { type: 'string' },
      production: { type: 'boolean' },
      'source-url': { type: 'string' },
      'source-revision': { type: 'string' },
      upload: { type: 'string' },
      url: { type: 'string' },
      'token-env': { type: 'string' },
      'allow-http': { type: 'boolean' },
      'omit-location': { type: 'boolean' },
      unmitigated: { type: 'boolean' },
      'allow-removals': { type: 'boolean' },
      'include-not-affected': { type: 'boolean' },
      'omit-mitigations': { type: 'boolean' },
      author: { type: 'string' },
      system: { type: 'string' },
      store: { type: 'string' },
      running: { type: 'string' },
      sbom: { type: 'string' },
      base: { type: 'string' },
      package: { type: 'string', multiple: true },
      advisory: { type: 'string' },
      epss: { type: 'boolean' },
      'fail-on': { type: 'string' },
      json: { type: 'boolean' },
    },
  });
}
const { values, positionals } = (() => {
  try {
    return argumentsFromCommandLine();
  } catch (error) {
    console.error(
      pilotCommands.has(process.argv[2] ?? '')
        ? 'Invalid pilot-report arguments.'
        : process.argv[2] === 'rehearse'
          ? 'Invalid rehearsal arguments.'
          : error instanceof Error
            ? error.message
            : 'Invalid arguments',
    );
    process.exit(1);
  }
})();
const [command = 'help', id] = positionals;
function output(value: unknown) {
  console.log(JSON.stringify(value, null, 2));
}
function shellArgument(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}
function libraryInput(path: string, ecosystem?: string) {
  const absolute = resolve(path);
  const stat = statSync(absolute);
  if (!stat.isFile() || stat.size > 2 * 1024 * 1024)
    throw new Error('Library input must be a regular file no larger than 2 MiB.');
  const data = readFileSync(absolute);
  if (data.byteLength > 2 * 1024 * 1024) throw new Error('Library input exceeds 2 MiB.');
  const components = parseLibraryList(data.toString('utf8'), ecosystem);
  if (!components.length || components.length > 20_000)
    throw new Error('Provide between 1 and 20000 libraries.');
  return components;
}
/** The repository a CI job runs for, from the variables GitHub Actions and GitLab CI set. */
function ciSource(env: NodeJS.ProcessEnv): { url?: string; revision?: string; repository?: string } {
  let url: string | undefined;
  let revision: string | undefined;
  if (env.GITHUB_ACTIONS === 'true' && env.GITHUB_REPOSITORY) {
    url = `${env.GITHUB_SERVER_URL ?? 'https://github.com'}/${env.GITHUB_REPOSITORY}`;
    revision = env.GITHUB_SHA;
  } else if (env.GITLAB_CI === 'true' && env.CI_PROJECT_URL) {
    url = env.CI_PROJECT_URL;
    revision = env.CI_COMMIT_SHA;
  }
  if (!url) return {};
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash)
      return {};
    return {
      url: parsed.href.replace(/\/$/, ''),
      repository: parsed.pathname.replace(/^\/|\/$/g, ''),
      ...(revision && /^[A-Za-z0-9._-]{1,100}$/.test(revision) ? { revision } : {}),
    };
  } catch {
    return {};
  }
}
function oneOf<T extends string>(
  flag: string,
  value: string | undefined,
  allowed: readonly T[],
): T | undefined {
  if (value === undefined) return undefined;
  if (!(allowed as readonly string[]).includes(value))
    throw new Error(`--${flag} must be one of: ${allowed.join(', ')}.`);
  return value as T;
}
function sbomOptions(project: string): SbomOptions {
  const ci = ciSource(process.env);
  const sourceUrl = values['source-url'] ?? ci.url;
  const sourceRevision = values['source-revision'] ?? (values['source-url'] ? undefined : ci.revision);
  const note =
    values.note ?? (ci.repository && !values['source-url'] ? `repository ${ci.repository}` : undefined);
  return {
    project,
    ...(values.name ? { name: values.name } : {}),
    ...(values['system-id'] ? { systemId: values['system-id'] } : {}),
    ...(values.owner ? { owner: values.owner } : {}),
    ...(values.environment ? { environment: values.environment } : {}),
    ...(note ? { note } : {}),
    ...(values.exposure
      ? { exposure: oneOf('exposure', values.exposure, ['internet', 'internal', 'unknown'] as const) }
      : {}),
    ...(values.criticality
      ? {
          criticality: oneOf('criticality', values.criticality, [
            'unknown',
            'low',
            'medium',
            'high',
            'critical',
          ] as const),
        }
      : {}),
    ...(sourceUrl ? { sourceUrl } : {}),
    ...(sourceRevision ? { sourceRevision } : {}),
    ...(values.production ? { production: true } : {}),
    toolVersion: VERSION,
  };
}
const SUPPORTED_FILES = Object.values(DEPENDENCY_FILES).flat().join(', ');
/** Builds an SBOM and refuses one with no packages: an empty SBOM would look like a clean result. */
function buildSbom(project: string): GeneratedSbom {
  const result = generateSbom(sbomOptions(project));
  if (!result.packages)
    throw new Error(
      `No packages found in ${resolve(project)}${result.files.length ? ` (read ${result.files.map((file) => file.path).join(', ')})` : ''}. Supported files: ${SUPPORTED_FILES}. For container images and other inputs, use Trivy or Syft; see docs/sbom.md.`,
    );
  return result;
}
function sbomSummary(result: GeneratedSbom, destination?: string, shown = Infinity): string {
  const files = result.files.filter((file) => file.packages);
  const lines = [
    `${result.system.name}: ${result.packages} package${result.packages === 1 ? '' : 's'} (${result.ecosystems.join(', ')}) from ${files.length} file${files.length === 1 ? '' : 's'}: ${files
      .slice(0, 8)
      .map((file) => file.path)
      .join(', ')}${files.length > 8 ? `, and ${files.length - 8} more` : ''}.`,
  ];
  if (result.unversioned)
    lines.push(
      `${result.unversioned} package${result.unversioned === 1 ? ' has' : 's have'} no exact version and ${result.unversioned === 1 ? 'is' : 'are'} watched by name only.`,
    );
  for (const warning of result.warnings.slice(0, shown)) lines.push(`warning: ${warning}`);
  if (result.warnings.length > shown)
    lines.push(
      `warning: ${result.warnings.length - shown} more; security-watch sbom --project lists them all.`,
    );
  if (destination) lines.push(`Wrote ${destination}.`);
  return lines.join('\n');
}
/** Replaces the destination in one step, so a reader never sees half a file. */
function replaceFile(destination: string, content: string): void {
  mkdirSync(dirname(destination), { recursive: true });
  const directory = mkdtempSync(join(dirname(destination), '.security-watch-'));
  try {
    const staged = join(directory, 'sbom.json');
    writeFileSync(staged, content, { flag: 'wx' });
    renameSync(staged, destination);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
/** The system an SBOM file is for: its `security-watch:system-id` property, else the file name. */
function systemIdOf(body: Buffer, path: string): string {
  try {
    const document = JSON.parse(body.toString('utf8')) as {
      metadata?: { properties?: Array<{ name?: unknown; value?: unknown }> };
    };
    const property = document.metadata?.properties?.find(
      (entry) => entry?.name === 'security-watch:system-id' && typeof entry.value === 'string',
    );
    if (property) return property.value as string;
  } catch {
    // The intake reports an unreadable SBOM; the file name still names the system.
  }
  return basename(path).replace(/(?:\.(?:cdx|spdx|bom|sbom|cyclonedx))?\.json$/i, '');
}
async function sendSbom(body: string | Buffer, systemId: string): Promise<void> {
  const tokenEnv = values['token-env'] ?? 'SECURITY_WATCH_INTAKE_TOKEN';
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(tokenEnv))
    throw new Error('--token-env must name an environment variable.');
  const token = process.env[tokenEnv];
  if (!token) throw new Error(`Set ${tokenEnv} to the intake upload token.`);
  const url = values.upload ?? values.url!;
  const result = await uploadSbom({
    url,
    systemId,
    body,
    token,
    ...(values['allow-http'] ? { allowHttp: true } : {}),
  });
  console.error(
    `Uploaded ${result.system_id}: ${result.packages} package${result.packages === 1 ? '' : 's'} will be watched from the next scan${
      result.warnings
        ? ` (${result.warnings} warning${result.warnings === 1 ? '' : 's'}, for example: ${result.warning_examples[0]})`
        : ''
    }.`,
  );
}
async function writeSbom(): Promise<void> {
  if ((values.project?.length ?? 0) > 1)
    throw new Error('sbom takes one --project; run it once per project.');
  if ((values['token-env'] || values['allow-http']) && !values.upload)
    throw new Error('--token-env and --allow-http apply to --upload.');
  const result = buildSbom(values.project?.[0] ?? '.');
  const content = JSON.stringify(result.bom, null, 2) + '\n';
  if (values.upload) {
    if (values.output) {
      const destination = resolve(values.output);
      if (existsSync(destination) && !statSync(destination).isFile())
        throw new Error('--output must name a file.');
      replaceFile(destination, content);
      console.error(sbomSummary(result, destination));
    } else console.error(sbomSummary(result));
    await sendSbom(content, result.system.id);
    return;
  }
  if (values.output) {
    const destination = resolve(values.output);
    if (existsSync(destination) && !statSync(destination).isFile())
      throw new Error('--output must name a file.');
    replaceFile(destination, content);
    console.error(sbomSummary(result, destination));
  } else {
    process.stdout.write(content);
    console.error(sbomSummary(result));
  }
}
function intakeProblems(config: Config): string[] {
  if (!config.intake) return [];
  const problems: string[] = [];
  for (const { token_env } of config.intake.tokens) {
    const value = process.env[token_env];
    if (!value) problems.push(`${token_env}: the intake upload token is not set.`);
    else if (value.length < 32 || /\s/.test(value))
      problems.push(
        `${token_env}: an upload token needs at least 32 characters without spaces (openssl rand -hex 32).`,
      );
  }
  try {
    intakeDirectory(config.inventory);
  } catch (error) {
    problems.push(`intake: ${error instanceof Error ? error.message : 'the SBOM folder cannot be used'}`);
  }
  for (const file of [config.intake.tls_cert_file, config.intake.tls_key_file])
    if (file && !existsSync(file)) problems.push(`intake: ${file} does not exist.`);
  return problems;
}
async function initialize(): Promise<void> {
  const directory = resolve(values.directory ?? '.');
  const configPath = resolve(directory, 'security-watch.yaml'),
    inventoryPath = resolve(directory, 'systems.yaml');
  if (existsSync(configPath) || existsSync(inventoryPath))
    throw new Error('Configuration or inventory already exists; init never overwrites it.');
  let provider = values.provider ?? 'none',
    model = values.model ?? '',
    endpoint = values.endpoint,
    allowPrivate = values['allow-private-endpoint'] ?? false,
    pollMinutes = values['poll-minutes'] ?? '30',
    lookbackMinutes = values['lookback-minutes'] ?? '40',
    notificationChoice = values.notifications ?? 'none',
    emailFrom = values['email-from'],
    emailTo = values['email-to'];
  const systems = values.systems === undefined ? undefined : starterSystems(values.systems);
  if (values.libraries && values.systems)
    throw new Error('--libraries creates one application inventory; choose --systems separately.');
  if (values.ecosystem && !values.libraries) throw new Error('--ecosystem requires --libraries.');
  const libraries = values.libraries ? libraryInput(values.libraries, values.ecosystem) : undefined;
  if (values.project && values.libraries)
    throw new Error('--project and --libraries both describe your libraries; choose one.');
  if (values.production && !values.project) throw new Error('--production requires --project.');
  // Read the projects first: a project with nothing to watch is reported before any question is asked.
  const projects = (values.project ?? []).map((project) => buildSbom(project));
  const sbomIds = new Set<string>();
  const sbomFiles = projects.map((project, index) => {
    let id = project.system.id;
    for (let suffix = 2; sbomIds.has(id); suffix++) id = `${project.system.id}-${suffix}`;
    sbomIds.add(id);
    return { id, project, path: resolve(values.project![index]!) };
  });
  const nonNpm = projects.some((project) => project.ecosystems.some((ecosystem) => ecosystem !== 'npm'));
  if (sbomFiles.some(({ id }) => existsSync(resolve(directory, 'sboms', `${id}.cdx.json`))))
    throw new Error('An SBOM with the same name already exists in sboms/; init never overwrites it.');
  if (provider === 'none' && (model || endpoint || allowPrivate))
    throw new Error('--model, --endpoint and --allow-private-endpoint require --provider.');
  if (provider !== 'none' && !PROVIDERS.some((entry) => entry.id === provider))
    throw new Error('Unknown provider. Run security-watch providers for the available names.');
  if (!values.yes && process.stdin.isTTY) {
    const prompt = createInterface({ input: process.stdin, output: process.stdout });
    try {
      console.log('AI providers: ' + PROVIDERS.map((entry) => entry.id).join(', '));
      if (!values.provider)
        provider = (await prompt.question('AI provider (default none): ')).trim() || 'none';
      if (provider !== 'none') {
        if (!PROVIDERS.some((entry) => entry.id === provider))
          throw new Error('Choose none or a provider from the list.');
        const definition = providerDefinition(provider);
        if (!model) model = (await prompt.question('Exact model ID or Azure deployment name: ')).trim();
        if (!model) throw new Error('Model ID is required.');
        if (!definition.endpoint && !endpoint) {
          endpoint = (await prompt.question('Full API endpoint URL, including the request path: ')).trim();
          if (!endpoint) throw new Error('API endpoint is required.');
        }
        if ((definition.local || endpoint) && !allowPrivate) {
          allowPrivate = /^y(es)?$/i.test(
            (
              await prompt.question('Permit this model to use a local/private HTTP(S) endpoint? (y/N): ')
            ).trim(),
          );
        }
      }
      if (!values['poll-minutes'])
        pollMinutes = (await prompt.question('Minutes between scans (default 30): ')).trim() || '30';
      if (!values['lookback-minutes'])
        lookbackMinutes =
          (await prompt.question('Minutes of recent news to check (default 40): ')).trim() || '40';
      if (!values.notifications)
        notificationChoice =
          (
            await prompt.question(
              'Notification channels: none, slack, email, or slack,email (default none): ',
            )
          ).trim() || 'none';
      if (
        notificationChoice
          .split(',')
          .map((value) => value.trim())
          .includes('email')
      ) {
        emailFrom ??= (await prompt.question('Email sender address: ')).trim();
        emailTo ??= (await prompt.question('Email recipient addresses, separated by commas: ')).trim();
      }
    } finally {
      prompt.close();
    }
  }
  const channels =
    notificationChoice === 'none'
      ? []
      : [...new Set(notificationChoice.split(',').map((value) => value.trim()))];
  if (channels.some((channel) => !['slack', 'email'].includes(channel)))
    throw new Error('--notifications must be none, slack, email, or slack,email.');
  if (channels.includes('email') && (!emailFrom || !emailTo))
    throw new Error('Email notifications require --email-from and --email-to.');
  if (!channels.includes('email') && (emailFrom || emailTo))
    throw new Error('--email-from and --email-to require --notifications email.');
  const config = parseConfig({
    version: 1,
    inventory: './systems.yaml',
    database: './data/watch.db',
    poll_interval_minutes: Number(pollMinutes),
    news_lookback_minutes: Number(lookbackMinutes),
    sources: {
      ...(libraries || nonNpm ? { osv: true } : {}),
      vendor_feeds: values['vendor-feeds']?.split(',').map((name) => name.trim()) ?? [],
    },
    ...(values.heartbeat ? { monitoring: { heartbeat_url_env: 'HEARTBEAT_URL' } } : {}),
    models:
      provider === 'none'
        ? { enabled: false }
        : {
            enabled: true,
            analysis: {
              provider,
              model,
              api_key_env: providerDefinition(provider).apiKeyEnv,
              ...(endpoint ? { endpoint } : {}),
              allow_private_endpoint: allowPrivate,
            },
          },
    policy: {
      library: { levels: ['critical'], basis: 'source_severity', channels },
      product: { levels: ['high', 'critical'], channels },
      news: { levels: ['high', 'critical'], channels },
      health_channels: channels,
    },
    notifications: {
      ...(channels.includes('slack') ? { slack: { webhook_url_env: 'SLACK_WEBHOOK_URL' } } : {}),
      ...(channels.includes('email')
        ? {
            email: {
              smtp_url_env: 'SMTP_URL',
              from: emailFrom,
              to: emailTo!.split(',').map((address) => address.trim()),
            },
          }
        : {}),
    },
  });
  mkdirSync(directory, { recursive: true });
  writeFileSync(
    configPath,
    '# Run doctor after editing this file. Credentials belong in a private env file.\n' + stringify(config),
    { flag: 'wx', mode: 0o600 },
  );
  for (const { id, project } of sbomFiles) {
    mkdirSync(resolve(directory, 'sboms'), { recursive: true });
    const bom = project.bom as { metadata: { properties: Array<{ name: string; value: string }> } };
    for (const property of bom.metadata.properties)
      if (property.name === 'security-watch:system-id') property.value = id;
    writeFileSync(resolve(directory, 'sboms', `${id}.cdx.json`), JSON.stringify(bom, null, 2) + '\n', {
      flag: 'wx',
    });
  }
  writeFileSync(
    inventoryPath,
    stringify(
      sbomFiles.length
        ? { sbom_directory: './sboms', systems: systems ?? [] }
        : {
            systems: systems ?? [
              {
                id: libraries ? 'application' : 'example-api',
                name: libraries ? 'Application' : 'Example API',
                note: 'Replace me: where this system runs and who to ask',
                environment: libraries ? 'unknown' : 'development',
                exposure: 'unknown',
                criticality: 'unknown',
                updated_at: new Date().toISOString(),
                components: libraries ?? [
                  {
                    id: 'example-parser',
                    ecosystem: 'npm',
                    name: 'example-parser',
                    version: '1.2.0',
                    note: 'Replace me: where this library is used',
                  },
                ],
                products: [],
                keywords: [],
              },
            ],
          },
    ),
    { flag: 'wx', mode: 0o600 },
  );
  if (sbomFiles.length) {
    for (const { id, project, path } of sbomFiles) {
      const destination = resolve(directory, 'sboms', `${id}.cdx.json`);
      console.log(sbomSummary(project, destination, 5));
      console.log(
        `Refresh it when dependencies change, or from CI (docs/sbom.md):\n  security-watch sbom --project ${shellArgument(path)} --system-id ${shellArgument(id)} --output ${shellArgument(destination)}`,
      );
    }
    if (nonNpm)
      console.log(
        'OSV is turned on: it covers the non-npm packages and receives their names and versions (see README, Boundaries and privacy).',
      );
  }
  const envExample = resolve(directory, '.env.example');
  if (!existsSync(envExample))
    writeFileSync(
      envExample,
      '# Copy this file to .env, set the values you use, then run chmod 600 .env.\n' +
        '# Load it with security-watch doctor --credentials-file .env.\n' +
        (provider === 'none'
          ? '# OPENAI_API_KEY=\n# ANTHROPIC_API_KEY=\n'
          : `${providerDefinition(provider).apiKeyEnv}=\n`) +
        (channels.includes('slack') ? 'SLACK_WEBHOOK_URL=\n' : '# SLACK_WEBHOOK_URL=\n') +
        (channels.includes('email') ? 'SMTP_URL=\n' : '# SMTP_URL=\n') +
        (values.heartbeat ? 'HEARTBEAT_URL=\n' : '# HEARTBEAT_URL=\n'),
      { flag: 'wx', mode: 0o600 },
    );
  console.log(
    `Created ${configPath} and ${inventoryPath}. ${sbomFiles.length ? 'Each SBOM in sboms/ is one system; add owners and notes with security-watch sbom --owner/--note, or describe more systems in systems.yaml.' : 'Add installed versions and deployment details to systems.yaml.'} Copy .env.example to .env and fill in any required credentials. Then run:\n  security-watch doctor --config ${shellArgument(configPath)} --credentials-file ${shellArgument(resolve(directory, '.env'))}\n  security-watch scan --config ${shellArgument(configPath)} --credentials-file ${shellArgument(resolve(directory, '.env'))} --dry-run\nNo messages were sent.`,
  );
}
/** `ecosystem:name@version`, such as npm:lodash@4.17.21, npm:@scope/pkg@1.0.0 or maven:org.x:lib@2.1. */
function packageArgument(value: string): PackageQuery {
  const colon = value.indexOf(':');
  if (colon < 1)
    throw new Error(`--package ${value}: write it as ecosystem:name@version, such as npm:lodash@4.17.21.`);
  const rest = value.slice(colon + 1).replace('==', '@');
  const at = rest.lastIndexOf('@');
  return at > 0
    ? { ecosystem: value.slice(0, colon), name: rest.slice(0, at), version: rest.slice(at + 1) }
    : { ecosystem: value.slice(0, colon), name: rest };
}

async function runCheck(): Promise<void> {
  if ((values.project?.length ?? 0) + (id ? 1 : 0) > 1) throw new Error('check reads one project at a time.');
  const project = id ?? values.project?.[0];
  const failOn = values['fail-on'] ?? 'high';
  if (!['critical', 'high', 'medium', 'low', 'none'].includes(failOn))
    throw new Error('--fail-on must be critical, high, medium, low or none.');
  if (values.package && (project || values.sbom || values.base || values.advisory))
    throw new Error(
      '--package checks the named packages only; leave out the project, --sbom, --base and --advisory.',
    );
  if (values.base && (values.sbom || values.advisory))
    throw new Error(
      '--base compares a project folder with git; it cannot be combined with --sbom or --advisory.',
    );
  if (values.sbom && project) throw new Error('Give a project or --sbom, not both.');
  const common = {
    ...(values.epss ? { epss: true } : {}),
    ...(values.production ? { production: true } : {}),
  };
  const target = {
    ...common,
    ...(project ? { project } : {}),
    ...(values.sbom ? { sbom: values.sbom } : {}),
  };
  let failing: CheckFinding[];
  let degraded: boolean;
  let result: unknown;
  let text: string;
  if (values.package) {
    const report = await checkPackages(values.package.map(packageArgument), common);
    [failing, degraded, result, text] = [report.findings, report.degraded, report, formatCheckReport(report)];
  } else if (values.advisory) {
    const report = await checkAdvisory(values.advisory, target);
    [failing, degraded, result, text] = [
      report.findings,
      report.project.degraded,
      report,
      formatAdvisoryReport(report),
    ];
  } else if (values.base) {
    const report = await checkChange({ ...target, base: values.base });
    [failing, degraded, result, text] = [
      report.added,
      report.head.degraded,
      report,
      formatChangeReport(report),
    ];
  } else {
    const report = await checkProject(target);
    [failing, degraded, result, text] = [report.findings, report.degraded, report, formatCheckReport(report)];
  }
  if (values.json) output(result);
  else console.log(text);
  const fails = failing.some((finding) => failsAt(finding, failOn as Severity | 'none'));
  process.exitCode = fails ? 1 : degraded ? 2 : 0;
}

async function main(): Promise<void> {
  if (values.version) {
    console.log(VERSION);
    return;
  }
  if (values.help || command === 'help') {
    console.log(help);
    return;
  }
  const commandFlags: Record<string, string[]> = {
    check: ['project', 'sbom', 'base', 'package', 'advisory', 'production', 'epss', 'fail-on', 'json'],
    mcp: [],
    sbom: [
      'project',
      'output',
      'name',
      'system-id',
      'owner',
      'environment',
      'note',
      'exposure',
      'criticality',
      'production',
      'source-url',
      'source-revision',
      'upload',
      'token-env',
      'allow-http',
    ],
    upload: ['input', 'url', 'system-id', 'token-env', 'allow-http'],
    intake: ['config'],
    init: [
      'project',
      'production',
      'directory',
      'yes',
      'systems',
      'libraries',
      'ecosystem',
      'vendor-feeds',
      'heartbeat',
      'provider',
      'model',
      'endpoint',
      'allow-private-endpoint',
      'poll-minutes',
      'lookback-minutes',
      'notifications',
      'email-from',
      'email-to',
    ],
    providers: [],
    templates: [],
    ecosystems: [],
    'normalize-libraries': ['input', 'ecosystem', 'output'],
    'import-sbom': ['input', 'output'],
    'shirudo-sboms': ['store', 'directory', 'running', 'apply', 'allow-removals', 'config'],
    coverage: ['config'],
    'inventory-drift': ['config'],
    doctor: ['config', 'no-ai'],
    unlock: ['config'],
    scan: ['config', 'dry-run', 'notify', 'fixture', 'no-ai'],
    rehearse: ['config', 'input', 'sink', 'output'],
    'pilot-cases': ['backup', 'from', 'until', 'output'],
    'pilot-response-template': ['backup', 'from', 'until', 'input', 'output'],
    'pilot-recall': ['backup', 'from', 'until', 'input', 'responses', 'output'],
    'pilot-score': ['backup', 'from', 'until', 'input', 'output'],
    'pilot-report': ['database', 'backup', 'from', 'until', 'output'],
    start: ['config', 'no-ai'],
    findings: ['config'],
    'shield-candidates': ['config', 'all', 'omit-location', 'unmitigated', 'output'],
    vex: ['config', 'system', 'include-not-affected', 'omit-mitigations', 'author', 'output'],
    status: ['config'],
    deliveries: ['config'],
    budget: ['config'],
    health: ['config', 'scan-only'],
    explain: ['config', 'no-ai'],
    history: ['config'],
    reviews: ['config', 'all', 'limit', 'after'],
    review: ['config', 'revision', 'disposition', 'reviewer', 'reason'],
    acknowledge: ['config', 'revision'],
    suppress: ['config', 'hours', 'reason'],
    retry: ['config'],
    backup: ['config', 'output'],
    'verify-backup': ['input'],
    prune: ['config', 'apply'],
    'test-notification': ['config', 'channel'],
  };
  for (const [name, flags] of Object.entries(commandFlags))
    if (name !== 'rehearse' && flags.includes('config')) flags.push('credentials-file');
  if (!commandFlags[command]) throw new Error(`Unknown command ${command}. Use --help.`);
  for (const flag of Object.keys(values))
    if (!commandFlags[command]!.includes(flag)) throw new Error(`--${flag} is not supported by ${command}.`);
  const needsId = [
    'explain',
    'history',
    'review',
    'acknowledge',
    'suppress',
    'retry',
    'check',
    'mcp',
  ].includes(command);
  if (positionals.length > (needsId ? 2 : 1)) throw new Error('Unexpected positional arguments. Use --help.');
  if (command === 'check') {
    await runCheck();
    return;
  }
  if (command === 'mcp') {
    const { mcpMain } = await import('./mcp-server.js');
    mcpMain(id ? [id] : []);
    return;
  }
  if (command === 'init') {
    await initialize();
    return;
  }
  if (command === 'providers') {
    output(PROVIDERS);
    return;
  }
  if (command === 'templates') {
    output(SYSTEM_TEMPLATES);
    return;
  }
  if (command === 'ecosystems') {
    output(ECOSYSTEMS);
    return;
  }
  if (command === 'sbom') {
    await writeSbom();
    return;
  }
  if (command === 'upload') {
    if (!values.input || !values.url) throw new Error('upload needs --input FILE.json and --url URL.');
    const path = resolve(values.input);
    const body = readFileSync(path);
    if (body.byteLength > 20 * 1024 * 1024) throw new Error('An SBOM may be at most 20 MiB.');
    await sendSbom(body, values['system-id'] ?? systemIdOf(body, path));
    return;
  }
  if (command === 'shirudo-sboms') {
    if (!values.store || !values.directory) throw new Error('--store DIR and --directory SBOM_DIR required');
    // With --config, systems described by hand in the inventory are known, so an image with the same
    // ID is reported instead of being refused by every scan.
    let reserved: string[] = [];
    if (values.config) {
      const inventoryPath = loadConfig(resolve(values.config)).inventory;
      const raw: unknown = parseYaml(readFileSync(inventoryPath, 'utf8'), { maxAliasCount: 0 });
      const systems = raw && typeof raw === 'object' ? (raw as { systems?: unknown }).systems : undefined;
      reserved = Array.isArray(systems)
        ? systems
            .map((system) =>
              system && typeof system === 'object' ? (system as { id?: unknown }).id : undefined,
            )
            .filter((value): value is string => typeof value === 'string')
        : [];
    }
    const plan = syncShirudoSboms({
      reserved,
      allowRemovals: Boolean(values['allow-removals']),
      store: resolve(values.store),
      output: resolve(values.directory),
      ...(values.running ? { exposure: resolve(values.running) } : {}),
      apply: Boolean(values.apply),
    });
    output(plan);
    if (!values.apply && (plan.images.some((item) => item.action === 'write') || plan.remove.length))
      console.error('Nothing was written. Run again with --apply to write this plan.');
    if (plan.problems.length) process.exitCode = 2;
    return;
  }
  if (command === 'import-sbom') {
    if (!values.input) throw new Error('--input PATH required');
    const report = importSbom(resolve(values.input));
    if (values.output)
      writeFileSync(resolve(values.output), JSON.stringify(report, null, 2) + '\n', {
        flag: 'wx',
        mode: 0o600,
      });
    else output(report);
    if (report.warnings.length) process.exitCode = 2;
    return;
  }
  if (command === 'normalize-libraries') {
    if (!values.input) throw new Error('--input PATH required');
    const components = libraryInput(values.input, values.ecosystem);
    if (values.output) {
      writeFileSync(resolve(values.output), JSON.stringify(components, null, 2) + '\n', {
        flag: 'wx',
        mode: 0o600,
      });
      console.log('Normalized library list saved.');
    } else output(components);
    return;
  }
  if (command === 'verify-backup') {
    if (!values.input) throw new Error('--input PATH required');
    output(await verifyBackup(resolve(values.input)));
    return;
  }
  if (pilotCommands.has(command)) {
    if (!values.from || !values.until || Boolean(values.database) === Boolean(values.backup))
      throw new Error();
    if ((command === 'pilot-cases' || command === 'pilot-response-template') && !values.output)
      throw new Error();
    if (command === 'pilot-response-template' && !values.input) throw new Error();
    if ((command === 'pilot-score' || command === 'pilot-recall') && !values.input) throw new Error();
    const destination = values.output === undefined ? undefined : resolve(values.output);
    // Reject SQLite sidecar and worker lock filenames before opening either input.
    if (destination && extname(destination).toLowerCase() !== '.json') throw new Error();
    const window = { from: values.from, until: values.until };
    let report;
    if (command === 'pilot-cases') report = await createPilotCasePacket(values.backup!, window);
    else if (command === 'pilot-response-template')
      report = await createPilotResponseTemplate(
        values.backup!,
        window,
        readPilotIncidentReference(values.input!),
      );
    else if (command === 'pilot-recall') {
      const reference = readPilotIncidentReference(values.input!);
      report =
        values.responses === undefined
          ? await scorePilotRecall(values.backup!, window, reference)
          : await scorePilotResponses(
              values.backup!,
              window,
              reference,
              readPilotResponseRegister(values.responses),
            );
    } else if (command === 'pilot-score')
      report = await scorePilotCases(values.backup!, window, readPilotFeedback(values.input!));
    else
      report = values.backup
        ? await readPilotBackupReport(values.backup, window)
        : readPilotReport(values.database!, window);
    if (!destination) output(report);
    else {
      const directory = mkdtempSync(join(dirname(destination), '.pilot-report-'));
      try {
        const staged = join(directory, 'report.json');
        writeFileSync(staged, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
        linkSync(staged, destination);
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    }
    return;
  }
  if (command === 'rehearse') {
    if (!values.input) throw new Error('--input required');
    const config = loadConfig(resolve(values.config ?? 'security-watch.yaml'));
    const report = await runRehearsal({
      config,
      inventory: loadInventory(config.inventory),
      scenario: readRehearsal(resolve(values.input)),
      sink: (values.sink ?? 'disabled') as RehearsalSink,
    });
    if (values.output)
      writeFileSync(resolve(values.output), JSON.stringify(report, null, 2) + '\n', {
        flag: 'wx',
        mode: 0o600,
      });
    else output(report);
    return;
  }
  if (values['credentials-file']) loadEnvFile(resolve(values['credentials-file']));
  const config = loadConfig(resolve(values.config ?? 'security-watch.yaml'));
  if (command === 'prune' && !config.maintenance?.retention)
    throw new Error('Configure maintenance.retention before planning or applying pruning.');
  if (values['no-ai']) config.models.enabled = false;
  if (command === 'intake') {
    const running = await startIntake(config, { log: (line) => console.log(line) });
    console.log(
      `Receiving SBOMs at ${running.url}/v1/sboms/SYSTEM_ID; they are written to ${intakeDirectory(config.inventory)}. Stop with Ctrl-C.`,
    );
    await new Promise<void>((done) => {
      process.once('SIGINT', done);
      process.once('SIGTERM', done);
    });
    await running.close();
    return;
  }
  if (command === 'unlock') {
    unlockStoppedWorker(config.database);
    console.log('Stopped-worker lock removed.');
    return;
  }
  if (command === 'doctor') {
    const inventory = loadInventory(config.inventory);
    const missing = missingCredentials(config);
    const routes = {
      library: config.policy.library.channels,
      product: config.policy.product.channels,
      news: config.policy.news.channels,
      health: config.policy.health_channels,
    };
    const enabledChannels = [...new Set(Object.values(routes).flat())];
    const smtp = config.notifications.email
      ? process.env[config.notifications.email.smtp_url_env]
      : undefined;
    const slack = config.notifications.slack
      ? process.env[config.notifications.slack.webhook_url_env]
      : undefined;
    const heartbeat = config.monitoring ? process.env[config.monitoring.heartbeat_url_env] : undefined;
    // Each mitigation export is read as a scan reads it; what it covers is shown so a mapping
    // mistake (an image ID that is no system ID) is seen before the first alert.
    const systemIds = new Set(inventory.systems.map((system) => system.id));
    const mitigationProblems: string[] = [];
    const mitigations = (config.mitigations ?? []).map((source) => {
      try {
        const exported = readMitigationExport(source, Date.now());
        mitigationProblems.push(...exportProblems(exported, source, Date.now()));
        const keys = new Set(exported.rows.map((row) => row.system));
        const systems = [...keys].map((key) =>
          Object.hasOwn(source.systems, key) ? source.systems[key]! : key,
        );
        const unknown = systems.filter((id) => !systemIds.has(id));
        if (unknown.length)
          mitigationProblems.push(
            `${source.name}: ${unknown.length} system key(s) in the export match no system in the inventory (${unknown
              .slice(0, 5)
              .join(', ')}${unknown.length > 5 ? ', …' : ''}); map them with systems: or add those systems.`,
          );
        return {
          name: source.name,
          format: source.format,
          rows: exported.rows.length,
          hosts: new Set(exported.rows.map((row) => `${row.system}\u0000${row.host}`)).size,
          systems_matched: systems.filter((id) => systemIds.has(id)).length,
          exported_at: exported.exported_at,
          stale: exported.stale,
        };
      } catch (error) {
        mitigationProblems.push(
          `${source.name}: the export cannot be read: ${
            (error as NodeJS.ErrnoException).code === 'ENOENT'
              ? 'the file does not exist'
              : (error as Error).message
          }.`,
        );
        return { name: source.name, format: source.format, readable: false };
      }
    });
    const problems = [
      // Delivery refuses such an address on every attempt; say so before the first alert is due.
      ...(slack && slackProblem(slack)
        ? [`${config.notifications.slack!.webhook_url_env}: ${slackProblem(slack)}.`]
        : []),
      ...(smtp && smtpProblem(smtp)
        ? [
            `${config.notifications.email!.smtp_url_env}: ${smtpProblem(smtp)}.${
              /%/.test(smtp) ? ' Write a literal % in a password as %25.' : ''
            }`,
          ]
        : []),
      ...intakeProblems(config),
      ...mitigationProblems,
      // The heartbeat refuses such an address on every ping.
      ...(heartbeat && heartbeatProblem(heartbeat, config.monitoring!.allow_private_endpoint)
        ? [`${config.monitoring!.heartbeat_url_env}: the external heartbeat address cannot be used.`]
        : []),
    ];
    // Feed addresses can carry access tokens; show where each one points, not the whole address.
    const feedHost = (value: string) => {
      try {
        return `${new URL(value).origin}/…`;
      } catch {
        return 'invalid URL';
      }
    };
    output({
      ok: missing.length === 0 && problems.length === 0,
      problems,
      systems: inventory.systems.length,
      components: inventory.systems.reduce((sum, s) => sum + s.components.length, 0),
      // Entries that were left out or will not match as written. Scans report the same list.
      import_warnings: inventory.import_warnings ?? [],
      // Entries accepted as written that may be a typing mistake, such as a capitalised npm name.
      name_notices: inventory.name_notices ?? [],
      missing_environment_variables: missing,
      database: config.database,
      models_enabled: config.models.enabled,
      poll_interval_minutes: config.poll_interval_minutes,
      news_lookback_minutes: config.news_lookback_minutes,
      sources: { ...config.sources, feeds: config.sources.feeds.map(feedHost) },
      feeds: config.sources.feeds.length + Number(config.sources.hacker_news),
      notification_routes: routes,
      notification_channels: enabledChannels,
      ...(mitigations.length ? { mitigations } : {}),
      ecosystems: [
        ...new Set(
          inventory.systems.flatMap((system) => system.components.map((component) => component.ecosystem)),
        ),
      ],
      external_heartbeat: config.monitoring
        ? {
            configured: true,
            interval_seconds: config.monitoring.interval_seconds,
            credential: config.monitoring.heartbeat_url_env,
          }
        : { configured: false },
      maintenance: config.maintenance ?? null,
      intake: config.intake
        ? {
            listen: config.intake.listen,
            tls: Boolean(config.intake.tls_cert_file),
            tokens: config.intake.tokens.map((token) => ({
              token_env: token.token_env,
              systems: token.systems,
              present: Boolean(process.env[token.token_env]),
            })),
          }
        : { configured: false },
      notices: [
        'Model compatibility is verified only by a real analysis request; doctor does not spend tokens or send notifications.',
        'Public advisory queries disclose package names/versions. Models receive relevant inventory context.',
        'System news impact is an AI assessment with citations; structured CVE version matching remains separate.',
        ...(!config.sources.osv &&
        inventory.systems.some((system) =>
          system.components.some((component) => component.ecosystem !== 'npm'),
        )
          ? [
              'Enable sources.osv for exact library queries outside npm. Other configured sources may not cover those libraries.',
            ]
          : []),
        ...(!config.monitoring
          ? [
              'External outage monitoring is not configured. A stopped host cannot send its own failure alert.',
            ]
          : []),
        ...(config.monitoring
          ? ['Configure the external service to alert when healthy pings stop. doctor does not send a ping.']
          : []),
        ...(enabledChannels.length
          ? [
              'Notification routes are enabled. Use test-notification to verify delivery; start sends queued notifications continuously.',
            ]
          : [
              'No notification routes are enabled. Scans will record findings without delivering alerts. Configure policy channels and notification destinations.',
            ]),
        ...((config.sources.hacker_news || config.sources.feeds.length) && !config.models.enabled
          ? ['Enable an analysis model to classify system news and assess deployment impact.']
          : []),
      ],
    });
    // `ok: false` always comes with a failing exit status, so a script can rely on either.
    if (missing.length || problems.length) process.exitCode = 2;
    return;
  }
  const allowed = new Set([
    'scan',
    'start',
    'findings',
    'shield-candidates',
    'vex',
    'status',
    'coverage',
    'inventory-drift',
    'deliveries',
    'budget',
    'health',
    'explain',
    'history',
    'reviews',
    'review',
    'acknowledge',
    'suppress',
    'retry',
    'backup',
    'prune',
    'test-notification',
  ]);
  if (!allowed.has(command)) throw new Error(`Unknown command ${command}. Use --help.`);
  const dry = command === 'scan' && Boolean(values['dry-run']);
  if (dry && values.notify) throw new Error('--dry-run and --notify cannot be combined.');
  if (dry) config.models.enabled = false;
  const readonly =
    (command === 'prune' && !values.apply) ||
    [
      'findings',
      'shield-candidates',
      'vex',
      'status',
      'coverage',
      'inventory-drift',
      'deliveries',
      'budget',
      'health',
      'explain',
      'history',
      'reviews',
    ].includes(command);
  if (readonly && !existsSync(config.database)) {
    output({ status: 'not_started', message: 'No database exists yet. Run scan or start.' });
    if (command === 'health') process.exitCode = 2;
    return;
  }
  const memory = dry || command === 'test-notification';
  const worker = command === 'scan' || command === 'start';
  const release = memory || !worker ? () => {} : acquireLock(config.database);
  let store: Store;
  try {
    store = new Store(
      memory ? ':memory:' : config.database,
      readonly ? { readOnly: true } : !worker && !memory ? { migrate: false } : {},
    );
  } catch (error) {
    release();
    throw error;
  }
  try {
    if (command === 'coverage' || command === 'inventory-drift') {
      const saved = JSON.parse(
        store.getMeta(command === 'coverage' ? 'source:coverage' : 'inventory:last_drift') ?? '[]',
      );
      output(command === 'coverage' ? refreshCoverage(saved) : saved);
      return;
    }
    if (command === 'reviews') {
      const limit = values.limit === undefined ? 100 : Number(values.limit);
      let after;
      if (values.after) {
        if (values.after.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(values.after))
          throw new Error('Invalid review cursor');
        try {
          after = JSON.parse(Buffer.from(values.after, 'base64url').toString('utf8'));
          if (!after || typeof after !== 'object' || Array.isArray(after))
            throw new Error('Invalid review cursor');
        } catch {
          throw new Error('Invalid review cursor');
        }
      }
      const reviews = store.reviews({
        includeResolved: Boolean(values.all),
        limit,
        ...(after ? { after } : {}),
      });
      const last = reviews.at(-1);
      output({
        reviews,
        summary: store.reviewSummary(),
        next_cursor:
          reviews.length === limit && last
            ? Buffer.from(
                JSON.stringify({
                  created_at: last.created_at,
                  finding_id: last.finding_id,
                  revision: last.revision,
                }),
              ).toString('base64url')
            : null,
      });
      return;
    }
    if (command === 'review') {
      if (
        !id ||
        !values.revision ||
        !values.reviewer ||
        !values.reason ||
        !['dismiss', 'investigate'].includes(values.disposition ?? '')
      )
        throw new Error(
          'Provide finding ID, --revision, --disposition dismiss|investigate, --reviewer and --reason',
        );
      store.reviewFinding(id, Number(values.revision), {
        disposition: values.disposition as 'dismiss' | 'investigate',
        reviewer: values.reviewer,
        reason: values.reason,
      });
      output({
        finding_id: id,
        revision: Number(values.revision),
        disposition: values.disposition,
        delivery_sent: false,
      });
      return;
    }
    if (command === 'findings') {
      const ages = maxAges(config.mitigations);
      output(store.findings().map((finding) => withCurrentMitigations(finding, ages, Date.now())));
      return;
    }
    if (command === 'vex') {
      const author = values.author ?? 'Security Watch';
      if (
        !author.trim() ||
        author.length > 200 ||
        /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/.test(author)
      )
        throw new Error('--author must be one line of at most 200 characters');
      // The packages and their versions come from the inventory as it is now, with the component
      // identifiers the last scan gave the findings.
      const inventory = currentInventory(config.inventory, store);
      if (values.system !== undefined && !inventory.systems.some((system) => system.id === values.system))
        throw new Error(`No system ${values.system} in the inventory`);
      const ages = maxAges(config.mitigations);
      const { document, skipped } = openVex({
        findings: store.findings().map((finding) => withCurrentMitigations(finding, ages, Date.now())),
        evidence: (ids) => store.getEvidence(ids),
        inventory,
        ...(values.system !== undefined ? { systemId: values.system } : {}),
        includeNotAffected: Boolean(values['include-not-affected']),
        author: author.trim(),
        // Fresh runtime mitigations are worth telling a consumer; they never change the status.
        mitigationNote: (finding) => {
          // Only a current status that covers at least one host is worth saying outside, with its time.
          if (values['omit-mitigations']) return undefined;
          const fresh = (finding.mitigations ?? []).filter(
            (status) => !status.stale && !status.not_listed && (status.states.mitigated ?? 0) > 0,
          );
          return fresh.length
            ? `Temporary runtime mitigation on ${fresh
                .map(
                  (status) =>
                    `${status.states.mitigated} of ${status.hosts} host(s) (${status.source}, ${status.exported_at.slice(0, 16).replace('T', ' ')} UTC)`,
                )
                .join('; ')}.`
            : undefined;
        },
      });
      if (values.output) {
        writeFileSync(resolve(values.output), JSON.stringify(document, null, 2) + '\n', {
          flag: 'wx',
          mode: 0o600,
        });
        const left = Object.entries(skipped)
          .map(([reason, count]) => `${count} ${reason.replaceAll('_', ' ')}`)
          .join(', ');
        console.log(
          `${document.statements.length} VEX statement(s) saved.${left ? ` Not written: ${left}.` : ''}`,
        );
      } else {
        output(document);
        const left = Object.entries(skipped)
          .map(([reason, count]) => `${count} ${reason.replaceAll('_', ' ')}`)
          .join(', ');
        if (left) console.error(`Not written: ${left}.`);
      }
      return;
    }
    if (command === 'shield-candidates') {
      // The inventory as it is now gives package versions; a stored location is the fallback.
      let inventory;
      try {
        inventory = currentInventory(config.inventory, store);
      } catch {
        inventory = undefined;
      }
      const report = shieldCandidates({
        findings: store.findings(),
        evidence: (ids) => store.getEvidence(ids),
        ...(inventory ? { inventory } : {}),
        controls: (findingId) => store.controls(findingId),
        all: Boolean(values.all),
        omitLocation: Boolean(values['omit-location']),
        unmitigatedOnly: Boolean(values.unmitigated),
        mitigationMaxAge: maxAges(config.mitigations),
      });
      if (!inventory)
        report.notes.push(
          'The inventory could not be read: a package and its installed version are shown only where an advisory matched exactly one package by version.',
        );
      if (values.output) {
        writeFileSync(resolve(values.output), JSON.stringify(report, null, 2) + '\n', {
          flag: 'wx',
          mode: 0o600,
        });
        console.log(`${report.candidates.length} shield candidate(s) saved.`);
      } else output(report);
      return;
    }
    if (command === 'deliveries') {
      output(store.jobs().map(({ payload, ...job }) => job));
      return;
    }
    if (command === 'budget') {
      output({
        reservations: store.budgets(),
        note: 'Reservations are conservative allowances, not provider invoices.',
      });
      return;
    }
    if (command === 'health') {
      const report = checkHealth(store, config, Date.now(), !values['scan-only']);
      output(report);
      if (!report.ok) process.exitCode = 2;
      return;
    }
    if (command === 'status') {
      const summary = store.summary();
      output({
        last_scan: JSON.parse(store.getMeta('last_scan') ?? 'null'),
        coverage: refreshCoverage(JSON.parse(store.getMeta('source:coverage') ?? '[]')),
        inventory_drift: JSON.parse(store.getMeta('inventory:last_drift') ?? '[]'),
        findings: summary.active_findings,
        reviews: store.reviewSummary(),
        ai_dismissal_policy: config.policy.ai_dismissals ?? 'review',
        delivery_states: summary.delivery_states,
        worker_lock: existsSync(`${config.database}.lock`),
        worker_lock_note:
          'Informational metadata can remain after a crash; exclusive SQLite ownership prevents concurrent workers.',
        external_heartbeat: JSON.parse(store.getMeta('external_heartbeat') ?? 'null'),
        maintenance: JSON.parse(store.getMeta('maintenance:last_run') ?? 'null'),
      });
      return;
    }
    if (command === 'explain') {
      const saved = id ? store.getFinding(id) : undefined;
      if (!saved) throw new Error('Finding not found');
      const finding = withCurrentMitigations(saved, maxAges(config.mitigations), Date.now());
      output({
        finding,
        decision: decide(finding, config),
        controls: store.controls(finding.id),
        evidence: store.getEvidence(finding.evidence_ids).map((e) => ({
          id: e.id,
          source: e.source,
          url: e.url,
          modified_at: e.modified_at,
          fetched_at: e.fetched_at,
          withdrawn: e.withdrawn ?? false,
          ...(e.cvss_v4 ? { cvss_v4: e.cvss_v4 } : {}),
          ...(e.references ? { references: e.references } : {}),
          ...(e.fix_commits ? { fix_commits: e.fix_commits } : {}),
          ...(e.weaknesses ? { weaknesses: e.weaknesses } : {}),
          ...(e.exploit_sources ? { exploit_sources: e.exploit_sources } : {}),
        })),
        note: 'Applicability reflects the cited evidence as last fetched. Inspect monitoring health for source outages.',
      });
      return;
    }
    if (command === 'history') {
      if (!id) throw new Error('Finding ID required');
      output(store.history(id));
      return;
    }
    if (command === 'acknowledge') {
      if (!id) throw new Error('Finding ID required');
      const expected = values.revision === undefined ? undefined : Number(values.revision);
      if (expected !== undefined && (!Number.isSafeInteger(expected) || expected < 1))
        throw new Error('--revision must be a positive whole number');
      const revision = store.acknowledge(id, expected);
      console.log(`Finding acknowledged at revision ${revision}.`);
      return;
    }
    if (command === 'suppress') {
      const hours = Number(values.hours);
      if (!id || !values.reason || !Number.isFinite(hours) || hours <= 0 || hours > 8760)
        throw new Error('Provide finding ID, --hours (1–8760) and --reason.');
      store.suppress(id, Date.now() + Math.floor(hours * 3_600_000), values.reason);
      console.log('Suppression saved with expiry.');
      return;
    }
    if (command === 'retry') {
      if (!id) throw new Error('Delivery ID required');
      store.retryJob(id);
      console.log('Delivery queued. A previous uncertain delivery may already have reached its destination.');
      return;
    }
    if (command === 'backup') {
      if (!values.output) throw new Error('--output PATH required');
      let verification: Awaited<ReturnType<typeof verifyBackup>> | undefined;
      // Check the snapshot before it appears at the requested path; a failed check leaves nothing behind.
      await store.backup(resolve(values.output), async (snapshot) => {
        verification = await verifyBackup(
          snapshot,
          config.maintenance?.backup ? { max_bytes: config.maintenance.backup.max_bytes } : undefined,
        );
      });
      output({ backup_created: true, verification });
      return;
    }
    if (command === 'prune') {
      output(store.prune(config.maintenance!.retention!, Date.now(), Boolean(values.apply)));
      return;
    }
    if (command === 'test-notification') {
      if (values.channel !== 'slack' && values.channel !== 'email')
        throw new Error('--channel slack|email required');
      const a: Assessment = {
        id: 'test',
        event_id: 'test',
        system_id: 'monitor',
        category: 'health',
        applicability: 'relevant',
        source_severity: 'low',
        priority: 'low',
        title: 'Security Watch notification test',
        summary: 'This is a user-requested delivery test, not a vulnerability finding.',
        reasons: [],
        evidence_ids: [],
        urls: [],
        exploited: false,
        updated_at: new Date().toISOString(),
      };
      store.saveAssessment(a, {
        action: 'notify',
        channels: [values.channel],
        reason: 'Explicit notification test',
      });
      const delivery = await deliverPending(
        store,
        {
          ...config,
          notifications: { ...config.notifications, max_attempts: 1 },
          policy: { ...config.policy, health_channels: [values.channel] },
        },
        safeHttp,
      );
      const job = store.jobs()[0];
      output({
        ...delivery,
        channel: values.channel,
        status: job?.status ?? 'not_sent',
        error: job?.last_error ?? null,
        note: 'This sends one test and does not change the monitor database or retry automatically.',
      });
      if (store.jobs().some((j) => j.status !== 'accepted')) process.exitCode = 2;
      return;
    }
    if (command === 'scan') {
      const inventory = loadInventory(config.inventory);
      // A fixture preview shows how findings are matched, not how fresh the inventory is: like the
      // demo, it counts the inventory as current, so the fixed-date examples keep working.
      // Only a dry run: a fixture scan that saves its results must not record a stale inventory as
      // current in the configured database.
      if (values.fixture && dry)
        for (const system of inventory.systems) system.updated_at = new Date().toISOString();
      if (values.notify) store.recoverSending();
      const delivery = { accepted: 0, failed: 0, unknown: 0 };
      const deliver = async () => {
        const result = await deliverPending(store, config, safeHttp);
        delivery.accepted += result.accepted;
        delivery.failed += result.failed;
        delivery.unknown += result.unknown;
      };
      firstScanNotice(config, store, Boolean(values.fixture));
      const report = await runScan({
        config,
        inventory,
        store,
        // A fixture stands for what the sources answer now: its records count as read now, so that a
        // preview does not turn into "unknown" as the file ages.
        ...(values.fixture
          ? {
              fixture: readFixture(resolve(values.fixture)).map((item) => ({
                ...item,
                fetched_at: new Date().toISOString(),
              })),
            }
          : {}),
        ...(values.notify ? { onUrgent: deliver } : {}),
      });
      output(report);
      if (values.notify) {
        await deliver();
        const summary = store.summary();
        output({
          delivery,
          pending: summary.pending,
          next_attempt_at:
            summary.next_pending_at === null ? null : new Date(summary.next_pending_at).toISOString(),
          note: 'Rate-limited retries and future digest jobs remain queued. Run start to keep delivering them.',
        });
        if (delivery.failed || delivery.unknown) process.exitCode = 2;
      }
      if (report.degraded) process.exitCode = 2;
      return;
    }
    if (values.fixture || values['dry-run'])
      throw new Error('start does not accept fixture or dry-run; use scan.');
    const missing = missingCredentials(config);
    if (missing.length) {
      console.error(
        `Missing environment variables: ${missing.join(', ')}. Monitoring will continue with explicit degraded status.`,
      );
      const finding = healthFinding(
        'credentials',
        'Configured model or delivery credentials are missing. Structured advisory matching continues.',
      );
      store.saveAssessment(finding, decide(finding, config));
    }
    store.recoverSending();
    // Receiving SBOMs is part of the worker, so one process keeps the inventory current and watches it.
    const intake = config.intake
      ? await startIntake(config, { log: (line) => console.log(line) })
      : undefined;
    if (intake)
      console.log(
        `Receiving SBOMs at ${intake.url}/v1/sboms/SYSTEM_ID into ${intakeDirectory(config.inventory)}.`,
      );
    const controller = new AbortController();
    const startedAt = new Date().toISOString();
    const catchingUpSince = catchingUpFrom(store, startedAt);
    let lastHeartbeat = 0;
    const heartbeat = (status: 'running' | 'stopping' | 'stopped') => {
      const now = Date.now();
      store.setMeta(
        'worker',
        JSON.stringify({
          pid: process.pid,
          status,
          started_at: startedAt,
          catching_up_since: catchingUpSince,
          heartbeat_at: new Date(now).toISOString(),
        }),
      );
      lastHeartbeat = now;
    };
    heartbeat('running');
    let stop = false,
      nextScan = 0;
    let scanning: Promise<void> | undefined;
    let maintaining: Promise<void> | undefined;
    const monitor = new HeartbeatMonitor();
    const maintenance = new MaintenanceScheduler();
    let monitorStatus: string | undefined;
    const shutdown = () => {
      stop = true;
      controller.abort();
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    console.log('Security Watch is running in the foreground. Configured routes are active.');
    try {
      firstScanNotice(config, store, false);
      while (!stop) {
        const tick = Date.now();
        // A clock set back must not pause the worker until it reaches the old time again.
        if (tick - lastHeartbeat >= 15_000 || tick < lastHeartbeat) heartbeat('running');
        const interval = config.poll_interval_minutes * 60_000;
        if (!scanning && !maintaining && (tick >= nextScan || nextScan - tick > interval)) {
          nextScan = tick + interval;
          scanning = (async () => {
            try {
              const report = await runScan({
                config,
                inventory: loadInventory(config.inventory),
                store,
                signal: controller.signal,
              });
              console.log(
                JSON.stringify({
                  at: report.at,
                  findings: report.findings.length,
                  degraded: report.degraded,
                  errors: report.errors,
                }),
              );
            } catch {
              if (controller.signal.aborted) return;
              const finding = healthFinding(
                'worker',
                'Scan failed. Check configuration, inventory and local storage. Previous findings are retained.',
              );
              store.setMeta(
                'last_scan',
                JSON.stringify({
                  at: new Date().toISOString(),
                  degraded: true,
                  errors: [{ source: 'worker', message: finding.summary }],
                }),
              );
              store.saveAssessment(finding, decide(finding, config));
              console.error('Scan failed; previous findings retained.');
            }
          })()
            .catch(() => {
              console.error('Worker cannot persist monitoring state; stopping.');
              process.exitCode = 1;
              stop = true;
            })
            .finally(() => {
              scanning = undefined;
            });
        }
        const delivery = await deliverPending(
          store,
          config,
          safeHttp,
          Date.now(),
          undefined,
          controller.signal,
        );
        if (delivery.failed || delivery.unknown)
          console.error(
            JSON.stringify({ delivery, action: 'Inspect deliveries and destination configuration.' }),
          );
        if (!scanning && !maintaining && config.maintenance && !stop)
          maintaining = maintenance
            .tick(store, config)
            .then((report) => {
              if (report) console.log(JSON.stringify({ maintenance: report }));
            })
            .catch(() => {
              console.error('Worker cannot persist maintenance state; stopping.');
              process.exitCode = 1;
              stop = true;
            })
            .finally(() => {
              maintaining = undefined;
            });
        const ping = await monitor.tick(store, config, safeHttp, Date.now(), controller.signal);
        if (ping && ping.status !== monitorStatus) {
          monitorStatus = ping.status;
          console.log(JSON.stringify({ external_heartbeat: ping }));
        }
        await delay(1000);
      }
      if (scanning) await scanning;
      if (maintaining) await maintaining;
    } finally {
      controller.abort();
      await intake?.close();
      if (scanning) await scanning;
      if (maintaining) await maintaining;
      heartbeat('stopped');
      process.off('SIGINT', shutdown);
      process.off('SIGTERM', shutdown);
    }
  } finally {
    store.close();
    release();
  }
}
main().catch((error) => {
  if (pilotCommands.has(command))
    console.error(
      error instanceof PilotReportError
        ? error.message
        : 'Pilot report failed. Supply one database or backup, a UTC date window and a new .json output path.',
    );
  else if (command === 'rehearse')
    console.error(
      'Rehearsal failed. Check input, bounds, sink mode and a new output path; no external delivery was attempted.',
    );
  else if (error instanceof z.ZodError)
    console.error(
      'Validation failed: ' + error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '),
    );
  else if (error instanceof Error && /YAML/i.test(error.name))
    console.error('Invalid YAML; check configuration/inventory syntax.');
  else console.error(error instanceof Error ? error.message : 'Operation failed');
  // check uses 1 for "found something"; a check that could not run is 2, like an incomplete one.
  process.exitCode = command === 'check' ? 2 : 1;
});
