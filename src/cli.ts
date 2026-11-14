#!/usr/bin/env node
import { parseArgs } from 'node:util';
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { stringify } from 'yaml';
import { z } from 'zod';
import { loadConfig, parseConfig, missingCredentials } from './config.js';
import { loadInventory } from './inventory.js';
import { importCycloneDx } from './sbom.js';
import { refreshCoverage } from './coverage.js';
import { Store, readPilotReport } from './store.js';
import { PilotReportError } from './pilot-report.js';
import { runScan, readFixture, healthFinding } from './engine.js';
import { deliverPending, slackProblem, smtpProblem } from './delivery.js';
import { safeHttp, validateDestination } from './http.js';

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
import { checkHealth } from './health.js';
import type { Assessment, Config } from './types.js';
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

  security-watch init [--directory PATH] [--yes] [--systems nodejs,python]
    [--libraries PATH --ecosystem php] [--vendor-feeds nodejs,python,php] [--heartbeat]
    [--provider NAME --model ID] [--endpoint URL] [--allow-private-endpoint]
    [--poll-minutes 30] [--lookback-minutes 40]
    [--notifications slack,email] [--email-from ADDRESS] [--email-to ADDRESS,ADDRESS]
  security-watch doctor [--config PATH] [--credentials-file PATH]
  security-watch providers
  security-watch templates
  security-watch ecosystems
  security-watch import-sbom --input PATH [--output PATH]
  security-watch coverage | inventory-drift [--config PATH]
  security-watch normalize-libraries --input PATH [--ecosystem php] [--output PATH]
  security-watch scan [--dry-run] [--notify] [--fixture PATH] [--no-ai]
  security-watch rehearse --config PATH --input SCENARIO.json [--sink disabled|accepted|failed|unknown] [--output NEW.json]
  security-watch start [--config PATH]
  security-watch findings | status | deliveries | budget
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
      ...(libraries ? { osv: true } : {}),
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
  writeFileSync(
    inventoryPath,
    stringify({
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
    }),
    { flag: 'wx', mode: 0o600 },
  );
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
    `Created ${configPath} and ${inventoryPath}. Add installed versions and deployment details to systems.yaml. Copy .env.example to .env and fill in any required credentials. Then run:\n  security-watch doctor --config ${shellArgument(configPath)} --credentials-file ${shellArgument(resolve(directory, '.env'))}\n  security-watch scan --config ${shellArgument(configPath)} --credentials-file ${shellArgument(resolve(directory, '.env'))} --dry-run\nNo messages were sent.`,
  );
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
    init: [
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
  const needsId = ['explain', 'history', 'review', 'acknowledge', 'suppress', 'retry'].includes(command);
  if (positionals.length > (needsId ? 2 : 1)) throw new Error('Unexpected positional arguments. Use --help.');
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
  if (command === 'import-sbom') {
    if (!values.input) throw new Error('--input PATH required');
    const report = importCycloneDx(resolve(values.input));
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
      output(store.findings());
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
      const finding = id ? store.getFinding(id) : undefined;
      if (!finding) throw new Error('Finding not found');
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
        ...(values.fixture ? { fixture: readFixture(resolve(values.fixture)) } : {}),
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
    const controller = new AbortController();
    const startedAt = new Date().toISOString();
    let lastHeartbeat = 0;
    const heartbeat = (status: 'running' | 'stopping' | 'stopped') => {
      const now = Date.now();
      store.setMeta(
        'worker',
        JSON.stringify({
          pid: process.pid,
          status,
          started_at: startedAt,
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
        if (Date.now() - lastHeartbeat >= 15_000) heartbeat('running');
        if (!scanning && !maintaining && Date.now() >= nextScan) {
          nextScan = Date.now() + config.poll_interval_minutes * 60_000;
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
  process.exitCode = 1;
});
