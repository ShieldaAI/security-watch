#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { stringify } from 'yaml';
import { z } from 'zod';
import { loadConfig, parseConfig, missingCredentials } from './config.js';
import { loadInventory } from './inventory.js';
import { Store } from './store.js';
import { runScan, readFixture, healthFinding } from './engine.js';
import { deliverPending } from './delivery.js';
import { safeHttp } from './http.js';
import { acquireLock, unlockStoppedWorker } from './lock.js';
import { decide } from './assessment.js';
import { checkHealth } from './health.js';
import type { Assessment } from './types.js';

const help = `Shielda Security Watch (experimental alpha)

  security-watch init [--directory PATH] [--yes]
  security-watch doctor [--config PATH]
  security-watch scan [--dry-run] [--notify] [--fixture PATH] [--no-ai]
  security-watch start [--config PATH]
  security-watch findings | status | deliveries | budget
  security-watch health [--scan-only]
  security-watch explain FINDING_ID
  security-watch history FINDING_ID
  security-watch acknowledge FINDING_ID
  security-watch suppress FINDING_ID --hours 24 --reason TEXT
  security-watch retry DELIVERY_ID   (verify receipt before retrying unknown delivery)
  security-watch backup --output PATH
  security-watch unlock             (only removes a stopped worker's lock)
  security-watch test-notification --channel slack|email

Default config: ./security-watch.yaml. scan records findings; --dry-run writes no state,
disables models and sends nothing. --notify sends due jobs. start runs the foreground scheduler and
configured notification routes. Model/feed requests can leave this machine; fixture
mode performs no source or model requests. No packages are installed or patched.
`;
function argumentsFromCommandLine() {
  return parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string' },
      directory: { type: 'string' },
      yes: { type: 'boolean' },
      'dry-run': { type: 'boolean' },
      notify: { type: 'boolean' },
      fixture: { type: 'string' },
      'no-ai': { type: 'boolean' },
      hours: { type: 'string' },
      reason: { type: 'string' },
      output: { type: 'string' },
      channel: { type: 'string' },
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
    console.error(error instanceof Error ? error.message : 'Invalid arguments');
    process.exit(1);
  }
})();
const [command = 'help', id] = positionals;
function output(value: unknown) {
  console.log(JSON.stringify(value, null, 2));
}
async function initialize(): Promise<void> {
  const directory = resolve(values.directory ?? '.');
  mkdirSync(directory, { recursive: true });
  const configPath = resolve(directory, 'security-watch.yaml'),
    inventoryPath = resolve(directory, 'systems.yaml');
  if (existsSync(configPath) || existsSync(inventoryPath))
    throw new Error('Configuration or inventory already exists; init never overwrites it.');
  let provider = 'none',
    model = '',
    slack = false;
  if (!values.yes && process.stdin.isTTY) {
    const prompt = createInterface({ input: process.stdin, output: process.stdout });
    try {
      provider =
        (await prompt.question('AI provider (none/openai/anthropic; default none): ')).trim() || 'none';
      if (!['none', 'openai', 'anthropic'].includes(provider))
        throw new Error('Choose none, openai or anthropic. Compatible endpoints can be configured in YAML.');
      if (provider !== 'none') {
        model = (await prompt.question('Exact model ID (from your provider): ')).trim();
        if (!model) throw new Error('Model ID is required.');
      }
      slack = /^y(es)?$/i.test(
        (await prompt.question('Configure Slack routes using SLACK_WEBHOOK_URL? (y/N): ')).trim(),
      );
    } finally {
      prompt.close();
    }
  }
  const channels = slack ? ['slack'] : [];
  const config = parseConfig({
    version: 1,
    inventory: './systems.yaml',
    database: './data/watch.db',
    models:
      provider === 'none'
        ? { enabled: false }
        : {
            enabled: true,
            analysis: {
              provider,
              model,
              api_key_env: provider === 'openai' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY',
            },
          },
    policy: {
      library: { levels: ['critical'], basis: 'source_severity', channels },
      product: { levels: ['high', 'critical'], channels },
      news: { levels: ['high', 'critical'], channels },
      health_channels: channels,
    },
    notifications: slack ? { slack: { webhook_url_env: 'SLACK_WEBHOOK_URL' } } : {},
  });
  writeFileSync(
    configPath,
    '# Read README.md for privacy, coverage and notification semantics.\n' + stringify(config),
    { flag: 'wx', mode: 0o600 },
  );
  writeFileSync(
    inventoryPath,
    stringify({
      systems: [
        {
          id: 'example-api',
          name: 'Example API',
          environment: 'development',
          exposure: 'unknown',
          criticality: 'unknown',
          updated_at: new Date().toISOString(),
          components: [{ id: 'example-parser', ecosystem: 'npm', name: 'example-parser', version: '1.2.0' }],
          products: [],
          keywords: [],
        },
      ],
    }),
    { flag: 'wx', mode: 0o600 },
  );
  console.log(
    `Created ${configPath} and ${inventoryPath}. Replace the example inventory, then run doctor and scan --dry-run. Credentials are read from environment variables; init sends no messages.`,
  );
}
async function main(): Promise<void> {
  if (values.version) {
    console.log('0.1.0-alpha.0');
    return;
  }
  if (values.help || command === 'help') {
    console.log(help);
    return;
  }
  const commandFlags: Record<string, string[]> = {
    init: ['directory', 'yes'],
    doctor: ['config', 'no-ai'],
    unlock: ['config'],
    scan: ['config', 'dry-run', 'notify', 'fixture', 'no-ai'],
    start: ['config', 'no-ai'],
    findings: ['config'],
    status: ['config'],
    deliveries: ['config'],
    budget: ['config'],
    health: ['config', 'scan-only'],
    explain: ['config', 'no-ai'],
    history: ['config'],
    acknowledge: ['config'],
    suppress: ['config', 'hours', 'reason'],
    retry: ['config'],
    backup: ['config', 'output'],
    'test-notification': ['config', 'channel'],
  };
  if (!commandFlags[command]) throw new Error(`Unknown command ${command}. Use --help.`);
  for (const flag of Object.keys(values))
    if (!commandFlags[command]!.includes(flag)) throw new Error(`--${flag} is not supported by ${command}.`);
  const needsId = ['explain', 'history', 'acknowledge', 'suppress', 'retry'].includes(command);
  if (positionals.length > (needsId ? 2 : 1)) throw new Error('Unexpected positional arguments. Use --help.');
  if (command === 'init') {
    await initialize();
    return;
  }
  const config = loadConfig(resolve(values.config ?? 'security-watch.yaml'));
  if (values['no-ai']) config.models.enabled = false;
  if (command === 'unlock') {
    unlockStoppedWorker(config.database);
    console.log('Stopped-worker lock removed.');
    return;
  }
  if (command === 'doctor') {
    const inventory = loadInventory(config.inventory);
    const missing = missingCredentials(config);
    output({
      ok: missing.length === 0,
      systems: inventory.systems.length,
      components: inventory.systems.reduce((sum, s) => sum + s.components.length, 0),
      missing_environment_variables: missing,
      database: config.database,
      models_enabled: config.models.enabled,
      feeds: config.sources.feeds.length,
      notices: [
        'Model compatibility is verified only by a real analysis request; doctor does not spend tokens or send notifications.',
        'Public advisory queries disclose package names/versions. Models receive relevant inventory context.',
        'Generic products are news candidates, not verified vulnerability coverage.',
      ],
    });
    if (missing.length) process.exitCode = 2;
    return;
  }
  const allowed = new Set([
    'scan',
    'start',
    'findings',
    'status',
    'deliveries',
    'budget',
    'health',
    'explain',
    'history',
    'acknowledge',
    'suppress',
    'retry',
    'backup',
    'test-notification',
  ]);
  if (!allowed.has(command)) throw new Error(`Unknown command ${command}. Use --help.`);
  const dry = command === 'scan' && Boolean(values['dry-run']);
  if (dry && values.notify) throw new Error('--dry-run and --notify cannot be combined.');
  if (dry) config.models.enabled = false;
  const readonly = ['findings', 'status', 'deliveries', 'budget', 'health', 'explain', 'history'].includes(
    command,
  );
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
        findings: summary.active_findings,
        delivery_states: summary.delivery_states,
        worker_lock: existsSync(`${config.database}.lock`),
        worker_lock_note:
          'Informational metadata can remain after a crash; exclusive SQLite ownership prevents concurrent workers.',
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
      store.acknowledge(id);
      console.log('Finding acknowledged.');
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
      await store.backup(resolve(values.output));
      console.log('Consistent backup created.');
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
      output(
        await deliverPending(
          store,
          { ...config, policy: { ...config.policy, health_channels: [values.channel] } },
          safeHttp,
        ),
      );
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
    const shutdown = () => {
      stop = true;
      controller.abort();
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    console.log('Security Watch is running in the foreground. Configured routes are active.');
    try {
      while (!stop) {
        if (Date.now() - lastHeartbeat >= 15_000) heartbeat('running');
        if (!scanning && Date.now() >= nextScan) {
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
        const delivery = await deliverPending(store, config, safeHttp);
        if (delivery.failed || delivery.unknown)
          console.error(
            JSON.stringify({ delivery, action: 'Inspect deliveries and destination configuration.' }),
          );
        await delay(1000);
      }
      if (scanning) await scanning;
    } finally {
      controller.abort();
      if (scanning) await scanning;
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
  if (error instanceof z.ZodError)
    console.error(
      'Validation failed: ' + error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '),
    );
  else if (error instanceof Error && /YAML/i.test(error.name))
    console.error('Invalid YAML; check configuration/inventory syntax.');
  else console.error(error instanceof Error ? error.message : 'Operation failed');
  process.exitCode = 1;
});
