import { readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import type { Config, ModelSpec } from './types.js';
import { isIP } from 'node:net';
import { privateAddress } from './http.js';
import {
  PROVIDER_IDS,
  providerDefinition,
  allowsMissingKey,
  modelOutputFormat,
  modelEndpoint,
} from './providers.js';

/**
 * A host that is plainly on this machine or a private network; cleartext HTTP is allowed only there.
 * An address is judged by its range. A name cannot be resolved here, so it is accepted when it has
 * no public form: a single label (a container or service name), a special-use or private suffix, or
 * a last label that cannot be a public top-level domain (`ollama.ml-tools`). The request itself is
 * refused if such a name turns out to resolve to a public address.
 */
function localHost(hostname: string): boolean {
  const host = hostname
    .replace(/^\[|\]$/g, '')
    .toLowerCase()
    .replace(/\.$/, '');
  if (isIP(host)) return privateAddress(host);
  if (!host || /^[0-9.]+$/.test(host)) return false;
  const last = host.slice(host.lastIndexOf('.') + 1);
  return (
    host === 'localhost' ||
    !host.includes('.') ||
    /\.(?:localhost|local|internal|intranet|private|corp|lan|home|home\.arpa|test|svc|cluster\.local|ts\.net)$/.test(
      host,
    ) ||
    // Public top-level domains are letters only, or punycode.
    (/[0-9_-]/.test(last) && !last.startsWith('xn--'))
  );
}

/** Two model settings that reach the same model at the same address, however each is written. */
function sameModel(first: ModelSpec, second: ModelSpec): boolean {
  const address = (spec: ModelSpec): string => {
    try {
      const url = new URL(modelEndpoint(spec));
      let path = url.pathname;
      try {
        path = decodeURIComponent(path);
      } catch {
        // Keep the path as written.
      }
      // A trailing dot on the host, doubled or trailing slashes, percent-encoding and letter case
      // are different spellings of one address.
      let host = url.hostname.toLowerCase().replace(/\.$/, '');
      // Every name for this machine is one address.
      if (
        ['localhost', '[::1]', '0.0.0.0', '[::]'].includes(host) ||
        host.endsWith('.localhost') ||
        /^127\.\d+\.\d+\.\d+$/.test(host) ||
        /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(host)
      )
        host = 'localhost';
      return `${url.protocol}//${host}:${url.port}${path.replace(/\/+/g, '/').replace(/\/$/, '').toLowerCase()}`;
    } catch {
      return (spec.endpoint ?? '').trim().toLowerCase();
    }
  };
  // "models/gemini-x" and "gemini-x", or "library/llama3", "llama3" and "llama3:latest", are one model.
  const name = (spec: ModelSpec) =>
    spec.model
      .toLowerCase()
      .replace(/^(?:models|library)\//, '')
      .replace(/:latest$/, '');
  return name(first) === name(second) && address(first) === address(second);
}

const envName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/);
const severity = z.enum(['unknown', 'low', 'medium', 'high', 'critical']);
const channels = z
  .array(z.enum(['slack', 'email']))
  .max(2)
  .refine((a) => new Set(a).size === a.length, 'Duplicate channel');
const retentionDays = z.number().int().min(1).max(3650).optional();
const model = z
  .object({
    provider: z.enum(PROVIDER_IDS),
    disclosure_profile: z.enum(['minimal', 'deployment-context']).default('minimal'),
    output_format: z.enum(['auto', 'json_schema', 'json_object', 'prompt']).default('auto'),
    model: z.string().min(1).max(200),
    api_key_env: envName.optional(),
    endpoint: z.url().optional(),
    allow_private_endpoint: z.boolean().default(false),
    input_usd_per_million: z.number().nonnegative().max(10000).optional(),
    output_usd_per_million: z.number().nonnegative().max(10000).optional(),
  })
  .strict()
  .transform((spec) => ({
    ...spec,
    api_key_env: spec.api_key_env ?? providerDefinition(spec.provider).apiKeyEnv,
  }));
const rule = z
  .object({
    levels: z.array(severity).min(1),
    basis: z.enum(['source_severity', 'priority']).default('priority'),
    channels: channels.default([]),
  })
  .strict();
export const configSchema = z
  .object({
    version: z.literal(1),
    inventory: z.string().min(1).default('./systems.yaml'),
    database: z.string().min(1).default('./data/watch.db'),
    poll_interval_minutes: z.number().int().min(1).max(1440).default(15),
    news_lookback_minutes: z.number().int().min(1).max(10080).default(60),
    inventory_stale_days: z.number().min(1).max(365).default(7),
    digest_interval_hours: z.number().int().min(1).max(168).default(24),
    sources: z
      .object({
        cve_now: z.boolean().default(true),
        hacker_news: z.boolean().default(true),
        osv: z.boolean().default(false),
        github: z.boolean().default(false),
        github_token_env: envName.default('GITHUB_TOKEN'),
        kev: z.boolean().default(false),
        feeds: z.array(z.url()).max(30).default([]),
        vendor_feeds: z
          .array(z.enum(['nodejs', 'python', 'php']))
          .max(3)
          .refine((values) => new Set(values).size === values.length, 'Duplicate vendor feed')
          .default([]),
        epss: z.boolean().default(false),
      })
      .strict()
      .default({
        cve_now: true,
        hacker_news: true,
        osv: false,
        github: false,
        github_token_env: 'GITHUB_TOKEN',
        kev: false,
        feeds: [],
        vendor_feeds: [],
        epss: false,
      }),
    models: z
      .object({
        enabled: z.boolean().default(false),
        analysis: model.optional(),
        verification: model.optional(),
        daily_request_limit: z.number().int().min(1).max(10000).default(100),
        daily_token_limit: z.number().int().min(100).max(10_000_000).default(1_000_000),
        daily_budget_usd: z.number().positive().max(10000).optional(),
        max_input_chars: z.number().int().min(1000).max(100_000).default(12_000),
        max_output_tokens: z.number().int().min(128).max(8192).default(1500),
        timeout_seconds: z.number().int().min(1).max(120).default(45),
      })
      .strict()
      .default({
        enabled: false,
        daily_request_limit: 100,
        daily_token_limit: 1_000_000,
        max_input_chars: 12000,
        max_output_tokens: 1500,
        timeout_seconds: 45,
      }),
    policy: z
      .object({
        library: rule.default({ levels: ['critical'], basis: 'source_severity', channels: [] }),
        product: rule.default({ levels: ['high', 'critical'], basis: 'priority', channels: [] }),
        news: rule.default({ levels: ['high', 'critical'], basis: 'priority', channels: [] }),
        urgent_unknown: z.boolean().default(true),
        exploited_override: z.boolean().default(true),
        malware_override: z.boolean().default(true),
        ai_dismissals: z.enum(['review', 'record']).optional(),
        review_before_news_suppression: z.boolean().optional(),
        news_signals: z.boolean().default(true),
        health_channels: channels.default([]),
      })
      .strict()
      .default({
        library: { levels: ['critical'], basis: 'source_severity', channels: [] },
        product: { levels: ['high', 'critical'], basis: 'priority', channels: [] },
        news: { levels: ['high', 'critical'], basis: 'priority', channels: [] },
        urgent_unknown: true,
        exploited_override: true,
        malware_override: true,
        ai_dismissals: 'review',
        news_signals: true,
        health_channels: [],
      })
      .superRefine((policy, ctx) => {
        if (
          policy.ai_dismissals !== undefined &&
          policy.review_before_news_suppression !== undefined &&
          policy.ai_dismissals !== (policy.review_before_news_suppression ? 'review' : 'record')
        )
          ctx.addIssue({
            code: 'custom',
            message: 'Conflicting AI dismissal policies; use ai_dismissals only.',
          });
      })
      .transform(({ review_before_news_suppression, ...policy }) => ({
        ...policy,
        ai_dismissals:
          policy.ai_dismissals ?? (review_before_news_suppression === false ? 'record' : 'review'),
      })),
    notifications: z
      .object({
        slack: z.object({ webhook_url_env: envName }).strict().optional(),
        email: z
          .object({ smtp_url_env: envName, from: z.email(), to: z.array(z.email()).min(1).max(20) })
          .strict()
          .optional(),
        max_attempts: z.number().int().min(1).max(10).default(3),
      })
      .strict()
      .default({ max_attempts: 3 }),
    monitoring: z
      .object({
        heartbeat_url_env: envName,
        interval_seconds: z.number().int().min(30).max(3600).default(60),
        allow_private_endpoint: z.boolean().default(false),
      })
      .strict()
      .optional(),
    intake: z
      .object({
        listen: z
          .string()
          .trim()
          .regex(
            /^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):\d{1,5}$/,
            'Use HOST:PORT, for example 127.0.0.1:8787 or [::]:8787',
          )
          .refine((value) => Number(value.slice(value.lastIndexOf(':') + 1)) <= 65535, 'Invalid port')
          .default('127.0.0.1:8787'),
        tokens: z
          .array(
            z
              .object({
                token_env: envName,
                systems: z
                  .array(
                    z
                      .string()
                      .regex(
                        /^(?:\*|[A-Za-z0-9][A-Za-z0-9._-]{0,99}\*?)$/,
                        'Use a system ID, an ID prefix ending in *, or * for every system',
                      ),
                  )
                  .min(1)
                  .max(1000)
                  .default(['*']),
              })
              .strict(),
          )
          .min(1)
          .max(100)
          .default([{ token_env: 'SECURITY_WATCH_INTAKE_TOKEN', systems: ['*'] }]),
        tls_cert_file: z.string().trim().min(1).max(4096).optional(),
        tls_key_file: z.string().trim().min(1).max(4096).optional(),
        allow_plain_http: z.boolean().default(false),
      })
      .strict()
      .superRefine((intake, ctx) => {
        if (Boolean(intake.tls_cert_file) !== Boolean(intake.tls_key_file))
          ctx.addIssue({
            code: 'custom',
            message: 'Set both tls_cert_file and tls_key_file, or neither',
            path: ['tls_cert_file'],
          });
        const host = intake.listen.slice(0, intake.listen.lastIndexOf(':')).replace(/^\[|\]$/g, '');
        // An address, not a name that starts like one: `127.example.com` can point anywhere.
        const loopback =
          host.toLowerCase() === 'localhost' ||
          (isIP(host) === 4 && host.startsWith('127.')) ||
          (isIP(host) === 6 && /^(?:0*:)*:?0*1$/.test(host));
        if (!loopback && !intake.tls_cert_file && !intake.allow_plain_http)
          ctx.addIssue({
            code: 'custom',
            message:
              'Listening beyond this machine sends upload tokens over the network: set tls_cert_file and tls_key_file, or allow_plain_http: true when a TLS proxy in front of it is the only way in',
            path: ['listen'],
          });
        const envs = intake.tokens.map((token) => token.token_env);
        if (new Set(envs).size !== envs.length)
          ctx.addIssue({ code: 'custom', message: 'Each token needs its own token_env', path: ['tokens'] });
      })
      .optional(),
    mitigations: z
      .array(
        z
          .object({
            name: z
              .string()
              .trim()
              .min(1)
              .max(40)
              .regex(
                /^[^\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]+$/,
                'Use a short single-line name',
              )
              .optional(),
            format: z.enum(['shirudo', 'generic']),
            file: z.string().trim().min(1).max(4096),
            max_age_minutes: z.number().int().min(5).max(10080).default(120),
            systems: z
              .record(z.string().trim().min(1).max(255), z.string().trim().min(1).max(200))
              .refine((map) => Object.keys(map).length <= 1000, 'At most 1,000 system mappings')
              .default({}),
          })
          .strict()
          .transform(({ name, ...source }) => ({
            ...source,
            name: name ?? (source.format === 'shirudo' ? 'Shirudo' : 'Mitigations'),
          })),
      )
      .max(10)
      .superRefine((sources, ctx) => {
        const names = sources.map((source) => source.name.toLowerCase());
        if (new Set(names).size !== names.length)
          ctx.addIssue({ code: 'custom', message: 'Give each mitigation source its own name' });
      })
      .optional(),
    maintenance: z
      .object({
        interval_hours: z.number().int().min(1).max(168).default(24),
        retention: z
          .object({
            analysis_cache_days: retentionDays,
            evidence_history_days: retentionDays,
            finding_history_days: retentionDays,
            accepted_delivery_days: retentionDays,
            inactive_findings_days: retentionDays,
            unreferenced_evidence_days: retentionDays,
            batch_size: z.number().int().min(1).max(10000).default(1000),
          })
          .strict()
          .refine(
            (value) =>
              Object.entries(value).some(([key, days]) => key !== 'batch_size' && days !== undefined),
            'Choose at least one retention period',
          )
          .optional(),
        backup: z
          .object({
            directory: z.string().trim().min(1).max(4096),
            keep: z.number().int().min(1).max(365).default(7),
            max_bytes: z
              .number()
              .int()
              .min(1)
              .max(20 * 1024 ** 3)
              .default(512 * 1024 ** 2),
          })
          .strict()
          .optional(),
      })
      .strict()
      .refine(
        (value) => value.retention !== undefined || value.backup !== undefined,
        'Configure retention or backups',
      )
      .optional(),
  })
  .strict()
  .superRefine((config, ctx) => {
    const { analysis, verification } = config.models;
    if (analysis && verification && sameModel(analysis, verification))
      ctx.addIssue({
        code: 'custom',
        message:
          'The verification model must differ from the analysis model; an identical model only repeats the first answer. Remove models.verification or choose another model.',
        path: ['models', 'verification'],
      });
    if (config.models.enabled && !config.models.analysis)
      ctx.addIssue({
        code: 'custom',
        message: 'Enabled models require an analysis model',
        path: ['models', 'analysis'],
      });
    for (const [name, spec] of Object.entries({
      analysis: config.models.analysis,
      verification: config.models.verification,
    })) {
      if (!spec) continue;
      const definition = providerDefinition(spec.provider);
      if (!definition.endpoint && !spec.endpoint)
        ctx.addIssue({
          code: 'custom',
          message: 'This provider requires an endpoint',
          path: ['models', name, 'endpoint'],
        });
      if (definition.local && !spec.allow_private_endpoint)
        ctx.addIssue({
          code: 'custom',
          message: 'Local provider requires allow_private_endpoint: true',
          path: ['models', name, 'allow_private_endpoint'],
        });
      try {
        modelOutputFormat(spec);
        if (spec.endpoint || definition.endpoint) modelEndpoint(spec);
      } catch (error) {
        ctx.addIssue({ code: 'custom', message: (error as Error).message, path: ['models', name] });
      }
      if (
        config.models.daily_budget_usd !== undefined &&
        (spec.input_usd_per_million === undefined || spec.output_usd_per_million === undefined)
      )
        ctx.addIssue({
          code: 'custom',
          message: 'A dollar budget requires input and output pricing for every configured model',
          path: ['models', name],
        });
      if (spec.endpoint) {
        const url = new URL(spec.endpoint);
        if (
          url.username ||
          url.password ||
          url.search ||
          url.hash ||
          (url.protocol !== 'https:' && !(spec.allow_private_endpoint && localHost(url.hostname))) ||
          !['https:', 'http:'].includes(url.protocol)
        )
          ctx.addIssue({
            code: 'custom',
            message:
              'Endpoint must be HTTPS, with no credentials/query/fragment; only an explicit private or local endpoint may use HTTP',
            path: ['models', name, 'endpoint'],
          });
      }
    }
    const used = new Set([
      ...config.policy.library.channels,
      ...config.policy.product.channels,
      ...config.policy.news.channels,
      ...config.policy.health_channels,
    ]);
    for (const channel of used)
      if (!config.notifications[channel])
        ctx.addIssue({
          code: 'custom',
          message: `Missing ${channel} notification configuration`,
          path: ['notifications', channel],
        });
    for (const feed of config.sources.feeds) {
      const url = new URL(feed);
      if (url.protocol !== 'https:' || url.username || url.password)
        ctx.addIssue({
          code: 'custom',
          message: 'Feeds must be public HTTPS URLs without credentials',
          path: ['sources', 'feeds'],
        });
    }
  });

export function parseConfig(value: unknown): Config {
  return configSchema.parse(value);
}
export function missingCredentials(config: Config): string[] {
  const missing: string[] = [];
  if (config.monitoring && !process.env[config.monitoring.heartbeat_url_env])
    missing.push(config.monitoring.heartbeat_url_env);
  if (config.models.enabled)
    for (const spec of [config.models.analysis, config.models.verification]) {
      if (spec && !process.env[spec.api_key_env] && !allowsMissingKey(spec)) missing.push(spec.api_key_env);
    }
  const destinations = new Set([
    ...config.policy.library.channels,
    ...config.policy.news.channels,
    ...config.policy.product.channels,
    ...config.policy.health_channels,
  ]);
  for (const channel of destinations) {
    const spec = config.notifications[channel];
    if (spec) {
      const env = 'webhook_url_env' in spec ? spec.webhook_url_env : spec.smtp_url_env;
      if (!process.env[env]) missing.push(env);
    }
  }
  return [...new Set(missing)];
}
export function loadConfig(path: string): Config {
  if (statSync(path).size > 1_048_576) throw new Error('Configuration exceeds 1 MiB');
  const raw = readFileSync(path, 'utf8');
  // Substitute parsed scalar values only, so an environment value cannot inject YAML syntax.
  function substitute(value: unknown): unknown {
    if (typeof value === 'string')
      return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_all, name: string) => {
        const replacement = process.env[name];
        if (replacement === undefined) throw new Error(`Missing configuration variable ${name}`);
        return replacement;
      });
    if (Array.isArray(value)) return value.map(substitute);
    if (value && typeof value === 'object')
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substitute(v)]));
    return value;
  }
  const config = parseConfig(substitute(parse(raw, { maxAliasCount: 0 })));
  config.inventory = resolve(dirname(resolve(path)), config.inventory);
  config.database = resolve(dirname(resolve(path)), config.database);
  if (config.intake?.tls_cert_file)
    config.intake.tls_cert_file = resolve(dirname(resolve(path)), config.intake.tls_cert_file);
  if (config.intake?.tls_key_file)
    config.intake.tls_key_file = resolve(dirname(resolve(path)), config.intake.tls_key_file);
  for (const source of config.mitigations ?? []) source.file = resolve(dirname(resolve(path)), source.file);
  if (config.maintenance?.backup)
    config.maintenance.backup.directory = resolve(
      dirname(resolve(path)),
      config.maintenance.backup.directory,
    );
  return config;
}
