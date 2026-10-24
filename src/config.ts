import { readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import type { Config } from './types.js';

const envName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/);
const severity = z.enum(['unknown', 'low', 'medium', 'high', 'critical']);
const channels = z
  .array(z.enum(['slack', 'email']))
  .max(2)
  .refine((a) => new Set(a).size === a.length, 'Duplicate channel');
const model = z
  .object({
    provider: z.enum(['openai', 'anthropic', 'openai-compatible']),
    model: z.string().min(1).max(200),
    api_key_env: envName,
    endpoint: z.url().optional(),
    allow_private_endpoint: z.boolean().default(false),
    input_usd_per_million: z.number().nonnegative().max(10000).optional(),
    output_usd_per_million: z.number().nonnegative().max(10000).optional(),
  })
  .strict();
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
    inventory_stale_days: z.number().min(1).max(365).default(7),
    digest_interval_hours: z.number().int().min(1).max(168).default(24),
    sources: z
      .object({
        osv: z.boolean().default(true),
        github: z.boolean().default(true),
        github_token_env: envName.default('GITHUB_TOKEN'),
        kev: z.boolean().default(true),
        feeds: z.array(z.url()).max(30).default([]),
      })
      .strict()
      .default({ osv: true, github: true, github_token_env: 'GITHUB_TOKEN', kev: true, feeds: [] }),
    models: z
      .object({
        enabled: z.boolean().default(false),
        analysis: model.optional(),
        verification: model.optional(),
        daily_request_limit: z.number().int().min(1).max(10000).default(100),
        daily_token_limit: z.number().int().min(100).max(10_000_000).default(100_000),
        daily_budget_usd: z.number().positive().max(10000).optional(),
        max_input_chars: z.number().int().min(1000).max(100_000).default(12_000),
        max_output_tokens: z.number().int().min(128).max(8192).default(1500),
        timeout_seconds: z.number().int().min(1).max(120).default(45),
      })
      .strict()
      .default({
        enabled: false,
        daily_request_limit: 100,
        daily_token_limit: 100000,
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
        health_channels: [],
      }),
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
  })
  .strict()
  .superRefine((config, ctx) => {
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
      if (spec.provider === 'openai-compatible' && !spec.endpoint)
        ctx.addIssue({
          code: 'custom',
          message: 'Compatible provider requires an endpoint',
          path: ['models', name, 'endpoint'],
        });
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
          (!spec.allow_private_endpoint && url.protocol !== 'https:') ||
          !['https:', 'http:'].includes(url.protocol)
        )
          ctx.addIssue({
            code: 'custom',
            message:
              'Endpoint must be HTTPS, with no credentials/query/fragment; explicit private endpoints may use HTTP',
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
  if (config.models.enabled)
    for (const spec of [config.models.analysis, config.models.verification]) {
      if (
        spec &&
        !process.env[spec.api_key_env] &&
        !(spec.provider === 'openai-compatible' && spec.allow_private_endpoint)
      )
        missing.push(spec.api_key_env);
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
  return config;
}
