import nodemailer from 'nodemailer';
import type { Assessment, Config, HttpClient, Notification } from './types.js';
import { cleanText } from './util.js';
import { decide } from './assessment.js';
import { Store } from './store.js';

export interface EmailMessage {
  url: string;
  from: string;
  to: string[];
  subject: string;
  text: string;
}
export interface EmailReceipt {
  accepted: string[];
  rejected: string[];
}
export type EmailSender = (message: EmailMessage) => Promise<EmailReceipt>;

export const sendEmail: EmailSender = async (message) => {
  const url = new URL(message.url);
  if (
    !['smtp:', 'smtps:'].includes(url.protocol) ||
    url.search ||
    url.hash ||
    (url.pathname && url.pathname !== '/')
  )
    throw new Error('Invalid SMTP configuration');
  const transport = nodemailer.createTransport({
    host: url.hostname,
    port: Number(url.port || (url.protocol === 'smtps:' ? 465 : 587)),
    secure: url.protocol === 'smtps:',
    requireTLS: true,
    ignoreTLS: false,
    ...(url.username
      ? { auth: { user: decodeURIComponent(url.username), pass: decodeURIComponent(url.password) } }
      : {}),
    tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' },
    connectionTimeout: 30_000,
    greetingTimeout: 30_000,
    socketTimeout: 30_000,
    disableFileAccess: true,
    disableUrlAccess: true,
  });
  try {
    const result = await transport.sendMail({
      from: message.from,
      to: message.to,
      subject: message.subject,
      text: message.text,
      disableFileAccess: true,
      disableUrlAccess: true,
    });
    return { accepted: result.accepted.map(String), rejected: result.rejected.map(String) };
  } finally {
    transport.close();
  }
};

function safeText(input: string, length: number): string {
  return cleanText(input, length)
    .replace(/[\r\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/@/g, '@\u200b')
    .slice(0, length);
}
export function notificationText(job: Notification): { subject: string; text: string } {
  const { assessment: a, reason } = JSON.parse(job.payload) as { assessment: Assessment; reason: string };
  const subject = safeText(`[${a.priority.toUpperCase()}] ${a.title}`, 180).replace(/[\n\r]/g, ' ');
  const urls = a.urls.filter((value) => {
    try {
      return ['https:', 'http:'].includes(new URL(value).protocol);
    } catch {
      return false;
    }
  });
  const lines = [
    subject,
    `Finding: ${a.id}`,
    `Delivery: ${job.id}`,
    `System: ${safeText(a.system_id, 200)}${a.component_id ? ` / ${safeText(a.component_id, 200)}` : ''}`,
    `Applicability: ${a.applicability}; source severity: ${a.source_severity}; priority: ${a.priority}`,
    ...(a.exploited ? ['Known exploitation reported.'] : []),
    safeText(a.summary, 750),
    ...a.reasons.slice(0, 4).map((r) => `• ${safeText(r, 180)}`),
    ...(a.fix ? [`Fix: ${safeText(a.fix, 160)}`] : []),
    `Rule: ${safeText(reason, 180)}`,
    `Assessment time: ${a.updated_at}`,
    ...urls.slice(0, 3).map((u) => safeText(u, 320)),
  ];
  return { subject, text: safeText(lines.join('\n'), 2900) };
}
function digestText(jobs: Notification[]): { subject: string; text: string } {
  const subject = `Security Watch digest: ${jobs.length} findings`;
  const entries = jobs.map((job) => {
    const { assessment: a } = JSON.parse(job.payload) as { assessment: Assessment };
    const sourceUrl = a.urls.find((value) => {
      try {
        return ['https:', 'http:'].includes(new URL(value).protocol);
      } catch {
        return false;
      }
    });
    return (
      `[${a.priority.toUpperCase()}] ${safeText(a.title, 90)}\n` +
      `Finding: ${a.id}\nDelivery: ${job.id}\n` +
      `System: ${safeText(a.system_id, 60)}${a.component_id ? ` / ${safeText(a.component_id, 60)}` : ''}\n` +
      `Applicability: ${a.applicability}; source: ${a.source_severity}\n` +
      `${safeText(sourceUrl ?? 'No source URL supplied', 160)}`
    );
  });
  return { subject, text: `${subject}\n\n${entries.join('\n\n')}` };
}
function retryAt(headers: Record<string, string>, now: number, attempts: number): number {
  const raw = Object.entries(headers).find(([name]) => name.toLowerCase() === 'retry-after')?.[1];
  const retry =
    raw === undefined ? NaN : /^\d+(\.\d+)?$/.test(raw) ? now + Number(raw) * 1000 : Date.parse(raw);
  // Bound remote instructions and avoid tight retry loops.
  return Number.isFinite(retry)
    ? Math.min(now + 86_400_000, Math.max(now + 1000, retry))
    : now + Math.min(3_600_000, 30_000 * 2 ** Math.min(attempts - 1, 7));
}
function statusCode(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null || !('responseCode' in error)) return undefined;
  const code = Number(error.responseCode);
  return Number.isFinite(code) ? code : undefined;
}

/** Sends due jobs; "accepted" means the destination accepted the request, not that a human read it. */
export async function deliverPending(
  store: Store,
  config: Config,
  http: HttpClient,
  now = Date.now(),
  emailSender: EmailSender = sendEmail,
): Promise<{ accepted: number; failed: number; unknown: number }> {
  const result = { accepted: 0, failed: 0, unknown: 0 };
  let job: Notification | undefined;
  const started = Date.now();
  let batches = 0;
  // One snapshot of due work avoids waiting in-process for rate limits or retry timers.
  while (
    batches++ < 50 &&
    Date.now() - started < 2000 &&
    (job = store.claimDue(now, Number(store.getMeta('delivery:slack:next_at') ?? 0) > now ? ['slack'] : []))
  ) {
    let batch = [job];
    try {
      if (JSON.parse(job.payload).mode === 'digest')
        batch.push(...store.claimAdditionalDigest(job.channel, now));
    } catch {
      /* Invalid payload is handled below. */
    }
    // A worker restart can load a new policy before its first source scan finishes. Do not
    // deliver previously queued routes or urgency blindly under that changed configuration.
    batch = batch.filter((entry) => {
      const current = store.getFinding(entry.finding_id);
      if (!current || current.active === false) {
        store.completeJob(entry.id, 'failed', now, 'Finding is no longer active');
        return false;
      }
      const decision = decide(current, config);
      if (decision.action === 'record' || !decision.channels.includes(entry.channel)) {
        store.completeJob(entry.id, 'failed', now, 'Notification policy no longer selects this destination');
        return false;
      }
      let mode: unknown;
      try {
        mode = JSON.parse(entry.payload).mode;
      } catch {
        store.completeJob(entry.id, 'failed', now, 'Invalid saved notification payload');
        result.failed++;
        return false;
      }
      if (mode !== decision.action) {
        store.completeJob(entry.id, 'failed', now, 'Notification urgency changed under the current policy');
        store.saveAssessment(current, decision, now, config.digest_interval_hours * 3_600_000);
        return false;
      }
      return true;
    });
    if (!batch.length) continue;
    const item = batch[0]!;
    const finish = (status: 'accepted' | 'failed' | 'unknown', message?: string) => {
      for (const entry of batch) {
        store.completeJob(entry.id, status, now, message);
        result[status]++;
      }
    };
    const retry = (message: string, at: number) => {
      for (const entry of batch) {
        if (entry.attempts >= config.notifications.max_attempts) {
          store.completeJob(entry.id, 'failed', now, `${message}; retry limit reached`);
          result.failed++;
        } else store.completeJob(entry.id, 'pending', at, message);
      }
    };
    let text: { subject: string; text: string };
    try {
      text = batch.length > 1 ? digestText(batch) : notificationText(item);
    } catch {
      finish('failed', 'Invalid saved notification payload');
      continue;
    }
    if (item.channel === 'slack') {
      const settings = config.notifications.slack;
      const secret = settings ? process.env[settings.webhook_url_env] : undefined;
      if (!secret) {
        finish('failed', 'Slack destination is not configured');
        continue;
      }
      try {
        const url = new URL(secret);
        if (
          url.protocol !== 'https:' ||
          url.hostname !== 'hooks.slack.com' ||
          !url.pathname.startsWith('/services/') ||
          url.username ||
          url.password ||
          url.search ||
          url.hash ||
          (url.port && url.port !== '443')
        ) {
          finish('failed', 'Slack webhook must be an HTTPS hooks.slack.com/services URL');
          continue;
        }
      } catch {
        finish('failed', 'Slack webhook URL is invalid');
        continue;
      }
      const nextSlackAt = Number(store.getMeta('delivery:slack:next_at') ?? 0);
      if (nextSlackAt > now) {
        for (const entry of batch) store.deferJob(entry.id, nextSlackAt);
        continue;
      }
      store.setMeta('delivery:slack:next_at', String(now + 1000));
      try {
        const escaped = text.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const response = await http(secret, {
          method: 'POST',
          redirects: 0,
          timeoutMs: 30_000,
          maxBytes: 16_384,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            text: escaped,
            mrkdwn: false,
            unfurl_links: false,
            unfurl_media: false,
            blocks: [{ type: 'section', text: { type: 'plain_text', text: text.text, emoji: false } }],
          }),
        });
        if (response.status === 200 && response.body.trim() === 'ok') finish('accepted');
        else if (response.status === 429 || response.status >= 500) {
          const at = retryAt(response.headers, now, item.attempts);
          if (response.status === 429) {
            store.setMeta('delivery:slack:next_at', String(at));
          }
          retry(`Slack rejected request with HTTP ${response.status}`, at);
        } else if (response.status >= 200 && response.status < 300)
          finish('unknown', 'Unexpected Slack success response; verify receipt before retrying');
        else finish('failed', `Slack rejected request with HTTP ${response.status}`);
      } catch {
        finish(
          'unknown',
          'Slack delivery interrupted; receipt is unknown. Verify the destination before retrying.',
        );
      }
    } else {
      const settings = config.notifications.email;
      const secret = settings ? process.env[settings.smtp_url_env] : undefined;
      if (!settings || !secret) {
        finish('failed', 'Email destination is not configured');
        continue;
      }
      try {
        const url = new URL(secret);
        if (
          !['smtp:', 'smtps:'].includes(url.protocol) ||
          url.search ||
          url.hash ||
          (url.pathname && url.pathname !== '/')
        ) {
          finish('failed', 'Invalid SMTP configuration');
          continue;
        }
      } catch {
        finish('failed', 'Invalid SMTP configuration');
        continue;
      }
      try {
        const receipt = await emailSender({
          url: secret,
          from: settings.from,
          to: [...new Set(settings.to)],
          subject: text.subject,
          text: text.text,
        });
        const expected = new Set(settings.to);
        const accepted = new Set(receipt.accepted);
        if (
          !receipt.rejected.length &&
          accepted.size === expected.size &&
          [...expected].every((address) => accepted.has(address))
        )
          finish('accepted');
        else if (receipt.accepted.length)
          finish(
            'unknown',
            'SMTP accepted only some recipients. Verify receipt before retrying to avoid duplicates.',
          );
        else finish('failed', 'SMTP did not accept any recipients');
      } catch (error) {
        const code = statusCode(error);
        if (code && code >= 400 && code < 500)
          retry(`SMTP rejected request with status ${code}`, retryAt({}, now, item.attempts));
        else if (code && code >= 500 && code < 600)
          finish('failed', `SMTP rejected request with status ${code}`);
        else
          finish(
            'unknown',
            'SMTP delivery interrupted; receipt is unknown. Verify the destination before retrying.',
          );
      }
    }
  }
  return result;
}
