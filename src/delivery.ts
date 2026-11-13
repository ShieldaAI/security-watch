import nodemailer from 'nodemailer';
import { createConnection, type Socket } from 'node:net';
import type { Assessment, Config, HttpClient, Notification } from './types.js';
import { cleanText } from './util.js';
import { decide } from './assessment.js';
import { Store } from './store.js';
import { NetworkError } from './http.js';

export interface EmailMessage {
  url: string;
  from: string;
  to: string[];
  subject: string;
  text: string;
  signal?: AbortSignal;
}
export interface EmailReceipt {
  accepted: string[];
  rejected: string[];
}
export type EmailSender = (message: EmailMessage) => Promise<EmailReceipt>;

class EmailConnectionError extends Error {
  constructor() {
    super('SMTP connection failed before sending');
  }
}

export const sendEmail: EmailSender = async (message) => {
  message.signal?.throwIfAborted();
  const url = new URL(message.url);
  if (
    !['smtp:', 'smtps:'].includes(url.protocol) ||
    url.search ||
    url.hash ||
    (url.pathname && url.pathname !== '/')
  )
    throw new Error('Invalid SMTP configuration');
  let socket: Socket | undefined;
  const transport = nodemailer.createTransport({
    host: url.hostname.replace(/^\[|\]$/g, ''),
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
    // Keep the underlying socket so cancellation also stops SMTP/STARTTLS traffic.
    getSocket: (_options, callback) => {
      if (message.signal?.aborted) {
        callback(new Error('Email delivery aborted'), {});
        return;
      }
      let connected = false;
      socket = createConnection({
        host: url.hostname.replace(/^\[|\]$/g, ''),
        port: Number(url.port || (url.protocol === 'smtps:' ? 465 : 587)),
        signal: message.signal,
      });
      const deadline = setTimeout(() => socket?.destroy(new Error('SMTP connection timeout')), 30_000);
      socket.once('close', () => clearTimeout(deadline));
      socket.once('error', () => {
        if (!connected) callback(new EmailConnectionError(), {});
      });
      socket.once('connect', () => {
        connected = true;
        clearTimeout(deadline);
        callback(null, { connection: socket });
      });
    },
  });
  let abort: (() => void) | undefined;
  try {
    const cancelled = new Promise<never>((_resolve, reject) => {
      abort = () => {
        reject(new Error('Email delivery aborted'));
        socket?.destroy();
        transport.close();
      };
      message.signal?.addEventListener('abort', abort, { once: true });
    });
    const sending = transport.sendMail({
      from: message.from,
      to: message.to,
      subject: message.subject,
      text: message.text,
      disableFileAccess: true,
      disableUrlAccess: true,
    });
    const result = await Promise.race([sending, cancelled]);
    return { accepted: result.accepted.map(String), rejected: result.rejected.map(String) };
  } finally {
    if (abort) message.signal?.removeEventListener('abort', abort);
    transport.close();
    socket?.destroy();
  }
};

function safeText(input: string, length: number): string {
  return cleanText(input, length)
    .replace(/[\r\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/@/g, '@\u200b')
    .slice(0, length);
}
/** The operator's own inventory names and notes, so the reader knows where to check. */
function locationLines(a: Assessment, length: number): string[] {
  const where = a.location;
  if (!where) return [];
  const single = (value: string, limit: number) => safeText(value, limit).replace(/\s*\n\s*/g, ' ');
  return [
    `Where to look: ${single(where.system, 120)}${where.owner ? ` (owner: ${single(where.owner, 80)})` : ''}${where.system_note ? ` - ${single(where.system_note, length)}` : ''}`,
    ...(where.component
      ? [
          `Affected item: ${single(where.component, 160)}${where.component_note ? ` - ${single(where.component_note, length)}` : ''}`,
        ]
      : []),
  ];
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
    ...locationLines(a, 300),
    `Applicability: ${a.applicability}; source severity: ${a.source_severity}; priority: ${a.priority}`,
    ...(a.news_analysis
      ? [
          `AI news classification: ${a.news_analysis.classification}; reported system impact: ${a.news_analysis.impact}`,
          `Affected products: ${safeText(a.news_analysis.affected_products.join('; ') || 'Not established', 180)}`,
          `Reported versions: ${safeText(a.news_analysis.affected_versions.join('; ') || 'Not established', 180)}`,
          `Prerequisites: ${safeText(a.news_analysis.prerequisites.join('; ') || 'Not established', 240)}`,
          `Impact reasoning: ${safeText(a.news_analysis.rationale, 400)}`,
        ]
      : []),
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
      locationLines(a, 120)
        .map((line) => `${line}\n`)
        .join('') +
      `Applicability: ${a.applicability}; source: ${a.source_severity}\n` +
      (a.news_analysis
        ? `AI news: ${a.news_analysis.classification}; impact: ${a.news_analysis.impact}\n`
        : '') +
      `${safeText(sourceUrl ?? 'No source URL supplied', 160)}`
    );
  });
  return { subject, text: `${subject}\n\n${entries.join('\n\n')}` };
}
function retryAt(headers: Record<string, string>, now: number, attempts: number): number {
  const raw = Object.entries(headers).find(([name]) => name.toLowerCase() === 'retry-after')?.[1];
  const retry =
    raw === undefined ? NaN : /^\d+(\.\d+)?$/.test(raw) ? now + Number(raw) * 1000 : Date.parse(raw);
  // Clamp Retry-After values to avoid immediate retries or excessive delays.
  return Number.isFinite(retry)
    ? Math.min(now + 86_400_000, Math.max(now + 1000, retry))
    : now + Math.min(3_600_000, 30_000 * 2 ** Math.min(attempts - 1, 7));
}
/**
 * A reason the SMTP address cannot be used, found without connecting. A user name or password
 * containing %, @, : or / must be percent-encoded (a literal % is written %25).
 */
export function smtpProblem(address: string): string | undefined {
  try {
    const url = new URL(address);
    if (
      !['smtp:', 'smtps:'].includes(url.protocol) ||
      !url.hostname ||
      url.search ||
      url.hash ||
      (url.pathname && url.pathname !== '/')
    )
      return 'Invalid SMTP configuration';
    decodeURIComponent(url.username);
    decodeURIComponent(url.password);
  } catch {
    return 'Invalid SMTP configuration: the address is not a valid smtp:// or smtps:// URL, or its user name or password is not percent-encoded';
  }
  return undefined;
}
function mailbox(address: string): string {
  const at = address.lastIndexOf('@');
  return at < 0 ? address : `${address.slice(0, at)}@${address.slice(at + 1).toLowerCase()}`;
}
/** Failures in the connection, TLS or sign-in steps happen before any message is handed over. */
function beforeEnvelope(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const code = 'code' in error ? String(error.code) : '';
  const command = 'command' in error ? String(error.command) : '';
  return (
    code === 'ETLS' ||
    code === 'EAUTH' ||
    ['CONN', 'STARTTLS', 'EHLO', 'HELO'].includes(command) ||
    /^AUTH\b/.test(command)
  );
}
function statusCode(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null || !('responseCode' in error)) return undefined;
  const code = Number(error.responseCode);
  return Number.isFinite(code) ? code : undefined;
}

export interface DeliveryOptions {
  /** The time treated as "now", in milliseconds. Defaults to the system clock. */
  now?: number;
  /** Replaces the built-in SMTP sender, for tests or a different transport. */
  emailSender?: EmailSender;
  /** Stops in-flight sends when aborted; queued jobs are left untouched. */
  signal?: AbortSignal;
  /** Where destination secrets are read from. Defaults to the process environment. */
  credentials?: Readonly<Record<string, string | undefined>>;
}

/**
 * Sends due jobs; "accepted" means the destination accepted the request, not that a human read it.
 * Pass the optional settings as one object. The positional form is kept for existing callers.
 */
export async function deliverPending(
  store: Store,
  config: Config,
  http: HttpClient,
  options?: DeliveryOptions | number,
  positionalSender?: EmailSender,
  positionalSignal?: AbortSignal,
  positionalCredentials?: Readonly<Record<string, string | undefined>>,
): Promise<{ accepted: number; failed: number; unknown: number }> {
  const settings: DeliveryOptions =
    typeof options === 'object'
      ? options
      : {
          ...(options === undefined ? {} : { now: options }),
          ...(positionalSender ? { emailSender: positionalSender } : {}),
          ...(positionalSignal ? { signal: positionalSignal } : {}),
          ...(positionalCredentials ? { credentials: positionalCredentials } : {}),
        };
  const now = settings.now ?? Date.now();
  const emailSender = settings.emailSender ?? sendEmail;
  const signal = settings.signal;
  const credentials = settings.credentials ?? process.env;
  const result = { accepted: 0, failed: 0, unknown: 0 };
  let job: Notification | undefined;
  const started = Date.now();
  let batches = 0;
  // One snapshot of due work avoids waiting in-process for rate limits or retry timers.
  while (
    !signal?.aborted &&
    batches++ < 50 &&
    Date.now() - started < 2000 &&
    (job = store.claimDue(now, Number(store.getMeta('delivery:slack:next_at') ?? 0) > now ? ['slack'] : []))
  ) {
    let batch = [job];
    let wantsDigest = false;
    try {
      wantsDigest = JSON.parse(job.payload).mode === 'digest';
    } catch {
      /* Invalid payload is handled below. */
    }
    if (wantsDigest) batch.push(...store.claimAdditionalDigest(job.channel, now));
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
        // Validate each saved entry before grouping it with other findings.
        if (mode === 'digest') digestText([entry]);
        else notificationText(entry);
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
    const digest = JSON.parse(batch[0]!.payload).mode === 'digest';
    if (digest && batch[0]!.channel === 'slack') {
      const fitting: Notification[] = [];
      for (const entry of batch) {
        if (digestText([entry]).text.length > 2900) {
          store.completeJob(entry.id, 'failed', now, 'Saved finding exceeds the Slack message limit');
          result.failed++;
        } else if (digestText([...fitting, entry]).text.length > 2900)
          store.deferJob(entry.id, now + 1000, 'Waiting for the next digest batch');
        else fitting.push(entry);
      }
      batch = fitting;
      if (!batch.length) continue;
    }
    const item = batch[0]!;
    const ids = batch.map((entry) => entry.id);
    // Another handle on the same database can take a job back while it is being sent. The outcome
    // can then no longer be recorded as usual; keep the worker running and never resend silently.
    const displaced = (error: unknown, sent: boolean): void => {
      if (!(error instanceof Error) || error.message !== 'Notification is not in flight') throw error;
      if (sent)
        store.markUncertain(
          ids,
          'The delivery result could not be recorded because the job was changed while it was being sent. Verify receipt before retrying.',
        );
      result.unknown += batch.length;
    };
    const finish = (status: 'accepted' | 'failed' | 'unknown', message?: string) => {
      // Sample once per acknowledgement so every item in an accepted digest shares its receipt time.
      const received = status === 'accepted' ? Date.now() : undefined;
      const acceptedAt = received !== undefined && received >= now ? received : undefined;
      try {
        store.completeBatch(ids, status, now, message, acceptedAt);
      } catch (error) {
        displaced(error, status !== 'failed');
        return;
      }
      result[status] += batch.length;
    };
    const retry = (message: string, at: number) => {
      for (const entry of batch) {
        try {
          if (entry.attempts >= config.notifications.max_attempts) {
            store.completeJob(entry.id, 'failed', now, `${message}; retry limit reached`);
            result.failed++;
          } else if ((store.revisionOf(entry.finding_id) ?? 0) > (entry.revision ?? Infinity))
            // A newer revision was saved while this one was being sent; it carries its own job.
            store.completeJob(entry.id, 'failed', now, 'Superseded by a newer assessment');
          else store.completeJob(entry.id, 'pending', at, message);
        } catch (error) {
          displaced(error, false);
          return;
        }
      }
    };
    let text: { subject: string; text: string };
    try {
      text = digest ? digestText(batch) : notificationText(item);
    } catch {
      finish('failed', 'Invalid saved notification payload');
      continue;
    }
    if (item.channel === 'slack') {
      const settings = config.notifications.slack;
      const secret = settings ? credentials[settings.webhook_url_env] : undefined;
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
          signal,
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
      } catch (error) {
        if (
          !signal?.aborted &&
          error instanceof NetworkError &&
          ['DNS_FAILED', 'CONNECTION_FAILED'].includes(error.code)
        )
          retry('Slack connection failed before sending', retryAt({}, now, item.attempts));
        else
          finish(
            'unknown',
            'Slack delivery interrupted; receipt is unknown. Verify the destination before retrying.',
          );
      }
    } else {
      const settings = config.notifications.email;
      const secret = settings ? credentials[settings.smtp_url_env] : undefined;
      if (!settings || !secret) {
        finish('failed', 'Email destination is not configured');
        continue;
      }
      const problem = smtpProblem(secret);
      if (problem) {
        finish('failed', problem);
        continue;
      }
      try {
        const receipt = await emailSender({
          url: secret,
          from: settings.from,
          to: [...new Set(settings.to)],
          subject: text.subject,
          text: text.text,
          signal,
        });
        // Mail servers and clients lower-case the domain; the mailbox part is left as written.
        const expected = new Set(settings.to.map(mailbox));
        const accepted = new Set(receipt.accepted.map(mailbox));
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
        if (!signal?.aborted && error instanceof EmailConnectionError)
          retry('SMTP connection failed before sending', retryAt({}, now, item.attempts));
        else if (!signal?.aborted && !code && beforeEnvelope(error))
          retry('SMTP TLS or sign-in failed before sending', retryAt({}, now, item.attempts));
        else if (code && code >= 400 && code < 500)
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
