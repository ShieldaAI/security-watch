import nodemailer from 'nodemailer';
import { createConnection, type Socket } from 'node:net';
import type { Assessment, Config, HttpClient, Notification } from './types.js';
import { FILLERS, INVISIBLE, cleanText, cut, singleLine } from './util.js';
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

/**
 * The message provably never reached the mail server: the failure happened before the client wrote
 * `MAIL FROM`. Only this error (or an explicit SMTP status) lets a job be retried automatically.
 */
class EmailNotSentError extends Error {
  constructor(readonly stage: 'connection' | 'session') {
    super(
      stage === 'connection'
        ? 'SMTP connection failed before sending'
        : 'SMTP TLS or sign-in failed before sending',
    );
  }
}

/**
 * What the mail transport's transaction log shows about one SMTP session. "No MAIL FROM was logged"
 * proves that none was written only if the log reports what the client writes. That is shown by a
 * logged client command (its EHLO comes before anything else), or by a session that ended before
 * the server said anything (a refused connection, a failed TLS handshake), where there was nothing
 * to write. Server replies without any client command mean the log cannot be relied on.
 */
export function smtpTranscript(): {
  observe: (entry: unknown, line: unknown) => void;
  envelopeStarted: () => boolean;
  nothingHandedOver: () => boolean;
} {
  let logged = false;
  let clientSeen = false;
  let serverSeen = false;
  let notSmtp = false;
  let envelopeStarted = false;
  return {
    observe(entry, line) {
      logged = true;
      const side = typeof entry === 'object' && entry !== null && 'tnx' in entry ? entry.tnx : undefined;
      // A first line from the server that is not an SMTP reply ("* OK IMAP ready", "SSH-2.0") is
      // another service on that port: an SMTP client writes nothing to it.
      if (side === 'server' && !serverSeen && !/^\d{3}(?:[ -]|$)/.test(String(line).trim())) notSmtp = true;
      if (side === 'server') serverSeen = true;
      if (side !== 'client') return;
      clientSeen = true;
      if (/^\s*(?:MAIL|RCPT|DATA|BDAT)\b/i.test(String(line))) envelopeStarted = true;
    },
    envelopeStarted: () => envelopeStarted,
    nothingHandedOver: () => logged && !envelopeStarted && (clientSeen || !serverSeen || notSmtp),
  };
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
  // The transport labels every socket error, timeout and unexpected close the same way at any stage,
  // including after the message body was transferred. The only proof that nothing was handed over is
  // that the client never wrote MAIL FROM, so the conversation is observed through the transport's
  // own transaction log.
  const transcript = smtpTranscript();
  const observe = transcript.observe;
  const transport = nodemailer.createTransport({
    logger: {
      level: () => undefined,
      trace: observe,
      debug: observe,
      info: observe,
      warn: observe,
      error: observe,
      fatal: observe,
    },
    debug: true,
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
        if (!connected) callback(new EmailNotSentError('connection'), {});
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
  } catch (error) {
    // A reply code from the server is passed on as it is: the caller decides from the code.
    if (
      message.signal?.aborted ||
      error instanceof EmailNotSentError ||
      statusCode(error) !== undefined ||
      !transcript.nothingHandedOver()
    )
      throw error;
    throw new EmailNotSentError('session');
  } finally {
    if (abort) message.signal?.removeEventListener('abort', abort);
    transport.close();
    socket?.destroy();
  }
};

function safeText(input: string, length: number, mentions = true): string {
  // The length is applied last: what is removed or reduced below must not count against it.
  // Fillers become spaces and characters that show as nothing are removed before any limit is
  // applied, so that they cannot push the visible end of a value past it. Some fillers count as
  // default-ignorable, so they are turned into spaces first; the removal comes before spaces are
  // counted, so that spaces they separated are one run.
  const cleaned = cleanText(
    input.replace(FILLERS, ' ').replace(/[\r]/g, '').replace(INVISIBLE, ''),
    Math.max(length, 4000),
  )
    // A lone half of a surrogate pair is not text; services may refuse a message that has one.
    .replace(/\p{Cs}/gu, '\ufffd')
    // A run of blanks moves what follows as far as a line break would.
    .replace(/[^\S\n]{2,}/g, ' ')
    .trim();
  // A value that does not fit ends with "…", so a reader never takes a cut value for a whole one
  // ("8.0.3" for "8.0.39"). An emoji is never cut in half.
  const fitted = cleaned.length <= length ? cleaned : `${cut(cleaned, length - 1).trimEnd()}…`;
  // Only a word Slack treats as a group mention ("@channel", "@here", "@everyone", "@group") gets
  // an invisible break; "express@4.21.2" and "@angular/core" stay exactly as written, so they can
  // be copied and searched for. It is added after the cut: cutting "@channels" to "@channel…"
  // makes a mention of what was none.
  return mentions ? fitted.replace(GROUP_MENTION, '@\u200b') : fitted;
}
/** "@" before a word Slack treats as a group mention, in any letter case. */
const GROUP_MENTION = /@(?=(?:channel|here|everyone|group)(?![\p{L}\p{N}_]))/giu;
/**
 * One value for one line of a message. Advisory text, model output and inventory names are placed
 * after fixed labels such as `Rule:` and `Where to look:`; a line break inside a value would let it
 * forge the next label, so every break becomes a space, and a run of blank characters, which can
 * push the rest of a value onto what looks like a line of its own, becomes one space.
 */
function single(value: string, length: number): string {
  return safeText(singleLine(value), length);
}
/**
 * A source link, kept exactly: a shortened link is a different address, so one that is too long is
 * left out, and nothing is inserted into it.
 */
function link(value: string): string | undefined {
  const written = value.trim();
  const cleaned = safeText(singleLine(written), 2000, false);
  // Shown only exactly as written: a link from which a character had to be removed (an invisible
  // mark, a line break) is another address, and so is a shortened one.
  // A link is never altered, so one with a group mention in it ("…/@channel") is left out too.
  return cleaned === written &&
    cleaned.length <= 320 &&
    !/\s/.test(cleaned) &&
    !new RegExp(GROUP_MENTION.source, 'iu').test(cleaned)
    ? cleaned
    : undefined;
}
/** A list from a model, each entry whole: as many as fit, then how many more there are. */
function listLine(label: string, items: string[], length: number): string {
  const values = items.map((item) => single(item, 4000)).filter(Boolean);
  if (!values.length) return `${label}: Not established`;
  const shown: string[] = [];
  let used = 0;
  for (const value of values) {
    if (value.length > length || (shown.length && used + value.length + 2 > length)) break;
    shown.push(value);
    used += value.length + 2;
  }
  const more = values.length - shown.length;
  return `${label}: ${shown.join('; ')}${more ? `${shown.length ? '; ' : ''}and ${more} more` : ''}`;
}
/** The operator's own inventory names and notes, so the reader knows where to check. */
function locationLines(a: Assessment, length: number): string[] {
  const where = a.location;
  if (!where) return [];
  // With no room for notes (length 0) the names alone are shown.
  const note = (value: string | undefined) => (value && length ? ` - ${single(value, length)}` : '');
  return [
    `Where to look: ${single(where.system, 120)}${where.owner ? ` (owner: ${single(where.owner, 80)})` : ''}${note(where.system_note)}`,
    ...(where.component
      ? [`Affected item: ${single(where.component, 160)}${note(where.component_note)}`]
      : []),
  ];
}
const webUrl = (value: string): boolean => {
  try {
    return ['https:', 'http:'].includes(new URL(value).protocol);
  } catch {
    return false;
  }
};
/**
 * The fixed versions, each whole. Many fixed branches (or Go pseudo-versions) can be long: as many
 * whole versions as fit are shown, and the line says how many more there are.
 */
function fixLine(fix: string): string {
  // Versions of one claim are joined with commas, versions of different claims with semicolons.
  const versions = singleLine(fix, fix.length)
    .split(/[;,]\s*/)
    .map((version) => single(version, 4000))
    .filter(Boolean);
  const shown: string[] = [];
  let length = 0;
  for (const version of versions) {
    // A version is never shown cut: one that is too long on its own is counted with the rest, and
    // the shorter ones after it are still shown.
    if (version.length > 120) continue;
    if (length + version.length + 2 > 300) break;
    shown.push(version);
    length += version.length + 2;
  }
  const more = versions.length - shown.length;
  if (!shown.length) return `Fix: ${versions.length} version(s) too long to show (run explain for all)`;
  return `Fix: ${shown.join('; ')}${more ? `; and ${more} more (run explain for all)` : ''}`;
}
/** One Slack section holds 3,000 characters. */
const MESSAGE_LIMIT = 2900;
/**
 * What articles state about a finding without an advisory severity, in one line. Built from the
 * score, the rating word and the subject (an identifier or an inventory name); article sentences
 * are never put in a message.
 */
function newsSignalLine(a: Assessment): string[] {
  const signals = a.news_signals;
  if (!signals) return [];
  const parts = [
    ...(signals.cvss
      ? [
          `CVSS ${signals.cvss.version ? `${signals.cvss.version} ` : ''}${signals.cvss.score} stated for ${signals.cvss.subject}`,
        ]
      : []),
    ...(signals.rating ? [`rated "${signals.rating.word}" for ${signals.rating.subject}`] : []),
    ...(signals.exploitation
      ? ['exploitation reported by an article (not a known-exploited catalog entry)']
      : []),
    ...(!signals.exploitation && signals.no_known_exploitation
      ? ['an article says no exploitation is known']
      : []),
    ...(signals.public_exploit ? ['public exploit code reported'] : []),
  ];
  return parts.length ? [single(`News signals: ${parts.join('; ')}`, 300)] : [];
}

/** FIRST's EPSS for the finding's CVE, when looked up. Numbers only. */
function epssLine(a: Assessment): string[] {
  const epss = a.epss;
  if (!epss || !Number.isFinite(epss.probability) || !Number.isFinite(epss.percentile)) return [];
  const percent = epss.probability * 100;
  const shown = percent < 0.1 ? 'under 0.1%' : `${percent < 10 ? percent.toFixed(1) : Math.round(percent)}%`;
  return [
    single(
      `EPSS for ${epss.cve}: ${shown} chance of exploitation in the next 30 days; higher than ${Math.floor(epss.percentile * 100)}% of scored CVEs (FIRST, ${epss.date})`,
      200,
    ),
  ];
}

export function notificationText(job: Notification): { subject: string; text: string } {
  const { assessment: a, reason } = JSON.parse(job.payload) as { assessment: Assessment; reason: string };
  const subject = single(`[${a.priority.toUpperCase()}] ${a.title}`, 180);
  const urls = a.urls.filter(webUrl);
  /** The lines every message keeps: what, where, how it applies and the summary. */
  const head = (notes: boolean) => [
    subject,
    `Finding: ${single(a.id, 200)}`,
    `Delivery: ${single(job.id, 200)}`,
    `System: ${single(a.system_id, 200)}${a.component_id ? ` / ${single(a.component_id, 200)}` : ''}`,
    ...locationLines(a, notes ? 300 : 0),
    `Applicability: ${single(a.applicability, 40)}; source severity: ${single(a.source_severity, 40)}; priority: ${single(a.priority, 40)}`,
    ...(a.exploited ? ['Known exploitation reported.'] : []),
    ...newsSignalLine(a),
    ...epssLine(a),
    `Summary: ${single(a.summary, 750)}`,
  ];
  // In the order they give way when the text is too long for one Slack section: the last of these
  // lines are dropped first, and a line is never cut in the middle.
  const extra = [
    ...(a.news_analysis
      ? [
          `AI news classification: ${single(a.news_analysis.classification, 60)}; reported system impact: ${single(a.news_analysis.impact, 60)}`,
          listLine('Affected products', a.news_analysis.affected_products, 180),
          listLine('Reported versions', a.news_analysis.affected_versions, 180),
          listLine('Prerequisites', a.news_analysis.prerequisites, 240),
          `Impact reasoning: ${single(a.news_analysis.rationale, 400)}`,
        ]
      : []),
    // Every reason: when there are more than fit, the last ones are left out with the note below.
    ...a.reasons.map((r) => `• ${single(r, 180)}`),
  ];
  // The fix, the rule that sent the message and the time close every message, whole, followed by
  // up to three source links.
  const tail = [
    ...(a.fix ? [fixLine(a.fix)] : []),
    `Rule: ${single(reason, 180)}`,
    `Assessment time: ${single(a.updated_at, 40)}`,
  ];
  const links = urls
    .map(link)
    .filter((value): value is string => value !== undefined)
    .slice(0, 3);
  const SHORTENED = '(Message shortened; run explain for the full finding.)';
  const size = (lines: string[]) => lines.reduce((total, line) => total + line.length + 1, 0) - 1;
  const full = [...head(true), ...extra, ...tail, ...links];
  // Everything fits: no note.
  if (size(full) <= MESSAGE_LIMIT) return { subject, text: full.join('\n') };
  // Otherwise the analysis and reasons give way first, whole lines from the end. Only when the
  // lines every message keeps still do not fit do the source links go, the last first, and then the
  // inventory notes.
  const rounds: Array<[boolean, number]> = [
    ...Array.from({ length: links.length + 1 }, (_, index): [boolean, number] => [
      true,
      links.length - index,
    ]),
    [false, 0],
  ];
  for (const [notes, count] of rounds) {
    const fixed = [...head(notes), SHORTENED, ...tail, ...links.slice(0, count)];
    let left = MESSAGE_LIMIT - size(fixed);
    if (left < 0) continue;
    const kept: string[] = [];
    for (const line of extra) {
      if (line.length + 1 > left) break;
      kept.push(line);
      left -= line.length + 1;
    }
    return {
      subject,
      text: [...head(notes), ...kept, SHORTENED, ...tail, ...links.slice(0, count)].join('\n'),
    };
  }
  // Only identifiers at their longest get here: the summary is cut until the message fits.
  const lines = head(false).slice(0, -1);
  const message = (cap: number) =>
    [...lines, `Summary: ${single(a.summary, cap)}`, SHORTENED, ...tail].join('\n');
  let cap = 750;
  let text = message(cap);
  while (text.length > MESSAGE_LIMIT && cap > 1) {
    cap = Math.max(1, cap - (text.length - MESSAGE_LIMIT));
    text = message(cap);
  }
  return { subject, text };
}
/** @internal Exported for tests; not part of the package root. */
export function digestText(jobs: Notification[]): { subject: string; text: string } {
  const subject = `Security Watch digest: ${jobs.length} findings`;
  const entries = jobs.map((job) => {
    const { assessment: a } = JSON.parse(job.payload) as { assessment: Assessment };
    return [
      `[${single(a.priority, 40).toUpperCase()}] ${single(a.title, 90)}`,
      `Finding: ${single(a.id, 200)}`,
      `Delivery: ${single(job.id, 200)}`,
      `System: ${single(a.system_id, 60)}${a.component_id ? ` / ${single(a.component_id, 60)}` : ''}`,
      ...locationLines(a, 120),
      `Applicability: ${single(a.applicability, 40)}; source: ${single(a.source_severity, 40)}`,
      ...newsSignalLine(a),
      ...epssLine(a),
      ...(a.news_analysis
        ? [
            `AI news: ${single(a.news_analysis.classification, 60)}; impact: ${single(a.news_analysis.impact, 60)}`,
          ]
        : []),
      a.urls
        .filter(webUrl)
        .map(link)
        .find((value) => value !== undefined) ?? 'No source URL supplied',
    ].join('\n');
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
/** Why a Slack webhook address cannot be used, or nothing. The text never repeats the address. */
export function slackProblem(address: string): string | undefined {
  try {
    const url = new URL(address);
    return url.protocol !== 'https:' ||
      url.hostname !== 'hooks.slack.com' ||
      !url.pathname.startsWith('/services/') ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (url.port && url.port !== '443')
      ? 'Slack webhook must be an HTTPS hooks.slack.com/services URL'
      : undefined;
  } catch {
    return 'Slack webhook URL is invalid';
  }
}
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
      const problem = slackProblem(secret);
      if (problem) {
        finish('failed', problem);
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
          // Refused before any connection was made: nothing left this machine.
          ['DNS_FAILED', 'CONNECTION_FAILED', 'DESTINATION_DENIED'].includes(error.code)
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
        // Only a failure the sender proved to precede the envelope is retried. Error labels alone
        // do not prove it: a dropped connection after the message body carries the same label.
        if (!signal?.aborted && error instanceof EmailNotSentError)
          retry(error.message, retryAt({}, now, item.attempts));
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
