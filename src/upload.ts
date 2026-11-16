import { isIP } from 'node:net';
import type { IntakeUpload } from './intake.js';

/** Sends an SBOM to a Security Watch intake (`security-watch upload`, the GitHub Action). */

export interface UploadOptions {
  /** Base address of the intake, for example `https://watch.example.com:8787`. */
  url: string;
  systemId: string;
  /** The SBOM JSON. */
  body: string | Uint8Array;
  token: string;
  /** Permit plain HTTP to a host that is not this machine. */
  allowHttp?: boolean;
  /** Attempts in all, for network errors, 429 and 5xx answers. Default 3. */
  attempts?: number;
  /** Per attempt. Default 120 seconds. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
}

const SYSTEM_ID = /^[a-z0-9][a-z0-9._-]{0,99}$/;

function loopback(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || (isIP(host) === 4 && host.startsWith('127.'));
}

/** The upload address for one system, refusing addresses that would leak the token. */
export function intakeAddress(base: string, systemId: string, allowHttp = false): URL {
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    throw new Error('The intake address must be a URL, for example https://watch.example.com:8787');
  }
  if (url.username || url.password || url.search || url.hash)
    throw new Error('The intake address must not contain credentials, a query or a fragment.');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (loopback(url.hostname) || allowHttp)))
    throw new Error(
      'The intake address must use HTTPS, so that the upload token is not sent in clear text (plain HTTP is accepted for this machine only, or with --allow-http).',
    );
  if (!SYSTEM_ID.test(systemId))
    throw new Error(
      'A system ID is 1 to 100 lower-case letters, digits, dots, hyphens or underscores, starting with a letter or digit.',
    );
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/v1/sboms/${encodeURIComponent(systemId)}`;
  return url;
}

export async function uploadSbom(options: UploadOptions): Promise<IntakeUpload> {
  const url = intakeAddress(options.url, options.systemId, options.allowHttp);
  const request = options.fetch ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise((done) => setTimeout(done, ms)));
  const attempts = options.attempts ?? 3;
  let last = 'no attempt was made';
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let retryAfter = 2000 * attempt;
    try {
      const response = await request(url, {
        method: 'PUT',
        headers: { authorization: `Bearer ${options.token}`, 'content-type': 'application/json' },
        body: typeof options.body === 'string' ? options.body : Buffer.from(options.body),
        // A redirect would carry the token to another address.
        redirect: 'error',
        signal: AbortSignal.timeout(options.timeoutMs ?? 120_000),
      });
      const text = (await response.text()).slice(0, 10_000);
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(text) as Record<string, unknown>;
      } catch {
        // The error below says what came back.
      }
      if (response.ok && typeof body.system_id === 'string') return body as unknown as IntakeUpload;
      const reason =
        typeof body.error === 'string'
          ? body.error
          : `HTTP ${response.status} without a Security Watch answer`;
      if (response.status !== 429 && response.status < 500)
        throw Object.assign(new Error(`Upload refused (${response.status}): ${reason}`), { final: true });
      last = `HTTP ${response.status}: ${reason}`;
      const seconds = Number(response.headers.get('retry-after'));
      if (Number.isFinite(seconds) && seconds > 0) retryAfter = Math.min(seconds, 30) * 1000;
    } catch (error) {
      if ((error as { final?: boolean }).final) throw error;
      last =
        error instanceof Error
          ? error.cause instanceof Error
            ? error.cause.message
            : error.message
          : 'error';
    }
    if (attempt < attempts) await sleep(retryAfter);
  }
  throw new Error(`Upload to ${url.origin} failed after ${attempts} attempts: ${last}`);
}
