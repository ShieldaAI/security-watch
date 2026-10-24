import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { lookup } from 'node:dns';
import { isIP, type LookupFunction } from 'node:net';
import ipaddr from 'ipaddr.js';
import type { HttpClient, HttpOptions, HttpResult } from './types.js';

export class NetworkError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = 'NetworkError';
  }
}

type ReleaseSlot = () => void;
interface OriginWaiter {
  ready: (release: ReleaseSlot) => void;
  fail: (error: NetworkError) => void;
  cleanup: () => void;
}
interface OriginSchedule {
  queue: OriginWaiter[];
  interval: number;
  nextStart: number;
  cooldown: number;
  active: number;
  timer?: ReturnType<typeof setTimeout>;
}
const originSchedules = new Map<string, OriginSchedule>();
const MAX_COOLDOWN_MS = 3_600_000;

function pumpOrigin(origin: string, schedule: OriginSchedule): void {
  clearTimeout(schedule.timer);
  schedule.timer = undefined;
  const delay = Math.max(0, schedule.nextStart, schedule.cooldown) - Date.now();
  if (!schedule.queue.length) {
    if (schedule.active) return;
    if (delay <= 0) originSchedules.delete(origin);
    else {
      schedule.timer = setTimeout(() => pumpOrigin(origin, schedule), delay);
      schedule.timer.unref();
    }
    return;
  }
  if (delay > 0) {
    schedule.timer = setTimeout(() => pumpOrigin(origin, schedule), delay);
    return;
  }
  const waiter = schedule.queue.shift()!;
  waiter.cleanup();
  schedule.active++;
  schedule.nextStart = Date.now() + schedule.interval;
  waiter.ready(() => {
    schedule.active--;
    pumpOrigin(origin, schedule);
  });
  pumpOrigin(origin, schedule);
}

function originSlot(origin: string, options: HttpOptions, deadline: number): Promise<ReleaseSlot> {
  const interval = options.minIntervalMs ?? 0;
  if (!Number.isFinite(interval) || interval < 0 || interval > MAX_COOLDOWN_MS)
    throw new NetworkError('INVALID_REQUEST_INTERVAL');
  let schedule = originSchedules.get(origin);
  if (!schedule && !interval) return Promise.resolve(() => {});
  if (!schedule) {
    schedule = { queue: [], interval, nextStart: 0, cooldown: 0, active: 0 };
    originSchedules.set(origin, schedule);
  }
  const current = schedule;
  current.interval = Math.max(current.interval, interval);
  return new Promise((resolve, reject) => {
    const remove = (code: string) => {
      const index = current.queue.indexOf(waiter);
      if (index < 0) return;
      current.queue.splice(index, 1);
      waiter.cleanup();
      waiter.fail(new NetworkError(code));
      pumpOrigin(origin, current);
    };
    const abort = () => remove('REQUEST_ABORTED');
    const timer = setTimeout(() => remove('REQUEST_TIMEOUT'), Math.max(0, deadline - Date.now()));
    const waiter: OriginWaiter = {
      ready: resolve,
      fail: reject,
      cleanup: () => {
        clearTimeout(timer);
        options.signal?.removeEventListener('abort', abort);
      },
    };
    current.queue.push(waiter);
    options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted) abort();
    else if (deadline <= Date.now()) remove('REQUEST_TIMEOUT');
    else pumpOrigin(origin, current);
  });
}

function recordCooldown(origin: string, status: number, retryAfter: string | string[] | undefined): void {
  const schedule = originSchedules.get(origin);
  if (!schedule || ![403, 429].includes(status) || typeof retryAfter !== 'string') return;
  const value = retryAfter.trim();
  const until = /^\d+$/.test(value) ? Date.now() + Number(value) * 1000 : Date.parse(value);
  if (!(until > Date.now())) return;
  schedule.cooldown = Math.max(schedule.cooldown, Math.min(until, Date.now() + MAX_COOLDOWN_MS));
  pumpOrigin(origin, schedule);
}

export function isPublicAddress(address: string): boolean {
  try {
    const parsed = ipaddr.process(address);
    return parsed.range() === 'unicast';
  } catch {
    return false;
  }
}
export function validateDestination(value: string, allowPrivate = false): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new NetworkError('INVALID_URL');
  }
  if (
    url.username ||
    url.password ||
    url.hash ||
    !['https:', ...(allowPrivate ? ['http:'] : [])].includes(url.protocol)
  )
    throw new NetworkError('DESTINATION_DENIED');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (
    !allowPrivate &&
    (host === 'localhost' || host.endsWith('.localhost') || (isIP(host) && !isPublicAddress(host)))
  )
    throw new NetworkError('DESTINATION_DENIED');
  return url;
}

export const safeHttp: HttpClient = async (value, options = {}) => {
  if (options.signal?.aborted) throw new NetworkError('REQUEST_ABORTED');
  const url = validateDestination(value, options.allowPrivate);
  const maxBytes = options.maxBytes ?? 4_194_304;
  const timeoutMs = options.timeoutMs ?? 20_000;
  const deadline = Date.now() + timeoutMs;
  if (Buffer.byteLength(options.body ?? '') > 2_097_152) throw new NetworkError('REQUEST_TOO_LARGE');
  const secureLookup: LookupFunction = (hostname, lookupOptions, callback) => {
    lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
      if (error || !addresses.length) {
        callback(new NetworkError('DNS_FAILED'), '', 4);
        return;
      }
      if (!options.allowPrivate && addresses.some((a) => !isPublicAddress(a.address))) {
        callback(new NetworkError('DESTINATION_DENIED'), '', 4);
        return;
      }
      // Resolve and validate the addresses actually used by the socket, including redirects.
      if (lookupOptions.all) callback(null, addresses);
      else callback(null, addresses[0]!.address, addresses[0]!.family);
    });
  };
  const release = await originSlot(url.origin, options, deadline);
  let response: HttpResult;
  try {
    if (options.signal?.aborted) throw new NetworkError('REQUEST_ABORTED');
    if (deadline <= Date.now()) throw new NetworkError('REQUEST_TIMEOUT');
    response = await new Promise<HttpResult>((resolve, reject) => {
      const request = url.protocol === 'https:' ? httpsRequest : httpRequest;
      let connected = false;
      const req = request(
        url,
        {
          method: options.method ?? 'GET',
          lookup: secureLookup,
          agent: false,
          signal: options.signal,
          headers: {
            'user-agent': 'Shielda-Security-Watch/0.1',
            'accept-encoding': 'identity',
            ...options.headers,
          },
        },
        (res) => {
          recordCooldown(url.origin, res.statusCode ?? 0, res.headers['retry-after']);
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > maxBytes) {
              clearTimeout(timer);
              reject(new NetworkError('RESPONSE_TOO_LARGE'));
              res.destroy();
              req.destroy();
              return;
            }
            chunks.push(chunk);
          });
          res.on('error', () => {
            clearTimeout(timer);
            reject(new NetworkError(options.signal?.aborted ? 'REQUEST_ABORTED' : 'RESPONSE_FAILED'));
          });
          res.on('end', () => {
            clearTimeout(timer);
            const headers = Object.fromEntries(
              Object.entries(res.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(',') : (v ?? '')]),
            );
            resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks).toString('utf8') });
          });
        },
      );
      const timer = setTimeout(
        () => req.destroy(new NetworkError('REQUEST_TIMEOUT')),
        Math.max(0, deadline - Date.now()),
      );
      req.on('socket', (socket) => {
        if (!socket.connecting) connected = true;
        else socket.once('connect', () => (connected = true));
      });
      req.on('error', (error) => {
        clearTimeout(timer);
        const code = 'code' in error ? error.code : undefined;
        const connectionFailed =
          !connected &&
          (['ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH'].includes(String(code)) ||
            (error instanceof NetworkError && error.code === 'REQUEST_TIMEOUT'));
        reject(
          options.signal?.aborted
            ? new NetworkError('REQUEST_ABORTED')
            : connectionFailed
              ? new NetworkError('CONNECTION_FAILED')
              : error instanceof NetworkError
                ? error
                : new NetworkError('REQUEST_FAILED'),
        );
      });
      if (options.body) req.write(options.body);
      req.end();
    });
  } finally {
    release();
  }
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    const redirects = options.redirects ?? 2;
    if (redirects <= 0 || (options.method && options.method !== 'GET'))
      throw new NetworkError('REDIRECT_DENIED');
    const location = response.headers.location;
    if (!location) throw new NetworkError('INVALID_REDIRECT');
    let destination: string;
    try {
      destination = new URL(location, url).href;
    } catch {
      throw new NetworkError('INVALID_REDIRECT');
    }
    const next = validateDestination(destination, options.allowPrivate);
    if (options.allowedRedirectOrigins && !options.allowedRedirectOrigins.includes(next.origin))
      throw new NetworkError('REDIRECT_DENIED');
    const nextOptions: HttpOptions = { ...options, redirects: redirects - 1 };
    // Never send authentication headers to a different origin.
    if (next.origin !== url.origin) nextOptions.headers = { accept: options.headers?.accept ?? '*/*' };
    return safeHttp(next.href, nextOptions);
  }
  return response;
};
