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
  const response = await new Promise<HttpResult>((resolve, reject) => {
    const request = url.protocol === 'https:' ? httpsRequest : httpRequest;
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
    const timer = setTimeout(() => req.destroy(new NetworkError('REQUEST_TIMEOUT')), timeoutMs);
    req.on('error', (error) => {
      clearTimeout(timer);
      reject(
        options.signal?.aborted
          ? new NetworkError('REQUEST_ABORTED')
          : error instanceof NetworkError
            ? error
            : new NetworkError('REQUEST_FAILED'),
      );
    });
    if (options.body) req.write(options.body);
    req.end();
  });
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
