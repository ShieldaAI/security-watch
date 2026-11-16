import { createHash, timingSafeEqual } from 'node:crypto';
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { parse } from 'yaml';
import { systemFromSbom } from './inventory.js';
import type { Config } from './types.js';
import { singleLine } from './util.js';

/**
 * Receives SBOMs from CI pipelines and writes them into the inventory's SBOM folder, where the next
 * scan picks them up. Every upload needs a bearer token; each token may be limited to some system
 * IDs. An upload is checked exactly as the scanner will read it, and is written only if it imports,
 * so a pipeline learns at once that its SBOM is unusable instead of a week later from a stale warning.
 */

export const INTAKE_MAX_BYTES = 20 * 1024 * 1024;
const SYSTEM_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const SBOM_SUFFIX = /(?:\.(?:cdx|spdx|bom|sbom|cyclonedx))?\.json$/i;
const MIN_TOKEN_LENGTH = 32;
const MAX_ACTIVE_UPLOADS = 4;
const FAILURE_WINDOW_MS = 60_000;
const MAX_FAILURES = 20;

export interface IntakeUpload {
  system_id: string;
  /** File name in the SBOM folder. */
  file: string;
  format: 'CycloneDX' | 'SPDX';
  /** Packages Security Watch will watch. */
  packages: number;
  /** Things a scan will report about this SBOM: packages or relationships it cannot use. */
  warnings: number;
  warning_examples: string[];
}

export interface IntakeOptions {
  /** Called with one line of JSON per upload or refusal. Never given a token. */
  log?: (line: string) => void;
  now?: () => number;
}

interface Token {
  env: string;
  digest: Buffer;
  systems: string[];
}

const digest = (value: string) => createHash('sha256').update(value).digest();

/** Reads the configured tokens from the environment and refuses missing or short ones. */
function readTokens(config: Config): Token[] {
  const intake = config.intake;
  if (!intake) throw new Error('Configure intake in the configuration file to receive SBOMs.');
  return intake.tokens.map(({ token_env, systems }) => {
    const value = process.env[token_env];
    if (!value) throw new Error(`Missing environment variable ${token_env} (an intake upload token).`);
    if (value.length < MIN_TOKEN_LENGTH || /\s/.test(value))
      throw new Error(
        `${token_env} must be at least ${MIN_TOKEN_LENGTH} characters without spaces; create one with: openssl rand -hex 32`,
      );
    return { env: token_env, digest: digest(value), systems };
  });
}

/** The SBOM folder named by the inventory, which is where uploads go. */
export function intakeDirectory(inventoryPath: string): string {
  const inventory = readInventoryDocument(inventoryPath);
  const folder = inventory.sbom_directory;
  if (typeof folder !== 'string' || !folder.trim())
    throw new Error(
      'The inventory has no sbom_directory. Add "sbom_directory: ./sboms" to it so that uploads have a place to go.',
    );
  const directory = resolve(dirname(resolve(inventoryPath)), folder.trim());
  if (!statSync(directory).isDirectory()) throw new Error(`sbom_directory is not a folder: ${directory}`);
  return directory;
}

function readInventoryDocument(path: string): Record<string, unknown> {
  if (statSync(path).size > 2 * 1024 * 1024) throw new Error('Inventory exceeds 2 MiB');
  const document: unknown = parse(readFileSync(path, 'utf8'), { maxAliasCount: 0 });
  return document && typeof document === 'object' && !Array.isArray(document)
    ? (document as Record<string, unknown>)
    : {};
}

/** IDs of systems written in the inventory itself. An upload may not replace one of them. */
function listedSystems(path: string): Set<string> {
  const systems = readInventoryDocument(path).systems;
  return new Set(
    Array.isArray(systems)
      ? systems
          .map((system) =>
            system && typeof system === 'object' ? (system as Record<string, unknown>).id : undefined,
          )
          .filter((id): id is string => typeof id === 'string')
      : [],
  );
}

/**
 * Another file in the folder that names the same system in its metadata. The scanner would read
 * that one first and ignore the upload, so the upload is refused instead of silently unused.
 */
function claimedElsewhere(directory: string, id: string): string | undefined {
  for (const name of readdirSync(directory).sort()) {
    if (name.startsWith('.') || !SBOM_SUFFIX.test(name) || name.replace(SBOM_SUFFIX, '') === id) continue;
    try {
      const path = join(directory, name);
      if (!statSync(path).isFile() || statSync(path).size > INTAKE_MAX_BYTES) continue;
      const document = JSON.parse(readFileSync(path, 'utf8')) as {
        metadata?: { properties?: Array<{ name?: unknown; value?: unknown }> };
      };
      const properties = document.metadata?.properties;
      if (
        Array.isArray(properties) &&
        properties.some((entry) => entry?.name === 'security-watch:system-id' && entry.value === id)
      )
        return name;
    } catch {
      // An unreadable file is reported by the scanner; it claims no system.
    }
  }
  return undefined;
}

const allowed = (token: Token, id: string) =>
  token.systems.some((pattern) =>
    pattern === '*' ? true : pattern.endsWith('*') ? id.startsWith(pattern.slice(0, -1)) : pattern === id,
  );

/** The request handler, separate from the listening socket so that it can be tested and embedded. */
export function createIntakeHandler(
  config: Config,
  options: IntakeOptions = {},
): (request: IncomingMessage, response: ServerResponse) => void {
  const tokens = readTokens(config);
  const directory = intakeDirectory(config.inventory);
  const now = options.now ?? Date.now;
  const log = options.log ?? (() => {});
  const failures = new Map<string, { count: number; since: number }>();
  let active = 0;

  const send = (
    response: ServerResponse,
    status: number,
    body: object,
    headers: Record<string, string> = {},
  ) => {
    if (response.headersSent) return;
    response.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...headers,
    });
    response.end(JSON.stringify(body) + '\n');
  };
  const record = (event: Record<string, unknown>) => log(JSON.stringify({ intake: event }));

  const authenticate = (request: IncomingMessage): Token | undefined => {
    const header = request.headers.authorization;
    const match = typeof header === 'string' ? /^Bearer ([^\s]+)$/i.exec(header) : null;
    if (!match) return undefined;
    const presented = digest(match[1]!);
    // Compare against every token so the time taken does not say which one nearly matched.
    let found: Token | undefined;
    for (const token of tokens) if (timingSafeEqual(presented, token.digest)) found ??= token;
    return found;
  };

  const receive = async (request: IncomingMessage, response: ServerResponse, id: string, token: Token) => {
    const declared = Number(request.headers['content-length']);
    if (Number.isFinite(declared) && declared > INTAKE_MAX_BYTES) {
      send(response, 413, { error: 'An SBOM may be at most 20 MiB.' }, { connection: 'close' });
      request.destroy();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > INTAKE_MAX_BYTES) {
        send(response, 413, { error: 'An SBOM may be at most 20 MiB.' }, { connection: 'close' });
        request.destroy();
        return;
      }
      chunks.push(chunk);
    }
    if (!size) {
      send(response, 400, { error: 'The request body is empty; send the SBOM JSON.' });
      return;
    }
    // Stage inside the folder: the final rename is then atomic, and the scanner skips dot-folders.
    const staging = mkdtempSync(join(directory, '.intake-'));
    try {
      const staged = join(staging, 'upload.json');
      writeFileSync(staged, Buffer.concat(chunks), { flag: 'wx', mode: 0o640 });
      const file = `${id}.json`;
      let loaded;
      try {
        loaded = systemFromSbom(staged, file, 'this SBOM');
      } catch (error) {
        send(response, 422, {
          error: `Not a usable SBOM: ${singleLine(error instanceof Error ? error.message : 'unreadable', 300)}`,
        });
        record({ system_id: id, refused: 'invalid SBOM', token_env: token.env });
        return;
      }
      if (loaded.system.id !== id) {
        send(response, 409, {
          error: `The SBOM is for system ${singleLine(loaded.system.id, 100)}, not ${id}. Upload it to /v1/sboms/${encodeURIComponent(loaded.system.id)} or change --system-id.`,
        });
        return;
      }
      const claimant = claimedElsewhere(directory, id);
      if (claimant) {
        send(response, 409, {
          error: `${claimant} in the SBOM folder already describes system ${id}; remove it on the monitor, or upload under its file name.`,
        });
        return;
      }
      if (listedSystems(config.inventory).has(id)) {
        send(response, 409, {
          error: `System ${id} is written in the inventory file; uploads cannot replace it. Choose another system ID.`,
        });
        return;
      }
      const components = loaded.system.components.length;
      if (!components) {
        send(response, 422, {
          error: 'The SBOM has no package Security Watch can watch.',
          warning_examples: [...loaded.notices, ...loaded.warnings].slice(0, 5),
        });
        return;
      }
      const format = loaded.system.provenance?.source === 'SPDX SBOM' ? 'SPDX' : 'CycloneDX';
      const target = `${id}${format === 'SPDX' ? '.spdx.json' : '.cdx.json'}`;
      renameSync(staged, join(directory, target));
      // One system, one file: an earlier upload in the other format would otherwise be read twice.
      for (const name of readdirSync(directory))
        if (
          name !== target &&
          !name.startsWith('.') &&
          name.replace(SBOM_SUFFIX, '') === id &&
          SBOM_SUFFIX.test(name)
        )
          unlinkSync(join(directory, name));
      const messages = [...loaded.notices, ...loaded.warnings].map((message) =>
        singleLine(message.startsWith(`${id}: `) ? message.slice(id.length + 2) : message, 300),
      );
      const result: IntakeUpload = {
        system_id: id,
        file: target,
        format,
        packages: components,
        warnings: messages.length,
        warning_examples: messages.slice(0, 5),
      };
      send(response, 200, result);
      record({
        system_id: id,
        file: target,
        packages: result.packages,
        warnings: result.warnings,
        token_env: token.env,
        at: new Date(now()).toISOString(),
      });
    } finally {
      rmSync(staging, { recursive: true, force: true });
    }
  };

  return (request, response) => {
    void (async () => {
      const remote = request.socket.remoteAddress ?? 'unknown';
      let url: URL;
      try {
        url = new URL(request.url ?? '/', 'http://intake.invalid');
      } catch {
        send(response, 400, { error: 'Invalid request target' });
        return;
      }
      if (url.pathname === '/healthz') {
        if (request.method !== 'GET' && request.method !== 'HEAD')
          send(response, 405, { error: 'Use GET' }, { allow: 'GET, HEAD' });
        else send(response, 200, { ok: true });
        return;
      }
      const route = /^\/v1\/sboms\/([^/]+)$/.exec(url.pathname);
      if (!route) {
        send(response, 404, { error: 'Not found. Upload with PUT /v1/sboms/SYSTEM_ID.' });
        return;
      }
      if (request.method !== 'PUT' && request.method !== 'POST') {
        send(response, 405, { error: 'Use PUT' }, { allow: 'PUT, POST' });
        return;
      }
      // A valid token is always served, so that someone sending bad tokens through the same proxy
      // cannot lock a pipeline out. Bad tokens beyond the limit get a cheaper, unlogged refusal.
      const token = authenticate(request);
      if (!token) {
        const recent = failures.get(remote);
        const entry =
          recent && now() - recent.since < FAILURE_WINDOW_MS ? recent : { count: 0, since: now() };
        entry.count++;
        failures.set(remote, entry);
        if (failures.size > 10_000) failures.clear();
        if (entry.count > MAX_FAILURES) {
          send(response, 429, { error: 'Too many failed attempts; wait a minute.' }, { 'retry-after': '60' });
          return;
        }
        send(response, 401, { error: 'A valid bearer token is required.' }, { 'www-authenticate': 'Bearer' });
        record({ refused: 'unauthenticated', remote });
        return;
      }
      let id: string;
      try {
        id = decodeURIComponent(route[1]!);
      } catch {
        id = '';
      }
      if (!SYSTEM_ID.test(id)) {
        send(response, 400, {
          error:
            'A system ID is 1 to 100 letters, digits, dots, hyphens or underscores, starting with a letter or digit.',
        });
        return;
      }
      if (!allowed(token, id)) {
        send(response, 403, { error: `This token may not upload system ${id}.` });
        record({ system_id: id, refused: 'not allowed for this token', token_env: token.env });
        return;
      }
      if (active >= MAX_ACTIVE_UPLOADS) {
        send(response, 503, { error: 'Busy; retry shortly.' }, { 'retry-after': '5' });
        return;
      }
      active++;
      try {
        await receive(request, response, id, token);
      } finally {
        active--;
      }
    })().catch((error: unknown) => {
      record({ error: singleLine(error instanceof Error ? error.message : 'unknown error', 300) });
      send(response, 500, {
        error:
          'The upload could not be stored; check disk space and permissions of the SBOM folder on the monitor.',
      });
    });
  };
}

export interface RunningIntake {
  /** Base address, for example `https://127.0.0.1:8787`. */
  url: string;
  close(): Promise<void>;
}

/** Starts listening. The returned promise settles once the socket is bound. */
export async function startIntake(config: Config, options: IntakeOptions = {}): Promise<RunningIntake> {
  const intake = config.intake;
  if (!intake) throw new Error('Configure intake in the configuration file to receive SBOMs.');
  const handler = createIntakeHandler(config, options);
  const tls = intake.tls_cert_file && intake.tls_key_file;
  const server: Server = tls
    ? createHttpsServer(
        {
          cert: readFileSync(intake.tls_cert_file!),
          key: readFileSync(intake.tls_key_file!),
          minVersion: 'TLSv1.2',
        },
        handler,
      )
    : createHttpServer(handler);
  server.headersTimeout = 15_000;
  server.requestTimeout = 120_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  const separator = intake.listen.lastIndexOf(':');
  const host = intake.listen.slice(0, separator).replace(/^\[|\]$/g, '');
  const port = Number(intake.listen.slice(separator + 1));
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen({ host, port }, () => {
      server.off('error', reject);
      resolveListen();
    });
  });
  const address = server.address() as AddressInfo;
  const shown = address.family === 'IPv6' ? `[${address.address}]` : address.address;
  return {
    url: `${tls ? 'https' : 'http'}://${shown}:${address.port}`,
    close: () =>
      new Promise((resolveClose) => {
        server.close(() => resolveClose());
        server.closeAllConnections();
      }),
  };
}
