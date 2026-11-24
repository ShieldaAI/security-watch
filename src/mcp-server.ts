#!/usr/bin/env node
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import {
  cachingHttp,
  checkAdvisory,
  checkChange,
  checkPackages,
  checkProject,
  formatAdvisoryReport,
  formatChangeReport,
  formatCheckReport,
  isUnreadableWarning,
  type CheckOptions,
} from './check.js';
import { loadConfig } from './config.js';
import { generateSbom } from './manifests.js';
import { maxAges, withCurrentMitigations } from './mitigations.js';
import { Store } from './store.js';
import type { Assessment, HttpClient, Severity } from './types.js';
import { cleanText } from './util.js';

/**
 * A Model Context Protocol server (stdio, newline-delimited JSON-RPC) that gives AI agents
 * Security Watch's checks for the project they have open. It reads files under one project root
 * and never outside it, never runs project code, writes only when `write_sbom` is called, and sends
 * package names and versions to OSV (plus CVE IDs to FIRST when EPSS is asked for).
 */

const PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_LINE = 4 * 1024 * 1024;
const MAX_TEXT = 60_000;
const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const VERSION = (
  JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }
).version;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
interface Message {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
}

const network =
  'Sends package names and versions (never file contents) to OSV (api.osv.dev) and reads the CISA known-exploited catalog.';
const pathProperty = {
  type: 'string',
  description:
    'A folder or one dependency file inside the project, relative to its root. Default: the whole project.',
};
const minSeverity = {
  type: 'string',
  enum: [...SEVERITIES],
  description:
    'Leave out findings below this priority. Malware and known-exploited findings are always shown; an advisory without a severity counts as medium. Default: low.',
};
const production = {
  type: 'boolean',
  description: 'Leave out development-only dependencies where the lockfile marks them. Default: false.',
};
const epss = {
  type: 'boolean',
  description: 'Add FIRST EPSS exploit-probability scores (sends CVE IDs to api.first.org). Default: false.',
};

export const TOOLS = [
  {
    name: 'check_project_vulnerabilities',
    title: 'Check project dependencies for known vulnerabilities',
    description: `Reads every lockfile and manifest in the project (npm, Python, Go, Rust, PHP, Ruby, Java, .NET, Dart, Elixir, Swift, Haskell) and lists known vulnerabilities and malicious packages in the installed versions, most urgent first, each with the fixed version and the file to change. ${network}`,
    inputSchema: {
      type: 'object',
      properties: {
        path: pathProperty,
        sbom: {
          type: 'string',
          description:
            'A CycloneDX or SPDX JSON SBOM inside the project (from Trivy, Syft, cdxgen, GitHub) to check instead of the dependency files.',
        },
        minSeverity,
        production,
        epss,
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true, destructiveHint: false },
  },
  {
    name: 'check_dependency_change',
    title: 'Check what a dependency change brings in',
    description: `Compares the project's dependency files at a git ref with the working tree (tracked files and untracked ones that are not ignored) and reports only the known vulnerabilities the change adds, and those it fixes. Use it after adding, removing or upgrading dependencies, before you hand the change back. Reads the base files from git; checks nothing out. ${network}`,
    inputSchema: {
      type: 'object',
      properties: {
        base: {
          type: 'string',
          description:
            'The git ref to compare with. HEAD for uncommitted changes. For a branch, the branch it merges into with three dots, such as origin/main..., compares with the point where the branch left it (plain origin/main would also count what main changed since). After committing, HEAD shows nothing: use HEAD~1 or origin/main....',
        },
        path: {
          ...pathProperty,
          description: 'A folder inside the project, relative to its root. Default: the whole project.',
        },
        minSeverity,
        production,
      },
      required: ['base'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true, destructiveHint: false },
  },
  {
    name: 'check_package',
    title: 'Check packages before adding or upgrading them',
    description: `Checks named package versions against OSV before you add or upgrade them: known vulnerabilities, malicious-package records (typosquats, hijacked releases) and the versions that fix each. Leave out the version to list every advisory for the package. OSV does not say whether a package exists: confirm an unfamiliar name in its registry. ${network}`,
    inputSchema: {
      type: 'object',
      properties: {
        packages: {
          type: 'array',
          minItems: 1,
          maxItems: 50,
          items: {
            type: 'object',
            properties: {
              ecosystem: {
                type: 'string',
                description:
                  'npm, PyPI, Go, crates.io, Packagist, RubyGems, Maven, NuGet, Pub, Hex, SwiftURL or Hackage (python, rust, php, ruby, java, dotnet, dart and elixir also work).',
              },
              name: {
                type: 'string',
                description:
                  'The package name as the registry spells it, such as lodash, @scope/pkg, requests or org.apache.logging.log4j:log4j-core.',
              },
              version: { type: 'string', description: 'The exact version, such as 4.17.21.' },
            },
            required: ['ecosystem', 'name'],
            additionalProperties: false,
          },
        },
        epss,
      },
      required: ['packages'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true, destructiveHint: false },
  },
  {
    name: 'check_advisory',
    title: 'Does this advisory affect the project?',
    description: `Looks up a CVE, GHSA, PYSEC, RUSTSEC, GO, MAL or other OSV identifier, says which packages and versions it concerns and whether this project has an affected version. Use it when someone asks whether a vulnerability in the news concerns them. ${network}`,
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'The advisory ID, such as CVE-2021-44906 or GHSA-xvch-5gv4-984h.',
        },
        path: pathProperty,
      },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true, destructiveHint: false },
  },
  {
    name: 'list_dependencies',
    title: 'List the project dependencies',
    description:
      'Lists the dependency files found in the project, package counts per ecosystem, packages that have no exact version (a manifest without its lockfile) and files that could not be read. Optionally lists every package. Reads files only; no network.',
    inputSchema: {
      type: 'object',
      properties: {
        path: pathProperty,
        production,
        includePackages: {
          type: 'boolean',
          description: 'Also list every package and version (up to 2,000). Default: false.',
        },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false, idempotentHint: true, destructiveHint: false },
  },
  {
    name: 'write_sbom',
    title: 'Write a CycloneDX SBOM',
    description:
      'Writes a CycloneDX 1.6 JSON SBOM of the project dependencies to a new file inside the project, for a customer, a compliance request (such as the EU Cyber Resilience Act), Dependency-Track, Trivy or a Security Watch monitor. It replaces an existing file only with overwrite: true, and only when that file is itself an SBOM; it never writes into hidden folders such as .github or .claude. No network.',
    inputSchema: {
      type: 'object',
      properties: {
        output: {
          type: 'string',
          description:
            'Where to write it, relative to the project root, ending in .json, such as sbom.cdx.json.',
        },
        path: pathProperty,
        production,
        name: {
          type: 'string',
          description:
            'System name written into the SBOM. Default: the name in package.json or pyproject.toml, or the folder name.',
        },
        owner: {
          type: 'string',
          description: 'Who to ask about this system, such as "Dana, platform team".',
        },
        environment: { type: 'string', description: 'Such as production or staging.' },
        note: { type: 'string', description: 'Where the system runs; Security Watch shows it in alerts.' },
        exposure: { type: 'string', enum: ['internet', 'internal', 'unknown'] },
        overwrite: {
          type: 'boolean',
          description: 'Replace the file if it exists and is a CycloneDX or SPDX SBOM. Default: false.',
        },
      },
      required: ['output'],
      additionalProperties: false,
    },
    // destructiveHint: with overwrite it replaces an existing SBOM file.
    annotations: { readOnlyHint: false, openWorldHint: false, idempotentHint: true, destructiveHint: true },
  },
] as const;

const WATCH_TOOL = {
  name: 'list_watch_findings',
  title: 'List open findings from the Security Watch monitor',
  description:
    'Lists the open findings recorded by the Security Watch monitor this server is configured with (SECURITY_WATCH_CONFIG): what affects which system, its priority, the fix and where to look. Reads the monitor database only; changes nothing and makes no network requests.',
  inputSchema: {
    type: 'object',
    properties: {
      minSeverity,
      system: { type: 'string', description: 'Only this system ID.' },
      limit: {
        type: 'integer',
        minimum: 1,
        maximum: 200,
        description: 'At most this many findings. Default: 50.',
      },
    },
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, openWorldHint: false, idempotentHint: true, destructiveHint: false },
} as const;

function real(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

function isInside(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/** A folder can be a project root unless it is a filesystem root, the home folder or above it. */
export function usableRoot(candidate: string, home = homedir()): boolean {
  const root = real(candidate);
  if (root === parse(root).root) return false;
  if (home && isInside(real(home), root)) return false;
  try {
    return statSync(root).isDirectory();
  } catch {
    return false;
  }
}

class ToolError extends Error {}

export interface ServerOptions {
  /** The project folder, or undefined to take it from the client's roots. */
  root?: string;
  /** The Security Watch configuration for list_watch_findings. */
  config?: string;
  http?: HttpClient;
  home?: string;
  now?: () => number;
}

export class SecurityWatchMcpServer {
  #root: string | undefined;
  #rootFromClient = false;
  readonly #config: string | undefined;
  readonly #http: HttpClient;
  readonly #home: string;
  readonly #now: () => number;
  readonly #send: (message: Json) => void;
  readonly #pending = new Map<string, (message: Message) => void>();
  readonly #running = new Map<string | number, AbortController>();
  #clientRoots = false;
  /** The client's answer to roots/list, while it is outstanding: tool calls wait for it. */
  #rootsPending: Promise<void> | undefined;
  #nextId = 1;

  constructor(options: ServerOptions, send: (message: Json) => void) {
    this.#home = options.home ?? homedir();
    this.#root = options.root && usableRoot(options.root, this.#home) ? real(options.root) : undefined;
    this.#config = options.config;
    this.#http = options.http ?? cachingHttp();
    this.#now = options.now ?? Date.now;
    this.#send = send;
  }

  get root(): string | undefined {
    return this.#root;
  }

  tools(): Json {
    return [...TOOLS, ...(this.#config ? [WATCH_TOOL] : [])] as unknown as Json;
  }

  /** Handles one message from the client. Responses go through `send`. */
  async handle(raw: unknown): Promise<void> {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      this.#send({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request' } });
      return;
    }
    const message = raw as Message;
    // A response to a request this server sent (roots/list).
    if (message.method === undefined && message.id !== undefined && message.id !== null) {
      const resolveReply = this.#pending.get(String(message.id));
      if (resolveReply) {
        this.#pending.delete(String(message.id));
        resolveReply(message);
      }
      return;
    }
    if (typeof message.method !== 'string') {
      this.#send({
        jsonrpc: '2.0',
        id: (message.id as Json) ?? null,
        error: { code: -32600, message: 'Invalid request' },
      });
      return;
    }
    const params = (
      typeof message.params === 'object' && message.params !== null ? message.params : {}
    ) as Record<string, unknown>;
    if (message.id === undefined || message.id === null) {
      this.#notification(message.method, params);
      return;
    }
    const id = message.id;
    const reply = (result: Json) => this.#send({ jsonrpc: '2.0', id, result });
    const fail = (code: number, text: string) =>
      this.#send({ jsonrpc: '2.0', id, error: { code, message: text } });
    switch (message.method) {
      case 'initialize': {
        const asked = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
        const capabilities = (params.capabilities ?? {}) as Record<string, unknown>;
        this.#clientRoots = typeof capabilities.roots === 'object' && capabilities.roots !== null;
        reply({
          protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0]!,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'security-watch', title: 'Shielda Security Watch', version: VERSION },
          instructions:
            'Security Watch checks the dependencies of the open project for known vulnerabilities and malicious packages. ' +
            'Call check_package before adding or upgrading a dependency, check_dependency_change (base "HEAD") after changing dependency files and before handing the change back, ' +
            'check_project_vulnerabilities for an overview, and check_advisory when asked whether a CVE or GHSA affects the project. ' +
            'Findings come from OSV and CISA KEV as of now; a clean result means no known advisory, not that the code is safe.',
        });
        return;
      }
      case 'ping':
        reply({});
        return;
      case 'tools/list':
        reply({ tools: this.tools() });
        return;
      case 'tools/call': {
        const controller = new AbortController();
        this.#running.set(id, controller);
        try {
          // A call that arrives right after start-up waits for the client to name the project.
          if (!this.#root && this.#rootsPending) await this.#rootsPending;
          const text = await this.#call(
            String(params.name ?? ''),
            this.#arguments(params.arguments),
            controller.signal,
          );
          if (!controller.signal.aborted)
            reply({ content: [{ type: 'text', text: clip(text) }], isError: false });
        } catch (error) {
          if (controller.signal.aborted) return;
          if (error instanceof UnknownTool) fail(-32602, error.message);
          else
            reply({
              content: [
                {
                  type: 'text',
                  text: error instanceof Error ? cleanText(error.message, 1000) : 'The check failed.',
                },
              ],
              isError: true,
            });
        } finally {
          this.#running.delete(id);
        }
        return;
      }
      default:
        fail(-32601, `Method not found: ${message.method}`);
    }
  }

  #notification(method: string, params: Record<string, unknown>): void {
    if (method === 'notifications/initialized' || method === 'notifications/roots/list_changed') {
      if (this.#clientRoots && (!this.#root || this.#rootFromClient)) this.#rootsPending = this.#askRoots();
    } else if (method === 'notifications/cancelled') {
      const requestId = params.requestId as string | number | undefined;
      if (requestId !== undefined) this.#running.get(requestId)?.abort();
    }
  }

  async #askRoots(): Promise<void> {
    const id = `security-watch-roots-${this.#nextId++}`;
    const answer = new Promise<Message>((done) => {
      this.#pending.set(id, done);
      setTimeout(() => {
        if (this.#pending.delete(id)) done({ error: 'timeout' });
      }, 10_000).unref();
    });
    this.#send({ jsonrpc: '2.0', id, method: 'roots/list', params: {} });
    const message = await answer;
    const roots = (message.result as { roots?: Array<{ uri?: unknown }> } | undefined)?.roots ?? [];
    for (const root of roots) {
      if (typeof root.uri !== 'string' || !root.uri.startsWith('file://')) continue;
      let path: string;
      try {
        path = fileURLToPath(root.uri);
      } catch {
        continue;
      }
      if (usableRoot(path, this.#home)) {
        this.#root = real(path);
        this.#rootFromClient = true;
        return;
      }
    }
  }

  #arguments(value: unknown): Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  }

  #project(): string {
    if (!this.#root)
      throw new ToolError(
        'No project folder is open: the server was started outside a project and the client named none. Restart it with the project path as its argument (security-watch mcp /path/to/project).',
      );
    return this.#root;
  }

  /** A path inside the project: no `..` out of it and no symbolic link that leads out. */
  #inside(path: unknown, what = 'path'): string {
    const root = this.#project();
    if (path === undefined || path === '' || path === '.') return root;
    if (typeof path !== 'string' || path.includes('\0'))
      throw new ToolError(`${what} must be a path inside the project.`);
    const absolute = resolve(root, path);
    if (!isInside(absolute, root) || !isInside(real(absolute), root))
      throw new ToolError(`${what} must be inside the project (${root}).`);
    if (!existsSync(absolute)) throw new ToolError(`${path} does not exist in the project.`);
    return real(absolute);
  }

  #options(signal: AbortSignal, args: Record<string, unknown>): CheckOptions {
    return { http: this.#http, now: this.#now(), signal, ...(args.epss === true ? { epss: true } : {}) };
  }

  async #call(name: string, args: Record<string, unknown>, signal: AbortSignal): Promise<string> {
    const min = severity(args.minSeverity);
    const prod = args.production === true ? { production: true } : {};
    switch (name) {
      case 'check_project_vulnerabilities': {
        if (args.sbom !== undefined && args.path !== undefined)
          throw new ToolError('Give path or sbom, not both.');
        const sbom = args.sbom === undefined ? undefined : this.#inside(args.sbom, 'sbom');
        if (sbom && !statSync(sbom).isFile()) throw new ToolError('sbom must be a JSON file.');
        const report = await checkProject({
          ...this.#options(signal, args),
          ...(sbom ? { sbom } : { project: this.#inside(args.path) }),
          ...prod,
        });
        return formatCheckReport(report, min);
      }
      case 'check_dependency_change': {
        if (typeof args.base !== 'string' || !args.base.trim())
          throw new ToolError('base is required, such as "HEAD".');
        const project = this.#inside(args.path);
        if (!statSync(project).isDirectory())
          throw new ToolError('path must be a folder for a change check.');
        const report = await checkChange({
          ...this.#options(signal, args),
          project,
          base: args.base.trim(),
          ...prod,
        });
        return formatChangeReport(report, min);
      }
      case 'check_package': {
        if (!Array.isArray(args.packages) || !args.packages.length)
          throw new ToolError('packages must list at least one package.');
        if (args.packages.length > 50) throw new ToolError('Check at most 50 packages at a time.');
        const packages = args.packages.map((item: unknown) => {
          const value = this.#arguments(item);
          if (typeof value.ecosystem !== 'string' || typeof value.name !== 'string')
            throw new ToolError('Each package needs an ecosystem and a name.');
          return {
            ecosystem: value.ecosystem,
            name: value.name,
            ...(typeof value.version === 'string' && value.version.trim() ? { version: value.version } : {}),
          };
        });
        const report = await checkPackages(packages, this.#options(signal, args));
        const text = formatCheckReport(report);
        const unversioned = packages.filter((item) => !item.version).length;
        return unversioned
          ? `${text}\n\nWithout a version every advisory for the package is listed; give the version you plan to install to see only what affects it.`
          : text;
      }
      case 'check_advisory': {
        if (typeof args.id !== 'string' || !args.id.trim())
          throw new ToolError('id is required, such as CVE-2021-44906.');
        const report = await checkAdvisory(args.id, {
          ...this.#options(signal, args),
          project: this.#inside(args.path),
        });
        return formatAdvisoryReport(report);
      }
      case 'list_dependencies':
        return this.#dependencies(args);
      case 'write_sbom':
        return this.#writeSbom(args);
      case 'list_watch_findings':
        if (this.#config) return this.#watchFindings(args, min);
        throw new UnknownTool(`Unknown tool ${name}`);
      default:
        throw new UnknownTool(`Unknown tool ${name}`);
    }
  }

  #dependencies(args: Record<string, unknown>): string {
    const project = this.#inside(args.path);
    let result;
    try {
      result = generateSbom({ project, ...(args.production === true ? { production: true } : {}) });
    } catch (error) {
      throw new ToolError(error instanceof Error ? error.message : 'Could not read the project.');
    }
    const files = result.files.filter((file) => file.packages);
    const out = [
      `${result.packages} package${result.packages === 1 ? '' : 's'}${result.ecosystems.length ? ` (${result.ecosystems.join(', ')})` : ''} from ${files.length} file${files.length === 1 ? '' : 's'}:`,
      ...files.map(
        (file) =>
          `- ${file.path}: ${file.ecosystem} ${file.kind}, ${file.packages} package${file.packages === 1 ? '' : 's'}`,
      ),
    ];
    const components = (result.bom.components ?? []) as Array<{
      name?: string;
      group?: string;
      version?: string;
      purl?: string;
    }>;
    const unversioned = components.filter((component) => !component.version);
    if (unversioned.length)
      out.push(
        '',
        `${unversioned.length} without an exact version (add or commit the lockfile so checks can compare versions): ${unversioned
          .slice(0, 30)
          .map((component) => component.purl ?? component.name)
          .join(', ')}${unversioned.length > 30 ? `, and ${unversioned.length - 30} more` : ''}`,
      );
    const unreadable = result.warnings.filter(isUnreadableWarning);
    const notes = result.warnings.filter((warning) => !isUnreadableWarning(warning));
    if (unreadable.length)
      out.push(
        '',
        'Could not be read (their packages are missing):',
        ...unreadable.slice(0, 20).map((warning) => `- ${warning}`),
      );
    if (notes.length) out.push('', 'Notes:', ...notes.slice(0, 20).map((warning) => `- ${warning}`));
    if (args.includePackages === true)
      out.push(
        '',
        'Packages:',
        ...components
          .slice(0, 2_000)
          .map(
            (component) =>
              `- ${component.purl ?? `${component.group ? `${component.group}/` : ''}${component.name}@${component.version ?? '?'}`}`,
          ),
        ...(components.length > 2_000 ? [`- and ${components.length - 2_000} more`] : []),
      );
    return out.join('\n');
  }

  #writeSbom(args: Record<string, unknown>): string {
    const root = this.#project();
    if (typeof args.output !== 'string' || !/\.json$/i.test(args.output))
      throw new ToolError('output must be a path inside the project ending in .json, such as sbom.cdx.json.');
    const destination = resolve(root, args.output);
    if (!isInside(destination, root)) throw new ToolError(`output must be inside the project (${root}).`);
    // Hidden folders hold settings (.github, .claude, .vscode, .git), never an SBOM.
    if (
      relative(root, destination)
        .split(/[\\/]/)
        .some((part) => part.startsWith('.'))
    )
      throw new ToolError('output must not be in a hidden folder or be a hidden file.');
    // The nearest folder that exists must be inside the project after links are followed, before
    // anything is created: a link inside the project can point outside it.
    let ancestor = dirname(destination);
    while (!existsSync(ancestor) && isInside(dirname(ancestor), root) && dirname(ancestor) !== ancestor)
      ancestor = dirname(ancestor);
    if (!isInside(real(ancestor), root)) throw new ToolError(`output must be inside the project (${root}).`);
    let existing;
    try {
      existing = lstatSync(destination); // also a link that points nowhere
    } catch {
      existing = undefined;
    }
    if (existing) {
      if (existing.isSymbolicLink() || !existing.isFile())
        throw new ToolError('output exists and is not a plain file; name a new file.');
      if (args.overwrite !== true)
        throw new ToolError(
          `${args.output} exists. Pass overwrite: true to replace it, if it is an older SBOM.`,
        );
      if (!isSbomFile(destination))
        throw new ToolError(
          `${args.output} exists and is not a CycloneDX or SPDX SBOM, so it is not replaced. Name a new file.`,
        );
    }
    const project = this.#inside(args.path);
    const text = (value: unknown) => (typeof value === 'string' && value.trim() ? value.trim() : undefined);
    const exposure = ['internet', 'internal', 'unknown'].includes(String(args.exposure))
      ? (args.exposure as 'internet' | 'internal' | 'unknown')
      : undefined;
    let result;
    try {
      result = generateSbom({
        project,
        toolVersion: VERSION,
        ...(args.production === true ? { production: true } : {}),
        ...(text(args.name) ? { name: text(args.name)! } : {}),
        ...(text(args.owner) ? { owner: text(args.owner)! } : {}),
        ...(text(args.environment) ? { environment: text(args.environment)! } : {}),
        ...(text(args.note) ? { note: text(args.note)! } : {}),
        ...(exposure ? { exposure } : {}),
      });
    } catch (error) {
      throw new ToolError(error instanceof Error ? error.message : 'Could not read the project.');
    }
    if (!result.packages) throw new ToolError('No dependencies found, so no SBOM was written.');
    mkdirSync(dirname(destination), { recursive: true });
    if (!isInside(real(dirname(destination)), root))
      throw new ToolError(`output must be inside the project (${root}).`);
    // Written beside the destination and renamed, so a reader never sees half a file.
    const staging = mkdtempSync(join(dirname(destination), '.security-watch-'));
    try {
      const staged = join(staging, 'sbom.json');
      writeFileSync(staged, `${JSON.stringify(result.bom, null, 2)}\n`, { flag: 'wx' });
      renameSync(staged, destination);
    } finally {
      rmSync(staging, { recursive: true, force: true });
    }
    const files = result.files.filter((file) => file.packages);
    return [
      `Wrote ${relative(root, destination) || basename(destination)}: CycloneDX 1.6, system "${result.system.name}" (ID ${result.system.id}), ${result.packages} package${result.packages === 1 ? '' : 's'} (${result.ecosystems.join(', ')}) from ${files.length} file${files.length === 1 ? '' : 's'}.`,
      ...(result.unversioned
        ? [`${result.unversioned} package${result.unversioned === 1 ? ' has' : 's have'} no exact version.`]
        : []),
      ...result.warnings
        .filter(isUnreadableWarning)
        .slice(0, 10)
        .map((warning) => `Not read, so its packages are missing from the SBOM: ${warning}`),
      'To keep it current, regenerate it when dependencies change (the Security Watch GitHub Action can do it on every merge).',
    ].join('\n');
  }

  #watchFindings(args: Record<string, unknown>, min: Severity): string {
    let config;
    try {
      config = loadConfig(resolve(this.#config!));
    } catch (error) {
      throw new ToolError(
        `Could not read the Security Watch configuration ${this.#config}: ${error instanceof Error ? error.message : 'error'}`,
      );
    }
    if (!existsSync(config.database))
      return 'The monitor has no database yet: run security-watch scan or start first.';
    const store = new Store(config.database, { readOnly: true });
    try {
      const ages = maxAges(config.mitigations);
      const order: readonly string[] = ['unknown', 'low', 'medium', 'high', 'critical'];
      const limit =
        typeof args.limit === 'number' && args.limit >= 1 ? Math.min(200, Math.floor(args.limit)) : 50;
      const open = store
        .findings()
        .filter(
          (finding: Assessment) =>
            finding.active !== false && !finding.withdrawn && finding.category !== 'health',
        )
        .filter((finding) => finding.applicability !== 'not_affected')
        .filter((finding) => typeof args.system !== 'string' || finding.system_id === args.system)
        // A finding without a severity counts as medium, as in the one-off checks.
        .filter(
          (finding) =>
            finding.exploited ||
            order.indexOf(finding.priority === 'unknown' ? 'medium' : finding.priority) >= order.indexOf(min),
        )
        .sort(
          (a, b) =>
            Number(b.exploited) - Number(a.exploited) ||
            order.indexOf(b.priority) - order.indexOf(a.priority) ||
            a.id.localeCompare(b.id),
        )
        .map((finding) => withCurrentMitigations(finding, ages, this.#now()));
      if (!open.length) return 'No open findings at or above this priority.';
      return [
        `${open.length} open finding${open.length === 1 ? '' : 's'}${open.length > limit ? `; the first ${limit}` : ''}:`,
        ...open
          .slice(0, limit)
          .map((finding) =>
            [
              `- [${finding.priority}] ${finding.title}${finding.exploited ? ' [known exploited]' : ''} (${finding.applicability})`,
              `  System: ${finding.location?.system ?? finding.system_id}${finding.location?.owner ? ` (owner: ${finding.location.owner})` : ''}${finding.location?.component ? `; ${finding.location.component}` : ''}`,
              `  ${finding.fix ? `Fix: ${finding.fix}. ` : ''}Finding ${finding.id}${finding.urls[0] ? ` ${finding.urls[0]}` : ''}`,
            ].join('\n'),
          ),
        '',
        'Acknowledge, suppress or review findings with the security-watch CLI; this tool only reads.',
      ].join('\n');
    } finally {
      store.close();
    }
  }
}

class UnknownTool extends Error {}

function isSbomFile(path: string): boolean {
  try {
    if (statSync(path).size > 50 * 1024 * 1024) return false;
    const value = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown> | null;
    return (
      typeof value === 'object' &&
      value !== null &&
      (value.bomFormat === 'CycloneDX' || typeof value.spdxVersion === 'string')
    );
  } catch {
    return false;
  }
}

function severity(value: unknown): Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value)
    ? (value as Severity)
    : 'low';
}

function clip(text: string): string {
  return text.length > MAX_TEXT
    ? `${text.slice(0, MAX_TEXT)}\n\n[Cut at ${MAX_TEXT} characters; narrow it with path or minSeverity.]`
    : text;
}

/** Serves MCP over stdio: one JSON-RPC message per line, answered as each finishes. */
export function serveStdio(
  options: ServerOptions,
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stdout,
): SecurityWatchMcpServer {
  const send = (message: Json) => output.write(`${JSON.stringify(message)}\n`);
  const server = new SecurityWatchMcpServer(options, send);
  const lines = createInterface({ input, crlfDelay: Infinity });
  lines.on('line', (line) => {
    if (!line.trim()) return;
    if (line.length > MAX_LINE) {
      send({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Message too large' } });
      return;
    }
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }
    for (const item of Array.isArray(message) ? message : [message]) void server.handle(item);
  });
  return server;
}

/**
 * `security-watch mcp [project]` and `security-watch-mcp [project]`. The project is the argument,
 * else CLAUDE_PROJECT_DIR, else the working folder, else the first root the client names.
 * SECURITY_WATCH_CONFIG names a monitor configuration for list_watch_findings.
 */
export function mcpMain(args: readonly string[]): void {
  if (args.includes('--help')) {
    process.stdout.write(
      "Usage: security-watch mcp [project]\n       security-watch-mcp [project | --client-roots]\n\nAn MCP server (stdio) that checks a project's dependencies for known vulnerabilities.\nSECURITY_WATCH_CONFIG=/path/security-watch.yaml adds list_watch_findings.\n",
    );
    return;
  }
  if (args.includes('--version')) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  const unknown = args.find((arg) => arg.startsWith('-') && arg !== '--client-roots');
  if (unknown) {
    process.stderr.write(`security-watch mcp: unknown option ${unknown}. Use --help.\n`);
    process.exitCode = 2;
    return;
  }
  const argument = args.find((arg) => !arg.startsWith('-'));
  // --client-roots: the caller could not tell which project is open (the plugin launcher, started
  // outside any project); the working folder is not one, so wait for the client to name it.
  const candidate =
    argument ??
    (args.includes('--client-roots') ? undefined : (process.env.CLAUDE_PROJECT_DIR ?? process.cwd()));
  const root = candidate === undefined ? undefined : resolve(process.cwd(), candidate);
  if (root && !usableRoot(root))
    process.stderr.write(
      `security-watch mcp: ${root} cannot be the project (a filesystem root, the home folder or not a folder); waiting for the client to name one.\n`,
    );
  const config = process.env.SECURITY_WATCH_CONFIG?.trim();
  serveStdio({ ...(root ? { root } : {}), ...(config ? { config } : {}) });
}

function isEntry(): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntry()) mcpMain(process.argv.slice(2));
