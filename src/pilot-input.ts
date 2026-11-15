import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { types } from 'node:util';
import { PilotReportError, validatePilotWindow, type PilotWindow } from './pilot-report.js';
type InputProblem = 'window' | 'labels' | 'incidents' | 'responses';
const MAX_INPUT_BYTES = 1024 * 1024;

export function pilotInstant(value: unknown, problem: InputProblem): string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value))
    throw new PilotReportError(problem);
  const time = Date.parse(value);
  if (!Number.isSafeInteger(time) || new Date(time).toISOString() !== value)
    throw new PilotReportError(problem);
  return value;
}

/** Copy only own enumerable data properties. Public API values may originate outside a JSON parser. */
export function dataFields(
  input: unknown,
  names: readonly string[],
  problem: InputProblem,
): Record<string, unknown> {
  if (!input || typeof input !== 'object' || types.isProxy(input)) throw new PilotReportError(problem);
  const prototype = Object.getPrototypeOf(input);
  if (
    (prototype !== null && prototype !== Object.prototype) ||
    Reflect.ownKeys(input).length !== names.length
  )
    throw new PilotReportError(problem);
  const data: Record<string, unknown> = Object.create(null);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new PilotReportError(problem);
    data[name] = descriptor.value;
  }
  return data;
}
export function dataArray(rows: unknown, max: number, problem: InputProblem): unknown[] {
  if (
    types.isProxy(rows) ||
    !Array.isArray(rows) ||
    Object.getPrototypeOf(rows) !== Array.prototype ||
    rows.length > max ||
    Reflect.ownKeys(rows).length !== rows.length + 1
  )
    throw new PilotReportError(problem);
  const result = [];
  for (let i = 0; i < rows.length; i++) {
    const item = Object.getOwnPropertyDescriptor(rows, String(i));
    if (!item?.enumerable || !Object.hasOwn(item, 'value')) throw new PilotReportError(problem);
    result.push(item.value as unknown);
  }
  return result;
}

export function capturePilotWindow(window: PilotWindow) {
  const requested = dataFields(window, ['from', 'until'], 'window');
  if (typeof requested.from !== 'string' || typeof requested.until !== 'string')
    throw new PilotReportError('window');
  return validatePilotWindow({ from: requested.from, until: requested.until }, Date.now());
}

/** JSON.parse checks grammar but would otherwise discard earlier duplicate labels or case references. */
function parseJson(text: string, problem: InputProblem): unknown {
  const value: unknown = JSON.parse(text);
  const stack: (Set<string> | null)[] = [];
  for (const token of text.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]]/gu)) {
    if (token[0] === '{' || token[0] === '[') {
      if (stack.length >= 6) throw new PilotReportError(problem);
      stack.push(token[0] === '{' ? new Set() : null);
    } else if (token[0] === '}' || token[0] === ']') stack.pop();
    else {
      const keys = stack.at(-1);
      if (!keys) continue;
      let next = token.index + token[0].length;
      while (next < text.length && /[ \t\r\n]/u.test(text[next]!)) next++;
      if (text[next] !== ':') continue;
      const key = JSON.parse(token[0]) as string;
      if (keys.has(key)) throw new PilotReportError(problem);
      keys.add(key);
    }
  }
  return value;
}

/** Read bounded private feedback without following links or opening a special file for blocking I/O. */
export function readPrivatePilotJson(path: string, problem: InputProblem): unknown {
  let fd: number | undefined;
  try {
    const original = lstatSync(path, { bigint: true });
    if (!original.isFile() || original.nlink !== 1n) throw new PilotReportError(problem);
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    const stat = fstatSync(fd, { bigint: true });
    if (
      !stat.isFile() ||
      stat.nlink !== 1n ||
      original.ino !== stat.ino ||
      original.dev !== stat.dev ||
      stat.size > BigInt(problem === 'responses' ? 2 * MAX_INPUT_BYTES : MAX_INPUT_BYTES) ||
      (process.platform !== 'win32' && (stat.mode & 0o077n) !== 0n)
    )
      throw new PilotReportError(problem);
    const bytes = Buffer.alloc(Number(stat.size) + 1);
    let pos = 0;
    while (pos < bytes.length) {
      const length = readSync(fd, bytes, pos, bytes.length - pos, null);
      if (!length) break;
      pos += length;
    }
    const after = fstatSync(fd, { bigint: true });
    const current = lstatSync(path, { bigint: true });
    if (
      BigInt(pos) !== stat.size ||
      !current.isFile() ||
      current.ino !== stat.ino ||
      current.dev !== stat.dev ||
      after.nlink !== 1n ||
      after.mtimeNs !== stat.mtimeNs ||
      after.ctimeNs !== stat.ctimeNs ||
      after.size !== stat.size
    )
      throw new PilotReportError(problem);
    return parseJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, pos)), problem);
  } catch {
    throw new PilotReportError(problem);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
