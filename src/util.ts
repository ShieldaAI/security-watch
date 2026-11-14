import { createHash } from 'node:crypto';
import type { Severity } from './types.js';
export const severityRank: Record<Severity, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };
export function highest(...values: Severity[]): Severity {
  return values.reduce((a, b) => (severityRank[a] >= severityRank[b] ? a : b), 'unknown');
}
export function hash(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}
export function timestamp(now = Date.now()): string {
  return new Date(now).toISOString();
}
export function cleanText(value: string, max = 4000): string {
  return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').slice(0, max);
}
/**
 * Characters that end or disturb a line: control characters (including NEL, U+0085) and the Unicode
 * line and paragraph separators. Mail clients and chat applications render them as line breaks.
 */
export const LINE_BREAKING = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const lineBreaking = (code: number) =>
  code <= 0x1f || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029;
/** Spaces that are not line-breaking characters; with those, everything `\s` matches. */
const blank = (code: number) =>
  code === 0x20 ||
  code === 0xa0 ||
  code === 0x1680 ||
  (code >= 0x2000 && code <= 0x200a) ||
  code === 0x202f ||
  code === 0x205f ||
  code === 0x3000 ||
  code === 0xfeff;
/**
 * The text on one line: every run of line-breaking characters, with the spaces around it, becomes a
 * single space. The work is proportional to the input and stops once `max` characters are kept, so
 * a value padded with megabytes of spaces costs nothing more than reading it.
 */
export function singleLine(value: string, max = 4000): string {
  const length = value.length;
  let index = 0;
  while (index < length && (blank(value.charCodeAt(index)) || lineBreaking(value.charCodeAt(index)))) index++;
  let out = '';
  let start = index;
  for (; index < length; index++) {
    const code = value.charCodeAt(index);
    if (!lineBreaking(code)) {
      // Enough is kept once a visible character lies past the limit. Spaces there are still read,
      // because a line break after them would remove them.
      if (!blank(code) && out.length + (index - start) >= max) break;
      continue;
    }
    let end = index;
    while (end > start && blank(value.charCodeAt(end - 1))) end--;
    out += value.slice(start, end);
    while (index < length && (blank(value.charCodeAt(index)) || lineBreaking(value.charCodeAt(index))))
      index++;
    // Nothing but separators was left: the text ends here.
    if (index < length) out += ' ';
    start = index;
    index--;
  }
  out += value.slice(start, Math.min(length, start + Math.max(0, max - out.length)));
  return out.slice(0, max).trimEnd();
}

/** A review binds JSON content independently of object insertion order. Array order is retained. */
export function canonicalHash(value: unknown): string {
  return createHash('sha256')
    .update(
      JSON.stringify(value, (_key, item) =>
        item && typeof item === 'object' && !Array.isArray(item)
          ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b)))
          : item,
      ),
    )
    .digest('hex');
}
