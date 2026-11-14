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
/** The text on one line: every run of line-breaking characters becomes a single space. */
export function singleLine(value: string, max = 4000): string {
  return value
    .replace(/\s*[\u0000-\u001f\u007f-\u009f\u2028\u2029]+\s*/gu, ' ')
    .trim()
    .slice(0, max);
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
