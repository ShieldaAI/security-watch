import { createHash } from 'node:crypto';
import type { Severity } from './types.js';
export const severityRank: Record<Severity, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };
export function highest(...values: Severity[]): Severity { return values.reduce((a,b) => severityRank[a] >= severityRank[b] ? a : b, 'unknown'); }
export function hash(value: unknown): string { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
export function timestamp(now = Date.now()): string { return new Date(now).toISOString(); }
export function cleanText(value: string, max = 4000): string { return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').slice(0,max); }
