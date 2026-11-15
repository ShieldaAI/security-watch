import { satisfies, validRange, parse } from '@renovatebot/pep440';
import type { Applicability } from './types.js';

/** Conservative final-release subset; unsupported syntax never establishes exclusion. */
export function pythonRangeStatus(version: string, range: string | undefined): Applicability {
  if (!range || range.length > 2_048) return 'unknown';
  const finalRelease = (value: string): boolean => {
    if (value.length > 128 || !/^\d+(?:\.\d+){0,15}$/.test(value)) return false;
    const parsed = parse(value);
    return Boolean(parsed && parsed.release.every(Number.isSafeInteger));
  };
  if (!finalRelease(version)) return 'unknown';
  const constraints = range.split(',');
  if (constraints.length > 32) return 'unknown';
  for (const constraint of constraints) {
    const match = /^(?:==|!=|<=|>=|<|>)\s*(\d+(?:\.\d+)*)$/.exec(constraint.trim());
    if (!match || !finalRelease(match[1]!)) return 'unknown';
  }
  try {
    if (!validRange(range)) return 'unknown';
    return satisfies(version, range) ? 'affected' : 'not_affected';
  } catch {
    return 'unknown';
  }
}
