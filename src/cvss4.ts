import { referenceBaseScore, referenceMetrics } from './vendor/cvss4-reference.js';
import type { CvssV4BaseScore } from './types.js';

const metricOrder = Object.keys(referenceMetrics);
const baseMetrics = metricOrder.slice(0, 11);

/** Validate the complete supplied vector, then explicitly project CVSS-B only. */
export function cvssV4BaseScore(vector: unknown): CvssV4BaseScore | undefined {
  if (typeof vector !== 'string' || vector.length > 1024 || !vector.startsWith('CVSS:4.0/')) return undefined;
  const parts = vector.split('/');
  if (parts.length < 12 || parts.length > 33) return undefined;
  const selected: Record<string, string> = Object.fromEntries(metricOrder.map((metric) => [metric, 'X']));
  let previous = -1;
  for (const part of parts.slice(1)) {
    const pair = part.split(':');
    if (pair.length !== 2) return undefined;
    const [metric, value] = pair as [string, string];
    const index = metricOrder.indexOf(metric);
    if (index <= previous || !referenceMetrics[metric]?.includes(value)) return undefined;
    selected[metric] = value;
    previous = index;
  }
  if (baseMetrics.some((metric) => selected[metric] === 'X')) return undefined;
  const baseVector = `CVSS:4.0/${baseMetrics.map((metric) => `${metric}:${selected[metric]}`).join('/')}`;
  // Source-supplied threat/environment/supplemental values are not local deployment facts.
  for (const metric of metricOrder.slice(11)) selected[metric] = 'X';
  try {
    const score = referenceBaseScore(selected);
    if (!Number.isFinite(score) || score < 0 || score > 10) return undefined;
    return { vector, base_vector: baseVector, score, context_removed: vector !== baseVector };
  } catch {
    return undefined;
  }
}
