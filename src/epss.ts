import type { Assessment, EpssScore, HttpClient } from './types.js';

/**
 * EPSS (FIRST's Exploit Prediction Scoring System): the estimated probability that a CVE is
 * exploited in the next 30 days. Shown with a finding; it decides nothing. FIRST updates scores
 * daily, so they are kept apart from everything that makes a finding revision, a review or a model
 * analysis: a new score never re-sends an alert or reopens a review.
 *
 * Only CVE identifiers are sent, to `api.first.org`. No inventory data.
 */
const ENDPOINT = 'https://api.first.org/data/v1/epss';
/** The API answers at most 100 rows a page; 50 identifiers keep one request one page. */
const BATCH = 50;
/** Requests per scan; the rest wait for the next scan, the longest unrefreshed first. */
const MAX_REQUESTS = 10;
/** A score is refreshed once a day, as FIRST publishes them. */
const REFRESH_MS = 86_400_000;
/** Identifiers kept at most; the cache only holds the CVEs of current findings. */
const MAX_IDENTIFIERS = 20_000;
const CVE = /^CVE-\d{4}-\d{4,19}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

/** One cached lookup: a score, or none when FIRST has no score for the CVE yet. */
export interface EpssEntry {
  /** Local time of the lookup, in milliseconds. */
  fetched: number;
  score?: EpssScore;
}
export type EpssCache = Record<string, EpssEntry>;

export interface EpssRefresh {
  cache: EpssCache;
  /** Requests that failed; the scan keeps the earlier scores for their identifiers. */
  failed: number;
  /** Identifiers still due after this scan's request budget. */
  pending: number;
}

/** Reads a stored cache, dropping anything malformed rather than failing the scan. */
export function readEpssCache(value: string | undefined): EpssCache {
  const cache: EpssCache = {};
  if (!value) return cache;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return cache;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return cache;
  for (const [id, raw] of Object.entries(parsed as Record<string, unknown>)) {
    if (!CVE.test(id) || !raw || typeof raw !== 'object') continue;
    const entry = raw as { fetched?: unknown; score?: unknown };
    if (typeof entry.fetched !== 'number' || !Number.isFinite(entry.fetched)) continue;
    const score = validScore(entry.score);
    cache[id] = score ? { fetched: entry.fetched, score } : { fetched: entry.fetched };
  }
  return cache;
}

function validScore(value: unknown): EpssScore | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const { probability, percentile, date } = value as Record<string, unknown>;
  return typeof probability === 'number' &&
    probability >= 0 &&
    probability <= 1 &&
    typeof percentile === 'number' &&
    percentile >= 0 &&
    percentile <= 1 &&
    typeof date === 'string' &&
    DATE.test(date)
    ? { probability, percentile, date }
    : undefined;
}

/** One row of the API's `data` array, or undefined when it is not one. */
function row(value: unknown): { cve: string; score: EpssScore } | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const { cve, epss, percentile, date } = value as Record<string, unknown>;
  if (typeof cve !== 'string' || !CVE.test(cve.toUpperCase())) return undefined;
  // The API writes numbers as strings ("0.016400000").
  const probability = typeof epss === 'string' && /^\d(?:\.\d{1,12})?$/.test(epss) ? Number(epss) : NaN;
  const rank =
    typeof percentile === 'string' && /^\d(?:\.\d{1,12})?$/.test(percentile) ? Number(percentile) : NaN;
  const score = validScore({ probability, percentile: rank, date });
  return score ? { cve: cve.toUpperCase(), score } : undefined;
}

/**
 * Looks up the CVEs that are due: never looked up, or looked up more than a day ago, the oldest
 * first, in batches, within the scan's request budget. The first failure ends the lookups of this
 * scan. The returned cache holds only the given CVEs.
 */
export async function refreshEpss(
  identifiers: readonly string[],
  stored: EpssCache,
  http: HttpClient,
  now: number,
): Promise<EpssRefresh> {
  const wanted = [...new Set(identifiers.map((id) => id.toUpperCase()).filter((id) => CVE.test(id)))].slice(
    0,
    MAX_IDENTIFIERS,
  );
  const cache: EpssCache = {};
  for (const id of wanted) if (stored[id]) cache[id] = stored[id];
  const due = wanted
    .filter((id) => !cache[id] || !(cache[id].fetched <= now) || now - cache[id].fetched >= REFRESH_MS)
    .sort((a, b) => (cache[a]?.fetched ?? -1) - (cache[b]?.fetched ?? -1) || a.localeCompare(b));
  let failed = 0;
  let sent = 0;
  for (let index = 0; index < due.length && sent < MAX_REQUESTS; index += BATCH) {
    const batch = due.slice(index, index + BATCH);
    sent++;
    try {
      const response = await http(`${ENDPOINT}?cve=${batch.join(',')}`, {
        maxBytes: 200_000,
        headers: { accept: 'application/json' },
      });
      if (response.status !== 200) throw new Error('EPSS_HTTP');
      const body = JSON.parse(response.body) as { status?: unknown; data?: unknown };
      if (body.status !== 'OK' || !Array.isArray(body.data)) throw new Error('EPSS_SCHEMA');
      const scores = new Map<string, EpssScore>();
      for (const item of body.data) {
        const parsed = row(item);
        if (parsed && batch.includes(parsed.cve)) scores.set(parsed.cve, parsed.score);
      }
      for (const id of batch) {
        const score = scores.get(id);
        cache[id] = score ? { fetched: now, score } : { fetched: now };
      }
    } catch (error) {
      if ((error as { name?: string })?.name === 'AbortError') throw error;
      failed++;
      break;
    }
  }
  const pending = wanted.filter(
    (id) => !cache[id] || !(cache[id].fetched <= now) || now - cache[id].fetched >= REFRESH_MS,
  ).length;
  return { cache, failed, pending };
}

/** The finding with the cached score of its CVE, or without one. Never part of its conclusion. */
export function attachEpss(assessment: Assessment, cache: EpssCache): Assessment {
  const { epss: _old, ...rest } = assessment;
  const score = cache[assessment.event_id.toUpperCase()]?.score;
  return score ? { ...rest, epss: score } : rest;
}
