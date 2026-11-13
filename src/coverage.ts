import type { CoverageReceipt } from './types.js';

export function coverageFreshness(
  receipt: Pick<CoverageReceipt, 'last_success_at' | 'fresh_until'>,
  now: number,
): CoverageReceipt['freshness'] {
  const success = receipt.last_success_at ? Date.parse(receipt.last_success_at) : NaN;
  const expiry = receipt.fresh_until ? Date.parse(receipt.fresh_until) : NaN;
  if (!Number.isFinite(success)) return 'never';
  return success <= now + 300_000 && Number.isFinite(expiry) && now <= expiry ? 'fresh' : 'stale';
}

/** Re-evaluate saved receipts at read time so a stopped monitor cannot look perpetually fresh. */
export function refreshCoverage(receipts: CoverageReceipt[], now = Date.now()): CoverageReceipt[] {
  return receipts.map((receipt) => ({ ...receipt, freshness: coverageFreshness(receipt, now) }));
}
