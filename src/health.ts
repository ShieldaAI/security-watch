import type { Config } from './types.js';
import { Store } from './store.js';

/** How long a running worker may take over its first scan before health reports none. */
const FIRST_SCAN_GRACE = 3_600_000;
/** How long a worker that died may have run after its last heartbeat (written every 15 seconds). */
const CRASH_MARGIN = 60_000;

export interface HealthReport {
  ok: boolean;
  status: 'healthy' | 'starting' | 'degraded';
  checked_at: string;
  issues: string[];
  last_scan_at: string | null;
  worker_heartbeat_at: string | null;
  delivery: { failed: number; unknown: number; overdue_pending: number };
}
function object(value: string | undefined): Record<string, unknown> | undefined {
  if (!value) return undefined;
  try {
    const data: unknown = JSON.parse(value);
    return data !== null && typeof data === 'object' && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}
function time(value: unknown): number {
  return typeof value === 'string' ? Date.parse(value) : NaN;
}
/**
 * Since when a worker starting at `startedAt` has been catching up without recording a scan. It is
 * kept across restarts until a scan is recorded, so a worker killed during every scan cannot renew
 * its startup grace by restarting; a restart after a recorded scan starts afresh. The time between
 * the previous worker's last sign of life and this start does not count.
 */
export function catchingUpFrom(store: Store, startedAt: string): string {
  try {
    const previous = JSON.parse(store.getMeta('worker') ?? 'null') as {
      status?: string;
      catching_up_since?: string;
      started_at?: string;
      heartbeat_at?: string;
    } | null;
    const scan = JSON.parse(store.getMeta('last_scan') ?? 'null') as { at?: string } | null;
    const since = time(previous?.catching_up_since);
    const scanned = time(scan?.at);
    const seen = Math.max(
      ...[time(previous?.heartbeat_at), time(previous?.started_at)].filter(Number.isFinite),
    );
    const start = Date.parse(startedAt);
    if (!Number.isFinite(since) || since > start || scanned >= since) return startedAt;
    // Only running time counts: the time the worker was stopped moves the start forward. A clean stop
    // records its last moment. A worker that died may have run up to a heartbeat interval past its
    // last heartbeat, so that much more of the gap counts as running: a crash loop, down for seconds,
    // cannot renew the grace however soon it dies.
    const gap = Number.isFinite(seen) && seen >= since && seen <= start ? start - seen : 0;
    const down = previous?.status === 'stopped' ? gap : Math.max(0, gap - CRASH_MARGIN);
    return new Date(since + down).toISOString();
  } catch {
    return startedAt;
  }
}

/** Read-only monitoring health check; does not assess system security or make network requests. */
export function checkHealth(
  store: Store,
  config: Config,
  now = Date.now(),
  requireWorker = true,
): HealthReport {
  const scan = object(store.getMeta('last_scan'));
  const worker = object(store.getMeta('worker'));
  const heartbeat = time(worker?.heartbeat_at);
  const started = time(worker?.started_at);
  const scanned = time(scan?.at);
  const issues: string[] = [];
  const staleAfter = Math.max(120_000, config.poll_interval_minutes * 120_000);
  // The first scan reads a day of advisories and every package lookup at about a request a second:
  // it can take well over the two minutes later scans need, so a running worker that has not
  // finished one yet is healthy for up to an hour.
  // Measured from when the worker began catching up, which survives restarts until a scan is
  // recorded: a worker killed during every scan does not renew its grace by restarting.
  const catchingUpSince = time(worker?.catching_up_since);
  const graceFrom =
    Number.isFinite(catchingUpSince) && catchingUpSince <= started ? catchingUpSince : started;
  const startupGrace =
    worker?.status === 'running' &&
    Number.isFinite(started) &&
    now >= started &&
    (Number.isFinite(scanned) && scanned >= started
      ? now - started <= 120_000
      : now - graceFrom <= FIRST_SCAN_GRACE);
  /** Whether this check passes only because a worker is still catching up. */
  let catchingUp = false;
  if (
    requireWorker &&
    (worker?.status !== 'running' ||
      !Number.isFinite(heartbeat) ||
      heartbeat > now + 5000 ||
      now - heartbeat > 90_000)
  )
    issues.push('Worker heartbeat is missing, stopped or stale.');
  if (!Number.isFinite(scanned)) {
    if (!startupGrace || !requireWorker) issues.push('No completed scan is recorded.');
  } else {
    const stale = now - scanned > staleAfter;
    if (stale && startupGrace && requireWorker && scanned < started) catchingUp = true;
    else if (scanned > now + 5000 || stale)
      issues.push('The last completed scan is stale or has an invalid future timestamp.');
    if (scan?.degraded !== false)
      issues.push('The last scan reported degraded monitoring; inspect status and findings.');
  }
  const delivery = store.deliveryIssues(now, 300_000, config);
  if (config.maintenance) {
    const maintenance = object(store.getMeta('maintenance:last_run'));
    if (maintenance?.ok === false)
      issues.push('Scheduled maintenance failed; inspect status and backup storage.');
    const lastSuccess = time(maintenance?.last_success_at);
    if (requireWorker && !startupGrace && !Number.isFinite(lastSuccess))
      issues.push('Scheduled maintenance has not completed successfully.');
    if (
      Number.isFinite(lastSuccess) &&
      (lastSuccess > now + 5000 || now - lastSuccess > config.maintenance.interval_hours * 7_200_000)
    )
      issues.push('Scheduled maintenance is overdue.');
  }
  if (delivery.failed) issues.push('Current notifications have failed; inspect deliveries.');
  if (delivery.unknown)
    issues.push('Current notification receipt is uncertain; verify delivery before retrying.');
  if (delivery.overdue_pending) issues.push('Current notifications are overdue by more than five minutes.');
  return {
    ok: issues.length === 0,
    // While a worker catches up the check passes, but it is "starting": no success is reported to
    // an external heartbeat until a scan completes.
    status: issues.length ? 'degraded' : Number.isFinite(scanned) && !catchingUp ? 'healthy' : 'starting',
    checked_at: new Date(now).toISOString(),
    issues,
    last_scan_at: Number.isFinite(scanned) ? new Date(scanned).toISOString() : null,
    worker_heartbeat_at: Number.isFinite(heartbeat) ? new Date(heartbeat).toISOString() : null,
    delivery,
  };
}
