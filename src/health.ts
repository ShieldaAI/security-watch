import type { Config } from './types.js';
import { Store } from './store.js';

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
/** Monitoring health, never a statement that monitored systems are secure. No network or writes. */
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
  const startupGrace =
    worker?.status === 'running' && Number.isFinite(started) && now >= started && now - started <= 120_000;
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
    if (scanned > now + 5000 || now - scanned > Math.max(120_000, config.poll_interval_minutes * 120_000))
      issues.push('The last completed scan is stale or has an invalid future timestamp.');
    if (scan?.degraded !== false)
      issues.push('The last scan reported degraded monitoring; inspect status and findings.');
  }
  const delivery = store.deliveryIssues(now, 300_000, config);
  if (delivery.failed) issues.push('Current notifications have failed; inspect deliveries.');
  if (delivery.unknown)
    issues.push('Current notification receipt is uncertain; verify delivery before retrying.');
  if (delivery.overdue_pending) issues.push('Current notifications are overdue by more than five minutes.');
  return {
    ok: issues.length === 0,
    status: issues.length ? 'degraded' : Number.isFinite(scanned) ? 'healthy' : 'starting',
    checked_at: new Date(now).toISOString(),
    issues,
    last_scan_at: Number.isFinite(scanned) ? new Date(scanned).toISOString() : null,
    worker_heartbeat_at: Number.isFinite(heartbeat) ? new Date(heartbeat).toISOString() : null,
    delivery,
  };
}
