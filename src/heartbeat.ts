import type { Config, HttpClient } from './types.js';
import type { Store } from './store.js';
import { checkHealth } from './health.js';
import { validateDestination } from './http.js';

export interface ExternalHeartbeat {
  status: 'accepted' | 'failed' | 'withheld';
  checked_at: string;
  last_success_at: string | null;
  reason: string | null;
}

/** Sends no inventory or logs. A separate service alerts when healthy pings stop arriving. */
export class HeartbeatMonitor {
  private nextAt = 0;

  async tick(
    store: Store,
    config: Config,
    http: HttpClient,
    now = Date.now(),
    signal?: AbortSignal,
  ): Promise<ExternalHeartbeat | undefined> {
    const settings = config.monitoring;
    if (!settings || signal?.aborted || now < this.nextAt) return undefined;
    this.nextAt = now + settings.interval_seconds * 1000;
    let lastSuccess: string | null = null;
    const saved = store.getMeta('external_heartbeat');
    try {
      const previous: unknown = JSON.parse(saved ?? 'null');
      if (
        previous &&
        typeof previous === 'object' &&
        'last_success_at' in previous &&
        typeof previous.last_success_at === 'string' &&
        Number.isFinite(Date.parse(previous.last_success_at))
      )
        lastSuccess = previous.last_success_at;
    } catch {
      // A malformed old receipt cannot establish a successful ping.
    }
    const report: ExternalHeartbeat = {
      status: 'withheld',
      checked_at: new Date(now).toISOString(),
      last_success_at: lastSuccess,
      reason: null,
    };
    const health = checkHealth(store, config, now);
    if (!health.ok || health.status !== 'healthy') {
      report.reason = 'Monitoring is not healthy; no success ping was sent.';
    } else {
      const endpoint = process.env[settings.heartbeat_url_env];
      if (!endpoint) {
        report.status = 'failed';
        report.reason = 'External heartbeat destination is not configured.';
      } else {
        try {
          validateDestination(endpoint, settings.allow_private_endpoint);
          const response = await http(endpoint, {
            method: 'GET',
            redirects: 0,
            timeoutMs: 5000,
            maxBytes: 4096,
            allowPrivate: settings.allow_private_endpoint,
            signal,
          });
          if (response.status >= 200 && response.status < 300) {
            report.status = 'accepted';
            report.last_success_at = report.checked_at;
          } else {
            report.status = 'failed';
            report.reason = `External heartbeat returned HTTP ${response.status}.`;
          }
        } catch {
          if (signal?.aborted) return undefined;
          report.status = 'failed';
          report.reason = 'External heartbeat request failed; the destination may not have received it.';
        }
      }
    }
    if (signal?.aborted) return undefined;
    store.setMeta('external_heartbeat', JSON.stringify(report));
    return report;
  }
}
