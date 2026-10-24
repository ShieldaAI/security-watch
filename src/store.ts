import { DatabaseSync, backup as sqliteBackup } from 'node:sqlite';
import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  rmSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Assessment, Config, Decision, Evidence, Notification } from './types.js';
import { hash } from './util.js';
import { decide } from './assessment.js';

type Row = Record<string, unknown>;
const SCHEMA_VERSION = 4;
function verifyFile(path: string, writable: boolean, create = false): void {
  const fd = openSync(
    path,
    (writable ? constants.O_RDWR : constants.O_RDONLY) |
      constants.O_NOFOLLOW |
      constants.O_NONBLOCK |
      (create ? constants.O_CREAT : 0),
    0o600,
  );
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1)
      throw new Error('Database paths must be regular files without hard links');
    if (writable) fchmodSync(fd, 0o600);
  } finally {
    closeSync(fd);
  }
}
function privateFile(path: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  // Do not follow links when checking or changing permissions, including dangling links.
  verifyFile(path, true, true);
}
function existingSidecars(path: string, writable: boolean): void {
  for (const file of [`${path}-wal`, `${path}-shm`, `${path}-journal`]) {
    try {
      lstatSync(file);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    verifyFile(file, writable);
  }
}
function notification(row: Row): Notification {
  return {
    id: String(row.id),
    finding_id: String(row.finding_id),
    channel: row.channel as Notification['channel'],
    payload: String(row.payload),
    status: row.status as Notification['status'],
    attempts: Number(row.attempts),
    available_at: Number(row.available_at),
    ...(row.last_error == null ? {} : { last_error: String(row.last_error) }),
  };
}
function evidenceFingerprint(evidence: Evidence): string {
  const { fetched_at: _fetched, ...content } = evidence;
  return hash(content);
}
function fingerprint(a: Assessment, decision: Decision): string {
  // Article wording, source arrival order and AI phrasing are not new security events.
  return hash({
    event: a.event_id,
    system: a.system_id,
    component: a.component_id,
    category: a.category,
    applicability: a.applicability,
    news_classification: a.news_analysis?.classification ?? null,
    news_impact: a.news_analysis?.impact ?? null,
    severity: a.source_severity,
    priority: a.priority,
    exploited: a.exploited,
    withdrawn: a.withdrawn ?? false,
    active: a.active !== false,
    fix: a.fix ?? null,
    action: decision.action,
  });
}

/** Durable state for one local worker. Stores evidence and results, never provider credentials. */
export class Store {
  readonly #db: DatabaseSync;
  readonly #path: string;
  constructor(path: string, options: { readOnly?: boolean; migrate?: boolean } = {}) {
    this.#path = path === ':memory:' ? path : resolve(path);
    if (this.#path !== ':memory:') {
      if ((options.readOnly || options.migrate === false) && !existsSync(this.#path))
        throw new Error('Database does not exist; run scan or start first');
      if (options.readOnly) verifyFile(this.#path, false);
      else privateFile(this.#path);
      existingSidecars(this.#path, !options.readOnly);
    }
    this.#db = new DatabaseSync(this.#path, { readOnly: options.readOnly ?? false });
    try {
      this.#db.exec('PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
      const version = Number((this.#db.prepare('PRAGMA user_version').get() as Row).user_version);
      if (version > SCHEMA_VERSION)
        throw new Error(`Database schema ${version} is newer than supported schema ${SCHEMA_VERSION}`);
      if (version < SCHEMA_VERSION && (options.readOnly || options.migrate === false))
        throw new Error('Database migration required; stop the worker and run scan or start first');
      if (!options.readOnly) this.#db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;');
      if (version === 0)
        this.#transaction(() => {
          this.#db.exec(`
          CREATE TABLE evidence (source TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(source,id));
          CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE findings (id TEXT PRIMARY KEY, payload TEXT NOT NULL, fingerprint TEXT NOT NULL, revision INTEGER NOT NULL,
            acknowledged_revision INTEGER, suppressed_until INTEGER, suppression_reason TEXT);
          CREATE TABLE notifications (id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id), revision INTEGER NOT NULL,
            channel TEXT NOT NULL CHECK(channel IN ('slack','email')), payload TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending','sending','accepted','unknown','failed')),
            attempts INTEGER NOT NULL DEFAULT 0, available_at INTEGER NOT NULL, last_error TEXT,
            UNIQUE(finding_id,revision,channel));
          CREATE INDEX notifications_due ON notifications(status,available_at);
          CREATE TABLE budgets (day TEXT PRIMARY KEY, requests INTEGER NOT NULL, tokens INTEGER NOT NULL, usd REAL NOT NULL);
          PRAGMA user_version = 1;
        `);
        });
      if (version < 2)
        this.#transaction(() => {
          this.#db
            .exec(`CREATE TABLE finding_revisions (finding_id TEXT NOT NULL REFERENCES findings(id), revision INTEGER NOT NULL,
          payload TEXT NOT NULL, decision TEXT NOT NULL, recorded_at INTEGER NOT NULL, PRIMARY KEY(finding_id,revision));
          INSERT INTO finding_revisions(finding_id,revision,payload,decision,recorded_at)
            SELECT id,revision,payload,'{"action":"record","channels":[],"reason":"Imported from schema 1"}',0 FROM findings;
          PRAGMA user_version = 2;`);
        });
      if (version < 3)
        this.#transaction(() => {
          this.#db
            .exec(`CREATE TABLE evidence_revisions (source TEXT NOT NULL, id TEXT NOT NULL, content_hash TEXT NOT NULL,
          payload TEXT NOT NULL, recorded_at INTEGER NOT NULL, PRIMARY KEY(source,id,content_hash));`);
          const insert = this.#db.prepare(
            'INSERT INTO evidence_revisions(source,id,content_hash,payload,recorded_at) VALUES(?,?,?,?,?)',
          );
          for (const row of this.#db.prepare('SELECT payload FROM evidence').all()) {
            const evidence = JSON.parse(String(row.payload)) as Evidence;
            insert.run(
              evidence.source,
              evidence.id,
              evidenceFingerprint(evidence),
              String(row.payload),
              Date.parse(evidence.fetched_at) || 0,
            );
          }
          this.#db.exec('PRAGMA user_version = 3;');
        });
      if (version < 4)
        this.#transaction(() => {
          this.#db.exec(
            'CREATE INDEX IF NOT EXISTS evidence_by_id ON evidence(id); PRAGMA user_version = 4;',
          );
        });
      if (!options.readOnly) this.#privateSidecars();
    } catch (error) {
      this.#db.close();
      throw error;
    }
  }
  #privateSidecars(): void {
    if (this.#path !== ':memory:') {
      verifyFile(this.#path, true);
      existingSidecars(this.#path, true);
    }
  }
  #transaction<T>(fn: () => T): T {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const value = fn();
      this.#db.exec('COMMIT');
      return value;
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
  }
  close(): void {
    this.#db.close();
  }
  saveEvidence(evidence: Evidence[], checkpoints: Record<string, string>): void {
    this.#transaction(() => {
      const put = this.#db.prepare(
        'INSERT INTO evidence(source,id,payload) VALUES(?,?,?) ON CONFLICT(source,id) DO UPDATE SET payload=excluded.payload',
      );
      const get = this.#db.prepare('SELECT payload FROM evidence WHERE source=? AND id=?');
      for (const e of evidence) {
        const modified = Date.parse(e.modified_at);
        const fetched = Date.parse(e.fetched_at);
        if (!Number.isFinite(modified) || !Number.isFinite(fetched))
          throw new Error('Evidence timestamps must be valid');
        const prior = get.get(e.source, e.id);
        if (prior) {
          const old = JSON.parse(String(prior.payload)) as Evidence;
          const previousModified = Date.parse(old.modified_at);
          if (
            modified < previousModified ||
            (modified === previousModified && fetched < Date.parse(old.fetched_at))
          )
            continue;
        }
        this.#db
          .prepare(
            'INSERT INTO evidence_revisions(source,id,content_hash,payload,recorded_at) VALUES(?,?,?,?,?) ON CONFLICT(source,id,content_hash) DO NOTHING',
          )
          .run(e.source, e.id, evidenceFingerprint(e), JSON.stringify(e), fetched);
        put.run(e.source, e.id, JSON.stringify(e));
      }
      for (const [key, value] of Object.entries(checkpoints)) this.setMeta(`checkpoint:${key}`, value);
    });
  }
  evidence(): Evidence[] {
    return this.#db
      .prepare('SELECT payload FROM evidence ORDER BY source,id')
      .all()
      .map((r) => JSON.parse(String(r.payload)) as Evidence);
  }
  getEvidence(ids: readonly string[]): Evidence[] {
    if (ids.length > 10_000) throw new Error('Too many evidence identifiers');
    if (!ids.length) return [];
    return this.#db
      .prepare('SELECT payload FROM evidence WHERE id IN (SELECT value FROM json_each(?)) ORDER BY source,id')
      .all(JSON.stringify([...new Set(ids)]))
      .map((row) => JSON.parse(String(row.payload)) as Evidence);
  }
  evidenceHistory(
    source: string,
    id: string,
  ): { content_hash: string; evidence: Evidence; recorded_at: number }[] {
    return this.#db
      .prepare(
        'SELECT content_hash,payload,recorded_at FROM evidence_revisions WHERE source=? AND id=? ORDER BY recorded_at,content_hash',
      )
      .all(source, id)
      .map((row) => ({
        content_hash: String(row.content_hash),
        evidence: JSON.parse(String(row.payload)) as Evidence,
        recorded_at: Number(row.recorded_at),
      }));
  }
  checkpoints(): Record<string, string> {
    return Object.fromEntries(
      this.#db
        .prepare("SELECT key,value FROM metadata WHERE key LIKE 'checkpoint:%' ORDER BY key")
        .all()
        .map((r) => [String(r.key).slice('checkpoint:'.length), String(r.value)]),
    );
  }
  saveAssessment(assessment: Assessment, decision: Decision, now = Date.now(), digestMs = 86_400_000): void {
    if (
      !Number.isSafeInteger(now) ||
      !Number.isSafeInteger(digestMs) ||
      digestMs < 0 ||
      !Number.isSafeInteger(now + digestMs)
    )
      throw new Error('Invalid notification time');
    this.#transaction(() => {
      const old = this.#db.prepare('SELECT * FROM findings WHERE id=?').get(assessment.id) as Row | undefined;
      const signature = fingerprint(assessment, decision);
      const changed = !old || signature !== old.fingerprint;
      const revision = old ? Number(old.revision) + (changed ? 1 : 0) : 1;
      this.#db
        .prepare(
          `INSERT INTO findings(id,payload,fingerprint,revision) VALUES(?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,fingerprint=excluded.fingerprint,revision=excluded.revision`,
        )
        .run(assessment.id, JSON.stringify(assessment), signature, revision);
      if (changed)
        this.#db
          .prepare(
            'INSERT INTO finding_revisions(finding_id,revision,payload,decision,recorded_at) VALUES(?,?,?,?,?)',
          )
          .run(assessment.id, revision, JSON.stringify(assessment), JSON.stringify(decision), now);
      if (changed)
        this.#db
          .prepare(
            "UPDATE notifications SET status='failed',last_error='Superseded by a newer assessment' WHERE finding_id=? AND status='pending'",
          )
          .run(assessment.id);
      // A changed routing configuration can stop a pending delivery without creating a duplicate in retained channels.
      const channels = decision.action === 'record' ? [] : [...new Set(decision.channels)];
      for (const channel of ['slack', 'email'])
        if (!channels.includes(channel as 'slack' | 'email')) {
          this.#db
            .prepare(
              "UPDATE notifications SET status='failed',last_error='Notification policy no longer selects this destination' WHERE finding_id=? AND channel=? AND status='pending'",
            )
            .run(assessment.id, channel);
        }
      const payload = JSON.stringify({ assessment, reason: decision.reason, mode: decision.action });
      // Cosmetic updates are not a new alert, but an unsent alert should carry the latest evidence.
      // Keep its original schedule/attempts; accepted and in-flight payloads remain immutable.
      this.#db
        .prepare("UPDATE notifications SET payload=? WHERE finding_id=? AND revision=? AND status='pending'")
        .run(payload, assessment.id, revision);
      if (
        decision.action === 'record' ||
        Number(old?.acknowledged_revision) === revision ||
        Number(old?.suppressed_until ?? 0) > now
      )
        return;
      const availableAt =
        decision.action === 'digest' && digestMs > 0 ? (Math.floor(now / digestMs) + 1) * digestMs : now;
      for (const channel of channels)
        this.#db
          .prepare(
            `INSERT INTO notifications(id,finding_id,revision,channel,payload,status,available_at)
        VALUES(?,?,?,?,?,'pending',?) ON CONFLICT(finding_id,revision,channel) DO UPDATE SET
          payload=excluded.payload,status='pending',available_at=MAX(notifications.available_at,excluded.available_at),last_error=NULL
          WHERE notifications.status='failed' AND notifications.last_error='Notification policy no longer selects this destination'`,
          )
          .run(randomUUID(), assessment.id, revision, channel, payload, availableAt);
    });
  }
  findings(): Assessment[] {
    return this.#db
      .prepare('SELECT payload FROM findings ORDER BY id')
      .all()
      .map((r) => JSON.parse(String(r.payload)) as Assessment);
  }
  getFinding(id: string): Assessment | undefined {
    const row = this.#db.prepare('SELECT payload FROM findings WHERE id=?').get(id);
    return row ? (JSON.parse(String(row.payload)) as Assessment) : undefined;
  }
  controls(
    id: string,
    now = Date.now(),
  ):
    | {
        revision: number;
        acknowledged: boolean;
        acknowledged_revision: number | null;
        suppressed: boolean;
        suppressed_until: number | null;
        suppression_reason: string | null;
      }
    | undefined {
    const row = this.#db
      .prepare(
        'SELECT revision,acknowledged_revision,suppressed_until,suppression_reason FROM findings WHERE id=?',
      )
      .get(id);
    if (!row) return undefined;
    return {
      revision: Number(row.revision),
      acknowledged: row.acknowledged_revision === row.revision,
      acknowledged_revision: row.acknowledged_revision === null ? null : Number(row.acknowledged_revision),
      suppressed: Number(row.suppressed_until ?? 0) > now,
      suppressed_until: row.suppressed_until === null ? null : Number(row.suppressed_until),
      suppression_reason: row.suppression_reason === null ? null : String(row.suppression_reason),
    };
  }
  summary(): {
    active_findings: number;
    delivery_states: Record<string, number>;
    pending: number;
    next_pending_at: number | null;
  } {
    const states = Object.fromEntries(
      this.#db
        .prepare('SELECT status,COUNT(*) AS count FROM notifications GROUP BY status')
        .all()
        .map((row) => [String(row.status), Number(row.count)]),
    );
    const slackAt = Number(this.getMeta('delivery:slack:next_at') ?? 0);
    const next = this.#db
      .prepare(
        "SELECT MIN(MAX(available_at,CASE WHEN channel='slack' THEN ? ELSE 0 END)) AS next FROM notifications WHERE status='pending'",
      )
      .get(slackAt)?.next;
    const count = this.#db
      .prepare(
        "SELECT COUNT(*) AS count FROM findings WHERE COALESCE(json_extract(payload,'$.active'),1) != 0",
      )
      .get()?.count;
    return {
      active_findings: Number(count ?? 0),
      delivery_states: states,
      pending: states.pending ?? 0,
      next_pending_at: next == null ? null : Number(next),
    };
  }
  deliveryIssues(
    now = Date.now(),
    maxPendingAgeMs = 300_000,
    config?: Config,
  ): { failed: number; unknown: number; overdue_pending: number } {
    if (!Number.isSafeInteger(now) || !Number.isSafeInteger(maxPendingAgeMs) || maxPendingAgeMs < 0)
      throw new Error('Invalid delivery health time');
    const slackAt = Number(this.getMeta('delivery:slack:next_at') ?? 0);
    if (config)
      this.#db.function('__watch_delivery_selected', { deterministic: true }, (payload, channel) => {
        const current = JSON.parse(String(payload)) as Assessment;
        const decision = decide(current, config);
        return decision.action !== 'record' &&
          decision.channels.includes(String(channel) as Notification['channel'])
          ? 1
          : 0;
      });
    const row = this.#db
      .prepare(
        `SELECT
      SUM(CASE WHEN n.status='failed' AND COALESCE(n.last_error,'') NOT IN (
        'Notification policy no longer selects this destination', 'Notification urgency changed under the current policy',
        'Finding is no longer active', 'Superseded by a newer assessment', 'Finding acknowledged before delivery') THEN 1 ELSE 0 END) AS failed,
      SUM(CASE WHEN n.status='unknown' THEN 1 ELSE 0 END) AS unknown,
      SUM(CASE WHEN n.status='pending' AND MAX(n.available_at,CASE WHEN n.channel='slack' THEN ? ELSE 0 END)<=? THEN 1 ELSE 0 END) AS overdue_pending
      FROM notifications n JOIN findings f ON f.id=n.finding_id
      WHERE n.status IN ('pending','unknown','failed') AND n.revision=f.revision AND COALESCE(json_extract(f.payload,'$.active'),1) != 0
      AND (f.acknowledged_revision IS NULL OR f.acknowledged_revision<>n.revision)
      AND (f.suppressed_until IS NULL OR f.suppressed_until<=?)
      ${config ? 'AND __watch_delivery_selected(f.payload,n.channel)=1' : ''}`,
      )
      .get(slackAt, now - maxPendingAgeMs, now);
    return {
      failed: Number(row?.failed ?? 0),
      unknown: Number(row?.unknown ?? 0),
      overdue_pending: Number(row?.overdue_pending ?? 0),
    };
  }
  history(
    id: string,
  ): { revision: number; assessment: Assessment; decision: Decision; recorded_at: number }[] {
    return this.#db
      .prepare(
        'SELECT revision,payload,decision,recorded_at FROM finding_revisions WHERE finding_id=? ORDER BY revision',
      )
      .all(id)
      .map((row) => ({
        revision: Number(row.revision),
        assessment: JSON.parse(String(row.payload)) as Assessment,
        decision: JSON.parse(String(row.decision)) as Decision,
        recorded_at: Number(row.recorded_at),
      }));
  }
  jobs(): Notification[] {
    return (this.#db.prepare('SELECT * FROM notifications ORDER BY available_at,id').all() as Row[]).map(
      notification,
    );
  }
  claimDue(now = Date.now(), excludedChannels: Notification['channel'][] = []): Notification | undefined {
    return this.#transaction(() => {
      const row = this.#db
        .prepare(
          `SELECT n.* FROM notifications n JOIN findings f ON f.id=n.finding_id
        WHERE n.status='pending' AND n.available_at<=? AND n.revision=f.revision
        AND (f.suppressed_until IS NULL OR f.suppressed_until<=?)
        AND (f.acknowledged_revision IS NULL OR f.acknowledged_revision<>n.revision)
        ${excludedChannels.length ? `AND n.channel NOT IN (${excludedChannels.map(() => '?').join(',')})` : ''}
        ORDER BY CASE WHEN json_valid(n.payload) THEN CASE WHEN json_extract(n.payload,'$.mode')='digest' THEN 1 ELSE 0 END ELSE 0 END,n.available_at,n.id LIMIT 1`,
        )
        .get(now, now, ...excludedChannels) as Row | undefined;
      if (!row) return undefined;
      this.#db
        .prepare("UPDATE notifications SET status='sending',attempts=attempts+1,last_error=NULL WHERE id=?")
        .run(String(row.id));
      return { ...notification(row), status: 'sending', attempts: Number(row.attempts) + 1 };
    });
  }
  claimAdditionalDigest(channel: Notification['channel'], now = Date.now(), limit = 4): Notification[] {
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > 4)
      throw new Error('Digest batch limit must be 0–4 additional findings');
    return this.#transaction(() => {
      const rows = this.#db
        .prepare(
          `SELECT n.* FROM notifications n JOIN findings f ON f.id=n.finding_id
        WHERE n.status='pending' AND n.channel=? AND n.available_at<=? AND n.revision=f.revision
        AND CASE WHEN json_valid(n.payload) THEN json_extract(n.payload,'$.mode')='digest' ELSE 0 END
        AND (f.suppressed_until IS NULL OR f.suppressed_until<=?)
        AND (f.acknowledged_revision IS NULL OR f.acknowledged_revision<>n.revision)
        ORDER BY n.available_at,n.id LIMIT ?`,
        )
        .all(channel, now, now, limit) as Row[];
      for (const row of rows)
        this.#db
          .prepare("UPDATE notifications SET status='sending',attempts=attempts+1,last_error=NULL WHERE id=?")
          .run(String(row.id));
      return rows.map((row) => ({
        ...notification(row),
        status: 'sending',
        attempts: Number(row.attempts) + 1,
      }));
    });
  }
  completeJob(
    id: string,
    status: 'accepted' | 'unknown' | 'failed' | 'pending',
    nextAt: number,
    error?: string,
  ): void {
    const changed = this.#db
      .prepare(
        "UPDATE notifications SET status=?,available_at=?,last_error=? WHERE id=? AND status='sending'",
      )
      .run(status, nextAt, error ?? null, id);
    if (Number(changed.changes) !== 1) throw new Error('Notification is not in flight');
  }
  deferJob(id: string, nextAt: number, reason = 'Waiting for destination rate limit'): void {
    const changed = this.#db
      .prepare(
        "UPDATE notifications SET status='pending',available_at=?,attempts=MAX(0,attempts-1),last_error=? WHERE id=? AND status='sending'",
      )
      .run(nextAt, reason, id);
    if (Number(changed.changes) !== 1) throw new Error('Notification is not in flight');
  }
  retryJob(id: string, now = Date.now()): void {
    this.#transaction(() => {
      const row = this.#db
        .prepare(
          `SELECT n.status,n.revision,f.revision AS current_revision,f.acknowledged_revision,f.suppressed_until
        FROM notifications n JOIN findings f ON f.id=n.finding_id WHERE n.id=?`,
        )
        .get(id);
      if (!row || !['failed', 'unknown'].includes(String(row.status)))
        throw new Error('Only failed or unknown deliveries can be manually retried');
      if (
        row.revision !== row.current_revision ||
        row.acknowledged_revision === row.revision ||
        Number(row.suppressed_until ?? 0) > now
      )
        throw new Error('Cannot retry a superseded, acknowledged or suppressed finding');
      this.#db
        .prepare(
          "UPDATE notifications SET status='pending',attempts=0,available_at=?,last_error='Manually queued after receipt verification' WHERE id=?",
        )
        .run(now, id);
    });
  }
  recoverSending(now = Date.now()): void {
    this.#db
      .prepare(
        "UPDATE notifications SET status='unknown',available_at=?,last_error='Delivery interrupted; receipt is unknown. Check the destination before retrying.' WHERE status='sending'",
      )
      .run(now);
  }
  acknowledge(id: string): void {
    this.#transaction(() => {
      if (!this.#db.prepare('UPDATE findings SET acknowledged_revision=revision WHERE id=?').run(id).changes)
        throw new Error('Finding not found');
      this.#db
        .prepare(
          "UPDATE notifications SET status='failed',last_error='Finding acknowledged before delivery' WHERE finding_id=? AND status='pending'",
        )
        .run(id);
    });
  }
  suppress(id: string, until: number, reason: string): void {
    if (!Number.isSafeInteger(until) || until <= Date.now() || !reason.trim())
      throw new Error('Suppression needs a future expiry and a reason');
    this.#transaction(() => {
      if (
        !this.#db
          .prepare('UPDATE findings SET suppressed_until=?,suppression_reason=? WHERE id=?')
          .run(until, reason.trim(), id).changes
      )
        throw new Error('Finding not found');
      this.#db
        .prepare(
          "UPDATE notifications SET available_at=MAX(available_at,?) WHERE finding_id=? AND status='pending'",
        )
        .run(until, id);
    });
  }
  getMeta(key: string): string | undefined {
    return this.#db.prepare('SELECT value FROM metadata WHERE key=?').get(key)?.value as string | undefined;
  }
  setMeta(key: string, value: string): void {
    this.#db
      .prepare(
        'INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
      )
      .run(key, value);
  }
  reserveBudget(
    day: string,
    maxRequests: number,
    maxTokens: number,
    maxUsd: number | undefined,
    tokens: number,
    usd: number | undefined,
  ): boolean {
    if (
      !/^\d{4}-\d{2}-\d{2}$/.test(day) ||
      ![maxRequests, maxTokens, tokens].every((n) => Number.isSafeInteger(n) && n >= 0) ||
      (usd !== undefined && (!Number.isFinite(usd) || usd < 0)) ||
      (maxUsd !== undefined && (!Number.isFinite(maxUsd) || maxUsd < 0))
    )
      throw new Error('Invalid model budget');
    return this.#transaction(() => {
      const previous = this.#db.prepare('SELECT * FROM budgets WHERE day=?').get(day);
      const requests = Number(previous?.requests ?? 0) + 1;
      const totalTokens = Number(previous?.tokens ?? 0) + tokens;
      const unpriced = Number(this.getMeta(`unpriced:${day}`) ?? 0);
      if (maxUsd !== undefined && (usd === undefined || unpriced > 0)) return false;
      const totalUsd = Number(previous?.usd ?? 0) + (usd ?? 0);
      if (
        !Number.isFinite(totalUsd) ||
        requests > maxRequests ||
        totalTokens > maxTokens ||
        (maxUsd !== undefined && totalUsd > maxUsd)
      )
        return false;
      this.#db
        .prepare(
          'INSERT INTO budgets(day,requests,tokens,usd) VALUES(?,?,?,?) ON CONFLICT(day) DO UPDATE SET requests=excluded.requests,tokens=excluded.tokens,usd=excluded.usd',
        )
        .run(day, requests, totalTokens, totalUsd);
      if (usd === undefined) this.setMeta(`unpriced:${day}`, String(unpriced + 1));
      return true;
    });
  }
  budgets(): {
    day: string;
    requests: number;
    tokens: number;
    usd: number | null;
    known_usd?: number;
    unpriced_requests?: number;
  }[] {
    return this.#db
      .prepare('SELECT * FROM budgets ORDER BY day')
      .all()
      .map((r) => {
        const unpriced = Number(this.getMeta(`unpriced:${String(r.day)}`) ?? 0);
        return {
          day: String(r.day),
          requests: Number(r.requests),
          tokens: Number(r.tokens),
          usd: unpriced ? null : Number(r.usd),
          ...(unpriced ? { known_usd: Number(r.usd), unpriced_requests: unpriced } : {}),
        };
      });
  }
  async backup(path: string): Promise<void> {
    const destination = resolve(path);
    if (existsSync(destination)) throw new Error('Backup destination already exists');
    mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
    const temporary = mkdtempSync(join(dirname(destination), '.security-watch-backup-'));
    const snapshot = join(temporary, 'snapshot.db');
    try {
      privateFile(snapshot);
      await sqliteBackup(this.#db, snapshot);
      // Publish a complete snapshot atomically, and never overwrite a file that appeared during backup.
      linkSync(snapshot, destination);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  }
}
