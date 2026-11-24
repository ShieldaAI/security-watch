import type { ModelProvider, OutputFormat } from './providers.js';
import type { Ecosystem } from './ecosystems.js';
import type { MitigationSource, MitigationStatus } from './mitigations.js';
export type Severity = 'unknown' | 'low' | 'medium' | 'high' | 'critical';
export type Category = 'library' | 'product' | 'news' | 'malware' | 'health';
export type Applicability = 'affected' | 'not_affected' | 'unknown' | 'conflicting' | 'relevant';
export type Channel = 'slack' | 'email';
export interface Provenance {
  source: string;
  reference?: string;
  recorded_at?: string;
}
export interface DeploymentObservation {
  observed_at: string;
  method: string;
  reference?: string;
}
export type ArtifactKind =
  | 'application'
  | 'library'
  | 'mcp_server'
  | 'mcp_client'
  | 'plugin'
  | 'skill'
  | 'model'
  | 'container'
  | 'other';
/** An operator's recorded result. Security Watch does not perform cryptographic verification. */
export interface DeclaredVerification {
  status: 'verified' | 'failed' | 'unknown';
  reference: string;
  recorded_at: string;
  recorded_by?: string;
}
export interface DependencyLink {
  ref: string;
  component_id?: string;
}
export interface DependencyRelationship {
  ref: string;
  depends_on: string[];
}
/** Lifecycle evidence is never an instruction to close or downgrade a finding. */
export interface DeclaredRemediation {
  event_id: string;
  stage: 'proposed' | 'changed' | 'deployed';
  verification: 'supported' | 'failed' | 'unknown';
  reference: string;
  recorded_at: string;
  recorded_by?: string;
}
export interface InventoryEvidence {
  origin?: string;
  digest?: string;
  provenance?: Provenance;
  observation?: DeploymentObservation;
  artifact_kind?: ArtifactKind;
  purl?: string;
  source_url?: string;
  source_revision?: string;
  sbom_ref?: string;
  dependencies?: DependencyLink[];
  signature_verification?: DeclaredVerification;
  attestation_verification?: DeclaredVerification;
  remediation_evidence?: DeclaredRemediation[];
}
export interface Component extends InventoryEvidence {
  id: string;
  ecosystem: Ecosystem;
  name: string;
  version?: string;
  /** Operator's pointer to where this library is used. Shown in notifications; never sent to models or sources. */
  note?: string;
}
export interface Product {
  name: string;
  version?: string;
  keywords: string[];
  /** Operator's pointer to where this product runs. Shown in notifications; never sent to models or sources. */
  note?: string;
}
/**
 * FIRST's EPSS for a finding's CVE: the estimated probability of exploitation in the next 30 days,
 * and its rank among all scored CVEs. Shown only; not part of a finding's revision or review.
 */
export interface EpssScore {
  /** The CVE it is for: the finding's event, or a CVE alias of its advisory when the event is a GHSA. */
  cve: string;
  /** 0 to 1. */
  probability: number;
  /** 0 to 1: the share of scored CVEs with a lower probability. */
  percentile: number;
  /** The day FIRST computed it, YYYY-MM-DD. */
  date: string;
}
/** Where a reader should look to confirm a finding. Copied from the inventory; not security evidence. */
export interface FindingLocation {
  system: string;
  owner?: string;
  system_note?: string;
  component?: string;
  component_note?: string;
}
export interface System extends InventoryEvidence {
  id: string;
  name: string;
  environment: string;
  owner?: string;
  /** Operator's pointer to where this system lives. Shown in notifications; never sent to models or sources. */
  note?: string;
  configuration?: Record<string, string | boolean | number>;
  sbom_dependencies?: DependencyRelationship[];
  exposure: 'internet' | 'internal' | 'unknown';
  criticality: Severity;
  updated_at: string;
  components: Component[];
  products: Product[];
  keywords: string[];
}
export interface Inventory {
  systems: System[];
  import_warnings?: string[];
  /**
   * Things to read once that do not degrade a scan: entries accepted as written that may not be what
   * was meant, and operating-system packages in an SBOM folder that are not matched.
   */
  name_notices?: string[];
}
export interface PackageClaim {
  ecosystem: string;
  name: string;
  range?: string;
  versions?: string[];
  matched_versions?: string[];
  fixed?: string;
}
export interface CvssV4BaseScore {
  /** Validated source vector; optional contextual metrics may be present. */
  vector: string;
  /** Exact CVSS-B vector used to derive score. CVSS is owned by FIRST and used by permission. */
  base_vector: string;
  score: number;
  context_removed: boolean;
}
export interface Evidence {
  id: string;
  source: string;
  kind: 'advisory' | 'news' | 'kev' | 'health';
  title: string;
  url: string;
  description: string;
  /** Whether the adapter retrieved full text, an excerpt or no usable content. */
  content_status?: 'full' | 'excerpt' | 'unavailable';
  aliases: string[];
  severity: Severity;
  /** Bounded source diagnostics. Does not establish applicability, exploitation or deployment context. */
  cvss_v4?: { base_scores: CvssV4BaseScore[]; unsupported_vectors: number };
  modified_at: string;
  fetched_at: string;
  published_at?: string;
  packages: PackageClaim[];
  withdrawn?: boolean;
  exploited?: boolean;
  malware?: boolean;
  /**
   * Links the advisory publishes, most specific first. Inputs for whoever writes a fix or a runtime
   * shield. Never sent to models; not part of the evidence content hash.
   */
  references?: AdvisoryReference[];
  /** Commits the advisory records as fixing the problem (OSV `GIT` ranges). Same rules as references. */
  fix_commits?: FixCommit[];
  /** Weakness identifiers such as CWE-502. Same rules as references. */
  weaknesses?: string[];
  /**
   * Public exploit code the source reports, such as `exploit-db` or `github-poc` (cve.now). Published
   * code, not exploitation in the wild. Same rules as references.
   */
  exploit_sources?: string[];
}
export type ReferenceType =
  'fix' | 'evidence' | 'advisory' | 'report' | 'detection' | 'introduced' | 'package' | 'source' | 'web';
export interface AdvisoryReference {
  type: ReferenceType;
  url: string;
}
export interface FixCommit {
  repo: string;
  commit: string;
}
export interface ModelSpec {
  provider: ModelProvider;
  /** Minimal identifiers by default. Extra deployment context requires explicit opt-in per model. */
  disclosure_profile?: 'minimal' | 'deployment-context';
  output_format?: OutputFormat;
  model: string;
  api_key_env: string;
  endpoint?: string;
  allow_private_endpoint: boolean;
  input_usd_per_million?: number;
  output_usd_per_million?: number;
}
export interface Config {
  version: 1;
  inventory: string;
  database: string;
  poll_interval_minutes: number;
  news_lookback_minutes: number;
  inventory_stale_days: number;
  digest_interval_hours: number;
  sources: {
    cve_now: boolean;
    hacker_news: boolean;
    osv: boolean;
    github: boolean;
    github_token_env: string;
    kev: boolean;
    feeds: string[];
    vendor_feeds?: ('nodejs' | 'python' | 'php')[];
    /** Look up FIRST's EPSS for the CVEs of current findings (CVE identifiers only). Default false. */
    epss?: boolean;
  };
  models: {
    enabled: boolean;
    analysis?: ModelSpec;
    verification?: ModelSpec;
    daily_request_limit: number;
    daily_token_limit: number;
    daily_budget_usd?: number;
    max_input_chars: number;
    max_output_tokens: number;
    timeout_seconds: number;
  };
  policy: {
    library: Rule;
    product: Rule;
    news: Rule;
    urgent_unknown: boolean;
    exploited_override: boolean;
    malware_override: boolean;
    /** Review both AI-only dismissal routes by default. */
    ai_dismissals?: 'review' | 'record';
    /** Deprecated configuration alias; true maps to review, false to record. */
    review_before_news_suppression?: boolean;
    /**
     * Read stated CVSS scores, vendor ratings and exploitation reports from news to raise the
     * priority of findings without an advisory severity. Default true.
     */
    news_signals?: boolean;
    health_channels: Channel[];
  };
  notifications: {
    slack?: { webhook_url_env: string };
    email?: { smtp_url_env: string; from: string; to: string[] };
    max_attempts: number;
  };
  monitoring?: {
    heartbeat_url_env: string;
    interval_seconds: number;
    allow_private_endpoint: boolean;
  };
  /** An HTTPS endpoint that accepts SBOM uploads from CI pipelines into the inventory's SBOM folder. */
  intake?: {
    /** `HOST:PORT`. Default `127.0.0.1:8787`. */
    listen: string;
    /** Bearer tokens, each read from an environment variable and limited to some system IDs. */
    tokens: Array<{ token_env: string; systems: string[] }>;
    tls_cert_file?: string;
    tls_key_file?: string;
    /** Required to listen beyond loopback without TLS, for example behind a TLS proxy. */
    allow_plain_http: boolean;
  };
  /**
   * Runtime mitigation status read from JSON Lines exports (Shirudo's `node_vulns`, or the generic
   * format). Shown in alerts and `shield-candidates`; never changes applicability, priority or routing.
   */
  mitigations?: MitigationSource[];
  maintenance?: {
    interval_hours: number;
    retention?: {
      analysis_cache_days?: number;
      evidence_history_days?: number;
      finding_history_days?: number;
      accepted_delivery_days?: number;
      inactive_findings_days?: number;
      unreferenced_evidence_days?: number;
      batch_size?: number;
    };
    backup?: {
      directory: string;
      keep: number;
      max_bytes: number;
    };
  };
}
export interface Rule {
  levels: Severity[];
  basis: 'source_severity' | 'priority';
  channels: Channel[];
}
export interface Assessment {
  /** Only news evidence supports this candidate; AI impact remains a separate claim. */
  news_only?: boolean;
  remediation?: RemediationEvidence;
  /** Inventory names and notes for the reader of a notification. Not part of alert deduplication. */
  location?: FindingLocation;
  /** EPSS for the finding's CVE when `sources.epss` is on. Shown only; changes nothing. */
  epss?: EpssScore;
  /** Runtime mitigation status, one per configured source that covers the system. Shown only; changes nothing. */
  mitigations?: MitigationStatus[];
  /** News-only or generic product context without deterministic package applicability. */
  news_candidate?: boolean;
  /**
   * The supported version ranges exclude the installed version, but the advisory evidence has not
   * been refreshed for two poll intervals, so applicability is `unknown`. The source's own health
   * finding reports the outage; this result goes to the review digest instead of an urgent alert.
   */
  stale_exclusion?: boolean;
  active?: boolean;
  id: string;
  event_id: string;
  system_id: string;
  component_id?: string;
  category: Category;
  applicability: Applicability;
  source_severity: Severity;
  priority: Severity;
  title: string;
  summary: string;
  reasons: string[];
  evidence_ids: string[];
  urls: string[];
  exploited: boolean;
  fix?: string;
  updated_at: string;
  withdrawn?: boolean;
  relevance?: 'relevant' | 'irrelevant' | 'unknown';
  /** Model assessment of the article, separate from version-range applicability. */
  news_analysis?: NewsAnalysis;
  /** What articles state about a finding that has no advisory severity, read without a model. */
  news_signals?: NewsSignals;
  ai?: {
    model: string;
    provider: string;
    prompt_version: string;
    status: 'complete' | 'unavailable' | 'conflicting';
  };
}
/** One statement an article makes about a finding's subject, with the sentence it was read from. */
export interface NewsStatement {
  /** The identifier or inventory name the statement is tied to. */
  subject: string;
  /** The sentence, shortened. Untrusted article text. */
  excerpt: string;
}
/**
 * What news articles state about a finding without an advisory severity, read without a model.
 * Signals only raise priority; see the configuration guide for what is read.
 */
export interface NewsSignals {
  /** The highest CVSS base score stated for the subject. */
  cvss?: NewsStatement & { score: number; version?: string; level: Severity };
  /** A vendor's word rating ("Severity: moderate", "rated Important"). */
  rating?: NewsStatement & { level: Severity; word: string };
  /** The article reports exploitation. Not a known-exploited catalog entry. */
  exploitation?: NewsStatement;
  /** The article says no exploitation is known. Shown only. */
  no_known_exploitation?: NewsStatement;
  /** The article reports public exploit code. Shown only. */
  public_exploit?: NewsStatement;
}
export type AiReviewReason = 'ai_general_news' | 'ai_not_affected' | 'ai_irrelevant';
export interface AiReview {
  finding_id: string;
  revision: number;
  reason: AiReviewReason;
  status: 'pending' | 'investigate' | 'dismissed' | 'superseded';
  created_at: number;
  reviewed_at: number | null;
  reviewer: string | null;
  note: string | null;
  evidence: { source: string; id: string; content_hash: string }[];
  assessment: Assessment;
}
export interface Decision {
  /** A durable local review is required even when channels is empty. */
  review?: AiReviewReason;
  action: 'notify' | 'digest' | 'record';
  channels: Channel[];
  reason: string;
}
export interface Notification {
  id: string;
  finding_id: string;
  /** The persisted finding revision selected when this delivery was enqueued. */
  revision?: number;
  channel: Channel;
  payload: string;
  status: 'pending' | 'sending' | 'accepted' | 'unknown' | 'failed';
  attempts: number;
  available_at: number;
  /** Local UTC time in milliseconds when the destination acknowledged this notification. */
  accepted_at?: number;
  last_error?: string;
}
export interface HttpOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  maxBytes?: number;
  timeoutMs?: number;
  /** Minimum delay between request starts to an origin; shared by concurrent calls. */
  minIntervalMs?: number;
  allowPrivate?: boolean;
  redirects?: number;
  /** When present, every redirect must remain within one of these exact origins. */
  allowedRedirectOrigins?: string[];
  signal?: AbortSignal;
}
export interface HttpResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}
export type HttpClient = (url: string, options?: HttpOptions) => Promise<HttpResult>;
export interface CoverageReceipt {
  source: string;
  attempted_at: string;
  last_success_at?: string;
  fresh_until?: string;
  status: 'complete' | 'partial' | 'failed';
  freshness: 'fresh' | 'stale' | 'never';
  evidence_count: number;
  errors: string[];
  scope: string;
  /**
   * Present on an incomplete receipt when the source still read every record for the inventory's own
   * packages; what it missed are other records. Version exclusions from the source remain supported.
   */
  package_results?: 'complete';
}
export interface InventoryDrift {
  system_id: string;
  component_id?: string;
  change: 'added' | 'removed' | 'changed';
  fields: string[];
  before_digest?: string;
  after_digest?: string;
}
export interface RemediationEvidence {
  status: 'review_required' | 'version_excluded' | 'observed_version_excluded';
  observed_at?: string;
  artifact_digest?: string;
  source_urls: string[];
  requirements: string[];
  configuration: Record<string, string | boolean | number>;
  note: string;
  operator_records?: DeclaredRemediation[];
  signature_verification?: DeclaredVerification;
  attestation_verification?: DeclaredVerification;
}
export interface SourceResult {
  evidence: Evidence[];
  errors: { source: string; message: string }[];
  checkpoints: Record<string, string>;
  coverage: CoverageReceipt[];
}
export interface AiAnalysis {
  relevance: 'relevant' | 'irrelevant' | 'unknown';
  priority: Severity;
  summary: string;
  evidence_ids: string[];
  quotes: { evidence_id: string; quote: string }[];
  news_analysis?: NewsAnalysis | null;
}
export interface NewsAnalysis {
  classification: 'new_vulnerability' | 'known_vulnerability_update' | 'general_news' | 'unknown';
  impact: 'affected' | 'not_affected' | 'unknown' | 'not_applicable';
  affected_products: string[];
  /** Affected or fixed versions quoted from the source. */
  affected_versions: string[];
  /** Source wording describing the conditions necessary for exploitation. */
  prerequisites: string[];
  rationale: string;
  quotes: { evidence_id: string; quote: string }[];
}
