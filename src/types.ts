export type Severity = 'unknown' | 'low' | 'medium' | 'high' | 'critical';
export type Category = 'library' | 'product' | 'news' | 'malware' | 'health';
export type Applicability = 'affected' | 'not_affected' | 'unknown' | 'conflicting' | 'relevant';
export type Channel = 'slack' | 'email';
export interface Component {
  id: string;
  ecosystem: 'npm';
  name: string;
  version?: string;
}
export interface Product {
  name: string;
  version?: string;
  keywords: string[];
}
export interface System {
  id: string;
  name: string;
  environment: string;
  owner?: string;
  exposure: 'internet' | 'internal' | 'unknown';
  criticality: Severity;
  updated_at: string;
  components: Component[];
  products: Product[];
  keywords: string[];
}
export interface Inventory {
  systems: System[];
}
export interface PackageClaim {
  ecosystem: string;
  name: string;
  range?: string;
  versions?: string[];
  matched_versions?: string[];
  fixed?: string;
}
export interface Evidence {
  id: string;
  source: string;
  kind: 'advisory' | 'news' | 'kev' | 'health';
  title: string;
  url: string;
  description: string;
  /** News adapters disclose whether the article text, only an excerpt, or no article was retrieved. */
  content_status?: 'full' | 'excerpt' | 'unavailable';
  aliases: string[];
  severity: Severity;
  modified_at: string;
  fetched_at: string;
  published_at?: string;
  packages: PackageClaim[];
  withdrawn?: boolean;
  exploited?: boolean;
  malware?: boolean;
}
export interface ModelSpec {
  provider: 'openai' | 'anthropic' | 'openai-compatible';
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
    health_channels: Channel[];
  };
  notifications: {
    slack?: { webhook_url_env: string };
    email?: { smtp_url_env: string; from: string; to: string[] };
    max_attempts: number;
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
  /** News-only or generic product context without deterministic package applicability. */
  news_candidate?: boolean;
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
  /** Evidence-grounded model opinion, distinct from authoritative applicability. */
  news_analysis?: NewsAnalysis;
  ai?: {
    model: string;
    provider: string;
    prompt_version: string;
    status: 'complete' | 'unavailable' | 'conflicting';
  };
}
export interface Decision {
  action: 'notify' | 'digest' | 'record';
  channels: Channel[];
  reason: string;
}
export interface Notification {
  id: string;
  finding_id: string;
  channel: Channel;
  payload: string;
  status: 'pending' | 'sending' | 'accepted' | 'unknown' | 'failed';
  attempts: number;
  available_at: number;
  last_error?: string;
}
export interface HttpOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  maxBytes?: number;
  timeoutMs?: number;
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
export interface SourceResult {
  evidence: Evidence[];
  errors: { source: string; message: string }[];
  checkpoints: Record<string, string>;
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
  /** Source wording describing affected or fixed versions, not invented normalized ranges. */
  affected_versions: string[];
  /** Source wording describing the conditions necessary for exploitation. */
  prerequisites: string[];
  rationale: string;
  quotes: { evidence_id: string; quote: string }[];
}
