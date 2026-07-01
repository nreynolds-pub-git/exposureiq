export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingState = 'ACTIVE' | 'RESURFACED' | 'FIXED';

export interface Source {
  name: string;                  // API filter code (RED-HAT:VM)
  display_name?: string | null;  // human label (Red Hat Insights)
  first_seen: string;
  last_seen: string;
  asset_count: number;
  finding_count: number;
}

export interface EnrichedFinding {
  finding_id: string;
  cve_id: string;
  severity: Severity | null;
  state: FindingState | null;
  source: string;
  asset_id: string;
  asset_name: string | null;
  asset_ipv4: string | null;
  asset_fqdn: string | null;
  asset_operating_system: string | null;
  first_observed: string | null;
  last_observed: string | null;
  cve_description: string | null;
  cvss3_base_score: number | null;
  cvss3_severity: string | null;
  vpr_score: number | null;
  remediation: string | null;
  enriched: boolean;
  plugin_id: string | null;
  plugin_family: string | null;
  plugin_platform_match: boolean | null;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  unknown: number;
}

export interface FilterState {
  sources: string[];
  cves: string[];
  asset: string;
  severities: Severity[];
  states: FindingState[];
  enrichedOnly: boolean | null;
  hideNoPlugins: boolean;
  sort: string;  // "" = default; otherwise "field:asc" or "field:desc"
}

export interface PullJob {
  id: number;
  started_at: string;
  completed_at: string | null;
  status: 'RUNNING' | 'SUCCESS' | 'FAILED' | 'PARTIAL';
  sources_processed: number;
  findings_pulled: number;
  cves_enriched: number;
  error_message: string | null;
}

export interface PipelineProgress {
  is_running: boolean;
  stage: string;
  source?: string | null;
  current_n: number;
  total_n: number;
  message?: string | null;
  started_at?: string | null;
  updated_at?: string | null;
}
