export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingState = 'ACTIVE' | 'RESURFACED' | 'FIXED';

export interface Source {
  name: string;
  first_seen: string;
  last_seen: string;
  asset_count: number;
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
  first_observed: string | null;
  last_observed: string | null;
  cve_description: string | null;
  cvss3_base_score: number | null;
  cvss3_severity: string | null;
  vpr_score: number | null;
  vpr_severity: string | null;
  remediation: string | null;
  enriched: boolean;
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
