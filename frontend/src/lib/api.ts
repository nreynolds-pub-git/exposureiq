import type {
  EnrichedFinding,
  FilterState,
  PullJob,
  SeverityCounts,
  Source,
} from './types';

const BASE = '/api';

function buildQuery(filters: FilterState): URLSearchParams {
  const q = new URLSearchParams();
  filters.sources.forEach((s) => q.append('source', s));
  filters.cves.forEach((c) => q.append('cve', c));
  filters.severities.forEach((s) => q.append('severity', s));
  filters.states.forEach((s) => q.append('state', s));
  if (filters.asset) q.set('asset', filters.asset);
  if (filters.enrichedOnly !== null) q.set('enriched', String(filters.enrichedOnly));
  q.set('hide_no_plugins', String(filters.hideNoPlugins));
  return q;
}

async function jsonOrThrow<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API error ${res.status}: ${body || res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  async listSources(): Promise<Source[]> {
    return jsonOrThrow(await fetch(`${BASE}/sources`));
  },

  async listFindings(filters: FilterState, limit = 200, offset = 0): Promise<EnrichedFinding[]> {
    const q = buildQuery(filters);
    q.set('limit', String(limit));
    q.set('offset', String(offset));
    return jsonOrThrow(await fetch(`${BASE}/findings?${q}`));
  },

  async stats(filters: FilterState): Promise<SeverityCounts> {
    const q = buildQuery(filters);
    return jsonOrThrow(await fetch(`${BASE}/stats?${q}`));
  },

  async refresh(): Promise<{ status: string }> {
    return jsonOrThrow(await fetch(`${BASE}/refresh`, { method: 'POST' }));
  },

  async jobs(): Promise<PullJob[]> {
    return jsonOrThrow(await fetch(`${BASE}/jobs`));
  },

  exportUrl(filters: FilterState, format: 'csv' | 'json'): string {
    const q = buildQuery(filters);
    q.set('format', format);
    return `${BASE}/findings/export?${q}`;
  },
};
