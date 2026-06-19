import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './lib/api';
import type { FilterState } from './lib/types';
import { SeverityChart } from './components/SeverityChart';
import { FilterBar } from './components/FilterBar';
import { FindingsTable } from './components/FindingsTable';
import { ExportButtons } from './components/ExportButtons';

const emptyFilters: FilterState = {
  sources: [],
  cves: [],
  asset: '',
  severities: [],
  states: [],
  enrichedOnly: null,
};

export default function App() {
  const [filters, setFilters] = useState<FilterState>(emptyFilters);

  const stats = useQuery({
    queryKey: ['stats', filters],
    queryFn: () => api.stats(filters),
  });
  const sources = useQuery({ queryKey: ['sources'], queryFn: api.listSources });
  const findings = useQuery({
    queryKey: ['findings', filters],
    queryFn: () => api.listFindings(filters),
  });

  const handleRefresh = async () => {
    await api.refresh();
  };

  return (
    <div className="flex min-h-screen flex-col">
      {/* Header */}
      <header className="border-b border-white/10 bg-tenable-black px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="font-semibold tracking-tight">
              <span className="text-tenable-yellow">t1</span>-cve-enricher
            </div>
            <div className="text-xs uppercase tracking-widest text-white/50">
              Control over chaos
            </div>
          </div>
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={handleRefresh}>
              Refresh data
            </button>
            <ExportButtons filters={filters} />
          </div>
        </div>
        <div className="mt-6">
          <SeverityChart counts={stats.data} loading={stats.isLoading} />
        </div>
      </header>

      {/* Filter bar */}
      <div className="border-b border-white/10 bg-tenable-black/50 px-6 py-3">
        <FilterBar
          sources={sources.data ?? []}
          filters={filters}
          onChange={setFilters}
        />
      </div>

      {/* Findings table */}
      <main className="flex-1 overflow-auto px-6 py-6">
        <FindingsTable
          findings={findings.data ?? []}
          loading={findings.isLoading}
        />
      </main>

      <footer className="border-t border-white/10 px-6 py-3 text-xs text-white/40">
        Showing {findings.data?.length ?? 0} findings · enrichment cached locally · scrapes
        <code className="ml-1 rounded bg-white/10 px-1 py-0.5">tenable.com/cve/&#123;ID&#125;</code>
      </footer>
    </div>
  );
}
