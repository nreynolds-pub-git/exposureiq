import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './lib/api';
import type { FilterState } from './lib/types';
import { SeverityChart } from './components/SeverityChart';
import { FilterBar } from './components/FilterBar';
import { FindingsTable } from './components/FindingsTable';
import { ExportButtons } from './components/ExportButtons';
import { ThemeToggle } from './components/ThemeToggle';
import { SettingsPanel } from './components/SettingsPanel';
import { PipelineStatusBar } from './components/PipelineStatusBar';
import { ExplainModal } from './components/ExplainModal';
import type { ExplainContext } from './lib/llm';

const emptyFilters: FilterState = {
  sources: [],
  cves: [],
  asset: '',
  severities: [],
  states: [],
  enrichedOnly: null,
  hideNoPlugins: true,
  sort: '',
};

const PAGE_SIZE = 500;

export default function App() {
  const [filters, setFilters] = useState<FilterState>(emptyFilters);
  const [page, setPage] = useState(0);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [explainCtx, setExplainCtx] = useState<ExplainContext | null>(null);

  // Reset to page 0 whenever filters change so users don't end up on
  // an out-of-range page after narrowing the result set.
  // (Wrapped in useEffect-style pattern via setFilters call site below.)
  const setFiltersResetPage = (next: FilterState) => {
    setFilters(next);
    setPage(0);
  };

  const stats = useQuery({
    queryKey: ['stats', filters],
    queryFn: () => api.stats(filters),
  });
  const sources = useQuery({ queryKey: ['sources'], queryFn: api.listSources });
  const findings = useQuery({
    queryKey: ['findings', filters, page],
    queryFn: () => api.listFindings(filters, PAGE_SIZE, page * PAGE_SIZE),
  });

  const handleRefresh = async () => {
    await api.refresh();
  };

  return (
    <div className="flex min-h-screen flex-col">
      <PipelineStatusBar />
      {/* Header */}
      <header className="border-b border-tenable-black/10 dark:border-white/10 bg-white dark:bg-tenable-black px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="font-semibold tracking-tight rounded-md bg-tenable-black px-2.5 py-1 text-white">
              <span className="text-tenable-yellow">t1</span>-cve-enricher
            </div>
            <div className="text-xs uppercase tracking-widest text-tenable-black/60 dark:text-white/50">
              Control over chaos
            </div>
          </div>
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={handleRefresh}>
              Refresh data
            </button>
            <ExportButtons filters={filters} />
            <button
              onClick={() => setSettingsOpen(true)}
              className="rounded-md border border-tenable-black/20 dark:border-white/20 bg-tenable-black/5 dark:bg-white/5 px-2 py-1.5 text-tenable-black/70 dark:text-white/70 hover:text-tenable-black dark:hover:text-white transition"
              title="LLM provider settings"
              aria-label="LLM provider settings"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="h-4 w-4"
              >
                <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
            </button>
            <ThemeToggle />
          </div>
        </div>
        <div className="mt-6">
          <SeverityChart counts={stats.data} />
        </div>
      </header>

      {/* Filter bar */}
      <div className="border-b border-tenable-black/10 dark:border-white/10 bg-white/50 dark:bg-tenable-black/50 px-6 py-3">
        <FilterBar
          sources={sources.data ?? []}
          stats={stats.data}
          filters={filters}
          onChange={setFilters}
        />
      </div>

      {/* Findings table */}
      <main className="flex-1 overflow-auto px-6 py-6">
        <FindingsTable
          findings={findings.data ?? []}
          loading={findings.isLoading}
          filters={filters}
          onFiltersChange={setFiltersResetPage}
          onExplain={setExplainCtx}
        />
        {(() => {
          const totalFindings = stats.data
            ? stats.data.critical + stats.data.high + stats.data.medium + stats.data.low
            : 0;
          const totalPages = Math.max(1, Math.ceil(totalFindings / PAGE_SIZE));
          const start = page * PAGE_SIZE + 1;
          const end = Math.min((page + 1) * PAGE_SIZE, totalFindings);
          return (
            <div className="mt-4 flex items-center justify-between text-xs text-tenable-black/60 dark:text-white/60">
              <div>
                Showing {start.toLocaleString()}–{end.toLocaleString()} of{' '}
                {totalFindings.toLocaleString()} findings
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="rounded-md border border-tenable-black/20 dark:border-white/20 px-2 py-1 disabled:opacity-30"
                >
                  Prev
                </button>
                <span>
                  Page {page + 1} of {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  className="rounded-md border border-tenable-black/20 dark:border-white/20 px-2 py-1 disabled:opacity-30"
                >
                  Next
                </button>
              </div>
            </div>
          );
        })()}
      </main>

      <SettingsPanel open={settingsOpen} onClose={() => setSettingsOpen(false)} />
      <ExplainModal
        context={explainCtx}
        onClose={() => setExplainCtx(null)}
        onOpenSettings={() => {
          setExplainCtx(null);
          setSettingsOpen(true);
        }}
      />

      <footer className="border-t border-tenable-black/10 dark:border-white/10 px-6 py-3 text-xs text-tenable-black/50 dark:text-white/40">
        Showing {findings.data?.length ?? 0} findings · enrichment cached locally · CVE intel from
        <code className="ml-1 rounded bg-tenable-black/10 dark:bg-white/10 px-1 py-0.5">tenable.com/cve/&#123;ID&#125;</code>
        and plugin data from
        <code className="ml-1 rounded bg-tenable-black/10 dark:bg-white/10 px-1 py-0.5">tenable.com/plugins/api/v1/</code>
      </footer>
    </div>
  );
}
