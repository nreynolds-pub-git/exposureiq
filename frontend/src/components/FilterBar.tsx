import type { FilterState, Severity, Source, SeverityCounts } from '../lib/types';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

interface Props {
  sources: Source[];
  stats: SeverityCounts | undefined;
  filters: FilterState;
  onChange: (next: FilterState) => void;
}

export function FilterBar({ sources, stats, filters, onChange }: Props) {
  // Single-select source semantics: filters.sources is [] (all) or [oneCode]
  const selectedCode = filters.sources[0] ?? '';
  const selectedSource = sources.find((s) => s.name === selectedCode);

  // Asset count: source-specific if one chosen, otherwise sum across all sources.
  // (Sum may double-count assets visible in multiple sources — acceptable v1.)
  const totalAssets = selectedSource
    ? selectedSource.asset_count
    : sources.reduce((sum, s) => sum + s.asset_count, 0);

  // Findings count: from stats endpoint (already filter-aware)
  const totalFindings = stats
    ? stats.critical + stats.high + stats.medium + stats.low + stats.info + stats.unknown
    : 0;

  const toggleSeverity = (sev: Severity) => {
    const next = filters.severities.includes(sev)
      ? filters.severities.filter((s) => s !== sev)
      : [...filters.severities, sev];
    onChange({ ...filters, severities: next });
  };

  const clearAll = () =>
    onChange({
      sources: [],
      cves: [],
      asset: '',
      severities: [],
      states: [],
      enrichedOnly: null,
      hideNoPlugins: true,
    });

  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      {/* Source dropdown */}
      <select
        className="appearance-none rounded-md border border-tenable-black/20 dark:border-white/20 bg-tenable-black/5 dark:bg-white/5 pl-3 pr-8 py-1.5 text-tenable-black dark:text-white outline-none focus:border-tenable-yellow bg-no-repeat bg-[right_0.5rem_center] bg-[length:1rem] bg-[url('data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 20 20%22 fill=%22%231E2426%22><path fill-rule=%22evenodd%22 d=%22M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z%22 clip-rule=%22evenodd%22/></svg>')] dark:bg-[url('data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 20 20%22 fill=%22%23ffffff%22><path fill-rule=%22evenodd%22 d=%22M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z%22 clip-rule=%22evenodd%22/></svg>')]"
        value={selectedCode}
        onChange={(e) =>
          onChange({
            ...filters,
            sources: e.target.value === '' ? [] : [e.target.value],
          })
        }
      >
        <option value="">All sources</option>
        {sources.map((s) => (
          <option key={s.name} value={s.name}>
            {s.display_name ?? s.name}
          </option>
        ))}
      </select>

      {/* Stats panel — reads from the source filter + stats endpoint */}
      <div className="flex items-baseline gap-4 rounded-md border border-tenable-black/10 dark:border-white/10 px-3 py-1.5 text-xs">
        <div>
          <span className="text-tenable-black/60 dark:text-white/60">Assets:</span>{' '}
          <span className="font-medium text-tenable-black dark:text-white">
            {totalAssets.toLocaleString()}
          </span>
        </div>
        <div>
          <span className="text-tenable-black/60 dark:text-white/60">Findings:</span>{' '}
          <span className="font-medium text-tenable-black dark:text-white">
            {totalFindings.toLocaleString()}
          </span>
        </div>
      </div>

      {/* Asset search */}
      <input
        className="rounded-md border border-tenable-black/20 dark:border-white/20 bg-tenable-black/5 dark:bg-white/5 px-3 py-1.5 text-tenable-black dark:text-white placeholder-tenable-black/40 dark:placeholder-white/40 outline-none focus:border-tenable-yellow"
        placeholder="Search asset (name / FQDN / IP)…"
        value={filters.asset}
        onChange={(e) => onChange({ ...filters, asset: e.target.value })}
      />

      {/* CVE input */}
      <input
        className="rounded-md border border-tenable-black/20 dark:border-white/20 bg-tenable-black/5 dark:bg-white/5 px-3 py-1.5 text-tenable-black dark:text-white placeholder-tenable-black/40 dark:placeholder-white/40 outline-none focus:border-tenable-yellow"
        placeholder="CVE-2024-1234"
        value={filters.cves.join(',')}
        onChange={(e) =>
          onChange({
            ...filters,
            cves: e.target.value
              .split(',')
              .map((c) => c.trim().toUpperCase())
              .filter(Boolean),
          })
        }
      />

      {/* Severity pills */}
      <div className="flex gap-1.5">
        {SEVERITIES.map((sev) => {
          const active = filters.severities.includes(sev);
          return (
            <button
              key={sev}
              onClick={() => toggleSeverity(sev)}
              className={
                'rounded-md px-2 py-0.5 text-xs uppercase transition ' +
                (active
                  ? severityActiveClass(sev)
                  : 'border border-tenable-black/20 dark:border-white/20 text-tenable-black/60 dark:text-white/60 hover:bg-tenable-black/5 dark:hover:bg-white/5')
              }
            >
              {sev}
            </button>
          );
        })}
      </div>

      <button
        onClick={clearAll}
        className="ml-auto text-xs text-tenable-black/60 dark:text-white/60 hover:text-tenable-black dark:hover:text-white"
      >
        Clear filters
      </button>
    </div>
  );
}

function severityActiveClass(sev: Severity): string {
  switch (sev) {
    case 'CRITICAL':
      return 'bg-sev-critical text-tenable-black';
    case 'HIGH':
      return 'bg-sev-high text-tenable-black';
    case 'MEDIUM':
      return 'bg-sev-medium text-tenable-black';
    case 'LOW':
      return 'bg-sev-low text-tenable-black';
  }
}
