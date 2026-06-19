import type { FilterState, Severity, Source } from '../lib/types';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

interface Props {
  sources: Source[];
  filters: FilterState;
  onChange: (next: FilterState) => void;
}

export function FilterBar({ sources, filters, onChange }: Props) {
  const toggleSource = (name: string) => {
    const next = filters.sources.includes(name)
      ? filters.sources.filter((s) => s !== name)
      : [...filters.sources, name];
    onChange({ ...filters, sources: next });
  };

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
    });

  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      {/* Asset search */}
      <input
        className="rounded-md border border-white/20 bg-white/5 px-3 py-1.5 text-white placeholder-white/40 outline-none focus:border-tenable-yellow"
        placeholder="Search asset (name / FQDN / IP)…"
        value={filters.asset}
        onChange={(e) => onChange({ ...filters, asset: e.target.value })}
      />

      {/* CVE input */}
      <input
        className="rounded-md border border-white/20 bg-white/5 px-3 py-1.5 text-white placeholder-white/40 outline-none focus:border-tenable-yellow"
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

      {/* Source pills */}
      <div className="flex flex-wrap gap-1.5">
        {sources.map((s) => {
          const active = filters.sources.includes(s.name);
          return (
            <button
              key={s.name}
              onClick={() => toggleSource(s.name)}
              className={
                'rounded-full px-3 py-1 text-xs transition ' +
                (active
                  ? 'bg-tenable-yellow text-tenable-black'
                  : 'border border-white/20 text-white/80 hover:bg-white/5')
              }
            >
              {s.name}
              <span className="ml-1.5 text-white/40">{s.asset_count}</span>
            </button>
          );
        })}
      </div>

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
                  : 'border border-white/20 text-white/60 hover:bg-white/5')
              }
            >
              {sev}
            </button>
          );
        })}
      </div>

      {/* Enriched toggle */}
      <select
        className="rounded-md border border-white/20 bg-white/5 px-2 py-1.5 text-xs text-white outline-none"
        value={filters.enrichedOnly === null ? '' : String(filters.enrichedOnly)}
        onChange={(e) =>
          onChange({
            ...filters,
            enrichedOnly: e.target.value === '' ? null : e.target.value === 'true',
          })
        }
      >
        <option value="">All findings</option>
        <option value="true">Enriched only</option>
        <option value="false">Un-enriched only</option>
      </select>

      <button onClick={clearAll} className="ml-auto text-xs text-white/60 hover:text-white">
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
    case 'INFO':
      return 'bg-sev-info text-white';
  }
}
