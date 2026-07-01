import type { EnrichedFinding, FilterState, Severity } from '../lib/types';
import type { ExplainContext } from '../lib/llm';

const SEVERITY_CLASSES: Record<Severity, string> = {
  CRITICAL: 'bg-sev-critical text-tenable-black',
  HIGH: 'bg-sev-high text-tenable-black',
  MEDIUM: 'bg-sev-medium text-tenable-black',
  LOW: 'bg-sev-low text-tenable-black',
  INFO: 'bg-sev-info text-tenable-black dark:text-white',
};

interface Props {
  findings: EnrichedFinding[];
  loading: boolean;
  filters: FilterState;
  onFiltersChange: (next: FilterState) => void;
  onExplain: (ctx: ExplainContext) => void;
}

type SortKey = 'asset' | 'vpr' | 'cvss3';

function nextSortValue(current: string, key: SortKey): string {
  // Cycle: none -> desc -> asc -> none for the clicked column.
  // Numeric columns default to desc (worst first); asset name defaults to asc.
  const [curKey, curDir] = current.split(':');
  if (curKey !== key) {
    return key === 'asset' ? `${key}:asc` : `${key}:desc`;
  }
  if (curDir === (key === 'asset' ? 'asc' : 'desc')) {
    return key === 'asset' ? `${key}:desc` : `${key}:asc`;
  }
  return ''; // third click clears
}

function SortIndicator({ active, direction }: { active: boolean; direction: string }) {
  if (!active) {
    return <span className="ml-1 text-tenable-black/20 dark:text-white/20">↕</span>;
  }
  return (
    <span className="ml-1 text-tenable-yellow">{direction === 'asc' ? '↑' : '↓'}</span>
  );
}

export function FindingsTable({ findings, loading, filters, onFiltersChange, onExplain }: Props) {
  const [curKey, curDir] = (filters.sort || '').split(':');
  const handleSort = (key: SortKey) =>
    onFiltersChange({ ...filters, sort: nextSortValue(filters.sort, key) });

  if (loading) {
    return <div className="text-tenable-black/60 dark:text-white/50">Loading findings…</div>;
  }
  if (findings.length === 0) {
    return (
      <div className="panel text-tenable-black/60 dark:text-white/60">
        No findings match the current filters. Try widening your selection, or run a refresh to
        populate the database.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-tenable-black/10 dark:border-white/10">
      <table className="w-full text-sm">
        <thead className="bg-tenable-black/5 dark:bg-white/5 text-left text-xs uppercase tracking-wider text-tenable-black/80 dark:text-white/60">
          <tr>
            <th className="px-3 py-2">Severity</th>
            <th className="px-3 py-2">CVE</th>
            <th className="px-3 py-2">
              <button
                onClick={() => handleSort('asset')}
                className="inline-flex items-center uppercase tracking-wider hover:text-tenable-black dark:hover:text-white"
              >
                Asset
                <SortIndicator active={curKey === 'asset'} direction={curDir} />
              </button>
            </th>
            <th className="px-3 py-2">Description</th>
            <th className="px-3 py-2">Source</th>
            <th className="px-3 py-2">
              <button
                onClick={() => handleSort('vpr')}
                className="inline-flex items-center uppercase tracking-wider hover:text-tenable-black dark:hover:text-white"
              >
                VPR
                <SortIndicator active={curKey === 'vpr'} direction={curDir} />
              </button>
            </th>
            <th className="px-3 py-2">
              <button
                onClick={() => handleSort('cvss3')}
                className="inline-flex items-center uppercase tracking-wider hover:text-tenable-black dark:hover:text-white"
              >
                CVSSv3
                <SortIndicator active={curKey === 'cvss3'} direction={curDir} />
              </button>
            </th>
            <th className="px-3 py-2">Fix Source</th>
            <th className="px-3 py-2">Remediation</th>
            <th className="px-3 py-2 w-24"></th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr
              key={f.finding_id}
              className="border-t border-tenable-black/5 dark:border-white/5 hover:bg-tenable-black/5 dark:hover:bg-tenable-black/5 dark:bg-white/5"
            >
              <td className="px-3 py-2">
                {f.severity && (
                  <span
                    className={
                      'rounded px-2 py-0.5 text-xs uppercase ' +
                      SEVERITY_CLASSES[f.severity]
                    }
                  >
                    {f.severity}
                  </span>
                )}
              </td>
              <td className="px-3 py-2 font-mono text-tenable-yellow">
                <a
                  href={`https://cloud.tenable.com/vm/#/vuln-intelligence/${f.cve_id}?affected=assets&info=events`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-tenable-black hover:underline dark:text-tenable-yellow dark:hover:underline font-medium underline-offset-2"
                  title="Open in Tenable Vulnerability Intelligence"
                >
                  {f.cve_id}
                </a>
              </td>
              <td className="px-3 py-2 max-w-xs">
                <div>{f.asset_name ?? <em className="text-tenable-black/50 dark:text-white/40">—</em>}</div>
                {f.asset_ipv4 && (
                  <div className="text-xs text-tenable-black/50 dark:text-white/40">
                    {f.asset_ipv4}
                  </div>
                )}
              </td>
              <td className="px-3 py-2 max-w-md">
                {f.cve_description ? (
                  <div
                    className="line-clamp-2 text-xs text-tenable-black/80 dark:text-white/80"
                    title={f.cve_description}
                  >
                    {f.cve_description}
                  </div>
                ) : (
                  <span className="text-tenable-black/40 dark:text-white/30">—</span>
                )}
              </td>
              <td className="px-3 py-2 text-tenable-black/80 dark:text-white/80">{f.source}</td>
              <td className="px-3 py-2">{f.vpr_score?.toFixed(1) ?? '—'}</td>
              <td className="px-3 py-2">{f.cvss3_base_score?.toFixed(1) ?? '—'}</td>
              <td className="px-3 py-2 text-xs">
                {f.plugin_family ? (
                  <div className="flex items-center gap-1">
                    <span className={f.plugin_platform_match ? 'text-tenable-black/80 dark:text-white/80' : 'text-data-purple'}>
                      {f.plugin_family.replace(/ Local Security Checks$/, '')}
                    </span>
                  </div>
                ) : (
                  <span className="text-tenable-black/40 dark:text-white/30">—</span>
                )}
              </td>
              <td className="px-3 py-2 max-w-md">
                {(() => {
                  if (!f.enriched) {
                    return (
                      <span className="text-xs uppercase tracking-wider text-data-orange">
                        Not enriched
                      </span>
                    );
                  }
                  const noFix =
                    !f.remediation ||
                    f.remediation === 'There is no known solution at this time.';
                  if (noFix) {
                    return (
                      <a
                        href={`https://cloud.tenable.com/vm/#/vuln-intelligence/${f.cve_id}?affected=assets&info=events`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-tenable-yellow hover:underline"
                        title="No fix from Tenable Research; open Vulnerability Intelligence for more context"
                      >
                        → Check Vulnerability Intelligence
                      </a>
                    );
                  }
                  return (
                    <span className="line-clamp-2 text-tenable-black/80 dark:text-white/80">{f.remediation}</span>
                  );
                })()}
              </td>
              <td className="px-3 py-2 text-right">
                <button
                  onClick={() =>
                    onExplain({
                      cve_id: f.cve_id,
                      asset_name: f.asset_name ?? null,
                      source: f.source,
                      severity: f.severity ?? null,
                      vpr_score: f.vpr_score ?? null,
                      cve_description: f.cve_description ?? null,
                      remediation: f.remediation ?? null,
                      plugin_family: f.plugin_family ?? null,
                      plugin_platform_match: f.plugin_platform_match ?? null,
                      asset_operating_system: f.asset_operating_system ?? null,
                    })
                  }
                  className="rounded-md border border-tenable-yellow/40 bg-tenable-yellow/10 px-2 py-1 text-xs text-tenable-black dark:text-tenable-yellow hover:bg-tenable-yellow/20 transition whitespace-nowrap"
                  title="Explain this finding with AI"
                >
                  Explain ✨
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
