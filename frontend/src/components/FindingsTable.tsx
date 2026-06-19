import type { EnrichedFinding, Severity } from '../lib/types';

const SEVERITY_CLASSES: Record<Severity, string> = {
  CRITICAL: 'bg-sev-critical text-tenable-black',
  HIGH: 'bg-sev-high text-tenable-black',
  MEDIUM: 'bg-sev-medium text-tenable-black',
  LOW: 'bg-sev-low text-tenable-black',
  INFO: 'bg-sev-info text-white',
};

interface Props {
  findings: EnrichedFinding[];
  loading: boolean;
}

export function FindingsTable({ findings, loading }: Props) {
  if (loading) {
    return <div className="text-white/50">Loading findings…</div>;
  }
  if (findings.length === 0) {
    return (
      <div className="panel text-white/60">
        No findings match the current filters. Try widening your selection, or run a refresh to
        populate the database.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-white/10">
      <table className="w-full text-sm">
        <thead className="bg-white/5 text-left text-xs uppercase tracking-wider text-white/60">
          <tr>
            <th className="px-3 py-2">Severity</th>
            <th className="px-3 py-2">CVE</th>
            <th className="px-3 py-2">Asset</th>
            <th className="px-3 py-2">Source</th>
            <th className="px-3 py-2">VPR</th>
            <th className="px-3 py-2">CVSSv3</th>
            <th className="px-3 py-2">Remediation</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr
              key={f.finding_id}
              className="border-t border-white/5 hover:bg-white/5"
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
                  href={`https://www.tenable.com/cve/${f.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="hover:underline"
                >
                  {f.cve_id}
                </a>
              </td>
              <td className="px-3 py-2">
                <div>{f.asset_name ?? <em className="text-white/40">—</em>}</div>
                <div className="text-xs text-white/40">
                  {f.asset_fqdn || f.asset_ipv4 || ''}
                </div>
              </td>
              <td className="px-3 py-2 text-white/80">{f.source}</td>
              <td className="px-3 py-2">{f.vpr_score?.toFixed(1) ?? '—'}</td>
              <td className="px-3 py-2">{f.cvss3_base_score?.toFixed(1) ?? '—'}</td>
              <td className="px-3 py-2 max-w-md">
                {f.enriched ? (
                  <span className="line-clamp-2 text-white/80">
                    {f.remediation ?? <em className="text-white/40">no guidance</em>}
                  </span>
                ) : (
                  <span className="text-xs uppercase tracking-wider text-data-orange">
                    Not enriched
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
