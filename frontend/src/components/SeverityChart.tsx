import { BarChart, Bar, XAxis, ResponsiveContainer, Cell, Tooltip } from 'recharts';
import type { SeverityCounts } from '../lib/types';

const SEVERITY_COLORS = {
  Critical: '#FF8837',
  High: '#E7FF00',
  Medium: '#4EA5FF',
  Low: '#71FFC6',
  Info: '#44494B',
  Unknown: '#888888',
};

interface Props {
  counts: SeverityCounts | undefined;
  loading: boolean;
}

export function SeverityChart({ counts, loading }: Props) {
  const data = counts
    ? [
        { name: 'Critical', count: counts.critical },
        { name: 'High', count: counts.high },
        { name: 'Medium', count: counts.medium },
        { name: 'Low', count: counts.low },
        { name: 'Info', count: counts.info },
        { name: 'Unknown', count: counts.unknown },
      ]
    : [];

  const total = data.reduce((acc, d) => acc + d.count, 0);

  return (
    <div>
      <div className="mb-2 flex items-baseline justify-between">
        <h2 className="text-sm uppercase tracking-widest text-white/60">
          Severity distribution
        </h2>
        <div className="text-xs text-white/50">
          {loading ? 'Loading…' : `${total.toLocaleString()} findings in view`}
        </div>
      </div>
      <div className="h-32 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 8, left: 8, bottom: 0 }}>
            <XAxis
              dataKey="name"
              tick={{ fill: '#FFFFFFCC', fontSize: 12 }}
              axisLine={{ stroke: '#FFFFFF22' }}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: '#FFFFFF10' }}
              contentStyle={{
                background: '#1E2426',
                border: '1px solid #FFFFFF22',
                borderRadius: 6,
                fontSize: 12,
              }}
              labelStyle={{ color: '#FFFFFF' }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={SEVERITY_COLORS[entry.name as keyof typeof SEVERITY_COLORS]}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
