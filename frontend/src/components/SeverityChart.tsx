import { BarChart, Bar, XAxis, ResponsiveContainer, Cell, Tooltip } from 'recharts';
import type { SeverityCounts } from '../lib/types';
import { useTheme } from '../lib/useTheme';

const SEVERITY_COLORS = {
  Critical: '#FF8837',
  High: '#E7FF00',
  Medium: '#71FFC6',
  Low: '#4EA5FF',
};

interface Props {
  counts: SeverityCounts | undefined;
}

export function SeverityChart({ counts }: Props) {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const data = counts
    ? [
        { name: 'Critical', count: counts.critical },
        { name: 'High', count: counts.high },
        { name: 'Medium', count: counts.medium },
        { name: 'Low', count: counts.low },
      ]
    : [];


  return (
    <div>
      <div className="mb-2">
        <h2 className="text-sm uppercase tracking-widest text-tenable-black/60 dark:text-white/60">
          Severity distribution
        </h2>
      </div>
      <div className="h-32 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 8, left: 8, bottom: 0 }}>
            <XAxis
              dataKey="name"
              tick={{ fill: isDark ? '#FFFFFFCC' : '#1E2426CC', fontSize: 12 }}
              axisLine={{ stroke: isDark ? '#FFFFFF22' : '#1E242622' }}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: isDark ? '#FFFFFF10' : '#1E242610' }}
              contentStyle={{
                background: isDark ? '#1E2426' : '#FFFFFF',
                border: `1px solid ${isDark ? '#FFFFFF22' : '#1E242622'}`,
                borderRadius: 6,
                fontSize: 12,
                color: isDark ? '#FFFFFF' : '#1E2426',
              }}
              labelStyle={{ color: isDark ? '#FFFFFF' : '#1E2426', fontWeight: 600 }}
              itemStyle={{ color: isDark ? '#FFFFFFCC' : '#1E2426CC' }}
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
