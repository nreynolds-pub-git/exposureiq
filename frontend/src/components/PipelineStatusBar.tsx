import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import type { PipelineProgress } from '../lib/types';

const STAGE_LABELS: Record<string, string> = {
  idle: 'Idle',
  discovery: 'Discovering sources',
  extraction: 'Pulling findings',
  cve_enrichment: 'Enriching CVE intelligence',
  plugin_enrichment: 'Looking up Tenable plugins',
};

/**
 * Top-of-page progress strip. Renders a thin yellow strip with stage + counts
 * when the pipeline is running, and a one-line "Last run: ..." footer with a
 * "Run pipeline" button when idle.
 *
 * Polls /api/progress every 2s while running, every 30s while idle.
 */
export function PipelineStatusBar() {
  const queryClient = useQueryClient();
  const [pollMs, setPollMs] = useState(30_000);

  const { data } = useQuery<PipelineProgress>({
    queryKey: ['progress'],
    queryFn: () => api.getProgress(),
    refetchInterval: pollMs,
    refetchIntervalInBackground: false,
  });

  // Speed up polling when running, slow back down when idle.
  useEffect(() => {
    if (data?.is_running) {
      setPollMs(2_000);
    } else if (pollMs !== 30_000) {
      setPollMs(30_000);
      // Refresh the findings/stats views once the pipeline finishes —
      // new data probably just landed.
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['sources'] });
    }
  }, [data?.is_running, pollMs, queryClient]);

  const refresh = useMutation({
    mutationFn: () => api.refresh(),
    onSuccess: () => {
      // Start polling fast immediately so the user sees the bar appear.
      setPollMs(2_000);
      setTimeout(
        () => queryClient.invalidateQueries({ queryKey: ['progress'] }),
        500,
      );
    },
  });

  if (!data) return null;

  if (data.is_running) {
    const pct =
      data.total_n > 0 ? Math.min(100, Math.round((data.current_n / data.total_n) * 100)) : 0;
    const stageLabel = STAGE_LABELS[data.stage] ?? data.stage;

    return (
      <div className="border-b border-tenable-yellow/40 bg-tenable-yellow/10 px-6 py-2 text-xs">
        <div className="flex items-center gap-3">
          <div className="h-3 w-3 animate-pulse rounded-full bg-tenable-yellow" />
          <span className="font-medium text-tenable-black dark:text-tenable-yellow">
            {stageLabel}
          </span>
          {data.total_n > 0 && (
            <span className="text-tenable-black/70 dark:text-white/70">
              {data.current_n.toLocaleString()} / {data.total_n.toLocaleString()} ({pct}%)
            </span>
          )}
          {data.message && (
            <span className="truncate text-tenable-black/60 dark:text-white/60">
              · {data.message}
            </span>
          )}
        </div>
        {/* Progress bar */}
        <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-tenable-black/10 dark:bg-white/10">
          <div
            className="h-full bg-tenable-yellow transition-all duration-500 ease-out"
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>
    );
  }

  // Idle: show a slim footer with the last-run message + a Run button.
  return (
    <div className="border-b border-tenable-black/10 dark:border-white/10 bg-tenable-black/5 dark:bg-white/5 px-6 py-1.5 text-xs">
      <div className="flex items-center justify-between">
        <span className="text-tenable-black/60 dark:text-white/50">
          {data.message ?? 'Pipeline idle'}
        </span>
        <button
          onClick={() => refresh.mutate()}
          disabled={refresh.isPending}
          className="rounded-md border border-tenable-black/20 dark:border-white/20 px-2.5 py-0.5 text-tenable-black/70 dark:text-white/70 hover:bg-tenable-black/10 dark:hover:bg-white/10 disabled:opacity-50"
          title="Trigger an immediate pipeline run"
        >
          {refresh.isPending ? 'Starting…' : 'Run pipeline'}
        </button>
      </div>
    </div>
  );
}
