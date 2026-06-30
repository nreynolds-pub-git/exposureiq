import { useEffect, useRef, useState } from 'react';
import { explainFinding, type ExplainContext } from '../lib/llm';
import { categoryFor } from '../lib/sourceCategory';
import { useApiKey } from '../lib/useApiKey';

interface Props {
  context: ExplainContext | null;
  onClose: () => void;
  onOpenSettings: () => void;
}

export function ExplainModal({ context, onClose, onOpenSettings }: Props) {
  const { apiKey, provider, configured } = useApiKey();
  const [loading, setLoading] = useState(false);
  const [text, setText] = useState<string>('');
  const [error, setError] = useState<string>('');
  // Track which finding we last fetched so opening the same row twice
  // does not re-trigger the LLM call unnecessarily.
  const lastFetchedRef = useRef<string>('');

  useEffect(() => {
    if (!context) {
      setText('');
      setError('');
      lastFetchedRef.current = '';
      return;
    }
    if (!configured) {
      setText('');
      setError('');
      return;
    }
    // Key the cache on CVE alone — the new prompt is asset-agnostic, so the
    // same explanation applies regardless of which asset the CVE was clicked on.
    const fetchKey = context.cve_id;
    if (fetchKey === lastFetchedRef.current) return;
    lastFetchedRef.current = fetchKey;

    let cancelled = false;
    setLoading(true);
    setText('');
    setError('');
    explainFinding(context, apiKey, provider)
      .then((result) => {
        if (!cancelled) setText(result);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message || 'Unknown error');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [context, apiKey, provider, configured]);

  if (!context) return null;

  const providerLabel = provider === 'claude' ? 'Claude' : 'Gemini';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-tenable-black/70 backdrop-blur p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-lg border border-tenable-black/20 dark:border-white/20 bg-white dark:bg-tenable-black p-6 text-tenable-black dark:text-white shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between">
          <div className="flex-1">
            <h2 className="text-lg font-semibold mb-3">{context.cve_id}</h2>
            <dl className="grid grid-cols-4 gap-x-4 gap-y-1 text-xs">
              <dt className="text-tenable-black/50 dark:text-white/40 uppercase tracking-wider">Severity</dt>
              <dt className="text-tenable-black/50 dark:text-white/40 uppercase tracking-wider">VPR</dt>
              <dt className="text-tenable-black/50 dark:text-white/40 uppercase tracking-wider">Source</dt>
              <dt className="text-tenable-black/50 dark:text-white/40 uppercase tracking-wider">Asset</dt>
              <dd className="text-tenable-black dark:text-white font-medium">
                {context.severity ?? <span className="text-tenable-black/40 dark:text-white/30">—</span>}
              </dd>
              <dd className="text-tenable-black dark:text-white font-medium">
                {context.vpr_score?.toFixed(1) ?? <span className="text-tenable-black/40 dark:text-white/30">—</span>}
              </dd>
              <dd className="text-tenable-black dark:text-white font-medium" title={`Connector: ${context.source}`}>
                {categoryFor(context.source)}
              </dd>
              <dd className="text-tenable-black dark:text-white font-medium truncate" title={context.asset_name ?? ''}>
                {context.asset_name ?? <span className="text-tenable-black/40 dark:text-white/30">—</span>}
              </dd>
            </dl>
          </div>
          <button
            onClick={onClose}
            className="text-tenable-black/60 dark:text-white/60 hover:text-tenable-black dark:hover:text-white text-xl leading-none ml-3"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {!configured ? (
          <div className="rounded-md border border-tenable-yellow/40 bg-tenable-yellow/10 p-4 text-sm">
            <p className="mb-3">
              No LLM provider configured. Add an API key in Settings to enable explanations.
            </p>
            <button
              onClick={onOpenSettings}
              className="rounded-md bg-tenable-yellow px-3 py-1.5 text-sm font-medium text-tenable-black hover:bg-opacity-90"
            >
              Open Settings
            </button>
          </div>
        ) : loading ? (
          <div className="flex items-center gap-3 py-8 text-sm text-tenable-black/70 dark:text-white/70">
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-tenable-black/30 dark:border-white/30 border-t-tenable-yellow" />
            Analyzing this finding with {providerLabel}…
          </div>
        ) : error ? (
          <div className="rounded-md border border-data-red/40 bg-data-red/10 p-4 text-sm">
            <p className="mb-2 font-medium">Could not generate an explanation.</p>
            <p className="font-mono text-xs text-tenable-black/70 dark:text-white/70 whitespace-pre-wrap break-all">
              {error}
            </p>
            <button
              onClick={() => {
                lastFetchedRef.current = '';
                // Force re-run by toggling effect deps: easiest is to clear error and re-set context noop
                setError('');
                setLoading(true);
                explainFinding(context, apiKey, provider)
                  .then((r) => setText(r))
                  .catch((e: Error) => setError(e.message))
                  .finally(() => setLoading(false));
              }}
              className="mt-3 rounded-md border border-tenable-black/20 dark:border-white/20 px-3 py-1 text-xs hover:bg-tenable-black/5 dark:hover:bg-white/5"
            >
              Retry
            </button>
          </div>
        ) : (
          <div className="space-y-3 text-sm leading-relaxed whitespace-pre-wrap">
            {renderExplanation(text)}
          </div>
        )}

        <div className="mt-5 border-t border-tenable-black/10 dark:border-white/10 pt-3 text-xs text-tenable-black/50 dark:text-white/40">
          Powered by {providerLabel}. Finding context was sent directly from this browser.
        </div>
      </div>
    </div>
  );
}

/**
 * Lightweight markdown renderer for the explanation body.
 * Handles the bold section headers the prompt asks for, but nothing fancier.
 */
function renderExplanation(text: string): JSX.Element[] {
  // Split into paragraphs on blank lines, render bold spans inline.
  const paragraphs = text.split(/\n\s*\n/).filter((p) => p.trim().length > 0);
  return paragraphs.map((p, i) => (
    <p key={i}>{renderInlineBold(p)}</p>
  ));
}

function renderInlineBold(text: string): (string | JSX.Element)[] {
  const parts: (string | JSX.Element)[] = [];
  const regex = /\*\*([^*]+)\*\*/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;
  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    parts.push(<strong key={key++}>{match[1]}</strong>);
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }
  return parts;
}
