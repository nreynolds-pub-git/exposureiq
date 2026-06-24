import { useEffect, useState } from 'react';
import { useApiKey, type LlmProvider } from '../lib/useApiKey';
import { clearExplanationCache, getCacheSize } from '../lib/llm';

interface Props {
  open: boolean;
  onClose: () => void;
}

const PROVIDER_INFO: Record<LlmProvider, { name: string; keyUrl: string; placeholder: string }> = {
  claude: {
    name: 'Anthropic Claude',
    keyUrl: 'https://console.anthropic.com/settings/keys',
    placeholder: 'sk-ant-...',
  },
  gemini: {
    name: 'Google Gemini',
    keyUrl: 'https://aistudio.google.com/app/apikey',
    placeholder: 'AIza...',
  },
};

export function SettingsPanel({ open, onClose }: Props) {
  const { apiKey, setApiKey, provider, setProvider } = useApiKey();
  const [draftKey, setDraftKey] = useState(apiKey);
  const [draftProvider, setDraftProvider] = useState<LlmProvider>(provider);
  const [cacheSize, setCacheSize] = useState(0);

  // Re-count cached explanations whenever the modal opens or after a clear,
  // so the count badge stays accurate without polling localStorage every render.
  useEffect(() => {
    if (open) setCacheSize(getCacheSize());
  }, [open]);

  useEffect(() => {
    if (open) {
      setDraftKey(apiKey);
      setDraftProvider(provider);
    }
  }, [open, apiKey, provider]);

  if (!open) return null;

  const handleSave = () => {
    setApiKey(draftKey.trim());
    setProvider(draftProvider);
    onClose();
  };

  const handleClear = () => {
    setDraftKey('');
    setApiKey('');
  };

  const handleClearCache = () => {
    clearExplanationCache();
    setCacheSize(0);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-tenable-black/70 backdrop-blur"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-lg border border-tenable-black/20 dark:border-white/20 bg-white dark:bg-tenable-black p-6 text-tenable-black dark:text-white shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-4 text-lg font-semibold">LLM provider settings</h2>

        <p className="mb-5 text-xs text-tenable-black/70 dark:text-white/70 leading-relaxed">
          To enable AI explanations, configure an API key from your preferred provider.
          Your key stays in this browser and is never sent to the t1-cve-enricher backend.
          When you click <span className="font-medium">Explain</span>, the finding's context
          is sent directly from your browser to the chosen provider.
        </p>

        <label className="mb-3 block text-xs">
          <span className="text-tenable-black/70 dark:text-white/70">Provider</span>
          <select
            value={draftProvider}
            onChange={(e) => setDraftProvider(e.target.value as LlmProvider)}
            className="mt-1 w-full rounded-md border border-tenable-black/20 dark:border-white/20 bg-tenable-black/5 dark:bg-white/5 px-3 py-1.5 text-sm outline-none focus:border-tenable-yellow"
          >
            <option value="claude">Anthropic Claude</option>
            <option value="gemini">Google Gemini</option>
          </select>
        </label>

        <label className="mb-2 block text-xs">
          <span className="text-tenable-black/70 dark:text-white/70">API key</span>
          <input
            type="password"
            value={draftKey}
            onChange={(e) => setDraftKey(e.target.value)}
            placeholder={PROVIDER_INFO[draftProvider].placeholder}
            className="mt-1 w-full rounded-md border border-tenable-black/20 dark:border-white/20 bg-tenable-black/5 dark:bg-white/5 px-3 py-1.5 text-sm font-mono outline-none focus:border-tenable-yellow"
          />
        </label>

        <p className="mb-5 text-xs text-tenable-black/60 dark:text-white/60">
          Get a key from{' '}
          <a
            href={PROVIDER_INFO[draftProvider].keyUrl}
            target="_blank"
            rel="noreferrer"
            className="text-tenable-black dark:text-tenable-yellow underline underline-offset-2"
          >
            {PROVIDER_INFO[draftProvider].name}
          </a>
          .
        </p>

        {cacheSize > 0 && (
          <div className="mb-4 flex items-center justify-between text-xs text-tenable-black/60 dark:text-white/60">
            <span>
              {cacheSize} cached explanation{cacheSize === 1 ? '' : 's'}
            </span>
            <button
              onClick={handleClearCache}
              className="underline underline-offset-2 hover:text-tenable-black dark:hover:text-white"
            >
              Clear cache
            </button>
          </div>
        )}

        <div className="flex items-center justify-between">
          <button
            onClick={handleClear}
            className="text-xs text-tenable-black/60 dark:text-white/60 hover:text-tenable-black dark:hover:text-white"
          >
            Clear saved key
          </button>
          <div className="flex gap-2">
            <button
              onClick={onClose}
              className="rounded-md border border-tenable-black/20 dark:border-white/20 px-3 py-1.5 text-sm text-tenable-black dark:text-white hover:bg-tenable-black/5 dark:hover:bg-white/5"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="rounded-md bg-tenable-yellow px-3 py-1.5 text-sm font-medium text-tenable-black hover:bg-opacity-90"
            >
              Save
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
