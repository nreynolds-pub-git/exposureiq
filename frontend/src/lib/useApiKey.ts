import { useEffect, useState } from 'react';

export type LlmProvider = 'claude' | 'gemini';

const KEY_STORAGE = 'llm.apiKey';
const PROVIDER_STORAGE = 'llm.provider';

/**
 * Manages the user's LLM provider choice and API key. Both live in
 * localStorage and never leave the browser — when "Explain" is clicked,
 * the request goes directly from the browser to api.anthropic.com or
 * generativelanguage.googleapis.com. The t1-cve-enricher backend never
 * sees the key.
 */
export function useApiKey() {
  const [apiKey, setApiKeyState] = useState<string>(() => {
    if (typeof window === 'undefined') return '';
    return localStorage.getItem(KEY_STORAGE) || '';
  });
  const [provider, setProviderState] = useState<LlmProvider>(() => {
    if (typeof window === 'undefined') return 'claude';
    const stored = localStorage.getItem(PROVIDER_STORAGE);
    return stored === 'gemini' ? 'gemini' : 'claude';
  });

  // Listen for changes from other tabs/windows so settings stay in sync.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === KEY_STORAGE) setApiKeyState(e.newValue || '');
      if (e.key === PROVIDER_STORAGE) {
        setProviderState(e.newValue === 'gemini' ? 'gemini' : 'claude');
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const setApiKey = (key: string) => {
    setApiKeyState(key);
    if (key) localStorage.setItem(KEY_STORAGE, key);
    else localStorage.removeItem(KEY_STORAGE);
  };

  const setProvider = (p: LlmProvider) => {
    setProviderState(p);
    localStorage.setItem(PROVIDER_STORAGE, p);
  };

  return { apiKey, setApiKey, provider, setProvider, configured: !!apiKey };
}
