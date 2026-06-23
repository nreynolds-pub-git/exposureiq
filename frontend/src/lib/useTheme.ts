import { useEffect, useState } from 'react';

export type Theme = 'light' | 'dark';

function readClass(): Theme {
  if (typeof document === 'undefined') return 'dark';
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
}

/**
 * Reads/writes the page theme. Source of truth is the .dark class on <html>
 * (set initially by the bootstrap script in index.html) and localStorage.
 * A MutationObserver keeps every consumer in sync — toggling from one
 * component re-renders all the others.
 */
export function useTheme() {
  const [theme, setTheme] = useState<Theme>(readClass);

  useEffect(() => {
    const observer = new MutationObserver(() => setTheme(readClass()));
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    });
    return () => observer.disconnect();
  }, []);

  const toggle = () => {
    const next: Theme = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.classList.toggle('dark', next === 'dark');
    localStorage.setItem('theme', next);
    // State updates via the observer; no setState needed here
  };

  return { theme, toggle };
}
