import type { LlmProvider } from './useApiKey';

/**
 * Per-provider model defaults. Bump these as new models ship.
 * Defaults to Claude Haiku 4.5 and Gemini 2.5 Flash — both tuned for
 * cheap, fast structured output. Cost is ~$0.001–$0.002 per first
 * click; cached responses (see explainFinding) are free thereafter.
 */
const CLAUDE_MODEL = 'claude-haiku-4-5';
const GEMINI_MODEL = 'gemini-2.5-flash';

/**
 * Subset of finding fields sent to the LLM. We deliberately keep this
 * minimal — only what the model needs to write a good explanation.
 * Keeps token cost down and avoids leaking irrelevant data.
 */
export interface ExplainContext {
  cve_id: string;
  asset_name: string | null;
  source: string;
  severity: string | null;
  vpr_score: number | null;
  cvss3_base_score: number | null;
  plugin_family: string | null;
  plugin_platform_match: boolean | null;
  remediation: string | null;
  cve_description: string | null;
}

const SYSTEM_PROMPT = `You are a senior security engineer explaining a Tenable finding to a customer. Be concise, actionable, plain-language.

Three sections with exact bolded headings, one short paragraph each:

**What this is.** Type of bug, affected software, attacker impact.

**Why it matters here.** Tie to this asset (infer purpose from its name) and source. Note if platform match is a cross-platform fallback.

**Fix.** Concrete action. Use the provided remediation if any; otherwise say none available and recommend Tenable Vulnerability Intelligence.

Under 280 words. No preamble. Start with the first heading.`;

function buildUserMessage(ctx: ExplainContext): string {
  const lines: string[] = [
    `Finding: ${ctx.cve_id}`,
    `Asset: ${ctx.asset_name ?? 'unknown'}`,
    `Source: ${ctx.source}`,
  ];

  if (ctx.severity) lines.push(`Tenable severity bucket: ${ctx.severity}`);
  if (ctx.vpr_score !== null) lines.push(`VPR score: ${ctx.vpr_score}`);
  if (ctx.cvss3_base_score !== null) lines.push(`CVSSv3 base score: ${ctx.cvss3_base_score}`);

  if (ctx.plugin_family) {
    const matchNote =
      ctx.plugin_platform_match === false
        ? ' (cross-platform fallback — no native plugin available for this source)'
        : '';
    lines.push(`Matched Tenable plugin family: ${ctx.plugin_family}${matchNote}`);
  }

  const noFix =
    !ctx.remediation || ctx.remediation === 'There is no known solution at this time.';
  if (noFix) {
    lines.push('Tenable Research remediation guidance: none available');
  } else {
    lines.push(`Tenable Research remediation guidance: ${ctx.remediation}`);
  }

  if (ctx.cve_description) {
    // Truncate very long descriptions (kernel-class CVEs can be huge)
    // to keep token cost down.
    const desc =
      ctx.cve_description.length > 800
        ? ctx.cve_description.slice(0, 800) + '... [truncated]'
        : ctx.cve_description;
    lines.push(`\nCVE description:\n${desc}`);
  }

  return lines.join('\n');
}

async function callClaude(prompt: string, apiKey: string): Promise<string> {
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      // Required for direct browser-to-API calls.
      'anthropic-dangerous-direct-browser-access': 'true',
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: 500,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Claude API returned ${response.status}: ${errorBody.slice(0, 300)}`,
    );
  }

  const data = await response.json();
  const block = data?.content?.[0];
  if (!block || block.type !== 'text' || typeof block.text !== 'string') {
    throw new Error('Claude returned an unexpected response shape');
  }
  return block.text;
}

async function callGemini(prompt: string, apiKey: string): Promise<string> {
  // Gemini takes the API key as a URL query param rather than a header.
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${encodeURIComponent(apiKey)}`;

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      systemInstruction: {
        parts: [{ text: SYSTEM_PROMPT }],
      },
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: {
        maxOutputTokens: 500,
        temperature: 0.4,
        // Gemini 2.5 Flash has thinking enabled by default. Thinking tokens
        // count against maxOutputTokens, so leaving it on means the actual
        // response gets truncated mid-sentence. For structured short-form
        // output like this we don't need thinking — disable it.
        thinkingConfig: { thinkingBudget: 0 },
      },
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Gemini API returned ${response.status}: ${errorBody.slice(0, 300)}`,
    );
  }

  const data = await response.json();
  const candidate = data?.candidates?.[0];
  const parts = candidate?.content?.parts ?? [];
  // Concatenate all text parts (Gemini may return multiple) and skip
  // 'thought' parts which are reasoning content, not user-facing output.
  const text = parts
    .filter((part: { thought?: boolean; text?: string }) => part.thought !== true && typeof part.text === 'string')
    .map((part: { text: string }) => part.text)
    .join('');

  if (!text) {
    const reason = candidate?.finishReason ?? 'unknown';
    throw new Error(`Gemini returned no text (finishReason: ${reason}).`);
  }

  // If the response was truncated by the token cap, surface it.
  if (candidate?.finishReason === 'MAX_TOKENS') {
    return text + '\n\n_[Response truncated — try increasing max_tokens in llm.ts]_';
  }
  if (candidate?.finishReason === 'SAFETY') {
    throw new Error('Gemini blocked this response due to safety filters. Try Claude instead.');
  }

  return text;
}

/**
 * Send a finding to the chosen LLM provider and return an explanation.
 * Throws on network errors, bad API keys, rate limits, or malformed responses.
 *
 * This function runs entirely in the browser — the API key is never sent
 * to the ExposureIQ backend. Requests go directly from the user's
 * browser to api.anthropic.com or generativelanguage.googleapis.com.
 */
const CACHE_PREFIX = 'llm.explain.cache.v1.';

function cacheKey(ctx: ExplainContext, provider: LlmProvider): string {
  return `${CACHE_PREFIX}${provider}::${ctx.cve_id}::${ctx.asset_name ?? ''}`;
}

/**
 * Read a cached explanation if one exists. Cached responses live in
 * localStorage so repeated clicks on the same finding never re-bill the API.
 */
export function getCachedExplanation(
  ctx: ExplainContext,
  provider: LlmProvider,
): string | null {
  try {
    return localStorage.getItem(cacheKey(ctx, provider));
  } catch {
    return null;
  }
}

/**
 * Count cached explanations currently in localStorage. Used by the Settings
 * panel to show how many cached responses exist and whether the Clear button
 * is worth showing.
 */
export function getCacheSize(): number {
  try {
    let count = 0;
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(CACHE_PREFIX)) count++;
    }
    return count;
  } catch {
    return 0;
  }
}

/**
 * Clear all cached explanations. Exposed for the Settings panel "Clear cache" button.
 */
export function clearExplanationCache(): void {
  try {
    const toRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(CACHE_PREFIX)) toRemove.push(k);
    }
    toRemove.forEach((k) => localStorage.removeItem(k));
  } catch {
    // localStorage unavailable; silently no-op
  }
}

export async function explainFinding(
  ctx: ExplainContext,
  apiKey: string,
  provider: LlmProvider,
): Promise<string> {
  if (!apiKey) {
    throw new Error('No API key configured. Open Settings to add one.');
  }

  // Cache check — return immediately if we already explained this finding.
  const cached = getCachedExplanation(ctx, provider);
  if (cached) return cached;

  const prompt = buildUserMessage(ctx);
  const result = provider === 'claude'
    ? await callClaude(prompt, apiKey)
    : await callGemini(prompt, apiKey);

  try {
    localStorage.setItem(cacheKey(ctx, provider), result);
  } catch {
    // Storage full or unavailable; non-fatal, just don't cache.
  }
  return result;
}
