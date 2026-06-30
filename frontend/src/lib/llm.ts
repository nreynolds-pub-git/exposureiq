import type { LlmProvider } from './useApiKey';
import { categoryFor } from './sourceCategory';

/**
 * Per-provider model defaults. Bump these as new models ship.
 * Defaults to Claude Haiku 4.5 and Gemini 2.5 Flash — both tuned for
 * cheap, fast structured output. Cost is ~$0.001–$0.002 per first
 * click; cached responses (see explainFinding) are free thereafter.
 */
const CLAUDE_MODEL = 'claude-haiku-4-5';
const GEMINI_MODEL = 'gemini-2.5-flash';

/**
 * Subset of finding fields used by the Explain feature.
 *
 * `vpr_score` and `severity` are displayed in the modal's metadata strip
 * for human context, but are deliberately NOT passed to the LLM.
 *
 * `asset_name` is similarly available for display but is NEVER sent to the
 * LLM — privacy invariant. The vendor identity in `source` is also never
 * sent; it is mapped through categoryFor() to a generic category first.
 */
export interface ExplainContext {
  cve_id: string;
  asset_name: string | null;
  source: string;
  severity: string | null;
  vpr_score: number | null;
  cve_description: string | null;
  remediation: string | null;
  plugin_family: string | null;
  plugin_platform_match: boolean | null;
  asset_operating_system?: string | null;
}

/**
 * System prompt: mitigation-first, source-cited, vendor-anonymized.
 *
 * Design notes:
 *  - Mitigations come BEFORE remediation because most vulnerability tools
 *    tell users when to patch (remediation) but not what to do right now
 *    (mitigation). The differentiator is mitigation-first guidance.
 *  - Source citations are required on every recommendation. This is the
 *    hallucination guard — the LLM cannot invent advice without grounding
 *    it in either the provided context or a well-known public reference.
 *  - The output structure is rigid by design. Customers reading these
 *    should know exactly where to look for each kind of information.
 */
const SYSTEM_PROMPT = `You are a senior security engineer producing actionable analysis of a vulnerability finding for a customer security team.

Output EXACTLY these sections in this order, with the bolded headings shown:

**Summary.** One sentence: what the bug is and the worst-case attacker impact.

**Mitigations.** Immediate stop-gap actions a defender can take right now to reduce risk before a permanent fix is possible. List 2-4 concrete actions as bullets. Each bullet must end with a source citation in parentheses, e.g. "(Source: CVE description)" or "(Source: Tenable remediation guidance)". Use only the inputs provided to you or well-known public references like "CISA KEV" or "MITRE ATT&CK".

**Remediation.** Permanent fix. 1-2 bullets. Cite source for each. If no remediation was provided, say so explicitly and recommend Tenable Vulnerability Intelligence as the next step.

**Asset context.** One sentence noting how the asset's category (cloud, endpoint, web app, etc.) shapes the practical risk. Use only the categorical asset info provided; never speculate about specific assets you weren't told about.

**Sources used.** Bullet list of every source you cited above.

Rules:
- Total response under 300 words.
- Never invent patch IDs, KB numbers, or version numbers — cite only what's in the inputs.
- Never reference specific asset names, IP addresses, or vendor product names. The inputs use generic categories on purpose.
- Cite MITRE ATT&CK only when you can name a specific technique ID (e.g. "Source: MITRE ATT&CK T1078"). Do not cite MITRE ATT&CK for generic security advice.
- Cite CISA KEV only if the CVE was provided to you as being on the KEV catalog, AND only when warning about active exploitation. Do not cite CISA KEV as a source for "deploy EDR" or similar generic recommendations.
- For mitigations or remediations that reflect general security hygiene rather than a specific provided input or well-known authoritative reference, cite "General security best practice" instead. Honesty beats false authority.
- Do not cite the asset's source category (EDR, CNAPP, DAST, etc.) as a source of guidance. The source category describes what the asset is, not where recommendations come from. If a recommendation is "use your existing EDR to do X", cite "General security best practice".
- No preamble. Start directly with "**Summary.**".`;

function buildUserMessage(ctx: ExplainContext): string {
  const lines: string[] = [
    `CVE: ${ctx.cve_id}`,
    `Source category: ${categoryFor(ctx.source)}`,
  ];

  if (ctx.asset_operating_system) {
    lines.push(`Asset OS family: ${ctx.asset_operating_system}`);
  }

  if (ctx.cve_description) {
    // Truncate very long descriptions (some kernel CVEs are huge) to control
    // token cost. The first 800 chars almost always contain the actionable
    // technical context.
    const desc =
      ctx.cve_description.length > 800
        ? ctx.cve_description.slice(0, 800) + '... [truncated]'
        : ctx.cve_description;
    lines.push(`\nCVE description:\n${desc}`);
  }

  // Plugin context. Useful for grounding remediation in Tenable's research
  // but we don't pass the vendor's full solution text — just whether one
  // exists. Keeps token cost bounded.
  const hasRemediation =
    !!ctx.remediation && ctx.remediation !== 'There is no known solution at this time.';
  if (hasRemediation) {
    // The remediation is typically short already; include it directly so the
    // LLM can cite specific patch IDs / versions without hallucinating.
    lines.push(`\nTenable remediation guidance: ${ctx.remediation}`);
  } else {
    lines.push('\nTenable remediation guidance: none available');
  }

  if (ctx.plugin_family) {
    const matchNote =
      ctx.plugin_platform_match === false ? ' (cross-platform fallback)' : '';
    lines.push(`Matched Tenable plugin family: ${ctx.plugin_family}${matchNote}`);
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
      max_tokens: 600,
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
        maxOutputTokens: 600,
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
    .filter(
      (part: { thought?: boolean; text?: string }) =>
        part.thought !== true && typeof part.text === 'string',
    )
    .map((part: { text: string }) => part.text)
    .join('');

  if (!text) {
    const reason = candidate?.finishReason ?? 'unknown';
    throw new Error(`Gemini returned no text (finishReason: ${reason}).`);
  }

  if (candidate?.finishReason === 'MAX_TOKENS') {
    return text + '\n\n_[Response truncated — try increasing max_tokens in llm.ts]_';
  }
  if (candidate?.finishReason === 'SAFETY') {
    throw new Error(
      'Gemini blocked this response due to safety filters. Try Claude instead.',
    );
  }

  return text;
}

/**
 * Cache key: deliberately drops asset_name. The new prompt produces the same
 * explanation regardless of which asset the CVE affects (asset identifiers
 * are never sent to the LLM). One explanation per (cve, provider) is correct
 * and maximizes cache reuse.
 *
 * Bumped to v2 to invalidate v1-cached responses which used the old prompt
 * and per-asset key.
 */
const CACHE_PREFIX = 'llm.explain.cache.v2.';

function cacheKey(ctx: ExplainContext, provider: LlmProvider): string {
  return `${CACHE_PREFIX}${provider}::${ctx.cve_id}`;
}

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
 * Count cached explanations currently in localStorage. Counts both v1 and v2
 * keys so the Settings panel's clear-cache UX still finds and clears legacy
 * entries.
 */
export function getCacheSize(): number {
  try {
    let count = 0;
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (k.startsWith(CACHE_PREFIX) || k.startsWith('llm.explain.cache.v1.'))) {
        count++;
      }
    }
    return count;
  } catch {
    return 0;
  }
}

export function clearExplanationCache(): void {
  try {
    const toRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (k.startsWith(CACHE_PREFIX) || k.startsWith('llm.explain.cache.v1.'))) {
        toRemove.push(k);
      }
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

  const cached = getCachedExplanation(ctx, provider);
  if (cached) return cached;

  const prompt = buildUserMessage(ctx);
  const result =
    provider === 'claude'
      ? await callClaude(prompt, apiKey)
      : await callGemini(prompt, apiKey);

  try {
    localStorage.setItem(cacheKey(ctx, provider), result);
  } catch {
    // Storage full or unavailable; non-fatal, just don't cache.
  }
  return result;
}
