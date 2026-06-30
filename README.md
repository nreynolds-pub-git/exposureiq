# ExposureIQ for Tenable One

> AI-powered mitigation guidance for vulnerability findings in Tenable One. Self-hosted, privacy-preserving, bring-your-own-LLM.

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

## What it is

ExposureIQ is a self-hosted FastAPI + React tool that:

1. Discovers third-party connectors, and their assets in Tenable One.
2. Pulls CVE findings via Tenable's documented APIs.
3. Presents them in a filterable, sortable, and exportable web UI.
4. On demand, generates structured AI explanations with explicit mitigation guidance and source citations.

Built for any Tenable One user. The killer feature is mitigation-first AI guidance. Most vulnerability tooling tells you what to patch (remediation), but knowing when you can actually deploy that patch is a different problem — change windows, freezes, regression testing, and dependency analysis all gate it. The time between "we know the fix" and "the fix is in production" can be days or months. In today's AI-driven threat landscape, Mean Time to Mitigate (MTTM) is often more relevant than Mean Time to Remediate (MTTR); ExposureIQ leads with what a defender can do right now to reduce risk before a patch is possible.

## How it's deployed

ExposureIQ is **self-hosted by the customer in their own environment.** Nothing about this tool runs on a Tenable-owned server. The customer:

- Clones the repo into their environment and builds the Docker container
- Configures their Tenable One API credentials
- Runs the pipeline and web UI locally (or on their own infrastructure)
- Optionally (for mitigation guidance) configures their own LLM provider API key for AI explanations

## Privacy by design

This tool is designed to keep customer data inside the customer environment by default.

**Asset identifiers never leave the environment.** When the Explain feature sends a finding to an LLM provider, asset name, IP address, FQDN, MAC address, and any other identifying field are stripped at the call site. The AI explanation produced for a vulnerability is identical regardless of which asset it affects in your tenant.

**Vendor names are anonymized to industry categories.** The connector that produced a finding (Crowdstrike, Wiz, Microsoft Defender, etc.) is mapped through a lookup table to a generic category (EDR, CNAPP, DAST, EASM) before any LLM call. Customers who consider their security stack commercially sensitive don't leak that information through this tool.

**BYOK for the LLM provider.** API keys live in your browser's localStorage and are sent directly from your browser to the LLM provider. The ExposureIQ backend never reads or stores LLM keys.

**Two explicit data paths leave the environment:**

1. **CVE enrichment.** The pipeline fetches `https://www.tenable.com/cve/{CVE-ID}` for each unique CVE it sees. Only the CVE ID is sent in the URL — no tenant data. Results are cached locally for `CVE_CACHE_TTL_DAYS` (default 7).
2. **AI Explanations.** Only when a user clicks the Explain button, and only with the privacy properties above applied. See [What data goes to the LLM](#what-data-goes-to-the-llm) below for the exact payload.

Everything else — assets, findings, plugin data, the joined database — stays on the host running this tool.

## Quick start

The recommended way to run ExposureIQ is as a Docker container. It bundles the backend, the built frontend, and all dependencies into a single image that serves both the UI and the API on one port.

### Prerequisites

- Docker Desktop (Mac/Windows) or Docker Engine (Linux)
- A Tenable One tenant with API credentials (Access Key + Secret Key)
- A user account with permission to read inventory assets and findings
- (Optional) An API key from Anthropic or Google AI Studio for the Explain feature

### 1. Clone and configure

    git clone <repo>
    cd exposureiq
    cp .env.example .env

Edit `.env` and fill in your Tenable API credentials. Other values have sensible defaults.

### 2. Build and run

    docker compose up -d --build

First build takes 2–3 minutes (downloads Node and Python base images, runs `npm ci` and `pip install`). Subsequent runs reuse the image and start in seconds.

Open `http://localhost:8000` in your browser. Click **Run pipeline** in the top-right of the status bar to trigger the first data pull (5–15 minutes on a cold cache; faster after).

The pipeline also runs automatically every 24 hours via the in-container scheduler. Change the schedule by setting `SCHEDULE_CRON` in `.env`.

### Updating to a new version

    git pull
    docker compose up -d --build

The SQLite database lives in a host-mounted `./data/` directory, so it survives container rebuilds and image updates.

## Running without Docker (for contributors)

If you're developing ExposureIQ rather than just running it, you can run the backend and frontend natively:

### Prerequisites

- Python 3.11+
- Node.js 22+
- Plus the Tenable credentials and optional LLM key as above

### Steps

    cp .env.example .env             # fill in Tenable credentials
    make install                     # backend and frontend deps
    make init-db                     # initialize ./data/enricher.db

In two terminals:

    # Terminal 1: backend
    make run-backend                 # FastAPI on :8000

    # Terminal 2: frontend
    make run-frontend                # Vite dev server on :5173

The Vite dev server proxies API calls to the backend, so open `http://localhost:5173` (not :8000) to get hot module reload.

Trigger an on-demand pipeline run with `make pull`, or click **Run pipeline** in the UI.

## AI Explanations

Each finding in the UI has an **Explain ✨** button. Clicking it opens a modal with structured, source-cited AI analysis.

### What you get

Every explanation has exactly five sections:

- **Summary** — one sentence: what the bug is, worst-case attacker impact
- **Mitigations** — 2–4 immediate stop-gap actions a defender can take right now to reduce risk before a permanent fix
- **Remediation** — the permanent fix (patch version, KB number, replacement component)
- **Asset context** — how the asset's category shapes the practical risk
- **Sources used** — explicit enumeration of every source cited above

Every recommendation has a source citation in parentheses — NVD, Tenable plugin research, CISA KEV, MITRE ATT&CK, or "General security best practice" when no specific authoritative source applies. The LLM is prompted to be honest about citation hygiene rather than mis-attribute generic advice to authoritative sources.

### Bring your own API key

Explanations require an API key from a supported LLM provider. **Your key lives in your browser's localStorage and is sent directly from your browser to the LLM provider.** The ExposureIQ backend never sees the key.

Supported providers:

| Provider | Default model | Cost per click | Where to get a key |
|---|---|---|---|
| **Anthropic Claude** | Claude Haiku 4.5 | ~$0.001 | [console.anthropic.com](https://console.anthropic.com/settings/keys) |
| **Google Gemini** | Gemini 2.5 Flash | ~$0.001 | [aistudio.google.com](https://aistudio.google.com/app/apikey) |

Configure in-app via the gear icon (top right). Switch providers at any time without touching code.

### What data goes to the LLM

When you click Explain, the following finding context is sent to your chosen provider:

- CVE ID
- CVE description (from Tenable's public CVE page)
- Asset OS family (e.g. "Windows", "Linux") — not the asset name or IP
- Source category (e.g. "EDR", "CNAPP") — not the vendor name
- Matched Tenable plugin family and remediation text (when available)

**What is explicitly NOT sent:**

- Asset name, FQDN, IP address, MAC address, or any identifying field
- Source connector vendor name (mapped to generic category before sending)
- Tag names or custom attributes
- VPR or CVSS scores (visible to humans in the UI as prioritization signals; not analytical context for the LLM)
- Other findings (each call is one finding at a time)

### Caching

Explanations are cached in your browser's localStorage, keyed by `cve_id::provider`. The same explanation applies regardless of which asset the CVE was found on (because the prompt is asset-agnostic), so a single cache entry serves all clicks for a given CVE. Re-clicking Explain on a CVE you've already explained is instant and costs nothing. Clear the cache from the gear icon when you want fresh responses.

### Compliance note

If your organization requires that no customer data train external models, both Anthropic and Google offer zero-retention enterprise tiers. Anthropic's is documented at [anthropic.com/legal/privacy](https://www.anthropic.com/legal/privacy). Configure your API key under the appropriate enterprise account; the tool's request format is unchanged.

## Configuration

All backend configuration is via environment variables. Copy `.env.example` to `.env` and fill in:

| Variable | Required | Description |
|---|---|---|
| `TENABLE_ACCESS_KEY` | yes | API access key from your Tenable user profile |
| `TENABLE_SECRET_KEY` | yes | API secret key |
| `TENABLE_BASE_URL` | no | Defaults to `https://cloud.tenable.com` |
| `DATABASE_PATH` | no | SQLite file location (default `./data/enricher.db`) |
| `CVE_CACHE_TTL_DAYS` | no | How long to trust a cached CVE record (default `7`) |
| `SCRAPER_USER_AGENT` | no | Identifies the tool to tenable.com |
| `SCRAPER_RATE_LIMIT_RPS` | no | Requests per second to tenable.com (default `2`) |
| `SCHEDULE_CRON` | no | Cron expression for the daily pull (default `0 2 * * *`) |
| `HOST` / `PORT` | no | FastAPI bind address (default `0.0.0.0:8000`) |
| `CORS_ORIGINS` | no | Comma-separated allowed origins (default `http://localhost:5173`) |
| `LOG_LEVEL` | no | Default `INFO` |

LLM API keys are **not** configured here — they are entered in the UI's Settings modal and stored in browser localStorage. The backend never reads or stores them.

## Architecture

See [EXPOSUREIQ_PLAN.md](EXPOSUREIQ_PLAN.md) for the full architecture document covering the pipeline stages, data model, AI Explain design, hard rules (documented APIs only, code-enforced privacy invariants), and source categorization mapping.

High-level overview:

- **Pipeline:** Source discovery → asset enrichment (`/api/v1/t1/inventory/assets/search` with `extra_properties`) → findings extraction → CVE enrichment (cached scrape of `tenable.com/cve/{ID}`) → plugin matching → SQLite storage
- **API:** FastAPI backend exposing `/api/findings`, `/api/sources`, `/api/stats`, `/api/progress`, etc.
- **UI:** React + Vite + Tailwind, single-page app with severity distribution chart, filterable findings table, on-demand Explain modal
- **Storage:** SQLite at `./data/enricher.db`. CVE intelligence and Tenable plugin data are cached and reused across pipeline runs.

## Development

    make lint            # ruff + mypy + eslint + tsc
    make test            # pytest backend + vitest frontend
    make format          # ruff format + prettier

Run `make` with no arguments for the full target list.

### Known dev-dependency advisories

Running `npm audit` will surface advisories in the Vite/esbuild dev toolchain. These affect the development server only — the static assets served from `frontend/dist/` after `npm run build` do not include esbuild or its dev-server. Customers running the production build are not exposed.

The flagged advisories are tracked upstream. Do not run `npm audit fix --force` — it will pull breaking changes in Vite that require config rewrites.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This is an independent tool that consumes data from Tenable One via supported APIs and from public CVE pages on `tenable.com`. It is not officially supported by Tenable.
