> ⚠️ This README describes the previous version. The tool is being reworked — see EXPOSUREIQ_PLAN.md for the current design.

# ExposureIQ for Tenable One

> A self-hosted remediation accelerator: pulls CVE-shaped findings from third-party connectors in Tenable One, joins them with Tenable's public CVE intelligence, and surfaces them in a filterable web UI with on-demand AI explanations.

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

## The problem

Tenable One ingests findings from third-party security tools (EDR, CSPM, cloud, SCA, etc.) so customers can see their full exposure picture in one place. When those third-party tools report findings as CVE identifiers, the CVEs arrive with the asset and severity, but without the deeper context that helps an analyst decide what to do — VPR, exploit availability, fix guidance, platform-specific remediation.

**ExposureIQ closes that workflow gap.** It pulls CVE-shaped findings from third-party connectors, joins each CVE against Tenable's public CVE database, matches each finding to the most appropriate Tenable plugin for its source platform, and presents the result in a filterable web UI. With an LLM API key, it can also generate a plain-language explanation of any finding on demand.

## How it's deployed

ExposureIQ is **self-hosted by the customer in their own environment.** Nothing about this tool runs on a Tenable-owned server. The customer:

- Clones the repo into their environment
- Configures their Tenable One API credentials
- Runs the pipeline and web UI locally (or on their own infrastructure)
- Optionally configures their own LLM provider API key for AI explanations

No customer data ever leaves their environment unless they explicitly opt in to AI explanations (see [Security & Data Flow](#security--data-flow) below).

## What it does

1. **Discovers** active third-party data sources in your Tenable One inventory
2. **Extracts** CVE-shaped findings from each source
3. **Enriches** each unique CVE with description, CVSS, VPR, and remediation guidance from `tenable.com/cve/{CVE-ID}`
4. **Matches** each finding to the Tenable plugin most appropriate for its source platform (Red Hat plugins for Red Hat findings, Microsoft plugins for Microsoft findings, etc.)
5. **Stores** the joined data in a local SQLite database
6. **Serves** a filterable, sortable, paginated web UI with severity distribution, source filtering, and JSON/CSV export
7. **Explains** any finding on demand using an LLM provider you configure (optional)

Runs daily by default. On-demand pulls via `make pull`.

## Quick start

The recommended way to run ExposureIQ is as a Docker container. It bundles
the backend, the built frontend, and all dependencies into a single image
that serves both the UI and the API on one port.

### Prerequisites

- Docker Desktop (Mac/Windows) or Docker Engine (Linux)
- A Tenable One tenant with API credentials (Access Key + Secret Key)
- A user account with permission to read inventory assets and findings
- (Optional) An API key from Anthropic or Google AI Studio for the Explain feature

### 1. Clone and configure

    git clone https://github.com/nreynolds-pub-git/exposureiq.git
    cd exposureiq
    cp .env.example .env

Edit `.env` and fill in your Tenable API credentials. Other values have
sensible defaults.

### 2. Build and run

    docker compose up -d --build

First build takes 2–3 minutes (downloads Node and Python base images, runs
`npm ci` and `pip install`). Subsequent runs reuse the image and start in
seconds.

Open `http://localhost:8000` in your browser. Click **Run pipeline** in the
top-right of the status bar to trigger the first data pull (5–15 minutes
on a cold cache; faster after).

The pipeline also runs automatically every 24 hours via the in-container
scheduler. Change the schedule by setting `SCHEDULE_CRON` in `.env`.

### Updating to a new version

    git pull
    docker compose up -d --build

The SQLite database lives in a host-mounted `./data/` directory, so it
survives container rebuilds and image updates.

## Running without Docker (for contributors)

If you're developing ExposureIQ rather than just running it, you can run
the backend and frontend natively:

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

The Vite dev server proxies API calls to the backend, so open
`http://localhost:5173` (not :8000) to get hot module reload.

Trigger an on-demand pipeline run with `make pull`, or click **Run
pipeline** in the UI.

## AI Explanations (Optional)

Each finding in the UI has an **Explain ✨** button. Clicking it opens a panel with a three-paragraph plain-language explanation: what the vulnerability is, why it matters on this specific asset, and how to fix it.

### Bring your own key

Explanations require an API key from a supported LLM provider. **Your key lives in your browser's localStorage and is sent directly from your browser to the LLM provider.** The ExposureIQ backend never sees the key.

Supported providers:

| Provider | Default model | Cost per click | Where to get a key |
|---|---|---|---|
| **Anthropic Claude** | Claude Haiku 4.5 | ~$0.001 | [console.anthropic.com](https://console.anthropic.com/settings/keys) |
| **Google Gemini** | Gemini 2.5 Flash | ~$0.001 | [aistudio.google.com](https://aistudio.google.com/app/apikey) |

Configure in-app via the gear icon (top right). Switch providers at any time without touching code.

### What data goes to the LLM

When you click Explain, the following finding context is sent to your chosen provider:

- CVE ID and description (from Tenable's public CVE page)
- Asset name
- Source connector name (e.g. "Red Hat Insights")
- Severity, VPR, and CVSSv3 scores
- The matched Tenable plugin family and remediation text

No raw tenant data, no API keys, no other findings. Each call is one finding at a time.

### Caching

Explanations are cached in your browser's localStorage, keyed by `cve_id::asset_name::provider`. Re-clicking Explain on a finding you've already explained is instant and costs nothing. Clear the cache from the gear icon when you want fresh responses.

### Compliance note

If your organization requires that no customer data train external models, both Anthropic and Google offer zero-retention enterprise tiers. Anthropic's is documented at [anthropic.com/legal/privacy](https://www.anthropic.com/legal/privacy). Configure your API key under the appropriate enterprise account; the tool's request format is unchanged.

## Security & Data Flow

This tool is designed to keep customer data inside the customer environment by default. Two paths data can leave your environment, both explicit and opt-in:

1. **CVE enrichment** — the pipeline fetches `https://www.tenable.com/cve/{CVE-ID}` for each unique CVE the first time it's seen. Only the CVE ID is sent in the URL. No tenant data is included. Results are cached locally for `CVE_CACHE_TTL_DAYS` (default 7).
2. **AI Explanations** — only when a user clicks the Explain button. See the previous section for the exact payload.

Everything else — assets, findings, plugin data, the joined database — stays on the host running this tool.

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


## Development

    make lint            # ruff + mypy + eslint + tsc
    make test            # pytest backend + vitest frontend
    make format          # ruff format + prettier

Run `make` with no arguments for the full target list.

## Known dev-dependency advisories

Running `npm audit` will surface advisories in the Vite/esbuild dev toolchain. These affect the development server only — the static assets served from `frontend/dist/` after `npm run build` do not include esbuild or its dev-server. Customers running the production build are not exposed.

The flagged advisories are tracked upstream. Do not run `npm audit fix --force` — it will pull breaking changes in Vite that require config rewrites.

## How CVE enrichment works

This tool uses the public Tenable CVE pages at `https://www.tenable.com/cve/{CVE-ID}` as its enrichment source. Behavior:

- Every CVE lookup is **cached** in SQLite, so the same CVE is fetched at most once per `CVE_CACHE_TTL_DAYS`
- The scraper is **rate-limited** (default 2 req/s) and identifies itself in the `User-Agent`
- `Retry-After` headers are respected
- If enrichment fails for a given CVE, the finding still appears in the UI with a `not enriched` flag — the rest of the pipeline keeps moving
- The plugin matcher then picks the most appropriate Tenable plugin per finding based on the source platform, so the remediation text in the UI matches what your customer's patching team will recognize

## Roadmap

- [x] Discovery, extraction, enrichment, filterable UI, JSON/CSV export
- [x] Multi-source pipeline (7 third-party sources)
- [x] Dark/light mode, server-side sort, pagination
- [x] AI explanations (Claude + Gemini, BYOK)
- [x] Containerized deployment (Dockerfile + docker-compose)
- [ ] Pipeline progress reporting (live status during long pulls)
- [ ] Per-asset finding history
- [ ] Trend deltas (new vs. resurfaced vs. fixed since last run)
- [ ] Plugin detail expand-on-click

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This is an independent tool that consumes data from Tenable One via supported APIs and from public CVE pages on `tenable.com`. It is not officially supported by Tenable.
