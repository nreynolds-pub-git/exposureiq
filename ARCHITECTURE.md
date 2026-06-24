# Architecture

This document explains how ExposureIQ is put together, why it's shaped this way, and where the seams are if you want to extend it.

## Mental model

This is a **scheduled ETL pipeline with a web frontend**, not a swarm of autonomous agents. The work is largely deterministic: fetch, look up, join, render. Framing it as ETL makes it cheaper to operate, easier to debug, and trivially restartable. The roadmap leaves room for an LLM-powered layer on top (natural-language query, synthesized remediation) where that judgment work actually earns its keep — see the README roadmap.

## Pipeline stages

```
┌──────────────────┐   ┌───────────────────┐   ┌────────────────────┐   ┌────────────┐   ┌──────┐
│ 1. Source        │──▶│ 2. Findings       │──▶│ 3. CVE             │──▶│ 4. Joiner  │──▶│ DB   │
│    Discovery     │   │    Extraction     │   │    Enrichment      │   │            │   │      │
└──────────────────┘   └───────────────────┘   └────────────────────┘   └────────────┘   └──────┘
        │                       │                       │
   reads Tenable           reads Tenable One       reads tenable.com/cve
   One inventory.          findings for each       (cached, rate-limited,
   Lists distinct          discovered source.      identified in UA).
   "sources" with          Filters to              Falls back gracefully.
   active assets.          CVE-shaped findings.
```

### 1. Source discovery (`workers/source_discovery.py`)

Queries Tenable One's inventory API for the distinct set of `sources` / `products` currently producing assets. Writes the result to the `sources` table with `first_seen` / `last_seen` timestamps. Runs once per pipeline execution.

**Why a dedicated stage:** sources can come and go (a customer enables a new connector mid-quarter). Decoupling discovery from extraction means a new source is picked up automatically — no code or config changes needed.

### 2. Findings extraction (`workers/findings_extractor.py`)

For each source from stage 1, paginates findings via the async export API (`tenable_one_export_inventory`). Filters to findings whose `finding_detection_name` looks like a CVE identifier (`CVE-\d{4}-\d{4,}`). Writes assets and findings to local tables, keyed by `finding_id` (idempotent — re-runs update `last_synced` and `state`).

**Scale note.** A single source can produce tens of thousands of findings. The async export is the right API for this — it chunks server-side and we stream chunks down. Synchronous search isn't viable at this volume.

**Worker pool design.** One worker process per source, parameterized by source name. Sources are isolated — a slow or failing source doesn't block others.

### 3. CVE enrichment (`workers/cve_enricher.py`)

Walks the distinct CVE IDs in the `findings` table, checks `cve_intel` for a cached record within TTL, and fetches missing or stale records from `https://www.tenable.com/cve/{CVE-ID}`. Parses out:

- Description
- CVSSv2 / CVSSv3 base scores and severities
- VPR score and severity
- EPSS score (when present)
- Remediation summary
- Published / last-modified dates

Stores parsed fields plus the raw HTML in `cve_intel` (raw HTML for audit / re-parsing if our scraper improves).

**Cache strategy.** TTL of 7 days by default. The same CVE typically appears on many assets across many sources, so cache hit rate quickly approaches 100% in steady state.

**Politeness.**

- Identifying `User-Agent` (`exposureiq/0.1 (+github.com/nreynolds-pub-git/exposureiq)`)
- Rate-limited (configurable, default 2 req/s)
- Honors `Retry-After`
- Fails soft: a CVE that fails to enrich still appears in the UI, flagged

**Future replacement.** When Tenable's Vulnerability Intelligence API becomes available to customers, only this stage changes. The cache layer, schema, and downstream consumers stay as-is. That isolation is intentional.

### 4. Joiner & API (`api/routes.py`, `joiner.py`)

The joiner isn't a separate batch step — it's a query. The API endpoints `LEFT JOIN findings → assets → cve_intel` on demand, so the UI always reflects the latest state. SQLite handles this comfortably for the data sizes we expect (millions of finding rows is fine).

## Data model

```sql
sources(name PK, first_seen, last_seen, asset_count)

assets(asset_id PK, asset_name, source FK→sources, asset_class,
       ipv4, fqdn, last_synced)

findings(finding_id PK, asset_id FK→assets, cve_id, severity, state,
         first_observed, last_observed, source, last_synced)

cve_intel(cve_id PK, description, cvss3_base_score, cvss3_severity,
          cvss2_base_score, cvss2_severity, vpr_score, vpr_severity,
          epss_score, remediation, published_date, last_modified_date,
          raw_html, fetched_at)

pull_jobs(id PK, started_at, completed_at, status,
          sources_processed, findings_pulled, cves_enriched,
          error_message)
```

Indexes on `findings(cve_id)`, `findings(asset_id)`, `findings(source)`, and `findings(severity)` keep filter queries fast.

## API surface

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Liveness probe |
| `GET` | `/api/sources` | List discovered third-party sources |
| `GET` | `/api/findings` | Filterable enriched findings list (paginated) |
| `GET` | `/api/findings/export` | Same filters, returns CSV or JSON |
| `GET` | `/api/cve/{cve_id}` | Full CVE intel record |
| `GET` | `/api/stats` | Severity distribution for the header chart (respects filters) |
| `POST` | `/api/refresh` | Trigger an on-demand pipeline run |
| `GET` | `/api/jobs` | Recent pull job history |

Filters accepted on `/api/findings`, `/api/findings/export`, and `/api/stats`:

- `source` (repeatable)
- `cve` (repeatable, exact match)
- `asset` (substring match on asset name / FQDN / IP)
- `severity` (repeatable)
- `state` (repeatable)
- `enriched` (boolean — only / exclude CVEs we couldn't enrich)

## Frontend

Single-page Vite + React + TypeScript + Tailwind app. State management is lightweight (React Query for server state, useState for UI state — no Redux, no Zustand).

Brand tokens (Tenable Soft Black, White, Highlight Yellow, plus the data palette) are defined in `tailwind.config.js` and used throughout.

Severity color mapping for the chart, chosen against the Tenable data palette and accessibility constraints (no yellow text on white, etc.):

| Severity | Color | Hex |
|---|---|---|
| Critical | Orange | `#FF8837` |
| High | Highlight Yellow | `#E7FF00` |
| Medium | Blue | `#4EA5FF` |
| Low | Green | `#71FFC6` |
| Info | Gray | `#44494B` |

## Deployment shape

Customer-hosted, single tenant. Container-friendly via `docker-compose.yml`. SQLite file is mounted as a volume so the cache survives container rebuilds.

For air-gapped or proxy-restricted environments, the `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` env vars are honored end-to-end so customers can point at their corporate cert bundle without code changes.

## Design decisions worth knowing

**Why SQLite, not Postgres.** Single-tenant, single-host, <10M rows. SQLite is faster to deploy, has zero ops, and is plenty for this workload. The DAL is thin enough that swapping to Postgres later is a couple hours of work if needed.

**Why scrape, not API.** Tenable's Vulnerability Intelligence isn't exposed via API today. Scraping the public CVE pages is the pragmatic path. The cache means request volume to `tenable.com` is small and gets smaller over time.

**Why one process per source instead of one process for all.** Isolation. A slow or broken source can't block others. Adding a new source is a config entry, not a code change.

**Why not a true agent framework.** The work is deterministic. Pretending it's agentic would add cost and debugging overhead with no benefit. The agentic layer in the roadmap is for tasks that *are* genuinely judgment-driven (NL query, remediation synthesis from sparse data).
