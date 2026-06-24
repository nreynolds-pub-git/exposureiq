---
name: "ExposureIQ for Tenable One"
author: "nreynolds-pub-git"
github_url: "https://github.com/nreynolds-pub-git/exposureiq"
description: "Self-hosted tool that enriches third-party CVE findings from Tenable One with VPR, remediation guidance, and AI explanations"
license: "MIT"
type: "tool"
tier: "unreviewed"
tags: ["vulnerability-management", "cve-enrichment", "tenable", "fastapi", "self-hosted", "ai-explanations"]
framework: "Custom"
integrations: ["Anthropic", "AWS Security Hub", "Cisco", "CrowdStrike", "Fortinet", "Microsoft Sentinel", "Netskope", "NVD", "PagerDuty", "Palo Alto", "Qualys", "Rapid7", "SentinelOne", "ServiceNow", "Snyk", "Splunk", "Tenable", "Wiz"]
date_added: 2026-06-24
---

ExposureIQ is a self-hosted remediation accelerator that closes the workflow gap when third-party security tools report findings to Tenable One as CVE identifiers. It pulls CVE-shaped findings from connectors, enriches them with Tenable's public CVE intelligence, matches each to the appropriate Tenable plugin, and surfaces everything in a filterable web UI with optional AI-powered explanations.

## What it does

- **Discovers** active third-party data sources in your Tenable One inventory
- **Extracts** CVE-shaped findings from each source  
- **Enriches** each unique CVE with description, CVSS, VPR, and remediation guidance from Tenable's public CVE database
- **Matches** findings to the most appropriate Tenable plugin based on source platform (Red Hat plugins for Red Hat findings, Microsoft plugins for Microsoft findings, etc.)
- **Serves** a filterable, sortable web UI with severity distribution, source filtering, and JSON/CSV export
- **Explains** any finding on demand using your choice of LLM provider (Anthropic Claude or Google Gemini)

Runs on a daily schedule by default, with on-demand pulls available via CLI.

## How it works

ExposureIQ is fully self-hosted in the customer's environment. Nothing runs on external servers — all processing, storage, and analysis happens locally. The tool uses FastAPI for the backend, React for the frontend, and SQLite for data persistence.

The pipeline fetches findings via Tenable One's API, enriches each unique CVE by scraping Tenable's public CVE pages (with caching and rate-limiting), and stores the joined data locally. The optional AI explanation feature runs entirely in the browser using BYOK (bring your own key) — API keys stay in localStorage and go directly from browser to LLM provider, never touching the backend.

Customers can deploy with Docker Compose (single command) or run backend and frontend separately for development. All configuration is via environment variables, with sensible defaults for everything except Tenable API credentials.
