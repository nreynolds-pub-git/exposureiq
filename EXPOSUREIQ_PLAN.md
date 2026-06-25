# ExposureIQ — Architecture & Design

ExposureIQ is an AI-powered mitigation guidance tool for vulnerability findings
in Tenable One. It pulls findings via Tenable's documented APIs, presents them
in a unified UI, and provides on-demand AI explanations focused on what a
defender can do right now to reduce risk.

## What it is

A self-hosted FastAPI + React tool that:

1. Discovers third-party connectors in a Tenable One tenant
2. Pulls CVE-shaped findings via documented Tenable APIs
3. Presents them in a filterable, sortable, exportable web UI
4. On demand, generates structured AI explanations with explicit source citations

Built for any Tenable One user. BYOK for the LLM provider.

## What makes it different

**Mitigation-first AI guidance.** Most vulnerability tooling tells you the
remediation: "upgrade to version X." That's useful in three weeks. ExposureIQ
leads with mitigations — firewall rules, segmentation, service flags,
monitoring — that reduce risk before a patch is possible.

**Source-cited recommendations.** Every line in an AI explanation points to
its origin (NVD CVE description, Tenable plugin, CISA KEV, MITRE ATT&CK) so
analysts can verify before they act.

**Privacy by design.** No asset identifiers (names, IPs, FQDNs, MACs) ever
leave the user's environment. Source connectors are anonymized to industry
categories before reaching the LLM. Explain output is identical regardless of
which asset a finding affects.

## Architecture

### Pipeline

The background pipeline runs daily (and on demand):

1. **Source discovery** — `GET /api/v1/t1/inventory/assets/properties`, walk
   the `products` enum, keep third-party connectors with non-zero asset counts
2. **Asset enrichment** — `POST /api/v1/t1/inventory/assets/search` with
   `?extra_properties=ipv4_addresses,fqdns,first_observed_at,last_observed_at,device_system_type`
   to capture IPv4, FQDN, observation dates, and OS
3. **Findings extraction** — `POST /api/v1/t1/inventory/findings/search` with
   `?extra_properties=finding_description,finding_vpr_score,finding_vpr2_score,finding_cves,finding_detection_id,first_observed_at,last_observed_at`
   to capture rich finding context including the Tenable-curated description
4. **Plugin matching** — for each CVE, look up the most relevant Tenable plugin
   (matched to the source platform) for canonical remediation text
5. **Storage** — SQLite tables: `sources`, `assets`, `findings`, `plugins`,
   `cve_plugins`, `pull_jobs`, `pipeline_progress`

### Data model

- **Finding** = an instance of a CVE on a specific asset (per Tenable's data model)
- **Asset** = a thing in the customer's environment that has findings
- **Plugin** = Tenable's canonical research artifact about a CVE; carries remediation text
- **CVE** is the join key between findings and plugins

Findings can reference multiple CVEs via the `finding_cves` array; ExposureIQ
explodes these to one row per (finding, cve) for clean joining.

### AI Explain

Triggered per-finding by the user. The Explain endpoint:

1. Reads finding context from the local DB
2. Constructs a sanitized payload (categorical asset info only, vendor anonymized)
3. Sends to the user's chosen LLM provider with the user's API key (BYOK)
4. Streams a structured response back to the UI

#### Payload sent to LLM

Always included:
- CVE ID
- CVE description (from `finding_description`)
- Asset categorical info: `os_family`, `asset_class`, `source_category`
- `has_vendor_remediation: bool` and `remediation_summary` (5-15 word headline
  extracted from the matched Tenable plugin's solution text)

Never included:
- Asset name, FQDN, IPv4, IPv6, MAC, or any other identifying field
- Connector vendor name (always mapped through `source_category.py`)
- Tag names, custom attributes
- VPR (used for UI prioritization, not LLM context)
- Full plugin solution text (cost; the headline anchors fix identifiers without bloat)

This is a code-enforced invariant. Sanitization happens at the Explain call
site, not by convention.

#### Output structure

The LLM is prompted to produce:

    Summary (1-2 sentences, plain English)

    MITIGATIONS (immediate stop-gap actions)
    - [action] — Source: [specific input or reference]
    - [action] — Source: ...

    REMEDIATION (permanent fix)
    - [action] — Source: ...

    ASSET-SPECIFIC CONTEXT (1-2 sentences, categorical only)

    SOURCES USED
    - [enumeration of cited sources]

Mitigations are ranked first. Every line item must cite its source.

### Source categorization (vendor anonymization)

File: `backend/src/t1_cve_enricher/llm/source_category.py`

Connector codes are mapped to generic industry categories before any AI call:

    SOURCE_CATEGORIES = {
        "MICROSOFT:TVM": "EDR",
        "SENTINEL-ONE:EDR": "EDR",
        "JAMF:EDR": "EDR",
        "ORCA:CSPM": "CNAPP",
        "WIZ:CONFIGURATION": "CNAPP",
        "WIZ:ISSUES": "CNAPP",
        "WIZ:VM": "CNAPP",
        "PALO-ALTO-NETWORKS:CSPM": "CNAPP",
        "PRISMA-CLOUD:CSPM": "CNAPP",
        "CY-COGNITO:DAST": "EASM",
        "MASTERCARD:DAST": "DAST",
        "INVICTI:WHITEHAT-DAST": "DAST",
        "SECURITY-SCORECARD:DAST": "Third-party risk rating",
        "RISK-RECON:RR": "Third-party risk rating",
        "RED-HAT:VM": "OS vulnerability scanner",
        "AWS:AINV": "Cloud inventory",
        "SNYK:SNYK": "SCA",
        "SERVICE-NOW:AINV": "CMDB",
    }
    # Default fallback: "Third-party security tool"

Add new connectors as they're encountered. Never let a vendor code reach the LLM.

## Hard rules

1. **Documented Tenable APIs only.** Specifically the `/api/v1/` surface. No
   internal endpoints (`/one/cam/v1/*`), no scraping, no UI-only routes.
2. **No asset identifiers in LLM payloads.** Code-enforced at the call site.
3. **No vendor names in LLM payloads.** Always map through `SOURCE_CATEGORIES`.
4. **BYOK for LLM.** Backend never holds an LLM API key.

## Scope

ExposureIQ targets **NVD-prefixed CVE weaknesses** (`NVD:CVE-*`).

Tenable One also exposes TVC-prefixed weaknesses — misconfigurations, malware
detections, subdomain takeovers, and other non-CVE findings. These are out of
scope. They're a different mitigation domain and benefit from different LLM
prompting; trying to handle both in one tool dilutes both.

## Resilience

The Tenable client honors `Retry-After` headers on 429 responses, with
tenacity-based exponential backoff (6 attempts, max 60s wait). This is
necessary for enterprise tenants with many connectors — pulling several
sources in parallel routinely triggers rate limits, and naive
fail-on-first-429 leaves most sources unprocessed.

## Deployment

Single Docker container. Three commands from clone to running:

    git clone <repo>
    cd exposureiq
    cp .env.example .env   # fill in Tenable API credentials

    docker compose up -d --build

    open http://localhost:8000

Click "Run pipeline" once. Daily auto-pulls thereafter. Click "Explain" on any
finding for AI mitigation guidance.

## Pitch reference

`ExposureIQ_for_Tenable_One.pptx` — five-slide deck for internal Tenable
audiences and customer-facing POV demos. The deck is the forcing function:
anything that ships under ExposureIQ must deliver on its slide 3 (MITIGATE /
REMEDIATE / CITE) and slide 4 (privacy by design).
