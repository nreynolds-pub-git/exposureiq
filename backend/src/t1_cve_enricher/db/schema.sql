-- =============================================================================
-- t1-cve-enricher schema
-- All statements are idempotent (CREATE IF NOT EXISTS) so the DB can be
-- initialised by running this file repeatedly.
-- =============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- Third-party data sources discovered in Tenable One
CREATE TABLE IF NOT EXISTS sources (
    name TEXT PRIMARY KEY,
    -- Human-readable label (e.g. "Red Hat Insights"). Populated by
    -- source_discovery from the connector's `name` field, distinct from
    -- the machine-readable `name` column (e.g. "RED-HAT:VM"). Nullable
    -- because older rows created before this column existed have NULL,
    -- and because we don't want the INSERT to hard-fail if Tenable ever
    -- returns a source without a human-readable name.
    display_name TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    asset_count INTEGER NOT NULL DEFAULT 0
);

-- Assets from third-party sources
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    asset_name TEXT,
    source TEXT NOT NULL,
    asset_class TEXT,
    ipv4 TEXT,
    fqdn TEXT,
    operating_system TEXT,
    last_synced TIMESTAMP NOT NULL,
    FOREIGN KEY (source) REFERENCES sources(name)
);

CREATE INDEX IF NOT EXISTS idx_assets_source ON assets(source);
CREATE INDEX IF NOT EXISTS idx_assets_name ON assets(asset_name);

-- CVE-shaped findings attached to assets
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT,
    state TEXT,
    first_observed TIMESTAMP,
    last_observed TIMESTAMP,
    source TEXT NOT NULL,
    -- VPR scores live on the finding (per Tenable's data model) — sourced
    -- from findings/search extra_properties, refreshed every pipeline run.
    vpr_score REAL,
    vpr2_score REAL,
    -- Tenable-curated finding description, also from findings/search.
    -- Distinct from cve_intel.description (NVD-style, from scraper):
    -- this is the per-finding Tenable interpretation.
    finding_description TEXT,
    last_synced TIMESTAMP NOT NULL,
    -- Composite primary key: one finding can reference multiple CVEs
    -- (the finding_cves array). We explode to one row per (finding, cve).
    PRIMARY KEY (finding_id, cve_id),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);

-- CVE intelligence cached from tenable.com/cve/{CVE-ID}
CREATE TABLE IF NOT EXISTS cve_intel (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss3_base_score REAL,
    cvss3_severity TEXT,
    cvss2_base_score REAL,
    cvss2_severity TEXT,
    vpr_score REAL,
    vpr_severity TEXT,
    epss_score REAL,
    remediation TEXT,
    published_date TEXT,
    last_modified_date TEXT,
    raw_html TEXT,
    fetched_at TIMESTAMP NOT NULL,
    plugin_search_attempted_at TIMESTAMP,
    fetch_status TEXT NOT NULL DEFAULT 'OK'  -- OK / NOT_FOUND / ERROR
);

CREATE INDEX IF NOT EXISTS idx_cve_intel_fetched_at ON cve_intel(fetched_at);

-- Pipeline run history
CREATE TABLE IF NOT EXISTS pull_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    status TEXT NOT NULL,            -- RUNNING / SUCCESS / FAILED / PARTIAL
    sources_processed INTEGER NOT NULL DEFAULT 0,
    findings_pulled INTEGER NOT NULL DEFAULT 0,
    cves_enriched INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_pull_jobs_started_at ON pull_jobs(started_at DESC);

-- =============================================================================
-- Plugin enrichment (v2 feature) -- added in plugin-enricher session
-- =============================================================================
CREATE TABLE IF NOT EXISTS plugins (
    plugin_id TEXT PRIMARY KEY,
    script_name TEXT,
    script_family TEXT,
    plugin_type TEXT,
    synopsis TEXT,
    description TEXT,
    solution TEXT,
    vpr_score REAL,
    vpr_severity TEXT,
    risk_factor TEXT,
    severity TEXT,
    cvss3_severity TEXT,
    cvss2_severity TEXT,
    cisa_known_exploited_date TEXT,
    plugin_publication_date TEXT,
    plugin_modification_date TEXT,
    raw_json TEXT,
    fetched_at TIMESTAMP NOT NULL,
    fetch_status TEXT NOT NULL DEFAULT 'OK'
);

CREATE INDEX IF NOT EXISTS idx_plugins_family ON plugins(script_family);
CREATE INDEX IF NOT EXISTS idx_plugins_type ON plugins(plugin_type);
CREATE INDEX IF NOT EXISTS idx_plugins_vpr ON plugins(vpr_score);
CREATE INDEX IF NOT EXISTS idx_plugins_risk ON plugins(risk_factor);
CREATE INDEX IF NOT EXISTS idx_plugins_kev ON plugins(cisa_known_exploited_date) WHERE cisa_known_exploited_date IS NOT NULL;

CREATE TABLE IF NOT EXISTS cve_plugins (
    cve_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, plugin_id)
);

CREATE INDEX IF NOT EXISTS idx_cve_plugins_cve ON cve_plugins(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_plugins_plugin ON cve_plugins(plugin_id);

-- =============================================================================
-- Live pipeline progress (single-row table)
-- The CHECK(id=1) constraint enforces "at most one row" so workers can do
-- simple UPDATE WHERE id=1 without managing row lifecycle. The /api/progress
-- endpoint reads this row; the UI polls every ~2s while is_running=1.
-- =============================================================================
CREATE TABLE IF NOT EXISTS pipeline_progress (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    is_running INTEGER NOT NULL DEFAULT 0,
    stage TEXT NOT NULL DEFAULT 'idle',
    source TEXT,
    current_n INTEGER NOT NULL DEFAULT 0,
    total_n INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    started_at TIMESTAMP,
    updated_at TIMESTAMP
);

INSERT OR IGNORE INTO pipeline_progress (id, stage) VALUES (1, 'idle');
