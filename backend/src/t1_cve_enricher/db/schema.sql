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
    last_synced TIMESTAMP NOT NULL,
    FOREIGN KEY (source) REFERENCES sources(name)
);

CREATE INDEX IF NOT EXISTS idx_assets_source ON assets(source);
CREATE INDEX IF NOT EXISTS idx_assets_name ON assets(asset_name);

-- CVE-shaped findings attached to assets
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT,
    state TEXT,
    first_observed TIMESTAMP,
    last_observed TIMESTAMP,
    source TEXT NOT NULL,
    last_synced TIMESTAMP NOT NULL,
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
