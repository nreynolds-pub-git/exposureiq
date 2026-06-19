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
