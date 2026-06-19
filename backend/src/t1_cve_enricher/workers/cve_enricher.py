"""CVE enricher worker.

Stage 3 of the pipeline. Walks the distinct CVE IDs in the `findings` table
and, for each one missing from the cache or with an expired cache entry,
fetches the Tenable CVE page and stores the parsed intel in `cve_intel`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog

from t1_cve_enricher.config import Settings
from t1_cve_enricher.db import get_connection
from t1_cve_enricher.tenable.cve_scraper import CveIntel, CveScraper

logger = structlog.get_logger(__name__)


def _find_cves_needing_enrichment(settings: Settings) -> list[str]:
    """Return CVE IDs present in findings but missing or stale in cve_intel."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.cve_cache_ttl_days)
    with get_connection(settings.database_path) as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT f.cve_id
            FROM findings f
            LEFT JOIN cve_intel c ON c.cve_id = f.cve_id
            WHERE c.cve_id IS NULL
               OR c.fetched_at < ?
               OR c.fetch_status = 'ERROR'
            ORDER BY f.cve_id
            """,
            (cutoff,),
        ).fetchall()
    return [r["cve_id"] for r in rows]


def _persist(settings: Settings, intel: CveIntel) -> None:
    """Upsert a CveIntel record."""
    with get_connection(settings.database_path) as conn:
        conn.execute(
            """
            INSERT INTO cve_intel (
                cve_id, description, cvss3_base_score, cvss3_severity,
                cvss2_base_score, cvss2_severity, vpr_score, vpr_severity,
                epss_score, remediation, published_date, last_modified_date,
                raw_html, fetched_at, fetch_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description = excluded.description,
                cvss3_base_score = excluded.cvss3_base_score,
                cvss3_severity = excluded.cvss3_severity,
                cvss2_base_score = excluded.cvss2_base_score,
                cvss2_severity = excluded.cvss2_severity,
                vpr_score = excluded.vpr_score,
                vpr_severity = excluded.vpr_severity,
                epss_score = excluded.epss_score,
                remediation = excluded.remediation,
                published_date = excluded.published_date,
                last_modified_date = excluded.last_modified_date,
                raw_html = excluded.raw_html,
                fetched_at = excluded.fetched_at,
                fetch_status = excluded.fetch_status
            """,
            (
                intel.cve_id,
                intel.description,
                intel.cvss3_base_score,
                intel.cvss3_severity,
                intel.cvss2_base_score,
                intel.cvss2_severity,
                intel.vpr_score,
                intel.vpr_severity,
                intel.epss_score,
                intel.remediation,
                intel.published_date,
                intel.last_modified_date,
                intel.raw_html,
                intel.fetched_at,
                intel.fetch_status,
            ),
        )


async def run(settings: Settings) -> int:
    """Enrich all stale or missing CVEs. Returns the count enriched."""
    cves = _find_cves_needing_enrichment(settings)
    logger.info("cve_enricher: started", count=len(cves))

    enriched = 0
    async with CveScraper(settings) as scraper:
        for cve_id in cves:
            intel = await scraper.fetch_one(cve_id)
            _persist(settings, intel)
            if intel.fetch_status == "OK":
                enriched += 1

    logger.info("cve_enricher: finished", enriched=enriched, total=len(cves))
    return enriched
