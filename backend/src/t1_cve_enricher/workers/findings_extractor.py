"""Findings extractor worker.

Stage 2 of the pipeline. For each known third-party source, pulls CVE-shaped
findings via the async export API and writes them to the local DB.

A finding is considered "CVE-shaped" when its detection name matches the
pattern CVE-YYYY-NNNN+. Other findings (Nessus plugins, OT detections, etc.)
are out of scope for this tool.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any

import structlog

from t1_cve_enricher.config import Settings
from t1_cve_enricher.db import get_connection
from t1_cve_enricher.tenable.client import TenableClient

logger = structlog.get_logger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _is_cve_shaped(finding: dict[str, Any]) -> bool:
    name = finding.get("finding_detection_name") or finding.get("finding_name") or ""
    return bool(CVE_PATTERN.match(name.strip()))


async def run(settings: Settings, sources: list[str]) -> int:
    """Pull CVE findings for each source. Returns total findings pulled."""
    logger.info("findings_extractor: started", source_count=len(sources))

    # Process sources concurrently — one task per source.
    tasks = [_pull_one_source(settings, src) for src in sources]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    total = 0
    for src, result in zip(sources, results, strict=False):
        if isinstance(result, Exception):
            logger.error("source failed", source=src, error=str(result))
            continue
        total += result

    logger.info("findings_extractor: finished", total=total)
    return total


async def _pull_one_source(settings: Settings, source: str) -> int:
    """Pull and persist findings for a single source."""
    logger.info("pulling source", source=source)
    async with TenableClient(settings) as client:
        findings = await client.export_findings(source)

    cve_findings = [f for f in findings if _is_cve_shaped(f)]
    logger.info(
        "filtered findings",
        source=source,
        total=len(findings),
        cve_shaped=len(cve_findings),
    )

    now = datetime.now(timezone.utc)
    with get_connection(settings.database_path) as conn:
        for f in cve_findings:
            asset = f.get("asset", {})
            asset_id = f["asset_id"]
            conn.execute(
                """
                INSERT INTO assets (asset_id, asset_name, source, asset_class,
                                    ipv4, fqdn, last_synced)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    asset_name = excluded.asset_name,
                    last_synced = excluded.last_synced
                """,
                (
                    asset_id,
                    asset.get("asset_name") or f.get("asset_name"),
                    source,
                    asset.get("asset_class"),
                    ",".join(asset.get("ipv4_addresses", [])) or None,
                    ",".join(asset.get("fqdns", [])) or None,
                    now,
                ),
            )
            cve_id = (f.get("finding_detection_name") or "").upper()
            conn.execute(
                """
                INSERT INTO findings (finding_id, asset_id, cve_id, severity, state,
                                      first_observed, last_observed, source, last_synced)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    severity = excluded.severity,
                    state = excluded.state,
                    last_observed = excluded.last_observed,
                    last_synced = excluded.last_synced
                """,
                (
                    f["finding_id"],
                    asset_id,
                    cve_id,
                    f.get("finding_severity"),
                    f.get("state"),
                    f.get("first_observed_at"),
                    f.get("last_observed_at"),
                    source,
                    now,
                ),
            )

    return len(cve_findings)
