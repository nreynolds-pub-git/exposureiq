"""Source discovery worker.

Stage 1 of the pipeline. Queries Tenable One inventory for the distinct set of
third-party sources currently producing assets, and upserts them to the
`sources` table with first_seen / last_seen tracking.

Runs once per pipeline execution.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from t1_cve_enricher.config import Settings
from t1_cve_enricher.db import get_connection
from t1_cve_enricher.tenable.client import TenableClient

logger = structlog.get_logger(__name__)


async def run(settings: Settings) -> list[str]:
    """Discover third-party sources in Tenable One. Returns the list of names."""
    logger.info("source_discovery: started")
    async with TenableClient(settings) as client:
        sources = await client.list_sources()

    now = datetime.now(UTC)
    names: list[str] = []
    with get_connection(settings.database_path) as conn:
        for src in sources:
            name = src["value"]  # API filter identifier (e.g. RED-HAT:VM)
            display_name = src.get("name", "")  # human-readable (e.g. "Red Hat Insights")
            asset_count = src.get("asset_count", 0)
            conn.execute(
                """
                INSERT INTO sources (name, display_name, first_seen, last_seen, asset_count)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    display_name = excluded.display_name,
                    last_seen = excluded.last_seen,
                    asset_count = excluded.asset_count
                """,
                (name, display_name, now, now, asset_count),
            )
            names.append(name)

    logger.info("source_discovery: finished", count=len(names))
    return names
