"""Findings extractor worker.

Stage 2 of the pipeline. For each known third-party source:

  1. Pull full asset records for that source (asset search endpoint)
  2. Pull CVE-shaped findings for that source (findings export endpoint)
  3. Join in memory by asset_id
  4. Upsert both into the local DB

We do these as separate queries because each endpoint returns the data it's
designed to return — asset search has asset attributes (name, IP, FQDN),
findings export has finding attributes (CVE, severity, state). The export
chunks we observed via MCP didn't always include rich asset metadata.
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from typing import Any

import structlog

from t1_cve_enricher.config import Settings
from t1_cve_enricher.db import get_connection
from t1_cve_enricher.workers import progress
from t1_cve_enricher.tenable.client import (
    INVENTORY_ASSETS_SEARCH,
    TenableClient,
)

logger = structlog.get_logger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _extract_cve_id(finding: dict[str, Any]) -> str | None:
    """Pull the CVE ID out of a finding record, or None if it isn't CVE-shaped."""
    candidates = [
        finding.get("finding_detection_name"),
        finding.get("finding_name"),
        finding.get("detection_name"),
        finding.get("name"),
    ]
    for c in candidates:
        if c and CVE_PATTERN.match(str(c).strip()):
            return str(c).strip().upper()
    return None


async def _pull_assets_for_source(client: TenableClient, source: str) -> dict[str, dict[str, Any]]:
    """Return assets keyed by asset_id for a given source."""
    assets: dict[str, dict[str, Any]] = {}
    offset = 0
    page_size = 500
    while True:
        body = {
            "filters": [{"property": "products", "operator": "=", "value": [source]}],
            "limit": page_size,
            "offset": offset,
        }
        data = await client._request("POST", INVENTORY_ASSETS_SEARCH, json_body=body)
        if not isinstance(data, dict):
            break
        records = data.get("assets") or data.get("data") or data.get("records") or []
        for asset in records:
            asset_id = asset.get("asset_id") or asset.get("id")
            if asset_id:
                assets[asset_id] = asset
        total = int(data.get("total", data.get("totalCount", 0)) or 0)
        offset += len(records)
        if not records or offset >= total:
            break
    return assets


def _asset_field(asset: dict[str, Any], *keys: str) -> Any:
    """Try multiple key variants and return the first non-empty value."""
    for k in keys:
        v = asset.get(k)
        if v not in (None, "", []):
            return v
    return None


def _join_arr(value: Any) -> str | None:
    """Comma-join an array-shaped field, or pass through a string."""
    if value is None:
        return None
    if isinstance(value, list):
        return ",".join(str(v) for v in value) or None
    return str(value)


async def run(settings: Settings, sources: list[str]) -> int:
    """Pull CVE findings for each source. Returns total findings persisted."""
    logger.info("findings_extractor: started", source_count=len(sources))
    progress.begin("extraction", total=len(sources), message=f"Pulling findings from {len(sources)} sources")

    # Each source pull happens in parallel; we tick the completion counter as
    # individual tasks finish so the UI sees real progress, not "0 -> done".
    completed = 0
    lock = asyncio.Lock()

    async def _tracked(src: str) -> int:
        nonlocal completed
        try:
            return await _pull_one_source(settings, src)
        finally:
            async with lock:
                completed += 1
                progress.tick(
                    completed,
                    message=f"Processed {completed}/{len(sources)} sources (just finished {src})",
                )

    tasks = [_tracked(src) for src in sources]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    total = 0
    for src, result in zip(sources, results, strict=False):
        if isinstance(result, Exception):
            logger.error("source failed", source=src, error=str(result))
            continue
        total += result  # type: ignore[operator]  # narrowed by isinstance check above

    logger.info("findings_extractor: finished", total=total)
    return total


async def _pull_one_source(settings: Settings, source: str) -> int:
    """Pull and persist data for a single source."""
    logger.info("pulling source", source=source)
    async with TenableClient(settings) as client:
        assets = await _pull_assets_for_source(client, source)
        asset_ids = list(assets.keys())
        if not asset_ids:
            logger.warning("source has no assets; skipping findings export", source=source)
            return 0
        findings = await client.export_findings(asset_ids=asset_ids)

    cve_findings = []
    for f in findings:
        cve_id = _extract_cve_id(f)
        if cve_id:
            f["_cve_id"] = cve_id
            cve_findings.append(f)

    logger.info(
        "filtered findings",
        source=source,
        assets=len(assets),
        total_findings=len(findings),
        cve_findings=len(cve_findings),
    )

    now = datetime.now(UTC)
    persisted = 0
    with get_connection(settings.database_path) as conn:
        # Upsert assets first
        for asset_id, asset in assets.items():
            conn.execute(
                """
                INSERT INTO assets (asset_id, asset_name, source, asset_class,
                                    ipv4, fqdn, last_synced)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    asset_name = excluded.asset_name,
                    asset_class = excluded.asset_class,
                    ipv4 = excluded.ipv4,
                    fqdn = excluded.fqdn,
                    last_synced = excluded.last_synced
                """,
                (
                    asset_id,
                    _asset_field(asset, "asset_name", "name"),
                    source,
                    _asset_field(asset, "asset_class", "class"),
                    _join_arr(_asset_field(asset, "ipv4_addresses", "ipv4")),
                    _join_arr(_asset_field(asset, "fqdns", "fqdn", "hostname")),
                    now,
                ),
            )

        # Then findings. If a finding references an asset we don't have in our
        # local store, skip it — the foreign key would fail anyway.
        for f in cve_findings:
            asset_id_raw = f.get("asset_id")
            if not asset_id_raw or asset_id_raw not in assets:
                continue
            finding_asset_id: str = str(asset_id_raw)
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
                    f.get("finding_id") or f.get("id"),
                    finding_asset_id,
                    f["_cve_id"],
                    f.get("finding_severity") or f.get("severity"),
                    f.get("state"),
                    f.get("first_observed_at") or f.get("first_observed"),
                    f.get("last_observed_at") or f.get("last_observed"),
                    source,
                    now,
                ),
            )
            persisted += 1

    logger.info("source persisted", source=source, findings=persisted)
    return persisted
