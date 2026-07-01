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
from t1_cve_enricher.tenable.client import (
    INVENTORY_ASSETS_SEARCH,
    TenableClient,
)
from t1_cve_enricher.workers import progress

logger = structlog.get_logger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _extract_cves(finding: dict[str, Any]) -> list[str]:
    """Pull the CVE list off a finding record.

    The authoritative source is `extra_properties.finding_cves`, which is an
    array of CVE strings. Some sources (e.g. Microsoft TVM) also put a single
    CVE in `finding_name` or `finding_detection_name`, but that pattern is
    inconsistent across connectors and can't represent multi-CVE findings.

    Returns a deduplicated, uppercase list. Empty list means the finding
    isn't CVE-shaped (e.g. an Orca malware detection or a misconfig) and
    should be filtered out by the caller.
    """
    extra = finding.get("extra_properties") or {}
    raw = extra.get("finding_cves") or []
    if not isinstance(raw, list):
        return []

    # Deduplicate while preserving order — some connectors list the same CVE
    # multiple times in the array (unclear why, but it happens).
    seen: set[str] = set()
    cves: list[str] = []
    for c in raw:
        if not c:
            continue
        normalized = str(c).strip().upper()
        if CVE_PATTERN.match(normalized) and normalized not in seen:
            seen.add(normalized)
            cves.append(normalized)
    return cves


def _extra(finding: dict[str, Any], key: str) -> Any:
    """Read a field from a finding's extra_properties dict, or None."""
    extra = finding.get("extra_properties") or {}
    return extra.get(key)


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
        # Request the rich asset properties we need. Without this, the response's
        # extra_properties field is {}. See findings_extractor docstring.
        extra_props = "ipv4_addresses,fqdns,first_observed_at,last_observed_at,device_system_type"
        url = f"{INVENTORY_ASSETS_SEARCH}?extra_properties={extra_props}"
        data = await client._request("POST", url, json_body=body)
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
    """Try multiple key variants and return the first non-empty value.

    The Tenable One inventory search endpoint returns the rich fields
    (ipv4_addresses, fqdns, device_system_type, ...) nested under an
    'extra_properties' object — only when we passed those names in the
    ?extra_properties=... query string of the request. We check the nested
    object first, then fall back to root-level keys for backward compat
    with other endpoints/responses that might use a flat shape.
    """
    extra = asset.get("extra_properties") or {}
    for k in keys:
        if k in extra:
            v = extra[k]
            if v not in (None, "", [], {}):
                return v
    for k in keys:
        v = asset.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


def _join_arr(value: Any) -> str | None:
    """Comma-join an array-shaped field, or pass through a string."""
    if value is None:
        return None
    if isinstance(value, list):
        return ",".join(str(v) for v in value) or None
    return str(value)


def _format_os(value: Any) -> str | None:
    """Normalize Tenable One's device_system_type to a customer-friendly form.

    Tenable One returns values like 'microsoft windows computer', 'linux computer',
    'apple os x computer' — verbose lowercase strings with a trailing ' computer'
    that reads as awkward in a customer-facing report. We strip the suffix and
    title-case the result, with a special case to keep 'OS' capitalized correctly.
    """
    if value is None or value == "":
        return None
    s = str(value).strip()
    # Strip the trailing " computer" the platform appends to device entries.
    if s.lower().endswith(" computer"):
        s = s[: -len(" computer")].strip()
    s = s.title()
    # Title-case mangles all-caps acronyms; fix the common ones we know.
    s = s.replace("Os X", "OS X").replace("Macos", "macOS")
    return s or None


async def run(settings: Settings, sources: list[str]) -> int:
    """Pull CVE findings for each source. Returns total findings persisted."""
    logger.info("findings_extractor: started", source_count=len(sources))
    progress.begin(
        "extraction", total=len(sources), message=f"Pulling findings from {len(sources)} sources"
    )

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
    """Pull and persist data for a single source.

    For each source we:
    1. Pull assets (with rich extra_properties for IPv4/FQDN/OS enrichment)
    2. Pull findings via /inventory/findings/search with extra_properties
       (gets us finding_cves array, VPR, description, observation dates in
       one call — no second-stage enrichment needed for these fields)
    3. Filter to findings that carry at least one CVE in finding_cves
       (drops malware detections, misconfigs, and anything else not CVE-shaped)
    4. Explode multi-CVE findings into one DB row per (finding, cve) pair

    Returns the number of DB rows persisted (which is >= the number of CVE-shaped
    findings because of the explosion).
    """
    logger.info("pulling source", source=source)
    async with TenableClient(settings) as client:
        assets = await _pull_assets_for_source(client, source)
        if not assets:
            logger.warning("source has no assets; skipping findings pull", source=source)
            return 0
        findings = await client.search_findings_for_source(source)

    # Filter and explode. One Tenable finding with N CVEs becomes N rows.
    exploded: list[tuple[dict[str, Any], str]] = []
    findings_with_cves = 0
    for f in findings:
        cves = _extract_cves(f)
        if not cves:
            continue
        findings_with_cves += 1
        for cve_id in cves:
            exploded.append((f, cve_id))

    logger.info(
        "filtered findings",
        source=source,
        assets=len(assets),
        total_findings=len(findings),
        findings_with_cves=findings_with_cves,
        findings_dropped_no_cve=len(findings) - findings_with_cves,
        rows_after_explode=len(exploded),
    )

    now = datetime.now(UTC)
    persisted = 0
    skipped_no_asset = 0
    with get_connection(settings.database_path) as conn:
        # Upsert assets first
        for asset_id, asset in assets.items():
            conn.execute(
                """
                INSERT INTO assets (asset_id, asset_name, source, asset_class,
                                    ipv4, fqdn, operating_system, last_synced)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    asset_name = excluded.asset_name,
                    asset_class = excluded.asset_class,
                    ipv4 = excluded.ipv4,
                    fqdn = excluded.fqdn,
                    operating_system = excluded.operating_system,
                    last_synced = excluded.last_synced
                """,
                (
                    asset_id,
                    _asset_field(asset, "asset_name", "name"),
                    source,
                    _asset_field(asset, "asset_class", "class"),
                    _join_arr(_asset_field(asset, "ipv4_addresses", "ipv4")),
                    _join_arr(_asset_field(asset, "fqdns", "fqdn", "hostname")),
                    _format_os(_asset_field(asset, "device_system_type")),
                    now,
                ),
            )

        # Then findings. If a finding references an asset we don't have in our
        # local store, skip it — the foreign key would fail anyway. This can
        # happen when the asset pull and findings pull race (rare but possible).
        for f, cve_id in exploded:
            asset_id_raw = f.get("asset_id")
            if not asset_id_raw or asset_id_raw not in assets:
                skipped_no_asset += 1
                continue
            finding_asset_id: str = str(asset_id_raw)
            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, asset_id, cve_id, severity, state,
                    first_observed, last_observed, source,
                    vpr_score, vpr2_score, finding_description,
                    last_synced
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id, cve_id) DO UPDATE SET
                    severity = excluded.severity,
                    state = excluded.state,
                    last_observed = excluded.last_observed,
                    vpr_score = excluded.vpr_score,
                    vpr2_score = excluded.vpr2_score,
                    finding_description = excluded.finding_description,
                    last_synced = excluded.last_synced
                """,
                (
                    f.get("id") or f.get("finding_id"),
                    finding_asset_id,
                    cve_id,
                    f.get("severity") or f.get("finding_severity"),
                    f.get("state"),
                    _extra(f, "first_observed_at"),
                    _extra(f, "last_observed_at"),
                    source,
                    _extra(f, "finding_vpr_score"),
                    _extra(f, "finding_vpr2_score"),
                    _extra(f, "finding_description"),
                    now,
                ),
            )
            persisted += 1

    logger.info(
        "source persisted",
        source=source,
        rows_persisted=persisted,
        rows_skipped_missing_asset=skipped_no_asset,
    )
    return persisted
