"""Plugin enricher worker.

Stage 3 of the pipeline. For each CVE present in cve_intel that doesn't
yet have linked plugins, search the Tenable plugins API for matching
plugins and persist them with a many-to-many link.

Design points:

- **Search-only** (no detail fan-out). Search returns the high-value
  fields (solution, VPR, family/type, risk_factor) for ~30 fields per
  hit. Detail endpoint adds ~48 more fields but doubles API calls.
  Full search _source is persisted as raw_json so v2 detail fan-out
  can be added later without re-fetching.
- **One search per CVE, deduplicated by plugin_id.** A single plugin
  often covers many CVEs (e.g. a Red Hat security advisory plugin can
  fix dozens of CVEs at once); the `plugins` PK is plugin_id so
  cross-CVE plugins are stored once and linked many times via
  `cve_plugins`.
- **Idempotent.** Re-running the worker on the same DB is a no-op for
  CVEs that already have plugin links. The "needs enrichment" query is
  a LEFT JOIN against cve_plugins; CVEs with at least one link are
  skipped. To force re-fetch, delete the cve_plugins rows for that CVE.
- **No matching policy.** The worker stores every plugin returned. The
  UI/query layer decides which plugins to surface for a given finding
  based on the asset's class (host vs web app vs container) and OS.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import structlog

from t1_cve_enricher.config import Settings
from t1_cve_enricher.db import get_connection
from t1_cve_enricher.tenable.plugins_client import PluginsClient

logger = structlog.get_logger(__name__)


def _find_cves_needing_plugin_search(settings: Settings) -> list[str]:
    """Return CVE IDs that are in cve_intel but have no rows in cve_plugins.

    A CVE is considered "enriched with plugins" if it has at least one
    row in cve_plugins — even if that row points to a plugin we couldn't
    fetch (since the search itself either returned hits or didn't).
    CVEs with zero plugin matches will be re-searched on every run
    until we add a "searched, no results" marker (v2).
    """
    with get_connection(settings.database_path) as conn:
        rows = conn.execute(
            """
            SELECT ci.cve_id
            FROM cve_intel ci
            LEFT JOIN cve_plugins cp ON cp.cve_id = ci.cve_id
            WHERE ci.fetch_status = 'OK' AND cp.cve_id IS NULL
            ORDER BY ci.cve_id
            """
        ).fetchall()
    return [r["cve_id"] for r in rows]


def _extract_plugin_row(src: dict[str, Any]) -> dict[str, Any]:
    """Map a plugins-API _source dict to our plugins table columns.

    Returns a dict matching the column names. Fields not present in the
    search response (cpe, see_also, exploit_available, scalar CVSS
    scores) are left as None — recoverable from raw_json later.
    """
    def _as_float(v: Any) -> float | None:
        if v is None or v == "":
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    def _as_str(v: Any) -> str | None:
        if v is None:
            return None
        s = str(v).strip()
        return s or None

    return {
        "plugin_id": str(src["_plugin_id"]),
        "script_name": _as_str(src.get("script_name")),
        "script_family": _as_str(src.get("script_family")),
        "plugin_type": _as_str(src.get("plugin_type")),
        "synopsis": _as_str(src.get("synopsis")),
        "description": _as_str(src.get("description")),
        "solution": _as_str(src.get("solution")),
        "vpr_score": _as_float(src.get("vpr_score")),
        # vpr_risk_factor and vprSeverity are duplicate fields in the API
        "vpr_severity": _as_str(src.get("vpr_risk_factor") or src.get("vprSeverity")),
        "risk_factor": _as_str(src.get("risk_factor")),
        "severity": _as_str(src.get("severity")),
        "cvss3_severity": _as_str(src.get("cvssV3Severity")),
        "cvss2_severity": _as_str(src.get("cvssV2Severity")),
        "cisa_known_exploited_date": _as_str(src.get("cisaKnownExploitedDate")),
        "plugin_publication_date": _as_str(src.get("plugin_publication_date")),
        "plugin_modification_date": _as_str(src.get("plugin_modification_date")),
        "raw_json": json.dumps(src, default=str),
    }


async def run(settings: Settings) -> int:
    """Enrich CVEs with matching plugin records. Returns count of plugin upserts."""
    cve_ids = _find_cves_needing_plugin_search(settings)
    logger.info("plugin_enricher: started", count=len(cve_ids))

    if not cve_ids:
        logger.info("plugin_enricher: nothing to do")
        return 0

    total_plugins = 0
    total_links = 0
    failed_cves: list[str] = []
    now = datetime.now(timezone.utc)

    async with PluginsClient(settings) as client:
        for i, cve_id in enumerate(cve_ids, 1):
            try:
                hits = await client.search_by_cve(cve_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("plugin search failed", cve_id=cve_id, error=str(exc))
                failed_cves.append(cve_id)
                continue

            if not hits:
                # CVE has no matching plugins. Insert a sentinel row in
                # cve_plugins so we don't re-search next run? Decided no:
                # plugin coverage grows over time as Tenable writes new
                # plugins, so re-searching empty cases is a feature.
                logger.debug("no plugins for cve", cve_id=cve_id)
                continue

            with get_connection(settings.database_path) as conn:
                for src in hits:
                    row = _extract_plugin_row(src)
                    conn.execute(
                        """
                        INSERT INTO plugins (
                            plugin_id, script_name, script_family, plugin_type,
                            synopsis, description, solution,
                            vpr_score, vpr_severity, risk_factor, severity,
                            cvss3_severity, cvss2_severity,
                            cisa_known_exploited_date,
                            plugin_publication_date, plugin_modification_date,
                            raw_json, fetched_at, fetch_status
                        ) VALUES (
                            :plugin_id, :script_name, :script_family, :plugin_type,
                            :synopsis, :description, :solution,
                            :vpr_score, :vpr_severity, :risk_factor, :severity,
                            :cvss3_severity, :cvss2_severity,
                            :cisa_known_exploited_date,
                            :plugin_publication_date, :plugin_modification_date,
                            :raw_json, :fetched_at, 'OK'
                        )
                        ON CONFLICT(plugin_id) DO UPDATE SET
                            script_name = excluded.script_name,
                            script_family = excluded.script_family,
                            plugin_type = excluded.plugin_type,
                            synopsis = excluded.synopsis,
                            description = excluded.description,
                            solution = excluded.solution,
                            vpr_score = excluded.vpr_score,
                            vpr_severity = excluded.vpr_severity,
                            risk_factor = excluded.risk_factor,
                            severity = excluded.severity,
                            cvss3_severity = excluded.cvss3_severity,
                            cvss2_severity = excluded.cvss2_severity,
                            cisa_known_exploited_date = excluded.cisa_known_exploited_date,
                            plugin_publication_date = excluded.plugin_publication_date,
                            plugin_modification_date = excluded.plugin_modification_date,
                            raw_json = excluded.raw_json,
                            fetched_at = excluded.fetched_at
                        """,
                        {**row, "fetched_at": now},
                    )
                    total_plugins += 1

                    conn.execute(
                        """
                        INSERT INTO cve_plugins (cve_id, plugin_id)
                        VALUES (?, ?)
                        ON CONFLICT(cve_id, plugin_id) DO NOTHING
                        """,
                        (cve_id, row["plugin_id"]),
                    )
                    total_links += 1

            # Periodic progress logging so a 100-min run isn't silent.
            if i % 100 == 0:
                logger.info(
                    "plugin_enricher: progress",
                    cve_processed=i,
                    cve_remaining=len(cve_ids) - i,
                    plugins_upserted=total_plugins,
                )

    logger.info(
        "plugin_enricher: finished",
        cves_processed=len(cve_ids),
        plugins_upserted=total_plugins,
        links_created=total_links,
        failed=len(failed_cves),
    )
    if failed_cves:
        logger.warning("plugin_enricher: failed cves", count=len(failed_cves), sample=failed_cves[:5])

    return total_plugins
