"""REST API routes.

All endpoints accept the same filter parameters where applicable:

    source     (repeatable)   filter by third-party source name
    cve        (repeatable)   filter by exact CVE ID
    asset      (string)       substring match on asset name / FQDN / IP
    severity   (repeatable)   CRITICAL / HIGH / MEDIUM / LOW / INFO
    state      (repeatable)   ACTIVE / RESURFACED / FIXED
    enriched   (bool)         only / exclude un-enriched CVEs
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Query
from pydantic import BaseModel

from t1_cve_enricher.api.export import build_csv_response, build_json_response
from t1_cve_enricher.config import get_settings
from t1_cve_enricher.db import get_connection
from t1_cve_enricher.enrichment.plugin_matcher import pick_best_plugin
from t1_cve_enricher.workers.scheduler import run_pipeline

logger = structlog.get_logger(__name__)
router = APIRouter()


# --- Models -------------------------------------------------------------------


class Source(BaseModel):
    name: str
    first_seen: datetime
    last_seen: datetime
    asset_count: int


class EnrichedFinding(BaseModel):
    finding_id: str
    cve_id: str
    severity: str | None
    state: str | None
    source: str
    asset_id: str
    asset_name: str | None
    asset_ipv4: str | None
    asset_fqdn: str | None
    first_observed: datetime | None
    last_observed: datetime | None
    cve_description: str | None
    cvss3_base_score: float | None
    cvss3_severity: str | None
    vpr_score: float | None
    vpr_severity: str | None
    remediation: str | None
    enriched: bool
    plugin_id: str | None = None
    plugin_family: str | None = None
    plugin_platform_match: bool | None = None


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0


class PullJob(BaseModel):
    id: int
    started_at: datetime
    completed_at: datetime | None
    status: str
    sources_processed: int
    findings_pulled: int
    cves_enriched: int
    error_message: str | None


# --- Query builder ------------------------------------------------------------


def _build_findings_query(
    sources: list[str] | None,
    cves: list[str] | None,
    asset: str | None,
    severities: list[str] | None,
    states: list[str] | None,
    enriched: bool | None,
) -> tuple[str, list[Any]]:
    """Return (sql, params) for the filtered findings query."""
    where: list[str] = []
    params: list[Any] = []

    if sources:
        where.append(f"f.source IN ({','.join('?' * len(sources))})")
        params.extend(sources)
    if cves:
        where.append(f"f.cve_id IN ({','.join('?' * len(cves))})")
        params.extend(c.upper() for c in cves)
    if asset:
        where.append(
            "(a.asset_name LIKE ? OR a.fqdn LIKE ? OR a.ipv4 LIKE ?)"
        )
        like = f"%{asset}%"
        params.extend([like, like, like])
    if severities:
        where.append(f"f.severity IN ({','.join('?' * len(severities))})")
        params.extend(s.upper() for s in severities)
    if states:
        where.append(f"f.state IN ({','.join('?' * len(states))})")
        params.extend(s.upper() for s in states)
    if enriched is True:
        where.append("c.cve_id IS NOT NULL AND c.fetch_status = 'OK'")
    elif enriched is False:
        where.append("(c.cve_id IS NULL OR c.fetch_status != 'OK')")

    sql = """
        SELECT
            f.finding_id, f.cve_id, f.severity, f.state, f.source,
            f.first_observed, f.last_observed,
            a.asset_id, a.asset_name, a.ipv4 AS asset_ipv4, a.fqdn AS asset_fqdn,
            c.description AS cve_description,
            c.cvss3_base_score, c.cvss3_severity,
            c.vpr_score, c.vpr_severity,
            c.remediation,
            CASE WHEN c.fetch_status = 'OK' THEN 1 ELSE 0 END AS enriched
        FROM findings f
        JOIN assets a ON a.asset_id = f.asset_id
        LEFT JOIN cve_intel c ON c.cve_id = f.cve_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    return sql, params


# --- Routes -------------------------------------------------------------------


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/sources", response_model=list[Source])
def list_sources():
    settings = get_settings()
    with get_connection(settings.database_path) as conn:
        rows = conn.execute("SELECT * FROM sources ORDER BY name").fetchall()
    return [Source(**dict(r)) for r in rows]


@router.get("/findings", response_model=list[EnrichedFinding])
def list_findings(
    source: list[str] | None = Query(default=None),
    cve: list[str] | None = Query(default=None),
    asset: str | None = None,
    severity: list[str] | None = Query(default=None),
    state: list[str] | None = Query(default=None),
    enriched: bool | None = None,
    limit: int = Query(default=100, ge=1, le=10000),
    offset: int = Query(default=0, ge=0),
):
    settings = get_settings()
    sql, params = _build_findings_query(source, cve, asset, severity, state, enriched)
    sql += " ORDER BY f.severity, f.last_observed DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    results: list[EnrichedFinding] = []
    with get_connection(settings.database_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        for r in rows:
            fields = dict(r)
            fields["enriched"] = bool(r["enriched"])
            plugin = pick_best_plugin(conn, r["cve_id"], r["source"])
            if plugin:
                fields["vpr_score"] = plugin["vpr_score"]
                fields["vpr_severity"] = plugin["vpr_severity"]
                fields["remediation"] = plugin["solution"]
                fields["plugin_id"] = plugin["plugin_id"]
                fields["plugin_family"] = plugin["script_family"]
                fields["plugin_platform_match"] = plugin["platform_match"]
            else:
                fields["plugin_id"] = None
                fields["plugin_family"] = None
                fields["plugin_platform_match"] = None
            results.append(EnrichedFinding(**fields))
    return results


@router.get("/findings/export")
def export_findings(
    source: list[str] | None = Query(default=None),
    cve: list[str] | None = Query(default=None),
    asset: str | None = None,
    severity: list[str] | None = Query(default=None),
    state: list[str] | None = Query(default=None),
    enriched: bool | None = None,
    format: str = Query(default="csv", pattern="^(csv|json)$"),
) -> Any:
    settings = get_settings()
    sql, params = _build_findings_query(source, cve, asset, severity, state, enriched)
    sql += " ORDER BY f.severity, f.last_observed DESC"
    with get_connection(settings.database_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    data = [dict(r) for r in rows]
    if format == "json":
        return build_json_response(data)
    return build_csv_response(data)


@router.get("/cve/{cve_id}")
def get_cve(cve_id: str) -> dict[str, Any]:
    settings = get_settings()
    with get_connection(settings.database_path) as conn:
        row = conn.execute(
            "SELECT * FROM cve_intel WHERE cve_id = ?", (cve_id.upper(),)
        ).fetchone()
    return dict(row) if row else {"cve_id": cve_id.upper(), "fetch_status": "MISSING"}


@router.get("/stats", response_model=SeverityCounts)
def severity_stats(
    source: list[str] | None = Query(default=None),
    cve: list[str] | None = Query(default=None),
    asset: str | None = None,
    severity: list[str] | None = Query(default=None),
    state: list[str] | None = Query(default=None),
    enriched: bool | None = None,
) -> SeverityCounts:
    settings = get_settings()
    sql, params = _build_findings_query(source, cve, asset, severity, state, enriched)
    counts = SeverityCounts()
    with get_connection(settings.database_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    for r in rows:
        sev = (r["severity"] or "").upper()
        if sev == "CRITICAL":
            counts.critical += 1
        elif sev == "HIGH":
            counts.high += 1
        elif sev == "MEDIUM":
            counts.medium += 1
        elif sev == "LOW":
            counts.low += 1
        elif sev == "INFO":
            counts.info += 1
        else:
            counts.unknown += 1
    return counts


@router.post("/refresh")
async def trigger_refresh(background_tasks: BackgroundTasks) -> dict[str, str]:
    """Fire off a pipeline run in the background."""
    background_tasks.add_task(asyncio.create_task, run_pipeline())
    return {"status": "started"}


@router.get("/jobs", response_model=list[PullJob])
def list_jobs(limit: int = Query(default=20, ge=1, le=200)):
    settings = get_settings()
    with get_connection(settings.database_path) as conn:
        rows = conn.execute(
            "SELECT * FROM pull_jobs ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [PullJob(**dict(r)) for r in rows]
