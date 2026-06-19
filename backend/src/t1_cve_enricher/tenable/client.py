"""Tenable One Inventory API client.

Implements the three operations this project needs:

    * list_sources()             — enumerate third-party data sources
    * count_findings_for_source() — quick existence check
    * export_findings(source)    — async export pattern, paginated chunks

API endpoints are based on the inventory API observed via the Tenable MCP
server. The exact paths are documented at the top of the file as constants
so they're easy to adjust if Tenable changes them.

All HTTP calls respect REQUESTS_CA_BUNDLE / SSL_CERT_FILE so that
environments with SSL-inspecting proxies (Netskope, Zscaler, etc.) work
without code changes.
"""

from __future__ import annotations

import asyncio
import os
import ssl
from typing import Any

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from t1_cve_enricher.config import Settings

logger = structlog.get_logger(__name__)


# --- API endpoint paths -------------------------------------------------------
# These map to the Tenable One Inventory API. If Tenable changes the URL
# structure these constants are the only thing that should need updating.

INVENTORY_ASSETS_PROPERTIES = "/api/v1/t1/inventory/assets/properties"
INVENTORY_FINDINGS_PROPERTIES = "/api/v1/t1/inventory/findings/properties"
INVENTORY_ASSETS_SEARCH = "/api/v1/t1/inventory/assets/search"
INVENTORY_FINDINGS_SEARCH = "/api/v1/t1/inventory/findings/search"
FINDINGS_EXPORT_INITIATE = "/api/v1/t1/inventory/export/findings"
EXPORT_STATUS = "/api/v1/t1/inventory/export/{export_id}/status"
EXPORT_CHUNK = "/api/v1/t1/inventory/export/{export_id}/download/{chunk_id}"

# Sources that are Tenable's own data, not third-party connectors. We exclude
# these from `list_sources()` since enriching Tenable's own findings against
# Tenable's CVE database is redundant.
TENABLE_NATIVE_SOURCES = {
    "Tenable Vulnerability Management",
    "Tenable Nessus",
    "Tenable Nessus Network Monitor",
    "Tenable Web App Scanning",
    "Tenable Cloud Security",
    "Tenable Identity Exposure",
    "Tenable OT Security",
    "Tenable Attack Surface Management",
    "TVM",
    "WAS",
    "CS",
}

EXPORT_POLL_INTERVAL_SECONDS = 3
EXPORT_POLL_MAX_ATTEMPTS = 200  # ~10 minutes at 3s interval


def _build_ssl_context() -> ssl.SSLContext | bool:
    """Honour REQUESTS_CA_BUNDLE / SSL_CERT_FILE for corporate proxies."""
    bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    if bundle:
        return ssl.create_default_context(cafile=bundle)
    return True


class TenableApiError(Exception):
    """Raised when the Tenable API returns an unexpected response."""


class TenableClient:
    """Async client for the Tenable One Inventory API."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._headers = {
            "X-ApiKeys": (
                f"accessKey={settings.tenable_access_key.get_secret_value()};"
                f"secretKey={settings.tenable_secret_key.get_secret_value()}"
            ),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self._client = httpx.AsyncClient(
            base_url=settings.tenable_base_url,
            headers=self._headers,
            timeout=httpx.Timeout(60.0, connect=10.0),
            verify=_build_ssl_context(),
        )

    async def __aenter__(self) -> "TenableClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # --- Generic request helper ---

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, TenableApiError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        response = await self._client.request(method, path, json=json_body, params=params)
        if response.status_code == 401:
            raise TenableApiError(
                "Tenable API rejected credentials (401). "
                "Verify TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY."
            )
        if response.status_code == 403:
            raise TenableApiError(
                "Tenable API returned 403. The API user may lack inventory permissions."
            )
        response.raise_for_status()
        if not response.content:
            return None
        return response.json()

    # --- Connection test ---

    async def test_connection(self) -> dict[str, Any]:
        """Sanity check used by the CLI smoke test.

        Calls the assets properties endpoint, which is cheap and proves both
        auth and basic inventory access work.
        """
        logger.info("testing tenable connection", base_url=self._settings.tenable_base_url)
        data = await self._request("GET", INVENTORY_ASSETS_PROPERTIES)
        # The response shape is `{"properties": [...]}` based on the MCP
        # response we observed. Handle both shapes defensively.
        properties = data.get("properties", data) if isinstance(data, dict) else data
        count = len(properties) if isinstance(properties, list) else 0
        return {"status": "ok", "asset_properties_returned": count}

    # --- Source discovery ---

    async def list_sources(self) -> list[dict[str, Any]]:
        """Return distinct third-party data sources currently in the tenant.

        Strategy:
            1. Hit the properties endpoint to get the enumerated `products`
               values (the user-facing data-source dimension).
            2. For each candidate, do a small asset search filtered by that
               product to get a current count.
            3. Return entries that are NOT Tenable-native and have asset_count > 0.

        Returns a list of dicts shaped as:
            { "name": "SentinelOne", "asset_count": 11 }
        """
        logger.info("listing third-party data sources")
        data = await self._request("GET", INVENTORY_ASSETS_PROPERTIES)
        properties = data.get("properties", data) if isinstance(data, dict) else data
        if not isinstance(properties, list):
            raise TenableApiError(f"Unexpected properties response shape: {type(data)}")

        # Pull the enumerated `products` (preferred) or `sources` (fallback) values.
        # Different tenant versions use one or the other as the canonical field.
        candidates: list[str] = []
        for prop in properties:
            name = prop.get("key") or prop.get("name") or prop.get("property")
            if name in ("products", "sources"):
                values = prop.get("values") or prop.get("enum") or []
                # Values can be a list of dicts ({"name":"X","value":"X"}) or strings.
                for v in values:
                    if isinstance(v, dict):
                        candidates.append(v.get("value") or v.get("name") or "")
                    elif isinstance(v, str):
                        candidates.append(v)
                if candidates:
                    break

        third_party = [c for c in candidates if c and c not in TENABLE_NATIVE_SOURCES]
        logger.info("found candidate sources", count=len(third_party))

        # Get a count for each so we can return only the ones with data.
        sources: list[dict[str, Any]] = []
        for name in third_party:
            count = await self._count_assets_for_source(name)
            if count > 0:
                sources.append({"name": name, "asset_count": count})

        sources.sort(key=lambda s: s["name"])
        logger.info("active third-party sources", count=len(sources))
        return sources

    async def _count_assets_for_source(self, source: str) -> int:
        """Quick count query for a single source."""
        body = {
            "filters": [
                {"property": "products", "operator": "=", "value": [source]},
            ],
            "limit": 1,
            "offset": 0,
        }
        try:
            data = await self._request("POST", INVENTORY_ASSETS_SEARCH, json_body=body)
        except (httpx.HTTPError, TenableApiError) as exc:
            logger.warning("source count failed", source=source, error=str(exc))
            return 0
        if not isinstance(data, dict):
            return 0
        # Response includes pagination metadata. Field names observed: "total",
        # sometimes "totalCount". Try both.
        return int(data.get("total", data.get("totalCount", 0)) or 0)

    # --- Findings export ---

    async def export_findings(
        self,
        source: str,
        severities: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Export findings for a given source via the async export API.

        Filters to CVE-shaped findings (any severity by default). The caller
        is responsible for further filtering to CVE-named detections.

        Returns a list of raw finding records as returned by the export
        chunks. The findings_extractor worker handles persistence.
        """
        severities = severities or ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        filters = [
            {"property": "products", "operator": "=", "value": [source]},
            {"property": "finding_severity", "operator": "=", "value": severities},
        ]

        export_id = await self._initiate_export(filters)
        logger.info("export started", source=source, export_id=export_id)
        chunk_ids = await self._wait_for_export(export_id)
        logger.info("export finished", source=source, chunks=len(chunk_ids))

        all_records: list[dict[str, Any]] = []
        for chunk_id in chunk_ids:
            records = await self._download_chunk(export_id, chunk_id)
            all_records.extend(records)
            logger.debug("chunk downloaded", export_id=export_id, chunk_id=chunk_id, n=len(records))

        logger.info("export complete", source=source, total_records=len(all_records))
        return all_records

    async def _initiate_export(self, filters: list[dict[str, Any]]) -> str:
        body = {"filters": filters}
        data = await self._request("POST", FINDINGS_EXPORT_INITIATE, json_body=body)
        if not isinstance(data, dict):
            raise TenableApiError(f"Unexpected export-initiate response: {data!r}")
        export_id = data.get("export_id") or data.get("exportId") or data.get("id")
        if not export_id:
            raise TenableApiError(f"Export initiation returned no id: {data!r}")
        return str(export_id)

    async def _wait_for_export(self, export_id: str) -> list[int]:
        """Poll the export status until it finishes. Returns the chunk IDs."""
        path = EXPORT_STATUS.format(export_id=export_id)
        for attempt in range(EXPORT_POLL_MAX_ATTEMPTS):
            data = await self._request("GET", path)
            status = (data or {}).get("status", "").upper()
            if status in ("FINISHED", "COMPLETED", "DONE"):
                chunks = data.get("chunks_available") or data.get("chunks") or data.get(
                    "available_chunks"
                ) or []
                return [int(c) for c in chunks]
            if status in ("FAILED", "ERROR", "CANCELLED"):
                raise TenableApiError(f"Export {export_id} failed with status {status}")
            logger.debug("export polling", export_id=export_id, status=status, attempt=attempt)
            await asyncio.sleep(EXPORT_POLL_INTERVAL_SECONDS)
        raise TenableApiError(
            f"Export {export_id} did not finish within "
            f"{EXPORT_POLL_INTERVAL_SECONDS * EXPORT_POLL_MAX_ATTEMPTS}s"
        )

    async def _download_chunk(self, export_id: str, chunk_id: int) -> list[dict[str, Any]]:
        path = EXPORT_CHUNK.format(export_id=export_id, chunk_id=chunk_id)
        data = await self._request("GET", path)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("records") or data.get("data") or []
        return []


# --- CLI smoke-test entry point ----------------------------------------------


async def _cli_smoke_test() -> None:
    """Hand-runnable end-to-end check.

    Run with:
        python -m t1_cve_enricher.tenable.client
    """
    from t1_cve_enricher.config import get_settings

    settings = get_settings()
    print(f"Connecting to {settings.tenable_base_url}…")
    async with TenableClient(settings) as client:
        health = await client.test_connection()
        print(f"  ✓ connection ok ({health['asset_properties_returned']} asset properties)")

        print("\nDiscovering third-party sources…")
        sources = await client.list_sources()
        if not sources:
            print("  (none found — your tenant has no third-party data sources)")
            return
        for src in sources:
            print(f"  • {src['name']:<30} {src['asset_count']:>6} assets")

        # Smoke-test the export pipeline on the smallest source so we don't
        # accidentally pull tens of thousands of findings.
        smallest = min(sources, key=lambda s: s["asset_count"])
        print(f"\nExporting findings for '{smallest['name']}' (sanity check)…")
        records = await client.export_findings(smallest["name"])
        print(f"  ✓ pulled {len(records)} finding records")
        if records:
            sample = records[0]
            print(f"  sample keys: {sorted(sample.keys())[:10]}")


def main() -> None:
    asyncio.run(_cli_smoke_test())


if __name__ == "__main__":
    main()
