"""Tenable One / TVM API client.

Wraps the subset of the Tenable API needed by this project:

- Inventory asset search (used by source discovery to list distinct sources)
- Inventory findings export (used by findings extraction)

All calls respect REQUESTS_CA_BUNDLE / SSL_CERT_FILE for environments with
SSL-inspecting proxies (Netskope, Zscaler, etc.).
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


def _build_ssl_context() -> ssl.SSLContext | bool:
    """Honour REQUESTS_CA_BUNDLE / SSL_CERT_FILE for corporate proxies."""
    bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    if bundle:
        return ssl.create_default_context(cafile=bundle)
    return True


class TenableClient:
    """Async client for Tenable One / TVM."""

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
            timeout=httpx.Timeout(30.0, connect=10.0),
            verify=_build_ssl_context(),
        )

    async def __aenter__(self) -> "TenableClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    @retry(
        retry=retry_if_exception_type(httpx.HTTPError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def list_sources(self) -> list[dict[str, Any]]:
        """Return the distinct list of third-party data sources currently
        producing assets in Tenable One.

        TODO: implement against the Tenable One Inventory API. The shape is:
            POST /inventory/api/v1/assets/properties/aggregate
            { "property": "sources", "limit": 200 }
        """
        logger.info("listing third-party sources")
        # PLACEHOLDER — replace with real API call
        return []

    async def export_findings(
        self,
        source: str,
        chunk_size: int = 1000,
    ) -> list[dict[str, Any]]:
        """Export all CVE-shaped findings for a given source.

        Uses the async export API (POST /inventory/api/v1/findings/export),
        polls until the job finishes, then streams down each chunk.

        TODO: implement. See ARCHITECTURE.md for the full pipeline description.
        """
        logger.info("exporting findings", source=source, chunk_size=chunk_size)
        # PLACEHOLDER — replace with real API call
        return []


async def discover_sources_in_use(settings: Settings) -> list[str]:
    """Convenience: return just the names of active third-party sources."""
    async with TenableClient(settings) as client:
        sources = await client.list_sources()
    return [s["name"] for s in sources]


# Re-export asyncio for callers
__all__ = ["TenableClient", "discover_sources_in_use", "asyncio"]
