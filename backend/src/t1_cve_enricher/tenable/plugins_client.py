"""HTTP client for tenable.com/plugins/api/v1/.

This is the public, unauthenticated plugins API at the same domain as the
CVE pages. Authoritative source for plugin-level data: solution text, VPR,
synopsis, script_family/type, risk factor, CISA KEV status.

Architecture notes:

- Public + unauthenticated. Same trust profile as cve_scraper.py.
- Polite by default: rate-limited via settings.scraper_rate_limit_rps
  (shared with cve_scraper — same domain, single politeness budget),
  identifying User-Agent, retry with exponential backoff on HTTP errors.
- Exact-match CVE search uses ?q="CVE-XXXX-YYYY" with literal quotes;
  unquoted q does fuzzy match and returns up to 10k irrelevant results.
- Search response is a stripped subset (~31 fields) of what the detail
  endpoint returns (~79 fields). For v1 we use search-only — captures
  solution, VPR, family/type, risk_factor, CISA KEV. Fields requiring
  the detail endpoint (cpe, see_also, exploit_available, full CVSS
  scores) are deferred to v2; the full raw record is persisted as JSON
  so they can be recovered later without re-fetching.
"""

from __future__ import annotations

import asyncio
import os
import ssl
from typing import Any

import httpx
import structlog
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from t1_cve_enricher.config import Settings

logger = structlog.get_logger(__name__)

PLUGINS_BASE = "https://www.tenable.com/plugins/api/v1"


def _build_ssl_context() -> ssl.SSLContext | bool:
    """Honour REQUESTS_CA_BUNDLE / SSL_CERT_FILE for corporate proxies."""
    bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    if bundle:
        return ssl.create_default_context(cafile=bundle)
    return True


class PluginsClient:
    """Async client for the public Tenable plugins API."""

    def __init__(self, settings: Settings):
        self._settings = settings
        # Reuse the scraper's rate limit and UA — same domain, same identity.
        self._rate_limit_delay = 1.0 / settings.scraper_rate_limit_rps
        self._last_request_at: float = 0.0
        self._lock = asyncio.Lock()
        self._client = httpx.AsyncClient(
            headers={
                "User-Agent": settings.scraper_user_agent,
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(30.0, connect=10.0),
            verify=_build_ssl_context(),
            follow_redirects=True,
        )

    async def __aenter__(self) -> PluginsClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _throttle(self) -> None:
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_request_at
            if elapsed < self._rate_limit_delay:
                await asyncio.sleep(self._rate_limit_delay - elapsed)
            self._last_request_at = asyncio.get_event_loop().time()

    @retry(
        retry=retry_if_exception_type(httpx.HTTPError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=15),
        reraise=True,
    )
    async def search_by_cve(self, cve_id: str, max_results: int = 500) -> list[dict[str, Any]]:
        """Return plugin records that cover the given CVE.

        Uses exact-match phrase query (q="<CVE-ID>"). Returns each hit's
        _source dict, with the plugin_id injected as _plugin_id for
        convenience. Empty list if no plugins match. Logs a warning if
        total > max_results, indicating we may have truncated results.
        """
        await self._throttle()
        params = {"q": f'"{cve_id}"', "size": max_results}
        url = f"{PLUGINS_BASE}/search"
        logger.debug("plugins search", cve_id=cve_id, max_results=max_results)

        response = await self._client.get(url, params=params)  # type: ignore[arg-type]  # TODO: type params as dict[str, str|int]
        response.raise_for_status()
        payload = response.json()

        if not payload.get("success"):
            logger.warning("plugins search returned success=false", cve_id=cve_id)
            return []

        data = payload.get("data") or {}
        hits = data.get("hits") or []
        total = data.get("total", len(hits))

        if total > max_results:
            logger.warning(
                "plugins search truncated by max_results",
                cve_id=cve_id,
                total=total,
                returned=len(hits),
            )

        results = []
        for hit in hits:
            src = hit.get("_source") or {}
            plugin_id = hit.get("_id") or src.get("script_id") or src.get("doc_id")
            if plugin_id:
                src["_plugin_id"] = str(plugin_id)
                results.append(src)
        return results

    @retry(
        retry=retry_if_exception_type(httpx.HTTPError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=15),
        reraise=True,
    )
    async def get_plugin(self, plugin_id: str) -> dict[str, Any] | None:
        """Fetch full plugin record by ID. Returns None on 404.

        Exposed for back-fill / debugging — the search endpoint is used
        for the main enrichment path.
        """
        await self._throttle()
        url = f"{PLUGINS_BASE}/nessus/{plugin_id}"
        response = await self._client.get(url)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        payload = response.json()
        if not payload.get("success"):
            return None
        data = payload.get("data") or {}
        src = data.get("_source")
        if src:
            src["_plugin_id"] = str(plugin_id)
        return src
