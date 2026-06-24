"""Scraper for tenable.com/cve/{CVE-ID} pages.

This module is the fallback enrichment path: Tenable's Vulnerability Intelligence
isn't exposed via API to customers as of this writing, but every CVE Tenable
tracks has a public page at https://www.tenable.com/cve/{CVE-ID}. We parse the
fields we care about and cache the result.

Design points:

- **Polite by default.** Identifying User-Agent, configurable rate limit
  (default 2 req/s), Retry-After honoured.
- **Cache-friendly.** Each CVE is fetched at most once per TTL window. The
  caller (cve_enricher worker) handles cache lookups; this module is the
  network layer.
- **Fail soft.** A failed fetch or parse returns a CveIntel record with
  fetch_status set to ERROR or NOT_FOUND — the rest of the pipeline keeps
  moving and the UI flags the finding.
- **Replaceable.** When the Vulnerability Intelligence API ships, swap the
  fetch_one() body. The CveIntel dataclass and the cache layer remain.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
import structlog
from bs4 import BeautifulSoup
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from t1_cve_enricher.config import Settings

logger = structlog.get_logger(__name__)

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class CveIntel:
    """Parsed CVE intelligence from tenable.com."""

    cve_id: str
    description: str | None = None
    cvss3_base_score: float | None = None
    cvss3_severity: str | None = None
    cvss2_base_score: float | None = None
    cvss2_severity: str | None = None
    vpr_score: float | None = None
    vpr_severity: str | None = None
    epss_score: float | None = None
    remediation: str | None = None
    published_date: str | None = None
    last_modified_date: str | None = None
    raw_html: str | None = None
    fetched_at: datetime | None = None
    fetch_status: str = "OK"  # OK / NOT_FOUND / ERROR


def _build_ssl_context() -> ssl.SSLContext | bool:
    """Honour REQUESTS_CA_BUNDLE / SSL_CERT_FILE for corporate proxies."""
    bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    if bundle:
        return ssl.create_default_context(cafile=bundle)
    return True


class CveScraper:
    """Async scraper for tenable.com CVE pages."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._rate_limit_delay = 1.0 / settings.scraper_rate_limit_rps
        self._last_request_at: float = 0.0
        self._lock = asyncio.Lock()
        self._client = httpx.AsyncClient(
            headers={
                "User-Agent": settings.scraper_user_agent,
                "Accept": "text/html,application/xhtml+xml",
            },
            timeout=httpx.Timeout(30.0, connect=10.0),
            verify=_build_ssl_context(),
            follow_redirects=True,
        )

    async def __aenter__(self) -> CveScraper:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _throttle(self) -> None:
        """Enforce rate limit across all calls on this scraper instance."""
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
    async def fetch_one(self, cve_id: str) -> CveIntel:
        """Fetch and parse a single CVE page."""
        if not CVE_ID_PATTERN.match(cve_id):
            return CveIntel(cve_id=cve_id, fetch_status="ERROR")

        await self._throttle()
        url = self._settings.scraper_cve_url_template.format(cve_id=cve_id)
        logger.debug("fetching cve", cve_id=cve_id, url=url)

        try:
            response = await self._client.get(url)
        except httpx.HTTPError as exc:
            logger.warning("cve fetch failed", cve_id=cve_id, error=str(exc))
            return CveIntel(
                cve_id=cve_id,
                fetched_at=datetime.now(UTC),
                fetch_status="ERROR",
            )

        if response.status_code == 404:
            return CveIntel(
                cve_id=cve_id,
                fetched_at=datetime.now(UTC),
                fetch_status="NOT_FOUND",
            )

        retry_after = response.headers.get("Retry-After")
        if response.status_code == 429 and retry_after:
            try:
                delay = int(retry_after)
            except ValueError:
                delay = 30
            logger.info("rate limited by upstream", cve_id=cve_id, retry_after=delay)
            await asyncio.sleep(delay)
            response.raise_for_status()  # let tenacity retry

        response.raise_for_status()
        return self._parse(cve_id, response.text)

    def _parse(self, cve_id: str, html: str) -> CveIntel:
        """Parse the __NEXT_DATA__ JSON embedded in a tenable.com CVE page.

        Tenable's CVE pages are server-side rendered by Next.js. All structured
        CVE data is in the <script id="__NEXT_DATA__"> JSON blob, not in the
        rendered HTML. Parsing the JSON is more reliable than selector-scraping.

        VPR score and remediation text are intentionally not extracted: they
        are not exposed on public CVE pages (verified against CVE-2021-44228 /
        Log4Shell). They remain on CveIntel for downstream compatibility but
        are always None when populated by this scraper. Authenticated VPR/
        remediation lookup can be added later as a second pass once Tenable's
        Vulnerability Intelligence API is available.
        """
        intel = CveIntel(
            cve_id=cve_id,
            raw_html=html,
            fetched_at=datetime.now(UTC),
            fetch_status="OK",
        )

        soup = BeautifulSoup(html, "lxml")
        node = soup.find("script", id="__NEXT_DATA__")
        if node is None or not node.string:  # type: ignore[union-attr]  # bs4 Tag|NavigableString narrowing
            logger.warning("cve page has no __NEXT_DATA__ blob", cve_id=cve_id)
            intel.fetch_status = "ERROR"
            return intel

        try:
            blob = json.loads(node.string)  # type: ignore[union-attr]  # bs4 Tag|NavigableString narrowing
            page_props = blob.get("props", {}).get("pageProps", {})
            # A rejected CVE has deprecated=True but is still populated, so
            # only treat explicit errorStatus as a real not-found signal.
            if page_props.get("errorStatus"):
                intel.fetch_status = "NOT_FOUND"
                return intel
            cve = page_props.get("cve")
            if not isinstance(cve, dict):
                logger.warning("cve page has no cve object", cve_id=cve_id)
                intel.fetch_status = "ERROR"
                return intel

            intel.description = _clean_str(cve.get("description"))
            intel.cvss3_base_score = _safe_float(cve.get("cvss3_base_score"))
            intel.cvss3_severity = _normalize_severity(cve.get("cvss3_severity"))
            intel.cvss2_base_score = _safe_float(cve.get("cvss2_base_score"))
            intel.cvss2_severity = _normalize_severity(cve.get("cvss2_severity"))
            intel.epss_score = _safe_float(cve.get("epss_score"))
            intel.published_date = _iso_date(
                cve.get("publication_date") or cve.get("nvd_published")
            )
            intel.last_modified_date = _iso_date(cve.get("nvd_modified"))
            # Not available on the public page; kept for dataclass compat.
            intel.vpr_score = None
            intel.vpr_severity = None
            intel.remediation = None
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            logger.warning("cve parse failed", cve_id=cve_id, error=str(exc))
            intel.fetch_status = "ERROR"

        return intel


def _safe_float(v: object) -> float | None:
    if v is None:
        return None
    try:
        return float(v)  # type: ignore[arg-type]  # TODO: tighten type of v in caller
    except (TypeError, ValueError):
        return None


def _clean_str(v: object) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _normalize_severity(v: object) -> str | None:
    """Normalize 'Critical'/'High'/etc. to upper-case canonical form."""
    if not v:
        return None
    s = str(v).strip().upper()
    return s if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"} else None


def _iso_date(v: object) -> str | None:
    """Return YYYY-MM-DD from a Tenable-style ISO timestamp, or None."""
    if not v:
        return None
    s = str(v)
    if len(s) >= 10 and s[4] == "-" and s[7] == "-":
        return s[:10]
    return None
