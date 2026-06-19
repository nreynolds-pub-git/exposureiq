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
import os
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

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

    async def __aenter__(self) -> "CveScraper":
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
                fetched_at=datetime.now(timezone.utc),
                fetch_status="ERROR",
            )

        if response.status_code == 404:
            return CveIntel(
                cve_id=cve_id,
                fetched_at=datetime.now(timezone.utc),
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
        """Parse the HTML of a tenable.com CVE page.

        NOTE: the exact selectors will need verification against a live page —
        the markup may have changed since this scaffold was written. The
        functions below encapsulate each field so they're easy to fix in
        isolation when the time comes.
        """
        soup = BeautifulSoup(html, "lxml")
        intel = CveIntel(
            cve_id=cve_id,
            raw_html=html,
            fetched_at=datetime.now(timezone.utc),
            fetch_status="OK",
        )
        try:
            intel.description = self._parse_description(soup)
            intel.cvss3_base_score, intel.cvss3_severity = self._parse_cvss(soup, "3")
            intel.cvss2_base_score, intel.cvss2_severity = self._parse_cvss(soup, "2")
            intel.vpr_score, intel.vpr_severity = self._parse_vpr(soup)
            intel.epss_score = self._parse_epss(soup)
            intel.remediation = self._parse_remediation(soup)
            intel.published_date = self._parse_date(soup, "Published")
            intel.last_modified_date = self._parse_date(soup, "Updated")
        except Exception as exc:  # noqa: BLE001 — we want fail-soft here
            logger.warning("cve parse failed", cve_id=cve_id, error=str(exc))
            intel.fetch_status = "ERROR"
        return intel

    # --- field parsers (selectors are best-effort; verify against live page) ---

    def _parse_description(self, soup: BeautifulSoup) -> str | None:
        for selector in ['[data-testid="cve-description"]', "section.description", "p.description"]:
            el = soup.select_one(selector)
            if el and el.get_text(strip=True):
                return el.get_text(strip=True)
        return None

    def _parse_cvss(self, soup: BeautifulSoup, version: str) -> tuple[float | None, str | None]:
        # Placeholder — tune selectors after inspecting an actual CVE page.
        label = f"CVSSv{version}"
        for el in soup.find_all(string=re.compile(label, re.IGNORECASE)):
            container = el.parent
            text = container.get_text(" ", strip=True) if container else ""
            match = re.search(r"(\d+\.\d+)\s*\(?(CRITICAL|HIGH|MEDIUM|LOW)?\)?", text, re.I)
            if match:
                score = float(match.group(1))
                severity = match.group(2).upper() if match.group(2) else None
                return score, severity
        return None, None

    def _parse_vpr(self, soup: BeautifulSoup) -> tuple[float | None, str | None]:
        for el in soup.find_all(string=re.compile(r"\bVPR\b", re.IGNORECASE)):
            container = el.parent
            text = container.get_text(" ", strip=True) if container else ""
            match = re.search(r"(\d+\.\d+)\s*\(?(CRITICAL|HIGH|MEDIUM|LOW)?\)?", text, re.I)
            if match:
                score = float(match.group(1))
                severity = match.group(2).upper() if match.group(2) else None
                return score, severity
        return None, None

    def _parse_epss(self, soup: BeautifulSoup) -> float | None:
        for el in soup.find_all(string=re.compile(r"\bEPSS\b", re.IGNORECASE)):
            container = el.parent
            text = container.get_text(" ", strip=True) if container else ""
            match = re.search(r"(\d+\.\d+(?:e-?\d+)?)", text)
            if match:
                return float(match.group(1))
        return None

    def _parse_remediation(self, soup: BeautifulSoup) -> str | None:
        for selector in [
            '[data-testid="cve-remediation"]',
            "section.remediation",
            "section#solution",
        ]:
            el = soup.select_one(selector)
            if el and el.get_text(strip=True):
                return el.get_text(" ", strip=True)
        return None

    def _parse_date(self, soup: BeautifulSoup, label: str) -> str | None:
        for el in soup.find_all(string=re.compile(label, re.IGNORECASE)):
            container = el.parent
            text = container.get_text(" ", strip=True) if container else ""
            match = re.search(r"(\d{4}-\d{2}-\d{2})", text)
            if match:
                return match.group(1)
        return None
