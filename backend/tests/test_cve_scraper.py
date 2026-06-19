"""Tests for the CVE scraper.

These are placeholders to confirm the scaffold is wired correctly. Real
parsing tests will need fixture HTML from a live tenable.com CVE page.
"""

from __future__ import annotations

import pytest

from t1_cve_enricher.tenable.cve_scraper import CVE_ID_PATTERN, CveIntel


@pytest.mark.parametrize(
    "cve_id,expected",
    [
        ("CVE-2024-1234", True),
        ("CVE-2024-12345", True),
        ("CVE-1999-0001", True),
        ("CVE-2024-12", False),  # too short
        ("CVE-24-1234", False),  # year too short
        ("notacve", False),
        ("", False),
    ],
)
def test_cve_id_pattern(cve_id: str, expected: bool) -> None:
    assert bool(CVE_ID_PATTERN.match(cve_id)) is expected


def test_cve_intel_defaults() -> None:
    intel = CveIntel(cve_id="CVE-2024-1234")
    assert intel.cve_id == "CVE-2024-1234"
    assert intel.fetch_status == "OK"
    assert intel.description is None
