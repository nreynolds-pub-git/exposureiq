"""Tests for the findings extractor."""

from __future__ import annotations

from t1_cve_enricher.workers.findings_extractor import (
    _asset_field,
    _extra,
    _extract_cves,
)


class TestExtractCves:
    def test_single_cve_from_array(self) -> None:
        f = {"extra_properties": {"finding_cves": ["CVE-2024-1234"]}}
        assert _extract_cves(f) == ["CVE-2024-1234"]

    def test_multiple_cves_from_array(self) -> None:
        f = {
            "extra_properties": {
                "finding_cves": ["CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9999"]
            }
        }
        assert _extract_cves(f) == ["CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9999"]

    def test_lowercase_normalized(self) -> None:
        f = {"extra_properties": {"finding_cves": ["cve-2024-1234"]}}
        assert _extract_cves(f) == ["CVE-2024-1234"]

    def test_whitespace_stripped(self) -> None:
        f = {"extra_properties": {"finding_cves": ["  CVE-2024-1234  "]}}
        assert _extract_cves(f) == ["CVE-2024-1234"]

    def test_duplicates_removed(self) -> None:
        f = {
            "extra_properties": {
                "finding_cves": ["CVE-2024-1234", "CVE-2024-1234", "cve-2024-1234"]
            }
        }
        assert _extract_cves(f) == ["CVE-2024-1234"]

    def test_non_cve_strings_filtered(self) -> None:
        f = {"extra_properties": {"finding_cves": ["CVE-2024-1234", "not-a-cve", "GHSA-1234"]}}
        assert _extract_cves(f) == ["CVE-2024-1234"]

    def test_empty_array_returns_empty_list(self) -> None:
        f = {"extra_properties": {"finding_cves": []}}
        assert _extract_cves(f) == []

    def test_missing_extra_properties_returns_empty(self) -> None:
        assert _extract_cves({}) == []
        assert _extract_cves({"extra_properties": None}) == []
        assert _extract_cves({"extra_properties": {}}) == []

    def test_missing_cves_field_returns_empty(self) -> None:
        f = {"extra_properties": {"finding_description": "something"}}
        assert _extract_cves(f) == []

    def test_non_list_cves_returns_empty(self) -> None:
        f = {"extra_properties": {"finding_cves": "CVE-2024-1234"}}
        assert _extract_cves(f) == []

    def test_empty_strings_in_array_filtered(self) -> None:
        f = {"extra_properties": {"finding_cves": ["CVE-2024-1234", "", None]}}
        assert _extract_cves(f) == ["CVE-2024-1234"]


class TestExtra:
    def test_reads_field(self) -> None:
        f = {"extra_properties": {"finding_description": "the description"}}
        assert _extra(f, "finding_description") == "the description"

    def test_returns_none_when_missing(self) -> None:
        assert _extra({}, "finding_description") is None
        assert _extra({"extra_properties": None}, "finding_description") is None
        assert _extra({"extra_properties": {}}, "finding_description") is None


class TestAssetField:
    def test_first_key_wins(self) -> None:
        asset = {"asset_name": "primary", "name": "fallback"}
        assert _asset_field(asset, "asset_name", "name") == "primary"

    def test_falls_back(self) -> None:
        asset = {"name": "fallback"}
        assert _asset_field(asset, "asset_name", "name") == "fallback"

    def test_skips_empty(self) -> None:
        asset = {"asset_name": "", "name": "fallback"}
        assert _asset_field(asset, "asset_name", "name") == "fallback"
