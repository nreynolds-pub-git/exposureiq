"""Tests for the findings extractor."""

from __future__ import annotations

from t1_cve_enricher.workers.findings_extractor import (
    _asset_field,
    _extract_cve_id,
    _join_arr,
)


class TestExtractCveId:
    def test_finding_detection_name(self) -> None:
        f = {"finding_detection_name": "CVE-2024-1234"}
        assert _extract_cve_id(f) == "CVE-2024-1234"

    def test_finding_name_fallback(self) -> None:
        f = {"finding_name": "CVE-2023-5476"}
        assert _extract_cve_id(f) == "CVE-2023-5476"

    def test_lowercase_normalized(self) -> None:
        f = {"finding_detection_name": "cve-2024-1234"}
        assert _extract_cve_id(f) == "CVE-2024-1234"

    def test_with_whitespace(self) -> None:
        f = {"finding_detection_name": " CVE-2024-1234 "}
        assert _extract_cve_id(f) == "CVE-2024-1234"

    def test_not_a_cve(self) -> None:
        f = {"finding_detection_name": "Microsoft Windows SMB Service Detection"}
        assert _extract_cve_id(f) is None

    def test_empty(self) -> None:
        assert _extract_cve_id({}) is None
        assert _extract_cve_id({"finding_detection_name": ""}) is None
        assert _extract_cve_id({"finding_detection_name": None}) is None


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

    def test_skips_none(self) -> None:
        asset = {"asset_name": None, "name": "fallback"}
        assert _asset_field(asset, "asset_name", "name") == "fallback"

    def test_skips_empty_list(self) -> None:
        asset = {"ipv4_addresses": [], "ipv4": "10.0.0.1"}
        assert _asset_field(asset, "ipv4_addresses", "ipv4") == "10.0.0.1"

    def test_all_missing(self) -> None:
        assert _asset_field({}, "asset_name", "name") is None


class TestJoinArr:
    def test_list_of_strings(self) -> None:
        assert _join_arr(["10.0.0.1", "10.0.0.2"]) == "10.0.0.1,10.0.0.2"

    def test_single_string(self) -> None:
        assert _join_arr("10.0.0.1") == "10.0.0.1"

    def test_empty_list(self) -> None:
        assert _join_arr([]) is None

    def test_none(self) -> None:
        assert _join_arr(None) is None
