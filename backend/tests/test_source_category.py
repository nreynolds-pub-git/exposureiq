"""Tests for source_category — vendor anonymization for LLM context."""

from __future__ import annotations

import pytest

from t1_cve_enricher.enrichment.source_category import (
    CNAPP,
    DAST,
    EASM,
    EDR,
    FALLBACK,
    SOURCE_CATEGORIES,
    TPRM,
    category_for,
)


class TestCategoryFor:
    def test_known_edr_source(self) -> None:
        assert category_for("MICROSOFT:TVM") == EDR
        assert category_for("SENTINEL-ONE:EDR") == EDR
        assert category_for("JAMF:EDR") == EDR

    def test_known_cnapp_source(self) -> None:
        assert category_for("ORCA:CSPM") == CNAPP
        assert category_for("WIZ:VM") == CNAPP
        assert category_for("PALO-ALTO-NETWORKS:CSPM") == CNAPP

    def test_cycognito_mapped_to_easm_not_dast(self) -> None:
        # Tenable's connector code says DAST but Cycognito is functionally EASM.
        # This test exists to prevent a well-meaning future contributor from
        # "fixing" the mapping to match the connector code suffix.
        assert category_for("CY-COGNITO:DAST") == EASM
        assert category_for("CY-COGNITO:DAST") != DAST

    def test_third_party_risk_rating(self) -> None:
        assert category_for("SECURITY-SCORECARD:DAST") == TPRM
        assert category_for("RISK-RECON:RR") == TPRM

    def test_unknown_source_returns_fallback(self) -> None:
        # Critical: unknown codes must return the generic fallback, not the
        # raw source code. This is the privacy invariant — no vendor name
        # ever leaks through this function.
        assert category_for("FOOBAR:VENDOR") == FALLBACK
        assert category_for("ACME-SECURITY:EDR") == FALLBACK

    def test_none_returns_fallback(self) -> None:
        assert category_for(None) == FALLBACK

    def test_empty_string_returns_fallback(self) -> None:
        assert category_for("") == FALLBACK

    def test_case_sensitive_lookup(self) -> None:
        # Tenable API returns canonical uppercase codes. Lowercase input is
        # caller error; better to return fallback than silently misclassify.
        assert category_for("microsoft:tvm") == FALLBACK
        assert category_for("Microsoft:TVM") == FALLBACK


class TestPrivacyInvariant:
    """The whole point of this module: no raw vendor name should ever be
    returned. These tests assert that property against the entire mapping
    plus a synthetic unknown set."""

    @pytest.mark.parametrize("source_code", list(SOURCE_CATEGORIES.keys()))
    def test_no_known_source_leaks_vendor_name(self, source_code: str) -> None:
        result = category_for(source_code)
        # The category string must not contain the vendor portion of the code
        # (the part before the colon, lowercased for comparison).
        vendor_part = source_code.split(":")[0].lower()
        # Whitelist legitimately category-like vendor parts that aren't vendor
        # names (e.g. "AWS" is a cloud, but "Cloud inventory" doesn't reveal
        # which provider — still, defensive check skips these).
        if vendor_part in {"aws"}:
            return
        assert vendor_part not in result.lower(), (
            f"category_for({source_code!r}) returned {result!r}, "
            f"which contains the vendor name {vendor_part!r}"
        )

    @pytest.mark.parametrize(
        "fake_source",
        [
            "FAKEVENDOR:EDR",
            "SECRETCORP:CSPM",
            "PROPRIETARY-TOOL:VM",
            "ACME:DAST",
        ],
    )
    def test_unknown_source_never_leaks_vendor_name(self, fake_source: str) -> None:
        result = category_for(fake_source)
        vendor_part = fake_source.split(":")[0].lower()
        assert vendor_part not in result.lower()
        assert result == FALLBACK
