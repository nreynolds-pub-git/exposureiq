"""Anonymize Tenable One connector source codes to generic industry categories.

The Explain feature sends finding context to a user-chosen LLM provider via
BYOK. Customers are sometimes contractually or commercially sensitive about
disclosing which specific security vendors they use. This module maps
connector source codes (e.g. "ORCA:CSPM") to generic industry categories
(e.g. "CNAPP") so that vendor identity never reaches the LLM.

Add new mappings as connectors are encountered. Unknown sources fall back to
a generic label rather than passing through the raw code.

The mapping reflects what each tool *is*, not what Tenable's connector code
calls it. For example, CY-COGNITO is EASM (External Attack Surface
Management), not DAST, despite Tenable's connector code suffix.
"""

from __future__ import annotations

# Category strings used in LLM prompts. Industry-standard acronyms when they
# exist; descriptive phrases otherwise. Keep short — these appear inline in
# prompts and consume tokens.
EDR = "EDR"
CNAPP = "CNAPP"
DAST = "DAST"
EASM = "EASM"
SCA = "SCA"
CMDB = "CMDB"
TPRM = "Third-party risk rating"
OS_SCANNER = "OS vulnerability scanner"
CLOUD_INVENTORY = "Cloud inventory"
FALLBACK = "Third-party security tool"


# Source code -> category. Keep alphabetized by source code within each category
# block to make extension obvious during code review.
SOURCE_CATEGORIES: dict[str, str] = {
    # EDR / endpoint
    "JAMF:EDR": EDR,
    "MICROSOFT:TVM": EDR,
    "SENTINEL-ONE:EDR": EDR,
    # CNAPP / cloud security
    "ORCA:CSPM": CNAPP,
    "PALO-ALTO-NETWORKS:CSPM": CNAPP,
    "PRISMA-CLOUD:CSPM": CNAPP,
    "WIZ:CONFIGURATION": CNAPP,
    "WIZ:ISSUES": CNAPP,
    "WIZ:VM": CNAPP,
    # DAST / web application scanning
    "INVICTI:WHITEHAT-DAST": DAST,
    "MASTERCARD:DAST": DAST,
    # EASM / external attack surface (note: Tenable codes Cycognito as :DAST
    # but the tool is functionally EASM)
    "CY-COGNITO:DAST": EASM,
    # Third-party risk rating
    "RISK-RECON:RR": TPRM,
    "SECURITY-SCORECARD:DAST": TPRM,
    # Other
    "AWS:AINV": CLOUD_INVENTORY,
    "RED-HAT:VM": OS_SCANNER,
    "SERVICE-NOW:AINV": CMDB,
    "SNYK:SNYK": SCA,
}


def category_for(source_code: str | None) -> str:
    """Return the industry category for a connector source code.

    Unknown or empty source codes return the generic fallback rather than the
    raw code, so vendor identity never leaks to the LLM through this function.

    Lookup is case-sensitive against the canonical Tenable connector codes
    (e.g. "MICROSOFT:TVM", not "microsoft:tvm"). Callers pulling source codes
    from the Tenable API will receive them in this form; callers constructing
    them by hand should match exactly.
    """
    if not source_code:
        return FALLBACK
    return SOURCE_CATEGORIES.get(source_code, FALLBACK)
