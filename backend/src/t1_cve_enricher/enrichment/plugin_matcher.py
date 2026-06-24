"""Per-finding plugin selection.

For a given (cve_id, source), pick the single "best" plugin to surface
on the findings table. Rules:

1. Map the source to a platform (RED-HAT:VM -> 'redhat', etc.).
2. Get all plugins linked to the CVE.
3. Drop "Misc." plugins (always generic placeholders).
4. Prefer plugins whose script_family matches the platform's expected
   family patterns. Among matches, the highest VPR wins.
5. If no platform match, fall back to the highest-VPR non-Misc plugin
   and mark platform_match=False so the UI can flag it.
6. If only "Misc." exists, return that with platform_match=False.

Recomputed per-request. Cheap because there's an index on cve_plugins
and most CVEs have <100 plugins.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

# --- Source -> platform table -----------------------------------------------
#
# The Tenable One source.value strings we observed in the lab data:
#   AWS:AINV, MICROSOFT:TVM, RED-HAT:VM, MASTERCARD:DAST,
#   SENTINEL-ONE:EDR, SERVICE-NOW:AINV, SNYK:SNYK
#
# Platforms here are coarse buckets used only for plugin-family matching.

SOURCE_TO_PLATFORM: dict[str, str] = {
    "RED-HAT:VM": "redhat",
    "MICROSOFT:TVM": "windows",
    "SENTINEL-ONE:EDR": "multi",  # endpoints could be any OS
    "MASTERCARD:DAST": "web",  # external attack surface = web apps
    "AWS:AINV": "multi",  # EC2 inventory spans OSes
    "SERVICE-NOW:AINV": "unknown",  # CMDB items vary too widely
    "SNYK:SNYK": "code",  # SCA / code-level findings
}

# --- Platform -> preferred family regex patterns ----------------------------
#
# Patterns use ^ to anchor at start. Add $ to require exact match,
# leave it off to allow prefix match. Multiple patterns per platform
# are tried in order; first match wins, then VPR is the tiebreaker
# inside the matching plugins.

_PLATFORM_FAMILY_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "redhat": [
        re.compile(r"^Red Hat Local Security Checks$"),
        re.compile(r"^Oracle Linux Local Security Checks$"),  # binary-compat
        re.compile(r"^CentOS Local Security Checks$"),  # binary-compat
    ],
    "windows": [
        re.compile(r"^Windows"),  # "Windows", "Windows : Microsoft Bulletins"
        re.compile(r"^Microsoft Bulletins$"),
    ],
    "web": [
        re.compile(r"^Web Servers$"),
        re.compile(r"^CGI abuses"),
    ],
    "code": [
        re.compile(r"^Snyk", re.IGNORECASE),
    ],
    "multi": [],  # no preference; fall back to highest VPR overall
    "unknown": [],  # same
}


def _family_matches(family: str | None, patterns: list[re.Pattern[str]]) -> bool:
    if not family:
        return False
    return any(p.match(family) for p in patterns)


def pick_best_plugin(
    conn: sqlite3.Connection,
    cve_id: str,
    source: str,
) -> dict[str, Any] | None:
    """Return the best plugin record for a finding, or None if no plugins exist.

    The returned dict has the same shape as a plugins-table row, plus a
    `platform_match` boolean indicating whether the matched plugin's
    family fits the asset's source platform.
    """
    platform = SOURCE_TO_PLATFORM.get(source, "unknown")
    patterns = _PLATFORM_FAMILY_PATTERNS.get(platform, [])

    rows = conn.execute(
        """
        SELECT p.plugin_id, p.script_name, p.script_family, p.plugin_type,
               p.synopsis, p.description, p.solution,
               p.vpr_score, p.vpr_severity, p.risk_factor, p.severity,
               p.cvss3_severity, p.cvss2_severity,
               p.cisa_known_exploited_date,
               p.plugin_publication_date, p.plugin_modification_date
        FROM plugins p
        JOIN cve_plugins cp ON cp.plugin_id = p.plugin_id
        WHERE cp.cve_id = ?
        ORDER BY (p.vpr_score IS NULL), p.vpr_score DESC
        """,
        (cve_id,),
    ).fetchall()

    if not rows:
        return None

    # Bucket the plugins. "Misc." is Tenable's generic placeholder family —
    # consistently returns "There is no known solution at this time." We
    # only surface it as a last resort.
    non_misc = [r for r in rows if (r["script_family"] or "") != "Misc."]
    misc_only = not non_misc

    if patterns and not misc_only:
        for row in non_misc:
            if _family_matches(row["script_family"], patterns):
                return {**dict(row), "platform_match": True}

    # No platform preference, or no plugin matched the patterns.
    # Fall back to highest-VPR non-Misc plugin (or Misc if that's all we have).
    fallback_pool = non_misc if not misc_only else rows
    return {**dict(fallback_pool[0]), "platform_match": False}
