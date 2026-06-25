"""One-pass diagnostic: dump the raw asset and finding JSON shape for every
known source in Tenable One.

For each source it prints the field-key inventory (so we can spot which keys
hold IPv4, OS, MAC, FQDN, first/last observed). Output also saves to
scripts/source_shapes.json for deeper inspection.

Read-only. Uses the same TenableClient + endpoints the extractor uses, so the
shapes printed here are exactly what findings_extractor.py sees.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from t1_cve_enricher.config import get_settings
from t1_cve_enricher.tenable.client import INVENTORY_ASSETS_SEARCH, TenableClient


# Fields we care about and the likely key variants per Tenable One source
FIELDS_OF_INTEREST = {
    "ipv4": ["ipv4_addresses", "ipv4", "ip_addresses", "last_ip", "mgmt_ip",
             "primary_ip", "ip", "network_interfaces"],
    "fqdn": ["fqdns", "fqdn", "hostname", "host_name", "computer_name"],
    "os":   ["operating_systems", "operating_system", "os", "os_name", "platform"],
    "mac":  ["mac_addresses", "mac", "macs"],
    "first_observed": ["first_observed", "first_seen", "first_observed_at", "created_at"],
    "last_observed":  ["last_observed",  "last_seen",  "last_observed_at",  "updated_at"],
}


async def sample_source(client: TenableClient, source: str) -> dict[str, Any] | None:
    """Pull a single asset for a source."""
    body = {
        "filters": [{"property": "products", "operator": "=", "value": [source]}],
        "limit": 1,
        "offset": 0,
    }
    data = await client._request("POST", INVENTORY_ASSETS_SEARCH, json_body=body)
    if not isinstance(data, dict):
        return None
    records = data.get("assets") or data.get("data") or data.get("records") or []
    return records[0] if records else None


def find_key_matches(record: dict[str, Any], candidates: list[str]) -> list[tuple[str, Any]]:
    """Return [(key, value), ...] for any candidate key that's present and non-empty."""
    matches = []
    for k in candidates:
        if k in record:
            v = record[k]
            if v not in (None, "", [], {}):
                matches.append((k, v))
    return matches


async def main() -> None:
    settings = get_settings()

    # Pull source list from the DB so we cover whatever's actually been discovered
    from t1_cve_enricher.db import get_connection
    with get_connection(settings.database_path) as conn:
        rows = conn.execute("SELECT name FROM sources ORDER BY name").fetchall()
        sources = [r["name"] for r in rows]
    print(f"Sweeping {len(sources)} sources: {sources}\n", file=sys.stderr)

    saved: dict[str, dict[str, Any]] = {}

    async with TenableClient(settings) as client:
        for src in sources:
            print(f"\n{'=' * 70}")
            print(f"SOURCE: {src}")
            print('=' * 70)
            try:
                asset = await sample_source(client, src)
            except Exception as e:
                print(f"  ERROR: {type(e).__name__}: {e}")
                continue
            if not asset:
                print("  No assets returned.")
                continue

            saved[src] = asset

            # Identify how each field of interest is represented
            for field_name, candidates in FIELDS_OF_INTEREST.items():
                hits = find_key_matches(asset, candidates)
                if hits:
                    for k, v in hits:
                        s = json.dumps(v, default=str)
                        if len(s) > 90:
                            s = s[:90] + "..."
                        print(f"  {field_name:18s}  via key {k!r:30s}  = {s}")
                else:
                    # No standard candidate matched — look for any key whose name
                    # hints at this field (helpful for catching unusual names)
                    name_hits = [k for k in asset.keys() if any(c.lower() in k.lower() for c in [field_name])]
                    if name_hits:
                        print(f"  {field_name:18s}  NO STANDARD KEY — name-hint matches: {name_hits}")
                    else:
                        print(f"  {field_name:18s}  not present")

            # Print all top-level keys for this asset so we can see if anything
            # else interesting (e.g. OS-related fields under a key we didn't expect)
            print(f"\n  All top-level keys ({len(asset)}):")
            for k in sorted(asset.keys()):
                v = asset[k]
                s = json.dumps(v, default=str)
                if len(s) > 80:
                    s = s[:80] + "..."
                print(f"    {k:30s} = {s}")

    # Save raw JSON for follow-up inspection
    out = Path("scripts/source_shapes.json")
    out.write_text(json.dumps(saved, indent=2, default=str))
    print(f"\n\nRaw asset JSONs saved to {out}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
