# scripts/

Diagnostic and one-shot utilities used while developing or debugging ExposureIQ.
Nothing in this folder runs as part of normal operation — these are tools you
invoke by hand when you need to inspect what Tenable One is actually returning
for a given source, or when a new connector type isn't behaving the way the
extractor expects.

## Operating principle

Everything in this folder is **read-only against Tenable One.** No writes,
no mutations, no side effects on your tenant. Safe to run during a demo or
against a production tenant.

Each script uses the same `TenableClient` configured from your `.env`, so
the data shapes you see here are exactly what `findings_extractor.py` sees
at extraction time.

## Scripts

### `diagnose_source_shapes.py`

**When to use it:** a new third-party connector has been added to Tenable One
and ExposureIQ isn't surfacing one or more of its fields (IPv4, OS, FQDN,
timestamps), or an existing connector starts returning a different shape after
a Tenable One platform update.

**What it does:** for every source currently in your `sources` table, fetches
one asset record via the inventory search endpoint and prints:

- The full key inventory of the asset response
- Which of our known field-of-interest keys (ipv4, fqdn, os, mac,
  first_observed, last_observed) are present and which aren't
- A name-hint scan to catch fields under unusual key names

It also saves the raw asset JSON for each source to
`scripts/source_shapes.json` (gitignored — output, not source) for follow-up
inspection.

**How to run:**

```bash
PYTHONPATH=backend/src python3 scripts/diagnose_source_shapes.py
```

Output goes to stdout for at-a-glance scanning, and to `source_shapes.json`
for grep / jq inspection.

**Reading the output:** the script flags each field-of-interest as "via key
X" (found, here's the key), "not present" (the response doesn't carry it), or
"NO STANDARD KEY — name-hint matches: [...]" (the field name doesn't match
our expected keys but something keyword-similar is present, worth a look).
