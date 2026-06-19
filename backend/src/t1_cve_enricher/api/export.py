"""CSV / JSON export helpers."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, date
from typing import Any

from fastapi.responses import Response


def _default(value: Any) -> Any:
    if isinstance(value, datetime | date):
        return value.isoformat()
    raise TypeError(f"unserializable: {type(value).__name__}")


def build_json_response(rows: list[dict[str, Any]]) -> Response:
    payload = json.dumps(rows, default=_default, indent=2)
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=findings.json"},
    )


def build_csv_response(rows: list[dict[str, Any]]) -> Response:
    if not rows:
        return Response(
            content="",
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"},
        )
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    for row in rows:
        normalised = {
            k: (v.isoformat() if isinstance(v, datetime | date) else v) for k, v in row.items()
        }
        writer.writerow(normalised)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )
