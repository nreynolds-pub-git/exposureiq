"""SQLite connection and schema initialisation."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


def _parse_timestamp(value: bytes) -> datetime | None:
    """Robust TIMESTAMP converter registered with sqlite3.

    Handles multiple wire formats we've seen in this database:
      - Python-adapter default:      "2026-03-14 02:00:40"
      - Python-adapter with usec:    "2026-03-14 02:00:40.256000"
      - Tenable ISO 8601 with Z:     "2026-03-14T02:00:40.256Z"
      - Tenable ISO 8601 with tz:    "2026-03-14T02:00:40+00:00"

    The default sqlite3 converter only handles the first two. Since findings
    are written with Tenable API strings directly, we need to accept all four.
    """
    if value is None:
        return None
    s = value.decode("utf-8").strip()
    if not s:
        return None
    # datetime.fromisoformat handles most cases in Python 3.11+, including
    # the "T" separator, fractional seconds, and "+00:00" tz suffix.
    # It does NOT handle the "Z" suffix, so we normalize that first.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Also handle the plain "YYYY-MM-DD HH:MM:SS" form (default sqlite adapter output)
    # by letting fromisoformat handle it too — it accepts space separator in 3.11+.
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        logger.warning("timestamp converter failed", value=s)
        return None


# Register once at import time. This replaces Python's default TIMESTAMP
# converter, which only handles space-separated formats without timezones.
sqlite3.register_converter("TIMESTAMP", _parse_timestamp)

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


# Columns that must exist on each table for the app to function.
# Format: table_name -> list of (column_name, column_definition).
# `column_definition` is the raw SQL used in ALTER TABLE ADD COLUMN when the
# column is missing — so it must be a valid, nullable-safe definition
# (no NOT NULL without a default). This list is the source of truth that
# schema.sql is checked against at startup.
_EXPECTED_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "sources": [
        ("display_name", "TEXT"),
    ],
    "findings": [
        ("vpr_score", "REAL"),
        ("vpr2_score", "REAL"),
        ("finding_description", "TEXT"),
    ],
    # Add more (table, column, definition) rows here as the schema evolves.
    # If a column is required (NOT NULL without a sensible default), you'll
    # need a real migration — this guard only handles nullable additions.
}


def _ensure_columns(conn: sqlite3.Connection) -> None:
    """Verify expected columns exist on each table; add missing nullables.

    This is a lightweight self-healing step for schema drift between the
    running code and schema.sql. If a column exists in _EXPECTED_COLUMNS
    but not in the actual table, we ALTER TABLE to add it. Safe for
    nullable columns; unsafe patterns (NOT NULL without default) should
    prompt a real migration instead of being handled here.
    """
    for table, columns in _EXPECTED_COLUMNS.items():
        # PRAGMA table_info returns (cid, name, type, notnull, dflt, pk) per column
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not existing:
            # Table doesn't exist at all — schema.sql didn't create it.
            # This is a real bug (either schema.sql is broken or the table
            # was renamed without updating _EXPECTED_COLUMNS). Fail loudly.
            raise RuntimeError(
                f"Schema check failed: table '{table}' does not exist. "
                f"Check backend/src/t1_cve_enricher/db/schema.sql."
            )
        for col_name, col_def in columns:
            if col_name not in existing:
                logger.warning(
                    "schema drift: adding missing column",
                    table=table,
                    column=col_name,
                    definition=col_def,
                )
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")


def init_db(db_path: Path) -> None:
    """Create the SQLite file (if missing), apply the schema, and reconcile columns."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_sql = SCHEMA_PATH.read_text()
    with sqlite3.connect(db_path) as conn:
        conn.executescript(schema_sql)
        _ensure_columns(conn)
        conn.commit()
    logger.info("db initialised", path=str(db_path))


@contextmanager
def get_connection(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with row factory set to sqlite3.Row."""
    conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
