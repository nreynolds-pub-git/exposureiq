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


def init_db(db_path: Path) -> None:
    """Create the SQLite file (if missing) and apply the schema."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_sql = SCHEMA_PATH.read_text()
    with sqlite3.connect(db_path) as conn:
        conn.executescript(schema_sql)
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
