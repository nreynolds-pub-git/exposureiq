"""Pipeline progress reporting.

Single-row state machine. Workers call begin/tick/finish to update what the
UI sees in real time. All functions are best-effort — a progress-reporting
failure (DB lock, schema mismatch, whatever) must never kill the pipeline.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from t1_cve_enricher.config import get_settings
from t1_cve_enricher.db import get_connection

logger = structlog.get_logger(__name__)


def begin(stage: str, total: int = 0, source: str | None = None, message: str | None = None) -> None:
    """Mark the start of a stage. Resets counters."""
    now = datetime.now(UTC)
    try:
        settings = get_settings()
        with get_connection(settings.database_path) as conn:
            conn.execute(
                """
                UPDATE pipeline_progress SET
                    is_running = 1,
                    stage = ?,
                    source = ?,
                    current_n = 0,
                    total_n = ?,
                    message = ?,
                    started_at = ?,
                    updated_at = ?
                WHERE id = 1
                """,
                (stage, source, total, message, now, now),
            )
    except Exception:
        logger.exception("progress.begin failed", stage=stage)


def tick(current: int, message: str | None = None, total: int | None = None) -> None:
    """Update the current count and optionally a status message.

    `total` is optional — pass it when the total becomes known mid-stage
    (e.g. CVE enrichment doesn't know the count until it queries the DB).
    """
    now = datetime.now(UTC)
    try:
        settings = get_settings()
        with get_connection(settings.database_path) as conn:
            if total is not None:
                conn.execute(
                    """
                    UPDATE pipeline_progress SET
                        current_n = ?,
                        total_n = ?,
                        message = COALESCE(?, message),
                        updated_at = ?
                    WHERE id = 1
                    """,
                    (current, total, message, now),
                )
            else:
                conn.execute(
                    """
                    UPDATE pipeline_progress SET
                        current_n = ?,
                        message = COALESCE(?, message),
                        updated_at = ?
                    WHERE id = 1
                    """,
                    (current, message, now),
                )
    except Exception:
        logger.exception("progress.tick failed")


def finish(message: str | None = None) -> None:
    """Mark the pipeline as idle. Called from the run_pipeline finally block
    so a crash mid-stage still clears the running flag."""
    now = datetime.now(UTC)
    try:
        settings = get_settings()
        with get_connection(settings.database_path) as conn:
            conn.execute(
                """
                UPDATE pipeline_progress SET
                    is_running = 0,
                    stage = 'idle',
                    source = NULL,
                    current_n = 0,
                    total_n = 0,
                    message = ?,
                    updated_at = ?
                WHERE id = 1
                """,
                (message, now),
            )
    except Exception:
        logger.exception("progress.finish failed")
