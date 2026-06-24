"""Scheduler: runs the full pipeline on a cron schedule and on demand.

Used both as a long-running scheduler (started from main.py via lifespan) and
as a CLI entrypoint for `make pull` / `python -m t1_cve_enricher.workers.scheduler --run-now`.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from t1_cve_enricher.config import Settings, get_settings
from t1_cve_enricher.db import get_connection
from t1_cve_enricher.workers import (
    cve_enricher,
    findings_extractor,
    plugin_enricher,
    progress,
    source_discovery,
)

logger = structlog.get_logger(__name__)

_scheduler: AsyncIOScheduler | None = None


async def run_pipeline(settings: Settings | None = None) -> None:
    """Run all three stages in sequence."""
    settings = settings or get_settings()
    started_at = datetime.now(UTC)
    job_id: int | None = None

    with get_connection(settings.database_path) as conn:
        cursor = conn.execute(
            "INSERT INTO pull_jobs (started_at, status) VALUES (?, ?)",
            (started_at, "RUNNING"),
        )
        job_id = cursor.lastrowid

    try:
        sources = await source_discovery.run(settings)
        findings_count = await findings_extractor.run(settings, sources)
        enriched_count = await cve_enricher.run(settings)
        plugin_count = await plugin_enricher.run(settings)
        logger.info("pipeline: plugin enrichment done", plugin_count=plugin_count)
        status = "SUCCESS"
        error = None
    except Exception as exc:
        logger.exception("pipeline failed")
        sources, findings_count, enriched_count = [], 0, 0
        status = "FAILED"
        error = str(exc)
    finally:
        with get_connection(settings.database_path) as conn:
            conn.execute(
                """
                UPDATE pull_jobs
                SET completed_at = ?,
                    status = ?,
                    sources_processed = ?,
                    findings_pulled = ?,
                    cves_enriched = ?,
                    error_message = ?
                WHERE id = ?
                """,
                (
                    datetime.now(UTC),
                    status,
                    len(sources),
                    findings_count,
                    enriched_count,
                    error,
                    job_id,
                ),
            )
        progress.finish(message=f"Last run: {status} at {datetime.now(UTC).isoformat()}")


def start_scheduler(settings: Settings) -> None:
    """Start the daily cron scheduler. Idempotent."""
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.add_job(
        run_pipeline,
        trigger=CronTrigger.from_crontab(settings.schedule_cron),
        kwargs={"settings": settings},
        id="daily_pipeline",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("scheduler started", cron=settings.schedule_cron)


def stop_scheduler() -> None:
    """Shut down the scheduler if running."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="t1-cve-enricher scheduler")
    parser.add_argument(
        "--run-now",
        action="store_true",
        help="Trigger an immediate pipeline run and exit.",
    )
    args = parser.parse_args()

    if args.run_now:
        asyncio.run(run_pipeline())
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
