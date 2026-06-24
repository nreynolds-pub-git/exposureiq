"""FastAPI application entry point."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path as _StaticPath

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from t1_cve_enricher import __version__
from t1_cve_enricher.api.routes import router as api_router
from t1_cve_enricher.config import get_settings
from t1_cve_enricher.db import init_db
from t1_cve_enricher.workers.scheduler import start_scheduler, stop_scheduler

logger = structlog.get_logger(__name__)


def configure_logging(level: str) -> None:
    """Configure structured logging."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hooks."""
    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info(
        "starting t1-cve-enricher",
        version=__version__,
        db_path=str(settings.database_path),
    )
    init_db(settings.database_path)
    start_scheduler(settings)
    yield
    logger.info("shutting down")
    stop_scheduler()


def create_app() -> FastAPI:
    """Build the FastAPI app."""
    settings = get_settings()
    app = FastAPI(
        title="t1-cve-enricher",
        description="Enriches third-party CVE findings ingested into Tenable One.",
        version=__version__,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router, prefix="/api")

    # Serve the built frontend if it's been built into ./frontend/dist.
    # In dev (running `make run-backend`), this directory doesn't exist
    # and we silently skip — the Vite dev server on :5173 handles the UI.
    # In the Docker image, it's baked in at build time.
    dist_dir = _StaticPath(__file__).resolve().parents[3] / "frontend" / "dist"
    if dist_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="frontend")

    return app


app = create_app()


def cli() -> None:
    """Console entry point (used by the `t1-cve-enricher` script)."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "t1_cve_enricher.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    cli()
