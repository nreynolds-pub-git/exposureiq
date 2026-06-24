"""Application configuration. All settings come from env / .env file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings, loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Tenable credentials
    tenable_access_key: SecretStr = Field(..., description="Tenable API access key")
    tenable_secret_key: SecretStr = Field(..., description="Tenable API secret key")
    tenable_base_url: str = Field(
        default="https://cloud.tenable.com",
        description="Tenable API base URL",
    )

    # Storage
    database_path: Path = Field(
        default=Path("./data/enricher.db"),
        description="SQLite database file path",
    )

    # CVE enrichment
    cve_cache_ttl_days: int = Field(default=7, ge=1, le=90)
    scraper_user_agent: str = Field(
        default="t1-cve-enricher/0.1 (+github.com/nreynolds-pub-git/t1-cve-enricher)",
    )
    scraper_rate_limit_rps: float = Field(default=2.0, gt=0)
    scraper_cve_url_template: str = Field(
        default="https://www.tenable.com/cve/{cve_id}",
    )

    # Scheduling
    schedule_cron: str = Field(default="0 2 * * *")

    # Server
    host: str = Field(default="0.0.0.0")  # binding all interfaces is intentional
    port: int = Field(default=8000, gt=0, lt=65536)
    cors_origins: str = Field(default="http://localhost:5173")

    # Logging
    log_level: str = Field(default="INFO")

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse comma-separated CORS_ORIGINS into a list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor."""
    return Settings()  # type: ignore[call-arg]  # env populates required fields
