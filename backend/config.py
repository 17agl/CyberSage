import os
from pathlib import Path
from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized application configuration loaded from environment or .env."""

    # Application
    PROJECT_NAME: str = "CyberSage SOC Platform"
    VERSION: str = "2.1.0"
    ENVIRONMENT: Literal["development", "production", "testing"] = "development"

    # API & Host Settings
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    API_PREFIX: str = "/api"

    # Database Configuration
    # Defaults to local SQLite if DATABASE_URL is not set; easily overridden with postgresql+psycopg://...
    DATABASE_URL: str = Field(
        default="sqlite:///data/alerts.db",
        description="SQLAlchemy Database URL (SQLite for local dev, PostgreSQL for production)",
    )
    SQLITE_LEGACY_PATH: Path = Path("data/alerts.db")

    # Security & Sessions
    SECRET_KEY: str = Field(
        default="cybersage-dev-secret-key-change-in-production-32bytes-min",
        description="Cryptographic secret key for session signing and tokens",
    )
    SESSION_COOKIE_NAME: str = "cybersage_session"
    SESSION_MAX_AGE_SECONDS: int = 60 * 60 * 24 * 7  # 7 days
    COOKIE_SECURE: bool = False  # Set to True in HTTPS/Production
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"

    # Multi-Tenant / Organization Defaults
    DEFAULT_ORGANIZATION_NAME: str = "Primary Security Operations"
    DEFAULT_ORGANIZATION_SLUG: str = "primary-soc"

    # LLM Triage Settings
    OPENAI_API_KEY: str = Field(default="", description="OpenAI API Key for LLM triage")
    OPENAI_MODEL: str = "gpt-4o-mini"
    CYBERSAGE_TRIAGE_MODE: Literal["auto", "real", "mock"] = "auto"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


# Instantiate singleton settings
settings = Settings()
