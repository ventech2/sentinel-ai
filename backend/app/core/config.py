"""Environment-backed application settings."""

from functools import lru_cache
from pathlib import Path

from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the API and database layers."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Sentinel AI API"
    environment: str = "development"
    database_url: str = "postgresql+asyncpg://localhost:5432/sentinel_ai"
    database_url_sync: str = "postgresql+psycopg://localhost:5432/sentinel_ai"
    allowed_origins: list[str] = ["http://localhost:3000"]
    redis_url: str = "redis://localhost:6379/0"
    remediation_repository_root: Path | None = None
    ingestion_max_repository_bytes: int = 500 * 1024 * 1024
    ingestion_clone_timeout_seconds: float = 90.0
    # Development/test-only override used by the HTTP smoke test. Production
    # deployments must leave this unset and use a public GitHub clone instead.
    ingestion_local_repository_root: Path | None = None
    report_export_directory: Path = Path("exports")

    ai_reasoning_provider: Literal["gemini", "openai"] = "gemini"

    gemini_api_key: SecretStr | None = None
    gemini_model: str = "gemini-3-flash-preview"
    gemini_timeout_seconds: float = 20.0

    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-5.6"
    openai_timeout_seconds: float = 20.0
    ai_context_lines: int = 12

    github_client_id: str | None = None
    github_client_secret: SecretStr | None = None
    github_redirect_uri: str = "http://localhost:8000/auth/github/callback"
    # Browser callback destination after the backend completes GitHub OAuth.
    frontend_url: str = "http://localhost:3000"
    github_oauth_scopes: str = "read:user user:email repo"
    oauth_token_encryption_key: SecretStr | None = None
    session_secret: SecretStr = SecretStr("replace-this-development-session-secret")
    # The frontend and API live on different origins in deployment.  Cookies
    # therefore need SameSite=None and HTTPS; a local HTTP setup may override
    # SESSION_HTTPS_ONLY=false in its uncommitted .env file only.
    session_same_site: Literal["lax", "strict", "none"] = "none"
    session_https_only: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
