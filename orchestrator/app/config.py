"""Configuration loaded from environment variables."""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the orchestrator.

    All settings can be overridden via environment variables (see .env.example).
    """

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Devin API ---
    devin_api_base: str = Field("https://api.devin.ai", alias="DEVIN_API_BASE")
    devin_api_key: str = Field("", alias="DEVIN_API_KEY")
    devin_org_id: str = Field("", alias="DEVIN_ORG_ID")
    devin_create_as_user_id: str | None = Field(None, alias="DEVIN_CREATE_AS_USER_ID")

    # --- GitHub ---
    github_api_base: str = Field("https://api.github.com", alias="GITHUB_API_BASE")
    github_token: str = Field("", alias="GITHUB_TOKEN")
    target_repo: str = Field("ezraodio/superset", alias="TARGET_REPO")
    issue_label: str = Field("devin-remediation", alias="ISSUE_LABEL")
    # Default branch of the target repo. Apache Superset's fork is `master`;
    # most repos are `main`. Injected into the Devin prompt so Devin branches
    # from the right base.
    target_base_branch: str = Field("master", alias="TARGET_BASE_BRANCH")

    # --- Webhooks / auth ---
    ingest_shared_secret: str = Field(
        "change-me-local-only", alias="INGEST_SHARED_SECRET"
    )

    # --- Policy ---
    min_cvss: float = Field(7.0, alias="MIN_CVSS")
    min_severity: str = Field("HIGH", alias="MIN_SEVERITY")  # LOW | MEDIUM | HIGH | CRITICAL
    max_concurrent_sessions: int = Field(5, alias="MAX_CONCURRENT_SESSIONS")
    dry_run: bool = Field(False, alias="DRY_RUN")
    mock_mode: bool = Field(False, alias="MOCK_MODE")

    # Router behavior: what to do for trivial-looking version bumps.
    # "bump_pr"  -> open version-bump PR directly (no Devin)
    # "dispatch" -> always dispatch Devin
    # "skip"     -> skip (Dependabot will handle)
    bump_strategy: str = Field("dispatch", alias="BUMP_STRATEGY")

    # --- Storage ---
    db_path: str = Field("./orchestrator.db", alias="ORCHESTRATOR_DB_PATH")

    # --- Server ---
    public_base_url: str = Field("http://localhost:8080", alias="PUBLIC_BASE_URL")


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_for_test() -> None:
    """Testing hook to force re-read of env."""
    global _settings
    _settings = None
