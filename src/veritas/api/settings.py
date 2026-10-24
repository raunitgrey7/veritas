"""Runtime settings for the API, read from the environment.

Everything has a safe default so the service starts with no configuration. Auth
is off until ``APP_API_KEY`` is set, which matches the charter: the core works
with no secrets, and protection is opt-in.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration."""

    model_config = SettingsConfigDict(env_prefix="APP_", env_file=None)

    api_key: str | None = None
    service_name: str = "veritas"
    log_level: str = "INFO"
    results_path: str = "benchmarks/results.json"


def get_settings() -> Settings:
    """Return a fresh Settings instance (re-reads the environment each call)."""
    return Settings()
