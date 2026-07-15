"""Validated local configuration for the ForensiX service."""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="FORENSIX_",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Literal["development", "test", "production"] = "development"
    data_dir: Path = Path("data")
    database_url: str | None = None
    adb_path: Path | None = None
    adb_mode: Literal["system", "mock"] = "mock"
    mock_adb_scenario: str = "authorized"
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:5173",)
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8765, ge=1024, le=65535)

    @field_validator("allowed_origins")
    @classmethod
    def validate_origins(cls, origins: tuple[str, ...]) -> tuple[str, ...]:
        if not origins:
            raise ValueError("At least one UI origin is required")
        if any(origin == "*" for origin in origins):
            raise ValueError("Wildcard origins are not permitted")
        return origins

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir.expanduser().resolve()

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.resolved_data_dir / 'forensix.db').as_posix()}"
