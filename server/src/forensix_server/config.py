"""Validated local configuration for the ForensiX service."""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from forensix_forensic.adb import MAX_PHYSICAL_BLOCK_BYTES
from forensix_forensic.integrations import AleappConfiguration, AleappRunner


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
    deployment_transport: Literal["loopback_http", "https"] = "loopback_http"
    session_ttl_minutes: int = Field(default=480, ge=15, le=1440)
    login_max_failures: int = Field(default=5, ge=3, le=20)
    login_lockout_minutes: int = Field(default=15, ge=1, le=1440)
    aleapp_program_path: Path | None = None
    aleapp_expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    aleapp_release_label: str = Field(default="v2026.1.0", min_length=1, max_length=64)
    aleapp_python_executable: Path | None = None
    aleapp_timeout_seconds: int = Field(default=1800, ge=30, le=7200)
    enable_experimental_physical_acquisition: bool = False
    max_physical_acquisition_bytes: int = Field(
        default=128 * 1024 * 1024 * 1024,
        ge=1024 * 1024,
        le=MAX_PHYSICAL_BLOCK_BYTES,
    )

    @field_validator("allowed_origins")
    @classmethod
    def validate_origins(cls, origins: tuple[str, ...]) -> tuple[str, ...]:
        if not origins:
            raise ValueError("At least one UI origin is required")
        if any(origin == "*" for origin in origins):
            raise ValueError("Wildcard origins are not permitted")
        return origins

    @model_validator(mode="after")
    def validate_aleapp_pair(self) -> "Settings":
        if (self.aleapp_program_path is None) != (self.aleapp_expected_sha256 is None):
            raise ValueError("ALEAPP program path and expected SHA-256 must be configured together")
        if self.deployment_transport == "loopback_http" and self.api_host not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("Plain HTTP deployment is restricted to a loopback host")
        return self

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir.expanduser().resolve()

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.resolved_data_dir / 'forensix.db').as_posix()}"

    @property
    def secure_cookies(self) -> bool:
        return self.deployment_transport == "https"

    def aleapp_runner(self) -> AleappRunner | None:
        if self.aleapp_program_path is None or self.aleapp_expected_sha256 is None:
            return None
        return AleappRunner(
            AleappConfiguration(
                program_path=self.aleapp_program_path,
                python_executable=self.aleapp_python_executable,
                expected_sha256=self.aleapp_expected_sha256,
                release_label=self.aleapp_release_label,
                timeout_seconds=self.aleapp_timeout_seconds,
            )
        )
