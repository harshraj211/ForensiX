"""Versioned models for a validation run and its integrity seal."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ValidationStatus(StrEnum):
    SUCCEEDED = "pass"
    WARNING = "warning"
    FAIL = "fail"
    SKIPPED = "skipped"


class ValidationOutcome(StrEnum):
    PASSED = "passed"
    PASSED_WITH_WARNINGS = "passed_with_warnings"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class ValidationCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    check_id: str = Field(pattern=r"^[a-z0-9_]{3,64}$")
    status: ValidationStatus
    summary: str = Field(min_length=1, max_length=500)
    observed: dict[str, str | int | bool | None] = Field(default_factory=dict)


class ValidationEnvironment(BaseModel):
    model_config = ConfigDict(frozen=True)

    operating_system: str = Field(min_length=1, max_length=64)
    operating_system_release: str = Field(min_length=1, max_length=128)
    machine: str = Field(min_length=1, max_length=64)
    python_version: str = Field(min_length=1, max_length=64)


class ValidationReport(BaseModel):
    """A redacted result. Raw device serials and inventory paths are never persisted."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = "forensix-validation/1.0"
    run_id: str = Field(min_length=36, max_length=36)
    started_at: datetime
    completed_at: datetime
    tool_version: str = Field(min_length=1, max_length=64)
    mode: str = Field(pattern=r"^(mock|system)$")
    outcome: ValidationOutcome
    environment: ValidationEnvironment
    adb_version: str | None = Field(default=None, max_length=64)
    adb_executable_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    device_serial_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    android_release: str | None = Field(default=None, max_length=64)
    android_sdk: str | None = Field(default=None, max_length=16)
    build_fingerprint_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    checks: tuple[ValidationCheck, ...]
    limitations: tuple[str, ...]


class SealedValidationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    report: ValidationReport
    canonical_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
