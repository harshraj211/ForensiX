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


class ValidationConnectionType(StrEnum):
    WIRED_USB = "wired_usb"
    WIRELESS_ADB = "wireless_adb"
    OTHER_CONTROLLED = "other_controlled"


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


class ValidationRunContext(BaseModel):
    """Examiner-supplied context for a controlled physical-device validation run."""

    model_config = ConfigDict(frozen=True)

    device_role: str = Field(default="controlled_test_device", pattern=r"^controlled_test_device$")
    operator_id: str = Field(min_length=2, max_length=128, pattern=r"^[A-Za-z0-9_.:@-]+$")
    authority_reference: str = Field(min_length=3, max_length=256)
    connection_type: ValidationConnectionType
    release_commit: str = Field(pattern=r"^[a-fA-F0-9]{7,64}$")


class ValidationReport(BaseModel):
    """A redacted result. Raw device serials and inventory paths are never persisted."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(
        default="forensix-validation/1.1", pattern=r"^forensix-validation/1\.[01]$"
    )
    run_id: str = Field(min_length=36, max_length=36)
    started_at: datetime
    completed_at: datetime
    tool_version: str = Field(min_length=1, max_length=64)
    mode: str = Field(pattern=r"^system$")
    outcome: ValidationOutcome
    environment: ValidationEnvironment
    run_context: ValidationRunContext | None = None
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
