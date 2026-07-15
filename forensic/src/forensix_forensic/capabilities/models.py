from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from forensix_forensic.adb.models import SharedStorageRootProbe


class CapabilityStatus(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"


class CapabilityDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: CapabilityStatus
    reason_code: str
    explanation: str


class DeviceCapabilitySnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    assessed_at: datetime
    serial: str
    manufacturer: str | None
    model: str | None
    android_version: str | None
    sdk_level: int | None = Field(default=None, ge=1, le=10_000)
    build_fingerprint: str | None
    security_patch: str | None
    package_count: int = Field(ge=0)
    storage_roots: tuple[SharedStorageRootProbe, ...] = ()
    capabilities: dict[str, CapabilityDecision]
    warnings: tuple[str, ...]
    assessor_version: str = "0.2.0"
