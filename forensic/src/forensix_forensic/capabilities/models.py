from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from forensix_forensic.adb.models import SharedStorageRootProbe


class CapabilityStatus(StrEnum):
    SUPPORTED = "supported"
    LEGACY_SUPPORTED = "legacy_supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"


class CapabilityDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: CapabilityStatus
    reason_code: str
    explanation: str
    capability: str | None = None
    evidence: str | None = None
    limitations: str | None = None

    @property
    def reason(self) -> str:
        return self.explanation


class AndroidDeviceState(BaseModel):
    """Structured representation of observed device state independent of available capabilities."""

    model_config = ConfigDict(frozen=True)

    adb_state: str = "unknown"
    authorization_state: str = "unknown"
    lock_state: str = "unknown"
    root_state: str = "unknown"
    encryption_state: str = "unknown"
    storage_access_state: str = "unknown"
    accessibility_state: str = "unknown"
    usage_stats_state: str = "unknown"
    notification_listener_state: str = "unknown"
    shared_storage_state: str = "unknown"
    bootloader_state: str = "unknown"
    chipset_family: str = "unknown"
    chipset_model: str | None = None


class AcquisitionReadiness(BaseModel):
    model_config = ConfigDict(frozen=True)

    encryption_type: str
    credential_storage_state: str
    chipset_family: str
    filesystem_status: str
    explanation: str


class TemporaryRootReadiness(BaseModel):
    model_config = ConfigDict(frozen=True)

    eligibility_status: str
    provider_status: str
    reference_android_range: str
    reference_max_security_patch: str
    research_profile_id: str | None = None
    explanation: str


class LockedDeviceReadiness(BaseModel):
    model_config = ConfigDict(frozen=True)

    support_status: str
    operating_mode: str
    reference_android_range: str
    profile_status: str
    research_profile_id: str | None = None
    research_status: str = "not_catalogued"
    destructive_guessing_blocked: bool
    supported_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
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
    battery_level: int | None = Field(default=None, ge=0, le=100)
    battery_status: str | None = None
    device_state: AndroidDeviceState = Field(default_factory=AndroidDeviceState)
    acquisition_readiness: AcquisitionReadiness = AcquisitionReadiness(
        encryption_type="unknown",
        credential_storage_state="unknown",
        chipset_family="unknown",
        filesystem_status="root_and_unlock_verification_required",
        explanation=(
            "Encryption and credential-storage state were not reported by this assessment."
        ),
    )
    temporary_root_readiness: TemporaryRootReadiness = TemporaryRootReadiness(
        eligibility_status="unknown",
        provider_status="not_configured",
        reference_android_range="4.0-10.0",
        reference_max_security_patch="2019-10-31",
        research_profile_id=None,
        explanation=(
            "Temporary-root eligibility was not evaluated by this assessment. No validated "
            "temporary-root provider is configured."
        ),
    )
    locked_device_readiness: LockedDeviceReadiness = LockedDeviceReadiness(
        support_status="unknown",
        operating_mode="metadata_only",
        reference_android_range="5-13",
        profile_status="no_validated_profile",
        research_profile_id=None,
        research_status="not_catalogued",
        destructive_guessing_blocked=True,
        supported_actions=("Record device identifiers and observed boot state",),
        prohibited_actions=("Automated passcode entry on the device",),
        explanation="Locked-device readiness was not evaluated by this assessment.",
    )
    capabilities: dict[str, CapabilityDecision]
    warnings: tuple[str, ...]
    assessor_version: str = "0.5.0"
