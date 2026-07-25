"""Immutable transport and server models."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class DeviceState(StrEnum):
    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    OFFLINE = "offline"
    RECOVERY = "recovery"
    SIDELOAD = "sideload"
    BOOTLOADER = "bootloader"
    UNKNOWN = "unknown"


class DeviceTransport(BaseModel):
    model_config = ConfigDict(frozen=True)

    serial: str = Field(min_length=1, max_length=255)
    state: DeviceState
    product: str | None = Field(default=None, max_length=255)
    model: str | None = Field(default=None, max_length=255)
    device: str | None = Field(default=None, max_length=255)
    transport_id: str | None = Field(default=None, max_length=64)
    usb: str | None = Field(default=None, max_length=128)
    raw_state: str = Field(min_length=1, max_length=64)


class AdbServerInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    executable_path: str
    raw_output: str


class StorageProbeStatus(StrEnum):
    ACCESSIBLE = "accessible"
    MISSING = "missing"
    BLOCKED = "blocked"


class RootAccessStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    INDETERMINATE = "indeterminate"


class ContentProviderAccessStatus(StrEnum):
    AVAILABLE = "available"
    DENIED = "denied"
    MISSING = "missing"
    INDETERMINATE = "indeterminate"


class ContentProviderAccessProbe(BaseModel):
    """Content-free result of querying a fixed provider with an impossible predicate."""

    model_config = ConfigDict(frozen=True)

    profile: str = Field(min_length=1, max_length=64)
    status: ContentProviderAccessStatus
    reason_code: str = Field(min_length=1, max_length=64)
    explanation: str = Field(min_length=1, max_length=500)
    exit_code: int


class ContentProviderRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    values: dict[str, str | None]


class ContentProviderQueryResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    profile: str = Field(min_length=1, max_length=64)
    records: tuple[ContentProviderRecord, ...]
    discovered_count: int = Field(ge=0)
    truncated: bool
    max_records: int = Field(ge=1)


class RootAccessProbe(BaseModel):
    """Bounded result of the explicitly authorized fixed `su -c id` operation."""

    model_config = ConfigDict(frozen=True)

    status: RootAccessStatus
    uid: int | None = Field(default=None, ge=0)
    identity: str | None = Field(default=None, max_length=240)
    reason_code: str = Field(min_length=1, max_length=64)
    potential_side_effect: str = Field(min_length=1, max_length=500)


class SharedStorageRootProbe(BaseModel):
    model_config = ConfigDict(frozen=True)

    root_id: str
    display_path: str
    status: StorageProbeStatus
    exists: bool
    readable: bool
    reason_code: str


class StorageInventoryEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    relative_path: str = Field(min_length=1, max_length=1024)
    size_bytes: int | None = Field(default=None, ge=0)
    modified_time_raw: str | None = Field(default=None, max_length=32)
    modified_at: datetime | None = None
    timestamp_source: str | None = Field(default=None, max_length=64)
    timestamp_confidence: str | None = Field(default=None, max_length=16)


class StorageInventoryResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    root_id: str
    display_path: str
    entries: tuple[StorageInventoryEntry, ...]
    discovered_count: int = Field(ge=0)
    skipped_count: int = Field(ge=0)
    truncated: bool
    max_items: int = Field(ge=1)
    max_depth: int = Field(ge=1)


class PulledFileResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    root_id: str
    relative_path: str
    size_bytes: int = Field(ge=0)


class ScreenshotCaptureResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    size_bytes: int = Field(ge=8)
    media_type: str = "image/png"


class RootedBundleResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    profile: str
    size_bytes: int = Field(ge=1)


class PhysicalBlockProbe(BaseModel):
    model_config = ConfigDict(frozen=True)

    profile: str
    device_path: str
    size_bytes: int = Field(ge=1)
    encryption_state: str = "unknown"


class PhysicalBlockCaptureResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    profile: str
    size_bytes: int = Field(ge=1)


class BackupResult(BaseModel):
    """Result of an ADB backup operation for the downgrade-attack workflow."""

    model_config = ConfigDict(frozen=True)

    backup_file_size_bytes: int = Field(ge=0)
    destination_path: str
    package_name: str
    backup_format: str = "ab"
    success: bool
