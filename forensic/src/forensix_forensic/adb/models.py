"""Immutable transport and server models."""

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
