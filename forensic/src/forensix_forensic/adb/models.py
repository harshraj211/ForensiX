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
