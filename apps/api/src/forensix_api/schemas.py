"""Versioned API transport schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from forensix_forensic.adb.models import DeviceState
from forensix_forensic.capabilities.models import CapabilityDecision


class ApiErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str


class ApiErrorResponse(BaseModel):
    error: ApiErrorDetail


class HealthResponse(BaseModel):
    status: Literal["ok", "ready", "not_ready"]
    version: str
    database: Literal["ready", "unavailable"] | None = None


class AdbInfoResponse(BaseModel):
    version: str
    executable_path: str


class DeviceTransportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    serial: str
    state: DeviceState
    raw_state: str
    product: str | None
    model: str | None
    device: str | None
    transport_id: str | None
    usb: str | None


class DeviceDetectionResponse(BaseModel):
    detection_id: str
    observed_at: datetime
    result: Literal["no_devices", "single_device", "multiple_devices"]
    adb: AdbInfoResponse
    devices: list[DeviceTransportResponse]


class DeviceAssessmentRequest(BaseModel):
    serial: str = Field(min_length=1, max_length=255)


class DeviceCapabilityAssessmentResponse(BaseModel):
    assessment_id: str
    assessed_at: datetime
    serial: str
    manufacturer: str | None
    model: str | None
    android_version: str | None
    sdk_level: int | None
    build_fingerprint: str | None
    security_patch: str | None
    package_count: int
    capabilities: dict[str, CapabilityDecision]
    warnings: list[str]
    assessor_version: str
