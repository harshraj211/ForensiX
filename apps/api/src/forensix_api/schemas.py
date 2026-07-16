"""Versioned API transport schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from forensix_forensic.adb.models import DeviceState, SharedStorageRootProbe
from forensix_forensic.capabilities.models import CapabilityDecision
from forensix_server.acquisitions import AcquisitionModule, AcquisitionScope
from forensix_server.cases import CaseAccessLevel, CaseStatus
from forensix_server.jobs import JobState


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
    case_id: str | None = None
    observed_at: datetime
    result: Literal["no_devices", "single_device", "multiple_devices"]
    adb: AdbInfoResponse
    devices: list[DeviceTransportResponse]


class DeviceAssessmentRequest(BaseModel):
    serial: str = Field(min_length=1, max_length=255)
    case_id: str | None = Field(default=None, min_length=36, max_length=36)


class DeviceCapabilityAssessmentResponse(BaseModel):
    assessment_id: str
    case_id: str | None = None
    case_device_id: str | None = None
    assessed_at: datetime
    serial: str
    manufacturer: str | None
    model: str | None
    android_version: str | None
    sdk_level: int | None
    build_fingerprint: str | None
    security_patch: str | None
    package_count: int
    storage_roots: list[SharedStorageRootProbe] = Field(default_factory=list)
    capabilities: dict[str, CapabilityDecision]
    warnings: list[str]
    assessor_version: str


class CaseDeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    serial_suffix: str
    manufacturer: str | None
    model: str | None
    android_version: str | None
    sdk_level: int | None
    build_fingerprint: str | None
    security_patch: str | None
    registered_by: str
    first_seen_at: datetime
    last_seen_at: datetime


class CaseDeviceAssessmentResponse(BaseModel):
    id: str
    case_id: str
    device_id: str
    assessed_by: str
    assessed_at: datetime
    manufacturer: str | None
    model: str | None
    android_version: str | None
    sdk_level: int | None
    build_fingerprint: str | None
    security_patch: str | None
    package_count: int
    storage_roots: list[SharedStorageRootProbe] = Field(default_factory=list)
    capabilities: dict[str, CapabilityDecision]
    warnings: list[str]
    assessor_version: str


class AcquisitionPlanCreateRequest(BaseModel):
    device_id: str = Field(min_length=36, max_length=36)
    assessment_id: str = Field(min_length=36, max_length=36)
    scope: AcquisitionScope
    modules: list[AcquisitionModule] = Field(default_factory=list, max_length=3)
    limitations_acknowledged: Literal[True]


class AcquisitionPlanResponse(BaseModel):
    id: str
    case_id: str
    device_id: str
    assessment_id: str
    created_by: str
    scope: AcquisitionScope
    status: Literal["ready"]
    modules: list[AcquisitionModule]
    limitations: list[str]
    snapshot_hash: str
    plan_hash: str
    schema_version: str
    readiness_assessed_at: datetime
    readiness_expires_at: datetime
    created_at: datetime


class AcquisitionPlanListResponse(BaseModel):
    items: list[AcquisitionPlanResponse]
    total: int
    offset: int
    limit: int


class AcquisitionJobPrepareRequest(BaseModel):
    plan_id: str = Field(min_length=36, max_length=36)


class AcquisitionJobResponse(BaseModel):
    id: str
    case_id: str
    plan_id: str
    owner_id: str
    state: JobState
    progress_percent: int
    current_step: str | None
    current_module: str | None
    cancellation_requested: bool
    resume_supported: bool
    checkpoint: dict[str, Any] | None
    error_code: str | None
    error_message: str | None
    result_reference: str | None
    last_event_sequence: int
    version: int
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    executor_available: Literal[False] = False


class AcquisitionJobListResponse(BaseModel):
    items: list[AcquisitionJobResponse]
    total: int
    offset: int
    limit: int


class AcquisitionInventoryItemResponse(BaseModel):
    id: str
    ordinal: int
    relative_path: str
    path_hash: str
    extension: str | None


class AcquisitionInventoryResponse(BaseModel):
    id: str
    job_id: str
    case_id: str
    plan_id: str
    device_id: str
    created_by: str
    root_id: str
    display_path: str
    status: Literal["completed", "truncated"]
    discovered_count: int
    persisted_count: int
    skipped_count: int
    max_items: int
    max_depth: int
    manifest_hash: str
    started_at: datetime
    completed_at: datetime
    items: list[AcquisitionInventoryItemResponse] = Field(default_factory=list)
    total: int
    offset: int
    limit: int


class JobEventResponse(BaseModel):
    id: str
    job_id: str
    sequence: int
    event_type: str
    state: JobState
    progress_percent: int
    current_step: str | None
    current_module: str | None
    checkpoint: dict[str, Any] | None
    safe_detail: str | None
    created_at: datetime


class AuthBootstrapStatusResponse(BaseModel):
    bootstrap_required: bool


class AuthBootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=12, max_length=128)


class AuthLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=128)


class AuthUserResponse(BaseModel):
    user_id: str
    username: str
    display_name: str
    roles: list[str]
    permissions: list[str]


class AuthSessionResponse(BaseModel):
    user: AuthUserResponse
    expires_at: datetime
    csrf_token: str


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)
    legal_authority: str | None = Field(default=None, max_length=2_000)


class CaseUpdateRequest(BaseModel):
    expected_version: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)
    legal_authority: str | None = Field(default=None, max_length=2_000)


class CaseTransitionRequest(BaseModel):
    expected_version: int = Field(ge=1)
    status: CaseStatus


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_number: str
    title: str
    description: str | None
    legal_authority: str | None
    status: CaseStatus
    created_by: str
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    version: int


class CaseListResponse(BaseModel):
    items: list[CaseResponse]
    total: int
    offset: int
    limit: int


class CaseMemberRequest(BaseModel):
    user_id: str = Field(min_length=36, max_length=36)
    access_level: CaseAccessLevel


class CaseMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    user_id: str
    access_level: CaseAccessLevel
    assigned_at: datetime
    assigned_by: str


class CaseEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    actor_id: str
    event_type: str
    from_status: str | None
    to_status: str | None
    safe_detail: str | None
    created_at: datetime
