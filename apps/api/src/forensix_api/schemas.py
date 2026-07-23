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


class AdbDiagnosticResponse(BaseModel):
    mode: Literal["mock", "system"]
    status: Literal[
        "mock",
        "healthy",
        "missing",
        "execution_failed",
        "no_transports",
        "authorization_required",
        "offline",
        "unsupported_transport",
    ]
    available: bool
    platform: str
    executable_path: str | None
    version: str | None
    transport_counts: dict[str, int]
    checked_locations: list[str]
    guidance: list[str]


class ScrcpyDiagnosticResponse(BaseModel):
    available: bool
    status: Literal["missing", "digest_mismatch", "execution_failed", "invalid_executable", "ready"]
    executable_path: str | None
    version: str | None
    sha256: str | None
    guidance: list[str]


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


class ProviderCollectionRequest(BaseModel):
    case_id: str = Field(min_length=36, max_length=36)
    case_device_id: str = Field(min_length=36, max_length=36)
    serial: str = Field(min_length=1, max_length=255)
    profile: Literal["contacts", "sms", "call_log"]
    limitations_acknowledged: Literal[True]


class ProviderCollectionResponse(BaseModel):
    case_id: str
    case_device_id: str
    profile: Literal["contacts", "sms", "call_log"]
    records: list[dict[str, str | None]]
    discovered_count: int = Field(ge=0)
    truncated: bool
    max_records: int = Field(ge=1)
    limitation: str


class ScrcpyLaunchRequest(BaseModel):
    case_id: str = Field(min_length=36, max_length=36)
    case_device_id: str = Field(min_length=36, max_length=36)
    serial: str = Field(min_length=1, max_length=255)
    mode: Literal["mirror", "control"]
    interaction_acknowledged: Literal[True]


class ScrcpyLaunchResponse(BaseModel):
    process_id: int = Field(ge=1)
    mode: Literal["mirror", "control"]
    version: str
    executable_sha256: str
    side_effects: list[str]


class WebsiteLivePreviewRequest(BaseModel):
    case_id: str = Field(min_length=36, max_length=36)
    case_device_id: str = Field(min_length=36, max_length=36)
    serial: str = Field(min_length=1, max_length=255)
    limitations_acknowledged: Literal[True]


class WebsiteLivePreviewResponse(BaseModel):
    case_id: str
    case_device_id: str
    status: Literal["started", "stopped"]
    limitation: str


class RootAccessProbeRequest(BaseModel):
    serial: str = Field(min_length=1, max_length=255)
    side_effects_acknowledged: Literal[True]


class RootAccessProbeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    device_id: str
    probed_by: str
    status: Literal["available", "unavailable", "indeterminate"]
    uid: int | None
    identity: str | None
    reason_code: str
    potential_side_effect: str
    probe_hash: str
    expires_at: datetime
    probed_at: datetime


class RootedCaptureRequest(BaseModel):
    serial: str = Field(min_length=1, max_length=255)
    root_probe_id: str = Field(min_length=36, max_length=36)
    profile: Literal["android_providers", "android_system", "android_apps"]
    side_effects_acknowledged: Literal[True]


class PhysicalBlockProbeRequest(BaseModel):
    serial: str = Field(min_length=1, max_length=255)
    root_probe_id: str = Field(min_length=36, max_length=36)
    profile: Literal["userdata_by_name"]
    risk_acknowledged: Literal[True]


class PhysicalBlockProbeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    device_id: str
    root_probe_id: str
    probed_by: str
    profile: Literal["userdata_by_name"]
    device_path: str
    size_bytes: int
    encryption_state: Literal["unknown", "suspected", "not_detected"]
    probe_hash: str
    probed_at: datetime


class PhysicalBlockCaptureRequest(BaseModel):
    serial: str = Field(min_length=1, max_length=255)
    physical_probe_id: str = Field(min_length=36, max_length=36)
    acquisition_acknowledged: Literal[True]
    encryption_acknowledged: Literal[True]
    non_resumable_acknowledged: Literal[True]


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
    size_bytes: int | None
    modified_time_raw: str | None
    modified_at: datetime | None
    timestamp_source: str | None
    timestamp_confidence: Literal["medium"] | None


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


class AcquiredEvidenceFileResponse(BaseModel):
    id: str
    inventory_id: str
    inventory_item_id: str
    job_id: str
    case_id: str
    plan_id: str
    device_id: str
    acquired_by: str
    status: Literal["acquiring", "completed", "failed", "interrupted"]
    source_root_id: str
    source_path_hash: str
    storage_key: str
    manifest_storage_key: str
    size_bytes: int | None
    sha256: str | None
    manifest_hash: str | None
    transfer_limit_bytes: int
    tool_version: str
    validation_state: Literal["not_physically_validated"]
    partial_preserved: bool
    error_code: str | None
    error_message: str | None
    started_at: datetime
    completed_at: datetime | None


class BulkAcquireRequest(BaseModel):
    item_ids: list[str] = Field(min_length=1, max_length=50)


class BulkAcquireItemResponse(BaseModel):
    inventory_item_id: str
    outcome: Literal[
        "completed",
        "failed",
        "skipped_already_completed",
        "skipped_acquiring",
        "skipped_needs_review",
    ]
    file: AcquiredEvidenceFileResponse | None = None
    error_code: str | None = None
    error_message: str | None = None


class BulkAcquireResponse(BaseModel):
    batch_id: str
    case_id: str
    job_id: str
    requested_count: int
    completed_count: int
    failed_count: int
    skipped_count: int
    items: list[BulkAcquireItemResponse]


class AcquisitionResumeRequest(BaseModel):
    partial_disposition: Literal["retain", "discard"]


class AcquisitionPartialResponse(BaseModel):
    id: str
    evidence_file_id: str
    case_id: str
    job_id: str
    created_by: str
    storage_key: str
    status: Literal["active", "retained", "discarded", "sealed", "missing"]
    reason_code: str | None
    size_bytes: int | None
    sha256: str | None
    disposition_by: str | None
    created_at: datetime
    reconciled_at: datetime | None
    disposition_at: datetime | None


class ArtifactResponse(BaseModel):
    id: str
    evidence_file_id: str
    case_id: str
    device_id: str
    job_id: str
    category: Literal["image", "video", "audio", "document", "archive", "other"]
    subtype: str
    title: str
    summary: str
    source_relative_path: str
    source_path_hash: str
    extension: str | None
    detected_mime: str
    size_bytes: int
    status: Literal["active", "deleted", "recovered", "partial", "corrupted", "unverified"]
    primary_sha256: str
    parser_id: str
    parser_version: str
    timestamp_confidence: str
    collected_at: datetime
    provenance: dict[str, Any]
    metadata: dict[str, Any]
    schema_version: str
    created_at: datetime
    duplicate_count: int = 1


class ArtifactSearchResponse(BaseModel):
    items: list[ArtifactResponse]
    total: int
    offset: int
    limit: int
    category_facets: dict[str, int]


class ArtifactPreviewResponse(BaseModel):
    id: str | None
    artifact_id: str
    status: Literal["not_generated", "available", "rejected", "failed"]
    detected_mime: str | None
    extension_mismatch: bool
    output_mime: str | None
    output_size_bytes: int | None
    output_sha256: str | None
    width: int | None
    height: int | None
    source_width: int | None
    source_height: int | None
    media_metadata: dict[str, Any]
    worker_version: str | None
    limits: dict[str, Any]
    error_code: str | None
    error_message: str | None
    created_at: datetime | None


class TimelineEventResponse(BaseModel):
    id: str
    case_id: str
    artifact_id: str | None
    source_artifact_id: str | None
    job_id: str | None
    parser_run_id: str | None
    category: Literal[
        "device",
        "file",
        "media",
        "communication",
        "application",
        "location",
        "system",
        "acquisition",
        "custody",
    ]
    timestamp_type: str
    event_time: datetime
    original_time: str
    timezone_basis: str
    precision: str
    confidence: str
    summary: str
    builder_version: str
    event_hash: str


class TimelineSearchResponse(BaseModel):
    items: list[TimelineEventResponse]
    total: int
    offset: int
    limit: int
    category_facets: dict[str, int]


class BookmarkRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=1000)


class BookmarkResponse(BaseModel):
    id: str
    artifact_id: str
    user_id: str
    reason: str | None
    created_at: datetime


class TagRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class TagResponse(BaseModel):
    id: str
    name: str
    created_by: str
    created_at: datetime


class AnalystNoteRequest(BaseModel):
    body: str = Field(min_length=1, max_length=4000)
    supersedes_id: str | None = None


class AnalystNoteResponse(BaseModel):
    id: str
    artifact_id: str
    author_id: str
    body: str
    supersedes_id: str | None
    created_at: datetime


class ArtifactAnnotationsResponse(BaseModel):
    bookmark: BookmarkResponse | None
    tags: list[TagResponse]
    notes: list[AnalystNoteResponse]


class EvidenceVerificationResponse(BaseModel):
    id: str
    evidence_file_id: str
    case_id: str
    job_id: str
    verified_by: str
    status: Literal["verified", "mismatch", "missing", "error"]
    expected_file_sha256: str
    observed_file_sha256: str | None
    file_size_bytes: int | None
    file_matches: bool
    expected_manifest_sha256: str
    observed_manifest_sha256: str | None
    manifest_matches: bool
    error_code: str | None
    verification_hash: str
    tool_version: str
    verified_at: datetime


class EvidenceSourceResponse(BaseModel):
    id: str
    case_id: str
    device_id: str | None
    created_by: str
    source_type: Literal["imported_file", "logical_adb", "rooted_filesystem", "physical_block"]
    acquisition_level: Literal["logical", "selective", "filesystem", "physical"]
    status: Literal["pending", "sealed", "failed"]
    display_name: str
    source_name: str
    container_format: Literal["raw", "img", "dd", "tar", "zip", "directory_bundle", "unknown"]
    size_bytes: int | None
    sha256: str | None
    chunks_sha256: str | None
    manifest_sha256: str | None
    chunk_size_bytes: int
    chunk_count: int
    read_only_applied: bool
    validation_state: str
    limitations: list[str]
    tool_version: str
    error_code: str | None
    error_message: str | None
    sealed_at: datetime | None
    created_at: datetime


class EvidenceWorkingCopyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_source_id: str
    case_id: str
    created_by: str
    status: Literal["creating", "ready", "verification_failed"]
    size_bytes: int | None
    expected_source_sha256: str
    observed_sha256: str | None
    copy_method: str
    verified_at: datetime | None
    created_at: datetime


class EvidenceSourceVerificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_source_id: str
    working_copy_id: str | None
    case_id: str
    verified_by: str
    target_type: Literal["master", "working_copy"]
    status: Literal["verified", "mismatch", "missing", "error"]
    expected_sha256: str
    observed_sha256: str | None
    size_bytes: int | None
    error_code: str | None
    verification_hash: str
    tool_version: str
    verified_at: datetime


class EvidenceInspectionResponse(BaseModel):
    id: str
    evidence_source_id: str
    working_copy_id: str
    case_id: str
    inspected_by: str
    detected_type: Literal[
        "zip", "tar", "sqlite", "android_sparse", "ext4", "f2fs", "opaque", "unknown"
    ]
    confidence: Literal["high", "medium", "low"]
    encryption_state: Literal["not_detected", "suspected", "unknown"]
    signature: dict[str, Any]
    warnings: list[str]
    detector_version: str
    inspection_hash: str
    inspected_at: datetime


class RecoveryCandidateResponse(BaseModel):
    source_locator: str
    source_kind: Literal["sqlite_database", "sqlite_wal", "sqlite_rollback_journal", "unknown"]
    status: Literal[
        "candidate_regions_observed", "no_candidate_regions", "malformed", "unsupported"
    ]
    confidence: Literal["medium", "low"]
    page_size_bytes: int | None
    candidate_region_count: int
    source_size_bytes: int
    metadata: dict[str, Any]
    limitations: list[str]
    candidate_hash: str


class RecoveryAssessmentResponse(BaseModel):
    id: str
    evidence_source_id: str
    working_copy_id: str
    inspection_id: str
    case_id: str
    assessed_by: str
    maturity: Literal["experimental"]
    status: Literal["candidate_regions_observed", "no_candidate_regions", "unsupported"]
    candidate_region_count: int
    candidates: list[RecoveryCandidateResponse]
    limitations: list[str]
    assessment_hash: str
    tool_version: str
    assessed_at: datetime


class EvidenceParserRunRequest(BaseModel):
    parser_ids: list[str] | None = Field(default=None, max_length=20)


class EvidenceParserRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_source_id: str
    working_copy_id: str
    inspection_id: str
    case_id: str
    executed_by: str
    parser_id: str
    parser_version: str
    status: Literal["completed", "failed"]
    artifact_count: int
    source_sha256: str
    input_locator: str
    input_sha256: str
    run_hash: str
    error_code: str | None
    error_message: str | None
    started_at: datetime
    completed_at: datetime


class EvidenceSourceArtifactResponse(BaseModel):
    id: str
    parser_run_id: str
    evidence_source_id: str
    working_copy_id: str
    case_id: str
    category: Literal["contact", "communication", "application", "location", "system", "file"]
    subtype: str
    title: str
    summary: str
    event_time: datetime | None
    source_locator: str
    status: Literal["active", "deleted", "recovered", "partial", "corrupted", "unverified"]
    confidence: Literal["high", "medium", "low"]
    parser_id: str
    parser_version: str
    metadata: dict[str, Any]
    provenance: dict[str, Any]
    artifact_hash: str
    created_at: datetime


class AleappDiagnosticResponse(BaseModel):
    available: bool
    hash_verified: bool
    release_label: str
    program_path: str
    observed_sha256: str | None
    message: str


class PhysicalAcquisitionDiagnosticResponse(BaseModel):
    enabled: bool
    max_size_bytes: int
    maturity: Literal["experimental"] = "experimental"
    warning: str


class ApplicationArtifactSupportResponse(BaseModel):
    app_id: str
    display_name: str
    status: Literal["plaintext_parser", "interchange_parser", "detection_only"]
    maturity: Literal["experimental", "validated"]
    native_parser_id: str | None
    acquisition_requirements: list[str]
    limitations: list[str]


class EvidenceToolOutputResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    parser_run_id: str
    evidence_source_id: str
    working_copy_id: str
    case_id: str
    relative_path: str
    size_bytes: int
    sha256: str
    created_at: datetime


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


class CustodyEventCreateRequest(BaseModel):
    event_type: Literal["transferred", "amendment"]
    evidence_file_id: str | None = Field(default=None, min_length=36, max_length=36)
    from_custodian: str | None = Field(default=None, max_length=255)
    to_custodian: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)
    purpose: str | None = Field(default=None, max_length=1000)
    notes: str | None = Field(default=None, max_length=2000)
    related_event_id: str | None = Field(default=None, min_length=36, max_length=36)


class CustodyEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    evidence_file_id: str | None
    evidence_source_id: str | None
    parser_run_id: str | None
    report_id: str | None
    actor_id: str
    sequence: int
    event_type: str
    from_custodian: str | None
    to_custodian: str | None
    location: str | None
    purpose: str | None
    notes: str | None
    related_event_id: str | None
    previous_hash: str
    event_hash: str
    created_at: datetime


class CustodyCheckpointResponse(BaseModel):
    id: str
    case_id: str
    created_by: str
    custody_record_count: int
    custody_head_hash: str | None
    audit_sequence: int
    audit_head_hash: str | None
    filename: str
    size_bytes: int
    sha256: str
    schema_version: str
    anchor_status: Literal["not_externally_anchored"]
    created_at: datetime


class CustodyCheckpointAnchorCreateRequest(BaseModel):
    anchor_type: Literal[
        "external_timestamp",
        "digital_signature",
        "evidence_vault",
        "case_management",
        "other",
    ]
    anchor_provider: str = Field(min_length=1, max_length=255)
    anchor_reference: str = Field(min_length=1, max_length=512)
    anchored_at: datetime
    checkpoint_sha256: str = Field(min_length=64, max_length=64)
    receipt_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    notes: str | None = Field(default=None, max_length=2000)


class CustodyCheckpointAnchorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    checkpoint_id: str
    case_id: str
    recorded_by: str
    anchor_type: Literal[
        "external_timestamp",
        "digital_signature",
        "evidence_vault",
        "case_management",
        "other",
    ]
    anchor_provider: str
    anchor_reference: str
    anchored_at: datetime
    checkpoint_sha256: str
    receipt_sha256: str | None
    notes: str | None
    anchor_hash: str
    created_at: datetime


class CustodyCheckpointSignatureVerifyRequest(BaseModel):
    signature_algorithm: Literal[
        "rsa_pkcs1v15_sha256",
        "rsa_pss_sha256",
        "ecdsa_sha256",
    ]
    certificate_pem: str = Field(min_length=1, max_length=16384)
    signature_base64: str = Field(min_length=1, max_length=8192)
    signed_at: datetime
    checkpoint_sha256: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-fA-F]{64}$",
    )


class CustodyCheckpointSignatureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    checkpoint_id: str
    case_id: str
    verified_by: str
    signature_algorithm: Literal[
        "rsa_pkcs1v15_sha256",
        "rsa_pss_sha256",
        "ecdsa_sha256",
    ]
    signer_subject: str
    signer_issuer: str
    certificate_serial: str
    certificate_sha256: str
    signature_sha256: str
    signed_at: datetime
    certificate_not_before: datetime
    certificate_not_after: datetime
    checkpoint_sha256: str
    verification_hash: str
    created_at: datetime


class ReportOutputResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    format: Literal["pdf", "json", "csv"]
    media_type: str
    filename: str
    size_bytes: int
    sha256: str
    created_at: datetime


class ReportGenerateRequest(BaseModel):
    redaction_profile: Literal["full", "mask_sensitive", "metadata_only"] = "full"


class ReportReviewRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    note: str = Field(min_length=5, max_length=1000)


class ReportReviewResponse(BaseModel):
    id: str
    sequence: int
    decision: Literal["approved", "rejected"]
    reviewed_by: str
    note: str
    previous_hash: str
    event_hash: str
    created_at: datetime


class ReportResponse(BaseModel):
    id: str
    case_id: str
    generated_by: str
    report_type: Literal["preliminary"]
    status: Literal["available"]
    title: str
    schema_version: str
    template_version: str
    snapshot_size_bytes: int
    snapshot_sha256: str
    generated_at: datetime
    redaction_profile: Literal["full", "mask_sensitive", "metadata_only"]
    approval_state: Literal["unreviewed", "approved", "rejected"]
    latest_review: ReportReviewResponse | None
    outputs: list[ReportOutputResponse]


class ChainVerificationResponse(BaseModel):
    valid: bool
    record_count: int
    broken_sequence: int | None
    head_hash: str | None


class AuditLogResponse(BaseModel):
    id: str
    sequence: int
    case_id: str | None
    actor_id: str
    event_type: str
    object_type: str
    object_id: str
    detail: dict[str, Any]
    previous_hash: str
    entry_hash: str
    created_at: datetime
