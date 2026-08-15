"""Strict, versioned data contract shared by all report renderers."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class ReportIdentity(FrozenModel):
    report_id: str
    report_type: Literal["preliminary"] = "preliminary"
    generated_at: datetime
    generated_by_id: str
    generated_by_name: str
    preliminary_warning: str
    redaction_profile: Literal["full", "mask_sensitive", "metadata_only"] = "full"


class CaseSnapshot(FrozenModel):
    id: str
    case_number: str
    title: str
    description: str | None
    legal_authority: str | None
    status: str
    created_at: datetime


class DeviceSnapshot(FrozenModel):
    id: str
    serial_suffix: str
    manufacturer: str | None
    model: str | None
    android_version: str | None
    sdk_level: int | None
    build_fingerprint: str | None
    security_patch: str | None
    latest_assessment: dict[str, Any] | None


class AcquisitionSnapshot(FrozenModel):
    plan_id: str
    scope: str
    modules: list[str]
    limitations: list[str]
    plan_hash: str
    created_at: datetime
    inventory_status: str | None
    inventory_manifest_hash: str | None
    inventory_started_at: datetime | None
    inventory_completed_at: datetime | None


class ArtifactSnapshot(FrozenModel):
    id: str
    evidence_file_id: str
    title: str
    category: str
    status: str
    source_relative_path: str
    detected_mime: str
    size_bytes: int
    sha256: str
    collected_at: datetime
    bookmark_reason: str | None
    tags: list[str]
    analyst_notes: list[str]


class TimelineSnapshot(FrozenModel):
    artifact_id: str | None
    source_artifact_id: str | None
    parser_run_id: str | None
    category: str
    timestamp_type: str
    event_time: datetime
    timezone_basis: str
    confidence: str
    summary: str
    event_hash: str


class HashManifestItem(FrozenModel):
    evidence_file_id: str
    source_relative_path: str
    storage_key: str
    manifest_storage_key: str
    status: str
    size_bytes: int | None
    file_sha256: str | None
    manifest_sha256: str | None
    validation_state: str


class CustodySnapshot(FrozenModel):
    sequence: int
    event_type: str
    actor_id: str
    evidence_file_id: str | None
    evidence_source_id: str | None
    parser_run_id: str | None
    report_id: str | None
    purpose: str | None
    event_hash: str
    created_at: datetime


class EvidenceWorkingCopySnapshot(FrozenModel):
    id: str
    status: str
    size_bytes: int | None
    expected_source_sha256: str
    observed_sha256: str | None
    copy_method: str
    verified_at: datetime | None
    created_at: datetime


class EvidenceSourceVerificationSnapshot(FrozenModel):
    id: str
    target_type: str
    working_copy_id: str | None
    status: str
    expected_sha256: str
    observed_sha256: str | None
    size_bytes: int | None
    verification_hash: str
    tool_version: str
    verified_at: datetime


class EvidenceInspectionSnapshot(FrozenModel):
    id: str
    working_copy_id: str
    detected_type: str
    confidence: str
    encryption_state: str
    signature: dict[str, Any]
    warnings: list[str]
    detector_version: str
    inspection_hash: str
    inspected_at: datetime


class EvidenceParserRunSnapshot(FrozenModel):
    id: str
    working_copy_id: str
    parser_id: str
    parser_version: str
    status: str
    artifact_count: int
    source_sha256: str
    input_locator: str
    input_sha256: str
    run_hash: str
    error_code: str | None
    execution_detail: dict[str, Any]
    completed_at: datetime


class EvidenceToolOutputSnapshot(FrozenModel):
    id: str
    parser_run_id: str
    relative_path: str
    size_bytes: int
    sha256: str
    created_at: datetime


class EvidenceSourceSnapshot(FrozenModel):
    id: str
    display_name: str
    source_name: str
    source_type: str
    acquisition_level: str
    status: str
    container_format: str
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
    sealed_at: datetime | None
    created_at: datetime
    working_copies: list[EvidenceWorkingCopySnapshot]
    verifications: list[EvidenceSourceVerificationSnapshot]
    inspections: list[EvidenceInspectionSnapshot]
    parser_runs: list[EvidenceParserRunSnapshot]
    tool_outputs: list[EvidenceToolOutputSnapshot]


class ImportedArtifactSnapshot(FrozenModel):
    id: str
    evidence_source_id: str
    parser_run_id: str
    category: str
    subtype: str
    title: str
    summary: str
    event_time: datetime | None
    source_locator: str
    status: str
    confidence: str
    parser_id: str
    parser_version: str
    artifact_hash: str


class ReportSnapshot(FrozenModel):
    schema_version: Literal["1.1.0"] = "1.1.0"
    template_version: Literal["1.1.0"] = "1.1.0"
    tool_name: Literal["ForensiX"] = "ForensiX"
    tool_version: str
    report: ReportIdentity
    case: CaseSnapshot
    devices: list[DeviceSnapshot]
    acquisitions: list[AcquisitionSnapshot]
    evidence_sources: list[EvidenceSourceSnapshot] = Field(default_factory=list)
    imported_artifacts: list[ImportedArtifactSnapshot] = Field(default_factory=list)
    imported_evidence_summary: dict[str, int] = Field(default_factory=dict)
    evidence_summary: dict[str, int]
    selected_artifacts: list[ArtifactSnapshot]
    timeline: list[TimelineSnapshot]
    hash_manifest: list[HashManifestItem]
    integrity_summary: dict[str, int]
    custody: list[CustodySnapshot]
    errors: list[str]
    limitations: list[str]
    methodology: list[str]
