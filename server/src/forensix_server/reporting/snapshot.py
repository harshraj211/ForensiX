"""Strict, versioned data contract shared by all report renderers."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class ReportIdentity(FrozenModel):
    report_id: str
    report_type: Literal["preliminary"] = "preliminary"
    generated_at: datetime
    generated_by_id: str
    generated_by_name: str
    preliminary_warning: str


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
    artifact_id: str
    category: str
    timestamp_type: str
    event_time: datetime
    timezone_basis: str
    confidence: str
    summary: str
    event_hash: str


class HashManifestItem(FrozenModel):
    evidence_file_id: str
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
    report_id: str | None
    purpose: str | None
    event_hash: str
    created_at: datetime


class ReportSnapshot(FrozenModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    template_version: Literal["1.0.0"] = "1.0.0"
    tool_name: Literal["ForensiX"] = "ForensiX"
    tool_version: str
    report: ReportIdentity
    case: CaseSnapshot
    devices: list[DeviceSnapshot]
    acquisitions: list[AcquisitionSnapshot]
    evidence_summary: dict[str, int]
    selected_artifacts: list[ArtifactSnapshot]
    timeline: list[TimelineSnapshot]
    hash_manifest: list[HashManifestItem]
    integrity_summary: dict[str, int]
    custody: list[CustodySnapshot]
    errors: list[str]
    limitations: list[str]
    methodology: list[str]
