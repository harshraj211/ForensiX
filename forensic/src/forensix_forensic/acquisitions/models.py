"""Data models for acquisition pipeline execution and evidence packaging."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from forensix_forensic.capabilities.decision_engine import AcquisitionVector


class AcquisitionExecutionState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COLLECTING_METADATA = "COLLECTING_METADATA"
    EXTRACTING_LOGICAL_DATA = "EXTRACTING_LOGICAL_DATA"
    EXTRACTING_APP_ARTIFACTS = "EXTRACTING_APP_ARTIFACTS"
    PACKAGING_EVIDENCE = "PACKAGING_EVIDENCE"
    SEALED = "SEALED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AcquisitionArtifactFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    relative_path: str
    size_bytes: int = Field(ge=0)
    sha256_hash: str
    category: str
    source_vector: AcquisitionVector


class AcquisitionContainerManifest(BaseModel):
    model_config = ConfigDict(frozen=True)

    acquisition_id: str
    case_id: str
    device_serial: str
    vector_used: AcquisitionVector
    yield_score: int = Field(ge=0, le=100)
    started_at_iso: str
    finished_at_iso: str
    duration_seconds: float = Field(ge=0.0)
    artifacts: tuple[AcquisitionArtifactFile, ...] = ()
    total_size_bytes: int = Field(ge=0)
    manifest_sha256: str
    limitations: tuple[str, ...] = ()
    custom_metadata: dict[str, Any] = Field(default_factory=dict)


class AcquisitionPipelineResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    acquisition_id: str
    success: bool
    state: AcquisitionExecutionState
    vector_used: AcquisitionVector
    output_dir: str
    archive_path: str | None = None
    manifest: AcquisitionContainerManifest | None = None
    error_message: str | None = None
