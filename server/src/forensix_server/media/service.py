"""Case-authorized, process-isolated media analysis over sealed evidence.

The analysis worker reads a hash-verified sealed object in an isolated subprocess and
returns perceptual hashing, EXIF/GPS extraction, optional OCR, and heuristic
classification labels. Findings are persisted append-only and never mutate the source.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseInvalidStateError, CaseService
from forensix_server.custody import AuditService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    ArtifactRecord,
    Database,
    MediaAnalysisRecord,
)
from forensix_server.evidence import TimelineService

MEDIA_WORKER_VERSION = "1.0.0"
MEDIA_ANALYSIS_TIMEOUT_SECONDS = 12
MAX_SOURCE_BYTES = 25 * 1024 * 1024
MAX_WORKER_OUTPUT_BYTES = 64 * 1024
ANALYZABLE_CATEGORIES = frozenset({"image"})
CREATE_NO_WINDOW = cast(int, getattr(subprocess, "CREATE_NO_WINDOW", 0))

class MediaAnalysisError(CaseInvalidStateError):
    code = "MEDIA_ANALYSIS_INVALID"


class MediaAnalysisUnsupportedError(MediaAnalysisError):
    code = "MEDIA_ANALYSIS_UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class SimilarMedia:
    analysis: MediaAnalysisRecord
    distance: int


class MediaAnalysisService:
    """Creates one append-only media analysis per artifact without mutating evidence."""

    def get_status(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        artifact_id: str,
    ) -> MediaAnalysisRecord | None:
        self._require_analyze(session, principal, case_id)
        return session.scalar(
            select(MediaAnalysisRecord).where(
                MediaAnalysisRecord.artifact_id == artifact_id,
                MediaAnalysisRecord.case_id == case_id,
            )
        )

    def list_for_case(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        media_kind: str | None = None,
        gps_only: bool = False,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[MediaAnalysisRecord], int]:
        self._require_analyze(session, principal, case_id)
        conditions = [MediaAnalysisRecord.case_id == case_id]
        if media_kind is not None:
            conditions.append(MediaAnalysisRecord.media_kind == media_kind)
        if gps_only:
            conditions.append(MediaAnalysisRecord.gps_present.is_(True))
        total = int(
            session.scalar(select(func.count(MediaAnalysisRecord.id)).where(*conditions)) or 0
        )
        items = list(
            session.scalars(
                select(MediaAnalysisRecord)
                .where(*conditions)
                .order_by(
                    MediaAnalysisRecord.analyzed_at.desc(), MediaAnalysisRecord.id.desc()
                )
                .offset(offset)
                .limit(limit)
            )
        )
        return items, total

    def find_similar(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        artifact_id: str,
        *,
        max_distance: int = 10,
        limit: int = 25,
    ) -> tuple[MediaAnalysisRecord, list[SimilarMedia]]:
        self._require_analyze(session, principal, case_id)
        base = session.scalar(
            select(MediaAnalysisRecord).where(
                MediaAnalysisRecord.artifact_id == artifact_id,
                MediaAnalysisRecord.case_id == case_id,
            )
        )
        if base is None:
            raise MediaAnalysisError("This artifact has not been analyzed yet.")
        if base.perceptual_hash is None:
            raise MediaAnalysisError("This analysis has no perceptual hash to compare.")
        candidates = session.scalars(
            select(MediaAnalysisRecord).where(
                MediaAnalysisRecord.case_id == case_id,
                MediaAnalysisRecord.id != base.id,
                MediaAnalysisRecord.perceptual_hash.is_not(None),
            )
        )
        matches: list[SimilarMedia] = []
        for candidate in candidates:
            distance = _hamming_distance(base.perceptual_hash, candidate.perceptual_hash)
            if distance is not None and distance <= max_distance:
                matches.append(SimilarMedia(analysis=candidate, distance=distance))
        matches.sort(key=lambda item: (item.distance, item.analysis.id))
        return base, matches[:limit]

    def analyze(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        artifact_id: str,
    ) -> MediaAnalysisRecord:
        with database.session() as session:
            artifact = self._writable_artifact(session, principal, case_id, artifact_id)
            existing = session.scalar(
                select(MediaAnalysisRecord).where(
                    MediaAnalysisRecord.artifact_id == artifact_id
                )
            )
            if existing is not None:
                return existing
            if artifact.category not in ANALYZABLE_CATEGORIES:
                raise MediaAnalysisUnsupportedError(
                    "Only image artifacts can be analyzed by the bundled media worker."
                )
            evidence = session.get(AcquiredEvidenceFileRecord, artifact.evidence_file_id)
            if evidence is None or evidence.case_id != case_id or evidence.status != "completed":
                raise MediaAnalysisError("The sealed source evidence record is unavailable.")
            evidence_key = evidence.storage_key
            evidence_file_id = artifact.evidence_file_id
            expected_source_hash = artifact.primary_sha256

        store = EvidenceStore(database.data_dir / "evidence")
        store.resolve(evidence_key, require_file=True)
        source_hash = store.hash(evidence_key)
        if source_hash.hexdigest != expected_source_hash:
            return self._persist(
                database,
                principal,
                case_id,
                artifact_id,
                evidence_file_id,
                status="rejected",
                error_code="SOURCE_HASH_MISMATCH",
                error_message=(
                    "Analysis was blocked because source integrity verification failed."
                ),
            )
        if source_hash.size_bytes > MAX_SOURCE_BYTES:
            return self._persist(
                database,
                principal,
                case_id,
                artifact_id,
                evidence_file_id,
                status="rejected",
                error_code="SOURCE_TOO_LARGE",
                error_message="The source exceeds the bounded analysis input limit.",
            )

        source_path = store.resolve(evidence_key, require_file=True)
        result = self._run_worker(source_path, database.data_dir)
        status = cast(str, result.get("status"))
        if status != "analyzed":
            return self._persist(
                database,
                principal,
                case_id,
                artifact_id,
                evidence_file_id,
                status="rejected" if status == "rejected" else "failed",
                detected_mime=cast(str | None, result.get("detected_mime")),
                error_code=cast(str, result.get("code", "WORKER_FAILED")),
                error_message=cast(
                    str, result.get("message", "The isolated media worker failed safely.")
                ),
            )
        payload = cast(dict[str, Any], result["result"])
        return self._persist(
            database,
            principal,
            case_id,
            artifact_id,
            evidence_file_id,
            status="analyzed",
            payload=payload,
        )

    def _persist(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        artifact_id: str,
        evidence_file_id: str,
        *,
        status: str,
        payload: dict[str, Any] | None = None,
        detected_mime: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> MediaAnalysisRecord:
        data = payload or {}
        exif = cast(dict[str, Any], data.get("exif", {}))
        detections = cast(list[Any], data.get("detections", []))
        with database.session() as session:
            artifact = self._writable_artifact(session, principal, case_id, artifact_id)
            existing = session.scalar(
                select(MediaAnalysisRecord).where(
                    MediaAnalysisRecord.artifact_id == artifact_id
                )
            )
            if existing is not None:
                return existing
            record = MediaAnalysisRecord(
                artifact_id=artifact.id,
                evidence_file_id=evidence_file_id,
                case_id=case_id,
                analyzed_by=principal.user_id,
                media_kind=cast(str, data.get("media_kind", "image")),
                status=status,
                detected_mime=cast(str | None, data.get("detected_mime", detected_mime)),
                width=_maybe_int(data.get("width")),
                height=_maybe_int(data.get("height")),
                perceptual_hash=cast(str | None, data.get("perceptual_hash")),
                captured_at_raw=cast(str | None, data.get("captured_at_raw")),
                camera_make=_bounded(data.get("camera_make"), 128),
                camera_model=_bounded(data.get("camera_model"), 128),
                gps_present=bool(data.get("gps_present", False)),
                gps_latitude=_maybe_float(data.get("gps_latitude")),
                gps_longitude=_maybe_float(data.get("gps_longitude")),
                exif_json=_canonical_json(exif),
                ocr_status=cast(str, data.get("ocr_status", "not_attempted")),
                ocr_engine=cast(str | None, data.get("ocr_engine")),
                ocr_text=cast(str | None, data.get("ocr_text")),
                detection_json=_canonical_json(detections),
                detector_maturity=cast(str, data.get("detector_maturity", "heuristic")),
                error_code=error_code,
                error_message=error_message,
                analysis_hash="",
                worker_version=cast(str, data.get("worker_version", MEDIA_WORKER_VERSION)),
            )
            record.analysis_hash = _analysis_hash(record)
            session.add(record)
            session.flush()
            if record.status == "analyzed":
                TimelineService().materialize_media_capture(session, artifact, record)
            self._audit(session, record, principal.user_id)
            return record

    @staticmethod
    def _run_worker(source: Path, working_directory: Path) -> dict[str, Any]:
        specification = importlib.util.find_spec("forensix_forensic.media_analysis_worker")
        if specification is None or specification.origin is None:
            raise MediaAnalysisError("The isolated media-analysis worker is not installed.")
        creation_flags = CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            completed = subprocess.run(  # noqa: S603 - fixed executable and worker arguments
                [sys.executable, "-I", specification.origin, "--source", str(source)],
                cwd=working_directory,
                capture_output=True,
                check=False,
                creationflags=creation_flags,
                text=True,
                timeout=MEDIA_ANALYSIS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "failed",
                "code": "ANALYSIS_TIMEOUT",
                "message": "The isolated media worker exceeded its time limit.",
            }
        if len(completed.stdout.encode("utf-8")) > MAX_WORKER_OUTPUT_BYTES:
            return {
                "status": "failed",
                "code": "WORKER_OUTPUT_LIMIT",
                "message": "The isolated media worker exceeded its output limit.",
            }
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return {
                "status": "failed",
                "code": "WORKER_PROTOCOL_ERROR",
                "message": "The isolated media worker returned an invalid result.",
            }
        if not isinstance(payload, dict) or payload.get("status") not in {
            "analyzed",
            "failed",
            "rejected",
        }:
            return {
                "status": "failed",
                "code": "WORKER_PROTOCOL_ERROR",
                "message": "The isolated media worker returned an invalid result.",
            }
        return cast(dict[str, Any], payload)

    @staticmethod
    def _require_analyze(session: Session, principal: Principal, case_id: str) -> None:
        CaseService().get(session, principal, case_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot analyze case evidence.")

    def _writable_artifact(
        self, session: Session, principal: Principal, case_id: str, artifact_id: str
    ) -> ArtifactRecord:
        self._require_analyze(session, principal, case_id)
        artifact = session.get(ArtifactRecord, artifact_id)
        if artifact is None or artifact.case_id != case_id:
            raise MediaAnalysisError("The requested artifact is not available in this case.")
        return artifact

    @staticmethod
    def _audit(session: Session, record: MediaAnalysisRecord, actor_id: str) -> None:
        AuditService().append(
            session,
            case_id=record.case_id,
            actor_id=actor_id,
            event_type=f"media_analysis_{record.status}",
            object_type="media_analysis",
            object_id=record.id,
            detail={
                "artifact_id": record.artifact_id,
                "media_kind": record.media_kind,
                "perceptual_hash": record.perceptual_hash,
                "gps_present": record.gps_present,
                "ocr_status": record.ocr_status,
                "error_code": record.error_code,
                "status": record.status,
            },
            created_at=record.analyzed_at,
        )
        session.flush()


def _hamming_distance(left: str | None, right: str | None) -> int | None:
    if left is None or right is None or len(left) != len(right):
        return None
    try:
        return bin(int(left, 16) ^ int(right, 16)).count("1")
    except ValueError:
        return None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _maybe_int(value: Any) -> int | None:
    return int(value) if isinstance(value, (int, float)) else None


def _maybe_float(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def _bounded(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


def _analysis_hash(record: MediaAnalysisRecord) -> str:
    material = "|".join(
        str(part)
        for part in (
            record.artifact_id,
            record.evidence_file_id,
            record.case_id,
            record.media_kind,
            record.status,
            record.perceptual_hash,
            record.exif_json,
            record.ocr_status,
            record.ocr_text,
            record.detection_json,
            record.worker_version,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
