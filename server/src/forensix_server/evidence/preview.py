"""Case-authorized, process-isolated generation of non-evidentiary preview derivatives."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Principal
from forensix_server.cases import CaseInvalidStateError
from forensix_server.custody import AuditService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    ArtifactPreviewRecord,
    Database,
)

from .service import ArtifactService

PREVIEW_WORKER_VERSION = "1.1.0"
PREVIEW_TIMEOUT_SECONDS = 8
MAX_SOURCE_BYTES = 25 * 1024 * 1024
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
MAX_THUMBNAIL_EDGE = 1024
MAX_WORKER_OUTPUT_BYTES = 16 * 1024
SAFE_OUTPUT_MIME = "image/png"
SUPPORTED_SOURCE_MIMES = frozenset({"image/gif", "image/jpeg", "image/png", "image/webp"})
CREATE_NO_WINDOW = cast(int, getattr(subprocess, "CREATE_NO_WINDOW", 0))


class PreviewError(CaseInvalidStateError):
    code = "PREVIEW_INVALID"


class PreviewNotAvailableError(PreviewError):
    code = "PREVIEW_NOT_AVAILABLE"


@dataclass(frozen=True, slots=True)
class PreviewContent:
    path: Path
    media_type: str
    sha256: str


class ArtifactPreviewService:
    """Creates one append-only PNG derivative without mutating source artifacts."""

    def get_status(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        artifact_id: str,
    ) -> ArtifactPreviewRecord | None:
        ArtifactService().get(session, principal, case_id, artifact_id)
        return session.scalar(
            select(ArtifactPreviewRecord).where(
                ArtifactPreviewRecord.artifact_id == artifact_id,
                ArtifactPreviewRecord.case_id == case_id,
            )
        )

    def generate(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        artifact_id: str,
    ) -> ArtifactPreviewRecord:
        with database.session() as session:
            artifact = ArtifactService().get(session, principal, case_id, artifact_id)
            existing = session.scalar(
                select(ArtifactPreviewRecord).where(
                    ArtifactPreviewRecord.artifact_id == artifact_id
                )
            )
            if existing is not None:
                return existing
            evidence = session.get(AcquiredEvidenceFileRecord, artifact.evidence_file_id)
            if evidence is None or evidence.case_id != case_id or evidence.status != "completed":
                raise PreviewError("The sealed source evidence record is unavailable.")
            evidence_key = evidence.storage_key
            expected_source_hash = artifact.primary_sha256
            extension_mime = artifact.detected_mime

        store = EvidenceStore(database.data_dir / "evidence")
        source_path = store.resolve(evidence_key, require_file=True)
        source_hash = store.hash(evidence_key)
        if source_hash.hexdigest != expected_source_hash:
            return self._persist_outcome(
                database,
                principal,
                case_id,
                artifact_id,
                detected_mime="application/octet-stream",
                extension_mismatch=False,
                status="rejected",
                error_code="SOURCE_HASH_MISMATCH",
                error_message=(
                    "Preview was blocked because source evidence integrity verification failed."
                ),
            )
        if source_hash.size_bytes > MAX_SOURCE_BYTES:
            return self._persist_outcome(
                database,
                principal,
                case_id,
                artifact_id,
                detected_mime="application/octet-stream",
                extension_mismatch=False,
                status="rejected",
                error_code="SOURCE_TOO_LARGE",
                error_message="The source exceeds the bounded preview input limit.",
            )

        output_key = f"c/{case_id[:8]}/d/{artifact_id}.png"
        reservation = store.reserve_external(output_key)
        try:
            result = self._run_worker(source_path, reservation.partial_path, database.data_dir)
            status = cast(str, result["status"])
            detected_mime = cast(str, result.get("detected_mime", "application/octet-stream"))
            extension_mismatch = detected_mime != extension_mime
            if status != "available":
                reservation.close(preserve_partial=False)
                return self._persist_outcome(
                    database,
                    principal,
                    case_id,
                    artifact_id,
                    detected_mime=detected_mime,
                    extension_mismatch=extension_mismatch,
                    status="rejected" if status == "rejected" else "failed",
                    error_code=cast(str, result.get("code", "WORKER_FAILED")),
                    error_message=cast(
                        str,
                        result.get("message", "The isolated preview worker failed safely."),
                    ),
                )
            worker_result = cast(dict[str, Any], result["result"])
            detected_mime = cast(str, worker_result["detected_mime"])
            extension_mismatch = detected_mime != extension_mime
            validation_error = _validate_available_derivative(
                worker_result, reservation.partial_path
            )
            if validation_error is not None:
                reservation.close(preserve_partial=False)
                return self._persist_outcome(
                    database,
                    principal,
                    case_id,
                    artifact_id,
                    detected_mime=detected_mime,
                    extension_mismatch=extension_mismatch,
                    status="failed",
                    error_code="WORKER_OUTPUT_INVALID",
                    error_message=validation_error,
                )
            stored = reservation.seal()
            if stored.size_bytes > MAX_OUTPUT_BYTES:
                raise PreviewError("The generated derivative exceeded its output limit.")
            with database.session() as session:
                artifact = ArtifactService().get(session, principal, case_id, artifact_id)
                record = ArtifactPreviewRecord(
                    artifact_id=artifact.id,
                    evidence_file_id=artifact.evidence_file_id,
                    case_id=case_id,
                    generated_by=principal.user_id,
                    status="available",
                    extension_mismatch=extension_mismatch,
                    detected_mime=detected_mime,
                    output_mime=SAFE_OUTPUT_MIME,
                    output_storage_key=stored.storage_key,
                    output_size_bytes=stored.size_bytes,
                    output_sha256=stored.sha256,
                    width=int(worker_result["width"]),
                    height=int(worker_result["height"]),
                    source_width=int(worker_result["source_width"]),
                    source_height=int(worker_result["source_height"]),
                    media_metadata_json=json.dumps(
                        worker_result["media_metadata"], separators=(",", ":"), sort_keys=True
                    ),
                    worker_version=cast(str, worker_result["worker_version"]),
                    limits_json=_limits_json(),
                )
                session.add(record)
                session.flush()
                self._audit(session, record, principal.user_id)
                return record
        except subprocess.TimeoutExpired:
            reservation.close(preserve_partial=False)
            return self._persist_outcome(
                database,
                principal,
                case_id,
                artifact_id,
                detected_mime="application/octet-stream",
                extension_mismatch=False,
                status="failed",
                error_code="PREVIEW_TIMEOUT",
                error_message="The isolated preview worker exceeded its time limit.",
            )
        except Exception:
            reservation.close(preserve_partial=False)
            raise

    def content(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        artifact_id: str,
    ) -> PreviewContent:
        with database.session() as session:
            record = self.get_status(session, principal, case_id, artifact_id)
            if (
                record is None
                or record.status != "available"
                or record.output_storage_key is None
                or record.output_sha256 is None
                or record.output_mime != SAFE_OUTPUT_MIME
            ):
                raise PreviewNotAvailableError("No safe preview derivative is available.")
            storage_key = record.output_storage_key
            expected_hash = record.output_sha256
        store = EvidenceStore(database.data_dir / "evidence")
        observed = store.hash(storage_key)
        if observed.hexdigest != expected_hash or observed.size_bytes > MAX_OUTPUT_BYTES:
            raise PreviewNotAvailableError("The preview derivative failed integrity verification.")
        return PreviewContent(
            path=store.resolve(storage_key, require_file=True),
            media_type=SAFE_OUTPUT_MIME,
            sha256=expected_hash,
        )

    def _persist_outcome(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        artifact_id: str,
        *,
        detected_mime: str,
        extension_mismatch: bool,
        status: str,
        error_code: str,
        error_message: str,
    ) -> ArtifactPreviewRecord:
        with database.session() as session:
            artifact = ArtifactService().get(session, principal, case_id, artifact_id)
            existing = session.scalar(
                select(ArtifactPreviewRecord).where(
                    ArtifactPreviewRecord.artifact_id == artifact_id
                )
            )
            if existing is not None:
                return existing
            record = ArtifactPreviewRecord(
                artifact_id=artifact.id,
                evidence_file_id=artifact.evidence_file_id,
                case_id=case_id,
                generated_by=principal.user_id,
                status=status,
                extension_mismatch=extension_mismatch,
                detected_mime=detected_mime,
                output_mime=None,
                output_storage_key=None,
                output_size_bytes=None,
                output_sha256=None,
                width=None,
                height=None,
                source_width=None,
                source_height=None,
                media_metadata_json="{}",
                worker_version=PREVIEW_WORKER_VERSION,
                limits_json=_limits_json(),
                error_code=error_code,
                error_message=error_message,
            )
            session.add(record)
            session.flush()
            self._audit(session, record, principal.user_id)
            return record

    @staticmethod
    def _run_worker(source: Path, output: Path, working_directory: Path) -> dict[str, Any]:
        specification = importlib.util.find_spec("forensix_forensic.preview_worker")
        if specification is None or specification.origin is None:
            raise PreviewError("The isolated preview worker is not installed.")
        creation_flags = CREATE_NO_WINDOW if os.name == "nt" else 0
        completed = subprocess.run(  # noqa: S603 - fixed executable and worker arguments
            [
                sys.executable,
                "-I",
                specification.origin,
                "--source",
                str(source),
                "--output",
                str(output),
            ],
            cwd=working_directory,
            capture_output=True,
            check=False,
            creationflags=creation_flags,
            text=True,
            timeout=PREVIEW_TIMEOUT_SECONDS,
        )
        if len(completed.stdout.encode("utf-8")) > MAX_WORKER_OUTPUT_BYTES:
            return {
                "code": "WORKER_OUTPUT_LIMIT",
                "message": "The isolated preview worker exceeded its output limit.",
                "status": "failed",
            }
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return {
                "code": "WORKER_PROTOCOL_ERROR",
                "message": "The isolated preview worker returned an invalid result.",
                "status": "failed",
            }
        if not isinstance(payload, dict) or payload.get("status") not in {
            "available",
            "failed",
            "rejected",
        }:
            return {
                "code": "WORKER_PROTOCOL_ERROR",
                "message": "The isolated preview worker returned an invalid result.",
                "status": "failed",
            }
        if completed.returncode != 0 and payload.get("status") == "available":
            payload = {
                "code": "WORKER_PROTOCOL_ERROR",
                "message": "The isolated preview worker exited unsuccessfully.",
                "status": "failed",
            }
        elif completed.returncode == 0 and payload.get("status") != "available":
            payload["status"] = "failed"
            payload["code"] = "WORKER_PROTOCOL_ERROR"
        return cast(dict[str, Any], payload)

    @staticmethod
    def _audit(session: Session, record: ArtifactPreviewRecord, actor_id: str) -> None:
        AuditService().append(
            session,
            case_id=record.case_id,
            actor_id=actor_id,
            event_type=f"artifact_preview_{record.status}",
            object_type="artifact_preview",
            object_id=record.id,
            detail={
                "artifact_id": record.artifact_id,
                "detected_mime": record.detected_mime,
                "error_code": record.error_code,
                "extension_mismatch": record.extension_mismatch,
                "output_sha256": record.output_sha256,
                "status": record.status,
            },
            created_at=record.created_at,
        )
        session.flush()


def _limits_json() -> str:
    return json.dumps(
        {
            "max_image_pixels": MAX_IMAGE_PIXELS,
            "max_output_bytes": MAX_OUTPUT_BYTES,
            "max_source_bytes": MAX_SOURCE_BYTES,
            "max_thumbnail_edge": MAX_THUMBNAIL_EDGE,
            "max_exif_tags": 64,
            "max_exif_value_chars": 256,
            "timeout_seconds": PREVIEW_TIMEOUT_SECONDS,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _validate_available_derivative(result: dict[str, Any], path: Path) -> str | None:
    detected_mime = result.get("detected_mime")
    width = result.get("width")
    height = result.get("height")
    source_width = result.get("source_width")
    source_height = result.get("source_height")
    media_metadata = result.get("media_metadata")
    if (
        detected_mime not in SUPPORTED_SOURCE_MIMES
        or result.get("output_mime") != SAFE_OUTPUT_MIME
        or result.get("worker_version") != PREVIEW_WORKER_VERSION
        or type(width) is not int
        or type(height) is not int
        or type(source_width) is not int
        or type(source_height) is not int
        or not isinstance(media_metadata, dict)
        or not 1 <= width <= MAX_THUMBNAIL_EDGE
        or not 1 <= height <= MAX_THUMBNAIL_EDGE
        or source_width < 1
        or source_height < 1
        or source_width * source_height > MAX_IMAGE_PIXELS
    ):
        return "The isolated preview worker returned invalid derivative metadata."
    serialized_metadata = json.dumps(media_metadata, separators=(",", ":"), sort_keys=True)
    if len(serialized_metadata.encode("utf-8")) > 16 * 1024:
        return "The isolated preview worker returned excessive media metadata."
    if path.is_symlink() or not path.is_file():
        return "The isolated preview worker did not create a regular derivative file."
    size_bytes = path.stat().st_size
    if not 1 <= size_bytes <= MAX_OUTPUT_BYTES:
        return "The isolated preview worker produced an invalid derivative size."
    with path.open("rb") as stream:
        if stream.read(8) != b"\x89PNG\r\n\x1a\n":
            return "The isolated preview worker did not produce a PNG derivative."
    return None
