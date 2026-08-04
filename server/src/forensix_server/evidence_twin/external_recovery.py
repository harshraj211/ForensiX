"""Audited TestDisk/PhotoRec recovery runs for verified raw working copies."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from forensix_forensic.integrations import PhotoRecController, PhotoRecExecution
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError
from forensix_server.custody import AuditService
from forensix_server.db import (
    Database,
    EvidenceExternalRecoveryRunRecord,
    EvidenceWorkingCopyRecord,
)

from .inspection import EvidenceInspectionService
from .service import EvidenceTwinError, EvidenceTwinNotFoundError, EvidenceTwinService

EXTERNAL_RECOVERY_TOOL_ID = "cgsecurity.photorec"
EXTERNAL_RECOVERY_VERSION = "1.0.0"
SUPPORTED_IMAGE_TYPES = frozenset({"ext4", "f2fs"})


class EvidenceExternalRecoveryService:
    """Run a hash-pinned PhotoRec executable only on an immutable forensic working copy."""

    def run(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
        controller: PhotoRecController,
    ) -> EvidenceExternalRecoveryRunRecord:
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot run external recovery.")
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            existing = session.scalar(
                select(EvidenceExternalRecoveryRunRecord).where(
                    EvidenceExternalRecoveryRunRecord.working_copy_id == working_copy_id,
                    EvidenceExternalRecoveryRunRecord.evidence_source_id == source_id,
                    EvidenceExternalRecoveryRunRecord.case_id == case_id,
                    EvidenceExternalRecoveryRunRecord.tool_id == EXTERNAL_RECOVERY_TOOL_ID,
                )
            )
            if existing is not None:
                return existing
            working_copy = session.get(EvidenceWorkingCopyRecord, working_copy_id)
            if working_copy is None:
                raise EvidenceTwinNotFoundError(
                    "The requested Evidence Twin working copy does not exist."
                )

        EvidenceTwinService().verify_working_copy(
            database, principal, case_id, source_id, working_copy_id
        )
        inspection = EvidenceInspectionService().inspect_working_copy(
            database, principal, case_id, source_id, working_copy_id
        )
        now = datetime.now(UTC)
        run_id = str(uuid4())
        # Keep the controlled workspace shallow. Case/source/copy ownership is already
        # immutable database metadata, while UUID-only paths avoid Windows MAX_PATH
        # failures with long evidence identifiers and installation directories.
        storage_key = f"external-recovery/{run_id}"
        output_root = (database.data_dir / storage_key).resolve()
        _assert_output_root(database.data_dir, output_root)

        if inspection.detected_type not in SUPPORTED_IMAGE_TYPES:
            result = _unsupported_result(inspection.detected_type)
            return self._persist(
                database,
                principal,
                case_id,
                source_id,
                working_copy_id,
                inspection.id,
                run_id,
                storage_key,
                "unsupported",
                result,
                now,
            )

        source_path = (database.data_dir / "evidence").resolve()
        from forensix_forensic.storage import EvidenceStore

        working_path = EvidenceStore(source_path).resolve(
            working_copy.storage_key, require_file=True
        )
        try:
            execution = controller.recover(working_path, output_root)
        except Exception:
            # Never leave partial results presented as a completed evidence recovery run.
            shutil.rmtree(output_root, ignore_errors=True)
            raise
        result = _execution_result(execution)
        run_status = "completed" if execution.exit_code == 0 else "completed_with_warnings"
        return self._persist(
            database,
            principal,
            case_id,
            source_id,
            working_copy_id,
            inspection.id,
            run_id,
            storage_key,
            run_status,
            result,
            now,
        )

    def get(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
    ) -> EvidenceExternalRecoveryRunRecord:
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            record = session.scalar(
                select(EvidenceExternalRecoveryRunRecord).where(
                    EvidenceExternalRecoveryRunRecord.working_copy_id == working_copy_id,
                    EvidenceExternalRecoveryRunRecord.evidence_source_id == source_id,
                    EvidenceExternalRecoveryRunRecord.case_id == case_id,
                    EvidenceExternalRecoveryRunRecord.tool_id == EXTERNAL_RECOVERY_TOOL_ID,
                )
            )
            if record is None:
                raise EvidenceTwinNotFoundError(
                    "No TestDisk/PhotoRec recovery run exists for this working copy."
                )
            return record

    @staticmethod
    def _persist(
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
        inspection_id: str,
        run_id: str,
        storage_key: str,
        run_status: str,
        result: dict[str, Any],
        executed_at: datetime,
    ) -> EvidenceExternalRecoveryRunRecord:
        payload = {
            "case_id": case_id,
            "evidence_source_id": source_id,
            "executed_at": executed_at.isoformat(),
            "executed_by": principal.user_id,
            "inspection_id": inspection_id,
            "maturity": "experimental",
            "result": result,
            "status": run_status,
            "storage_key": storage_key,
            "tool_id": EXTERNAL_RECOVERY_TOOL_ID,
            "tool_version": EXTERNAL_RECOVERY_VERSION,
            "working_copy_id": working_copy_id,
        }
        files = result.get("output_files", [])
        record = EvidenceExternalRecoveryRunRecord(
            id=run_id,
            evidence_source_id=source_id,
            working_copy_id=working_copy_id,
            inspection_id=inspection_id,
            case_id=case_id,
            executed_by=principal.user_id,
            tool_id=EXTERNAL_RECOVERY_TOOL_ID,
            maturity="experimental",
            status=run_status,
            recovered_file_count=len(files) if isinstance(files, list) else 0,
            output_storage_key=storage_key,
            result_json=_canonical_json(result),
            run_hash=sha256(_canonical_json(payload).encode()).hexdigest(),
            tool_version=EXTERNAL_RECOVERY_VERSION,
            executed_at=executed_at,
        )
        with database.session() as session:
            session.add(record)
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="experimental_external_recovery_completed",
                object_type="evidence_working_copy",
                object_id=working_copy_id,
                detail={
                    "recovered_file_count": record.recovered_file_count,
                    "run_hash": record.run_hash,
                    "status": record.status,
                    "tool_id": record.tool_id,
                },
                created_at=executed_at,
            )
            session.flush()
            return record


def external_recovery_result(record: EvidenceExternalRecoveryRunRecord) -> dict[str, Any]:
    value: object = json.loads(record.result_json)
    if not isinstance(value, dict):
        raise EvidenceTwinError("The stored external recovery result is malformed.")
    return {str(key): item for key, item in value.items()}


def _execution_result(execution: PhotoRecExecution) -> dict[str, Any]:
    return {
        "command": list(execution.command),
        "console_summary": execution.console_summary,
        "executable_sha256": execution.executable_sha256,
        "exit_code": execution.exit_code,
        "output_files": [item.model_dump(mode="json") for item in execution.output_files],
        "output_total_bytes": execution.output_total_bytes,
        "version": execution.version or "unreported",
        "limitations": [
            "PhotoRec output is a file-carving candidate set, not a proof that files were "
            "deleted from Android.",
            "PhotoRec does not preserve the original directory tree and may not preserve "
            "original names.",
            "Recovery runs only on a verified working copy; the sealed source and device "
            "are not modified.",
            "Android encryption, unsupported image layouts, overwriting, and flash "
            "wear-leveling can prevent recovery.",
        ],
    }


def _unsupported_result(detected_type: str) -> dict[str, Any]:
    return {
        "command": [],
        "console_summary": "No external recovery command was run.",
        "executable_sha256": None,
        "exit_code": None,
        "output_files": [],
        "output_total_bytes": 0,
        "version": "not-run",
        "limitations": [
            f"The working copy was detected as {detected_type}; only raw ext4 or F2FS "
            "images are eligible.",
            "Android sparse images must be converted into a verified raw working copy "
            "before external recovery.",
            "ForensiX does not send live Android devices or sealed master evidence to PhotoRec.",
        ],
    }


def _assert_output_root(data_dir: Path, output_root: Path) -> None:
    allowed_root = (data_dir / "external-recovery").resolve()
    try:
        output_root.relative_to(allowed_root)
    except ValueError as error:
        raise EvidenceTwinError(
            "External recovery output path escaped the controlled workspace."
        ) from error
    if allowed_root.exists() and allowed_root.is_symlink():
        raise EvidenceTwinError("External recovery workspace must not be a symbolic link.")


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
