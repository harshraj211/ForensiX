"""Experimental, metadata-only recovery readiness for verified Evidence Twin copies."""

import json
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from forensix_forensic.evidence_io import (
    RECOVERY_PROBE_VERSION,
    ArchiveExtractionError,
    ArchivePolicy,
    RecoveryCandidate,
    SafeArchiveExtractor,
    assess_sqlite_recovery_file,
)
from forensix_forensic.extractors import CarvedFragment, CarvingResult, SQLiteCarver
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError
from forensix_server.custody import AuditService
from forensix_server.db import (
    Database,
    EvidenceRecoveryAssessmentRecord,
    EvidenceRecoveryCarvingRecord,
    EvidenceWorkingCopyRecord,
)

from .inspection import EvidenceInspectionService
from .service import EvidenceTwinError, EvidenceTwinNotFoundError, EvidenceTwinService

RECOVERY_CARVER_VERSION = "1.0.0"
MAX_CARVING_INPUT_BYTES = 64 * 1024 * 1024
MAX_CARVING_ARCHIVE_MEMBERS = 32
MAX_CARVING_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_CARVING_FRAGMENTS = 250


@dataclass(frozen=True, slots=True)
class _CarvingInput:
    path: Path
    locator: str


class EvidenceRecoveryAssessmentService:
    """Persist one immutable assessment without carving or creating recovered artifacts."""

    def assess(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
    ) -> EvidenceRecoveryAssessmentRecord:
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot assess recovery candidates.")
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            existing = session.scalar(
                select(EvidenceRecoveryAssessmentRecord).where(
                    EvidenceRecoveryAssessmentRecord.working_copy_id == working_copy_id,
                    EvidenceRecoveryAssessmentRecord.evidence_source_id == source_id,
                    EvidenceRecoveryAssessmentRecord.case_id == case_id,
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
        store = EvidenceStore(database.data_dir / "evidence")
        source_path = store.resolve(working_copy.storage_key, require_file=True)
        candidates = self._candidates(database.data_dir, source_path, inspection.detected_type)
        status = _assessment_status(candidates)
        candidate_region_count = sum(item.candidate_region_count for item in candidates)
        now = datetime.now(UTC)
        result = {
            "candidates": [
                {**asdict(item), "candidate_hash": item.canonical_sha256} for item in candidates
            ],
            "limitations": [
                "Candidate regions are not recovered records or proof of deletion.",
                "ForensiX did not carve cells, reconstruct transactions, or bypass encryption.",
                "Any later recovery parser requires known-answer validation and examiner review.",
            ],
        }
        payload = {
            "assessed_at": now.isoformat(),
            "assessed_by": principal.user_id,
            "candidate_region_count": candidate_region_count,
            "case_id": case_id,
            "evidence_source_id": source_id,
            "inspection_id": inspection.id,
            "maturity": "experimental",
            "result": result,
            "status": status,
            "tool_version": RECOVERY_PROBE_VERSION,
            "working_copy_id": working_copy_id,
        }
        record = EvidenceRecoveryAssessmentRecord(
            evidence_source_id=source_id,
            working_copy_id=working_copy_id,
            inspection_id=inspection.id,
            case_id=case_id,
            assessed_by=principal.user_id,
            maturity="experimental",
            status=status,
            candidate_region_count=candidate_region_count,
            result_json=_canonical_json(result),
            assessment_hash=sha256(_canonical_json(payload).encode()).hexdigest(),
            tool_version=RECOVERY_PROBE_VERSION,
            assessed_at=now,
        )
        with database.session() as session:
            session.add(record)
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="experimental_recovery_assessed",
                object_type="evidence_working_copy",
                object_id=working_copy_id,
                detail={
                    "assessment_hash": record.assessment_hash,
                    "candidate_region_count": candidate_region_count,
                    "maturity": "experimental",
                    "status": status,
                },
                created_at=now,
            )
            session.flush()
            return record

    def get(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
    ) -> EvidenceRecoveryAssessmentRecord:
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            record = session.scalar(
                select(EvidenceRecoveryAssessmentRecord).where(
                    EvidenceRecoveryAssessmentRecord.working_copy_id == working_copy_id,
                    EvidenceRecoveryAssessmentRecord.evidence_source_id == source_id,
                    EvidenceRecoveryAssessmentRecord.case_id == case_id,
                )
            )
            if record is None:
                raise EvidenceTwinNotFoundError(
                    "No recovery assessment exists for this Evidence Twin working copy."
                )
            return record

    @staticmethod
    def _candidates(
        data_dir: Path,
        source_path: Path,
        detected_type: str,
    ) -> tuple[RecoveryCandidate, ...]:
        if detected_type not in {"zip", "tar"}:
            candidate = assess_sqlite_recovery_file(source_path, "working_copy")
            return () if candidate.source_kind == "unknown" else (candidate,)
        workspace = (data_dir / "tmp" / f"recovery-{uuid4()}").resolve()
        try:
            member_store = EvidenceStore(workspace)
            members = SafeArchiveExtractor(
                ArchivePolicy(
                    max_members=256,
                    max_member_bytes=512 * 1024 * 1024,
                    max_total_bytes=1024 * 1024 * 1024,
                    max_path_depth=20,
                )
            ).extract(source_path, member_store, "members")
            candidates = tuple(
                assess_sqlite_recovery_file(
                    member_store.resolve(member.storage_key, require_file=True),
                    member.original_name,
                )
                for member in members
            )
            return tuple(item for item in candidates if item.source_kind != "unknown")
        except ArchiveExtractionError as error:
            raise EvidenceTwinError(
                f"Recovery assessment could not safely extract: {error}"
            ) from error
        finally:
            expected_parent = (data_dir / "tmp").resolve()
            if workspace.parent == expected_parent and workspace.name.startswith("recovery-"):
                shutil.rmtree(workspace, ignore_errors=True)


class EvidenceRecoveryCarvingService:
    """Perform a bounded fragment scan only against a verified working copy.

    This is deliberately a candidate-finding workflow. It does not alter the sealed source,
    modify the Android device, create a filesystem image, or certify that a byte fragment was
    deleted data. The persisted result provides a hashable lead for later examiner review.
    """

    def carve(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
    ) -> EvidenceRecoveryCarvingRecord:
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot scan recovery candidates.")
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            existing = session.scalar(
                select(EvidenceRecoveryCarvingRecord).where(
                    EvidenceRecoveryCarvingRecord.working_copy_id == working_copy_id,
                    EvidenceRecoveryCarvingRecord.evidence_source_id == source_id,
                    EvidenceRecoveryCarvingRecord.case_id == case_id,
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
        store = EvidenceStore(database.data_dir / "evidence")
        source_path = store.resolve(working_copy.storage_key, require_file=True)
        carving_result, input_locators, skipped_locators = self._scan(
            database.data_dir, source_path, inspection.detected_type
        )
        fragments = [
            {**asdict(fragment), "fragment_hash": _fragment_hash(fragment)}
            for fragment in carving_result.fragments
        ]
        status = (
            "candidate_fragments_observed"
            if fragments
            else "no_candidate_fragments"
            if input_locators
            else "unsupported"
        )
        result = {
            "fragments": fragments,
            "input_locators": input_locators,
            "skipped_locators": skipped_locators,
            "source_file_count": len(input_locators),
            "source_total_bytes": carving_result.source_total_bytes,
            "wal_fragments_found": carving_result.wal_fragments_found,
            "freelist_fragments_found": carving_result.freelist_fragments_found,
            "unallocated_fragments_found": carving_result.unallocated_fragments_found,
            "duration_seconds": carving_result.duration_seconds,
            "limitations": [
                "Candidate fragments are raw byte sequences, not verified deleted records "
                "or messages.",
                "Current, superseded, and stale SQLite content can produce the same fragment.",
                "This scan cannot bypass Android encryption, access non-acquired app "
                "sandboxes, or recover filesystem unallocated space.",
                "A qualified examiner must validate any lead against the sealed source "
                "and a known-answer method.",
                *carving_result.limitations,
            ],
        }
        now = datetime.now(UTC)
        payload = {
            "case_id": case_id,
            "evidence_source_id": source_id,
            "executed_at": now.isoformat(),
            "executed_by": principal.user_id,
            "inspection_id": inspection.id,
            "maturity": "experimental",
            "result": result,
            "status": status,
            "tool_version": RECOVERY_CARVER_VERSION,
            "working_copy_id": working_copy_id,
        }
        record = EvidenceRecoveryCarvingRecord(
            evidence_source_id=source_id,
            working_copy_id=working_copy_id,
            inspection_id=inspection.id,
            case_id=case_id,
            executed_by=principal.user_id,
            maturity="experimental",
            status=status,
            fragment_count=len(fragments),
            result_json=_canonical_json(result),
            run_hash=sha256(_canonical_json(payload).encode()).hexdigest(),
            tool_version=RECOVERY_CARVER_VERSION,
            executed_at=now,
        )
        with database.session() as session:
            session.add(record)
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="experimental_recovery_fragment_scan_completed",
                object_type="evidence_working_copy",
                object_id=working_copy_id,
                detail={
                    "fragment_count": record.fragment_count,
                    "maturity": "experimental",
                    "run_hash": record.run_hash,
                    "status": record.status,
                },
                created_at=now,
            )
            session.flush()
            return record

    def get(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
    ) -> EvidenceRecoveryCarvingRecord:
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            record = session.scalar(
                select(EvidenceRecoveryCarvingRecord).where(
                    EvidenceRecoveryCarvingRecord.working_copy_id == working_copy_id,
                    EvidenceRecoveryCarvingRecord.evidence_source_id == source_id,
                    EvidenceRecoveryCarvingRecord.case_id == case_id,
                )
            )
            if record is None:
                raise EvidenceTwinNotFoundError(
                    "No experimental recovery fragment scan exists for this working copy."
                )
            return record

    @staticmethod
    def _scan(
        data_dir: Path,
        source_path: Path,
        detected_type: str,
    ) -> tuple[CarvingResult, list[str], list[str]]:
        workspace: Path | None = None
        try:
            inputs: list[_CarvingInput] = []
            skipped: list[str] = []
            if detected_type in {"zip", "tar"}:
                workspace = (data_dir / "tmp" / f"recovery-carve-{uuid4()}").resolve()
                member_store = EvidenceStore(workspace)
                try:
                    members = SafeArchiveExtractor(
                        ArchivePolicy(
                            max_members=MAX_CARVING_ARCHIVE_MEMBERS,
                            max_member_bytes=MAX_CARVING_INPUT_BYTES,
                            max_total_bytes=MAX_CARVING_ARCHIVE_BYTES,
                            max_path_depth=20,
                        )
                    ).extract(source_path, member_store, "members")
                except ArchiveExtractionError as error:
                    raise EvidenceTwinError(
                        f"Recovery fragment scan could not safely extract: {error}"
                    ) from error
                for member in members:
                    member_path = member_store.resolve(member.storage_key, require_file=True)
                    candidate = assess_sqlite_recovery_file(member_path, member.original_name)
                    if candidate.source_kind == "unknown":
                        continue
                    if member_path.stat().st_size > MAX_CARVING_INPUT_BYTES:
                        skipped.append(member.original_name)
                        continue
                    inputs.append(_CarvingInput(member_path, member.original_name))
            elif detected_type == "sqlite":
                candidate = assess_sqlite_recovery_file(source_path, "working_copy")
                source_size = source_path.stat().st_size
                if (
                    candidate.source_kind != "unknown"
                    and source_size <= MAX_CARVING_INPUT_BYTES
                ):
                    inputs.append(_CarvingInput(source_path, "working_copy"))
                elif source_size > MAX_CARVING_INPUT_BYTES:
                    skipped.append("working_copy")

            # A database scan automatically considers its adjacent WAL. Avoid scanning the same
            # bytes twice when an archive contains both messages.db and messages.db-wal.
            input_paths = [item.path for item in inputs if not item.locator.endswith("-wal")]
            if not input_paths:
                input_paths = [item.path for item in inputs]
            result = SQLiteCarver().carve(input_paths, max_fragments=MAX_CARVING_FRAGMENTS)
            return result, [item.locator for item in inputs], skipped
        finally:
            if workspace is not None:
                expected_parent = (data_dir / "tmp").resolve()
                if (
                    workspace.parent == expected_parent
                    and workspace.name.startswith("recovery-carve-")
                ):
                    shutil.rmtree(workspace, ignore_errors=True)


def recovery_carving_result(record: EvidenceRecoveryCarvingRecord) -> dict[str, Any]:
    value: object = json.loads(record.result_json)
    if not isinstance(value, dict):
        raise EvidenceTwinError("The stored recovery fragment scan is malformed.")
    return {str(key): item for key, item in value.items()}


def _fragment_hash(fragment: CarvedFragment) -> str:
    return sha256(_canonical_json(asdict(fragment)).encode()).hexdigest()


def recovery_assessment_result(record: EvidenceRecoveryAssessmentRecord) -> dict[str, Any]:
    value: object = json.loads(record.result_json)
    if not isinstance(value, dict):
        raise EvidenceTwinError("The stored recovery assessment is malformed.")
    return {str(key): item for key, item in value.items()}


def _assessment_status(candidates: tuple[RecoveryCandidate, ...]) -> str:
    if any(item.status == "candidate_regions_observed" for item in candidates):
        return "candidate_regions_observed"
    if any(item.status == "no_candidate_regions" for item in candidates):
        return "no_candidate_regions"
    return "unsupported"


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
