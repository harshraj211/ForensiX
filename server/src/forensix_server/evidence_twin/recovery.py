"""Experimental, metadata-only recovery readiness for verified Evidence Twin copies."""

import json
import shutil
from dataclasses import asdict
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
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError
from forensix_server.custody import AuditService
from forensix_server.db import (
    Database,
    EvidenceRecoveryAssessmentRecord,
    EvidenceWorkingCopyRecord,
)

from .inspection import EvidenceInspectionService
from .service import EvidenceTwinError, EvidenceTwinNotFoundError, EvidenceTwinService


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
