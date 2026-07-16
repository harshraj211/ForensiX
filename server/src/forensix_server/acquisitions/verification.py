"""Append-only SHA-256 re-verification for acquired evidence and manifests."""

import asyncio
import json
from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_forensic.storage import (
    EvidenceNotFoundError,
    EvidenceStore,
    HashResult,
    StorageBoundaryError,
)
from forensix_server import __version__
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.custody import CustodyService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    CaseEventRecord,
    Database,
    EvidenceVerificationRecord,
)

from .execution import AcquisitionExecutionService
from .files import AcquisitionFileError


class EvidenceVerificationError(AcquisitionFileError):
    code = "EVIDENCE_VERIFICATION_INVALID"


class EvidenceVerificationService:
    """Re-hashes sealed bytes without modifying evidence or prior verification records."""

    async def verify(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
        evidence_file_id: str,
    ) -> EvidenceVerificationRecord:
        evidence = self._get_target(
            database,
            principal,
            case_id,
            job_id,
            evidence_file_id,
        )
        store = EvidenceStore(database.data_dir / "evidence")
        file_result, file_error = await _hash_safely(store, evidence.storage_key)
        manifest_result, manifest_error = await _hash_safely(store, evidence.manifest_storage_key)
        return self._persist(
            database,
            principal,
            evidence,
            file_result=file_result,
            file_error=file_error,
            manifest_result=manifest_result,
            manifest_error=manifest_error,
        )

    def list_for_job(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> list[EvidenceVerificationRecord]:
        AcquisitionExecutionService().get(session, principal, case_id, job_id)
        return list(
            session.scalars(
                select(EvidenceVerificationRecord)
                .where(
                    EvidenceVerificationRecord.case_id == case_id,
                    EvidenceVerificationRecord.job_id == job_id,
                )
                .order_by(EvidenceVerificationRecord.verified_at.desc())
            )
        )

    @staticmethod
    def _get_target(
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
        evidence_file_id: str,
    ) -> AcquiredEvidenceFileRecord:
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot verify evidence integrity.")
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            AcquisitionExecutionService().get(session, principal, case_id, job_id)
            evidence = session.get(AcquiredEvidenceFileRecord, evidence_file_id)
            if evidence is None or evidence.case_id != case_id or evidence.job_id != job_id:
                raise EvidenceVerificationError(
                    "The selected evidence file does not belong to this acquisition."
                )
            if (
                evidence.status != "completed"
                or evidence.sha256 is None
                or evidence.manifest_hash is None
                or evidence.size_bytes is None
            ):
                raise EvidenceVerificationError(
                    "Only completed evidence with recorded hashes can be verified."
                )
            session.expunge(evidence)
            return evidence

    @staticmethod
    def _persist(
        database: Database,
        principal: Principal,
        evidence: AcquiredEvidenceFileRecord,
        *,
        file_result: HashResult | None,
        file_error: str | None,
        manifest_result: HashResult | None,
        manifest_error: str | None,
    ) -> EvidenceVerificationRecord:
        assert evidence.sha256 is not None
        assert evidence.manifest_hash is not None
        assert evidence.size_bytes is not None
        verified_at = datetime.now(UTC)
        record_id = str(uuid4())
        file_matches = bool(
            file_result
            and file_result.hexdigest == evidence.sha256
            and file_result.size_bytes == evidence.size_bytes
        )
        manifest_matches = bool(
            manifest_result and manifest_result.hexdigest == evidence.manifest_hash
        )
        if file_error == "EVIDENCE_MISSING" or manifest_error == "EVIDENCE_MISSING":
            status = "missing"
        elif file_error or manifest_error:
            status = "error"
        elif file_matches and manifest_matches:
            status = "verified"
        else:
            status = "mismatch"
        error_code = file_error or manifest_error
        canonical = {
            "error_code": error_code,
            "evidence_file_id": evidence.id,
            "expected_file_sha256": evidence.sha256,
            "expected_manifest_sha256": evidence.manifest_hash,
            "file_matches": file_matches,
            "file_size_bytes": file_result.size_bytes if file_result else None,
            "id": record_id,
            "manifest_matches": manifest_matches,
            "observed_file_sha256": file_result.hexdigest if file_result else None,
            "observed_manifest_sha256": (manifest_result.hexdigest if manifest_result else None),
            "status": status,
            "tool_version": __version__,
            "verified_at": verified_at.isoformat(),
            "verified_by": principal.user_id,
        }
        verification_hash = sha256(
            json.dumps(
                canonical,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        with database.session() as session:
            record = EvidenceVerificationRecord(
                id=record_id,
                evidence_file_id=evidence.id,
                case_id=evidence.case_id,
                job_id=evidence.job_id,
                verified_by=principal.user_id,
                status=status,
                expected_file_sha256=evidence.sha256,
                observed_file_sha256=(file_result.hexdigest if file_result else None),
                file_size_bytes=file_result.size_bytes if file_result else None,
                file_matches=file_matches,
                expected_manifest_sha256=evidence.manifest_hash,
                observed_manifest_sha256=(manifest_result.hexdigest if manifest_result else None),
                manifest_matches=manifest_matches,
                error_code=error_code,
                verification_hash=verification_hash,
                tool_version=__version__,
                verified_at=verified_at,
            )
            session.add(record)
            CustodyService().append_automatic(
                session,
                case_id=evidence.case_id,
                actor_id=principal.user_id,
                event_type=(
                    "integrity_verified" if status == "verified" else "integrity_exception"
                ),
                evidence_file_id=evidence.id,
                purpose=f"Evidence integrity verification outcome: {status}.",
            )
            session.add(
                CaseEventRecord(
                    case_id=evidence.case_id,
                    actor_id=principal.user_id,
                    event_type=f"evidence_integrity_{status}",
                    safe_detail=(
                        f"verification_id={record.id};evidence_file_id={evidence.id};"
                        f"status={status}"
                    ),
                )
            )
            session.flush()
            return record


async def _hash_safely(
    store: EvidenceStore, storage_key: str
) -> tuple[HashResult | None, str | None]:
    try:
        return await asyncio.to_thread(store.hash, storage_key), None
    except EvidenceNotFoundError:
        return None, "EVIDENCE_MISSING"
    except StorageBoundaryError:
        return None, "EVIDENCE_STORAGE_BOUNDARY"
    except OSError:
        return None, "EVIDENCE_READ_FAILED"
