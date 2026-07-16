"""Durable reconciliation and review of interrupted acquisition partials."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseInvalidStateError, CaseService
from forensix_server.custody import AuditService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionPartialRecord,
    CaseEventRecord,
    Database,
)

from .execution import AcquisitionExecutionService


class AcquisitionRecoveryError(CaseInvalidStateError):
    code = "ACQUISITION_RECOVERY_INVALID"


class PartialIntegrityChangedError(AcquisitionRecoveryError):
    code = "PARTIAL_INTEGRITY_CHANGED"


class AcquisitionRecoveryService:
    """Tracks every partial and requires an explicit retention decision before restart."""

    def begin_attempt(
        self,
        database: Database,
        *,
        partial_id: str,
        evidence_file_id: str,
        case_id: str,
        job_id: str,
        created_by: str,
        storage_key: str,
    ) -> AcquisitionPartialRecord:
        with database.session() as session:
            record = AcquisitionPartialRecord(
                id=partial_id,
                evidence_file_id=evidence_file_id,
                case_id=case_id,
                job_id=job_id,
                created_by=created_by,
                storage_key=storage_key,
                status="active",
            )
            session.add(record)
            session.flush()
            return record

    def reconcile_attempt(
        self,
        database: Database,
        partial_id: str,
        *,
        reason_code: str,
        preserve: bool,
    ) -> AcquisitionPartialRecord:
        store = EvidenceStore(database.data_dir / "evidence")
        with database.session() as session:
            record = session.get(AcquisitionPartialRecord, partial_id)
            if record is None:
                raise AcquisitionRecoveryError("The acquisition partial record was not found.")
            self._reconcile_file(store, record, reason_code=reason_code, preserve=preserve)
            session.flush()
            return record

    def mark_sealed(
        self,
        database: Database,
        partial_id: str,
        *,
        size_bytes: int,
        sha256: str,
    ) -> None:
        with database.session() as session:
            record = session.get(AcquisitionPartialRecord, partial_id)
            if record is None or record.status != "active":
                raise AcquisitionRecoveryError(
                    "The active acquisition partial record changed before sealing."
                )
            record.status = "sealed"
            record.size_bytes = size_bytes
            record.sha256 = sha256
            record.reconciled_at = datetime.now(UTC)
            session.flush()

    def list_for_job(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> list[AcquisitionPartialRecord]:
        AcquisitionExecutionService().get(session, principal, case_id, job_id)
        return list(
            session.scalars(
                select(AcquisitionPartialRecord)
                .where(
                    AcquisitionPartialRecord.case_id == case_id,
                    AcquisitionPartialRecord.job_id == job_id,
                )
                .order_by(AcquisitionPartialRecord.created_at)
            )
        )

    def review_pending(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
        evidence_file_id: str,
        *,
        disposition: str,
    ) -> list[AcquisitionPartialRecord]:
        if disposition not in {"retain", "discard"}:
            raise AcquisitionRecoveryError("The partial disposition is unsupported.")
        if not principal.can(Permission.ACQUISITIONS_OPERATE):
            raise CaseAccessDeniedError("The current user cannot review acquisition partials.")
        store = EvidenceStore(database.data_dir / "evidence")
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            AcquisitionExecutionService().get(session, principal, case_id, job_id)
            evidence = session.get(AcquiredEvidenceFileRecord, evidence_file_id)
            if evidence is None or evidence.case_id != case_id or evidence.job_id != job_id:
                raise AcquisitionRecoveryError("The evidence file does not belong to this job.")
            records = list(
                session.scalars(
                    select(AcquisitionPartialRecord).where(
                        AcquisitionPartialRecord.evidence_file_id == evidence_file_id,
                        AcquisitionPartialRecord.status == "retained",
                        AcquisitionPartialRecord.disposition_at.is_(None),
                    )
                )
            )
            now = datetime.now(UTC)
            for record in records:
                if disposition == "discard":
                    self._discard_verified(store, record)
                    record.status = "discarded"
                    record.reason_code = "OPERATOR_DISCARDED"
                record.disposition_by = principal.user_id
                record.disposition_at = now
                session.add(
                    CaseEventRecord(
                        case_id=case_id,
                        actor_id=principal.user_id,
                        event_type=f"acquisition_partial_{disposition}ed",
                        safe_detail=f"partial_id={record.id};sha256={record.sha256}",
                    )
                )
                AuditService().append(
                    session,
                    actor_id=principal.user_id,
                    case_id=case_id,
                    event_type=f"acquisition_partial_{disposition}ed",
                    object_type="acquisition_partial",
                    object_id=record.id,
                    detail={"sha256": record.sha256, "size_bytes": record.size_bytes},
                    created_at=now,
                )
                session.flush()
            session.flush()
            return records

    def recover_after_restart(self, database: Database) -> int:
        """Reconcile active filesystem attempts; never auto-resume device operations."""
        store = EvidenceStore(database.data_dir / "evidence")
        with database.session() as session:
            partials = list(
                session.scalars(
                    select(AcquisitionPartialRecord).where(
                        AcquisitionPartialRecord.status == "active"
                    )
                )
            )
            for partial in partials:
                evidence = session.get(AcquiredEvidenceFileRecord, partial.evidence_file_id)
                if evidence is None:
                    continue
                partial_path = store.resolve(partial.storage_key)
                final_path = store.resolve(evidence.storage_key)
                if partial_path.exists():
                    result = store.hash(partial.storage_key)
                    partial.status = "retained"
                    partial.size_bytes = result.size_bytes
                    partial.sha256 = result.hexdigest
                    partial.reason_code = "BACKEND_RESTARTED"
                elif final_path.exists():
                    result = store.hash(evidence.storage_key)
                    partial.status = "sealed"
                    partial.size_bytes = result.size_bytes
                    partial.sha256 = result.hexdigest
                    partial.reason_code = "SEALED_BEFORE_RESTART"
                else:
                    partial.status = "missing"
                    partial.reason_code = "PARTIAL_MISSING_AFTER_RESTART"
                partial.reconciled_at = datetime.now(UTC)

            session.flush()

            acquiring = list(
                session.scalars(
                    select(AcquiredEvidenceFileRecord).where(
                        AcquiredEvidenceFileRecord.status == "acquiring"
                    )
                )
            )
            for evidence in acquiring:
                has_retained = session.scalar(
                    select(AcquisitionPartialRecord.id).where(
                        AcquisitionPartialRecord.evidence_file_id == evidence.id,
                        AcquisitionPartialRecord.status == "retained",
                    )
                )
                evidence.status = "interrupted"
                evidence.error_code = "SERVICE_RESTARTED"
                evidence.error_message = "The backend restarted before acquisition completion."
                evidence.partial_preserved = has_retained is not None
                evidence.completed_at = datetime.now(UTC)
                session.add(
                    CaseEventRecord(
                        case_id=evidence.case_id,
                        actor_id=evidence.acquired_by,
                        event_type="evidence_file_acquisition_interrupted",
                        safe_detail=(
                            f"record_id={evidence.id};partial_preserved="
                            f"{str(evidence.partial_preserved).lower()}"
                        ),
                    )
                )
                AuditService().append(
                    session,
                    actor_id=evidence.acquired_by,
                    case_id=evidence.case_id,
                    event_type="evidence_file_acquisition_interrupted",
                    object_type="evidence_file",
                    object_id=evidence.id,
                    detail={"partial_preserved": evidence.partial_preserved},
                    created_at=datetime.now(UTC),
                )
                session.flush()
            session.flush()
            return len(partials)

    @staticmethod
    def has_unreviewed_partial(session: Session, evidence_file_id: str) -> bool:
        return (
            session.scalar(
                select(AcquisitionPartialRecord.id).where(
                    AcquisitionPartialRecord.evidence_file_id == evidence_file_id,
                    AcquisitionPartialRecord.status == "retained",
                    AcquisitionPartialRecord.disposition_at.is_(None),
                )
            )
            is not None
        )

    @staticmethod
    def _reconcile_file(
        store: EvidenceStore,
        record: AcquisitionPartialRecord,
        *,
        reason_code: str,
        preserve: bool,
    ) -> None:
        path = store.resolve(record.storage_key)
        record.reason_code = reason_code[:64]
        record.reconciled_at = datetime.now(UTC)
        if not path.exists():
            record.status = "missing"
            return
        if preserve:
            result = store.hash(record.storage_key)
            record.status = "retained"
            record.size_bytes = result.size_bytes
            record.sha256 = result.hexdigest
            return
        record.size_bytes = path.stat().st_size
        path.unlink()
        record.status = "discarded"

    @staticmethod
    def _discard_verified(store: EvidenceStore, record: AcquisitionPartialRecord) -> None:
        path = store.resolve(record.storage_key)
        if not path.exists():
            raise PartialIntegrityChangedError(
                "The retained partial is missing; no discard action was recorded."
            )
        result = store.hash(record.storage_key)
        if result.hexdigest != record.sha256 or result.size_bytes != record.size_bytes:
            raise PartialIntegrityChangedError(
                "The retained partial changed after reconciliation; it was not deleted."
            )
        path.unlink()
