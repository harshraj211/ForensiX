"""Append-only custody history and tamper-evident global audit chaining."""

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Literal
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseInvalidStateError, CaseService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AuditLogRecord,
    CustodyEventRecord,
    EvidenceParserRunRecord,
    EvidenceSourceRecord,
    ReportRecord,
)

GENESIS_HASH = "0" * 64
CustodyEventType = Literal[
    "evidence_registered",
    "integrity_verified",
    "integrity_exception",
    "evidence_source_registered",
    "source_integrity_verified",
    "working_copy_verified",
    "parser_completed",
    "parser_failed",
    "transferred",
    "amendment",
    "report_generated",
]


class CustodyError(CaseInvalidStateError):
    code = "CUSTODY_EVENT_INVALID"


class AuditService:
    def append(
        self,
        session: Session,
        *,
        case_id: str | None,
        actor_id: str,
        event_type: str,
        object_type: str,
        object_id: str,
        detail: dict[str, Any],
        created_at: datetime,
    ) -> AuditLogRecord:
        previous = session.scalar(
            select(AuditLogRecord).order_by(AuditLogRecord.sequence.desc()).limit(1)
        )
        sequence = (previous.sequence + 1) if previous else 1
        previous_hash = previous.entry_hash if previous else GENESIS_HASH
        record_id = str(uuid4())
        detail_json = _canonical_json(detail)
        canonical = _canonical_json(
            {
                "actor_id": actor_id,
                "case_id": case_id,
                "created_at": _iso(created_at),
                "detail_json": detail_json,
                "event_type": event_type,
                "id": record_id,
                "object_id": object_id,
                "object_type": object_type,
                "sequence": sequence,
            }
        )
        entry_hash = sha256((previous_hash + canonical).encode("utf-8")).hexdigest()
        record = AuditLogRecord(
            id=record_id,
            sequence=sequence,
            case_id=case_id,
            actor_id=actor_id,
            event_type=event_type,
            object_type=object_type,
            object_id=object_id,
            detail_json=detail_json,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            created_at=created_at,
        )
        session.add(record)
        return record

    def list(
        self, session: Session, principal: Principal, *, limit: int | None = 500
    ) -> list[AuditLogRecord]:
        if not principal.can(Permission.AUDIT_VIEW):
            raise CaseAccessDeniedError("The current user cannot view audit history.")
        query = select(AuditLogRecord).order_by(AuditLogRecord.sequence)
        if limit is not None:
            query = query.limit(limit)
        return list(session.scalars(query))

    def verify(self, session: Session, principal: Principal) -> tuple[bool, int | None]:
        records = self.list(session, principal, limit=None)
        previous_hash = GENESIS_HASH
        for expected_sequence, record in enumerate(records, 1):
            canonical = _canonical_json(
                {
                    "actor_id": record.actor_id,
                    "case_id": record.case_id,
                    "created_at": _iso(record.created_at),
                    "detail_json": record.detail_json,
                    "event_type": record.event_type,
                    "id": record.id,
                    "object_id": record.object_id,
                    "object_type": record.object_type,
                    "sequence": record.sequence,
                }
            )
            expected_hash = sha256((previous_hash + canonical).encode("utf-8")).hexdigest()
            if (
                record.sequence != expected_sequence
                or record.previous_hash != previous_hash
                or record.entry_hash != expected_hash
            ):
                return False, record.sequence
            previous_hash = record.entry_hash
        return True, None


class CustodyService:
    def create_manual(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        event_type: Literal["transferred", "amendment"],
        evidence_file_id: str | None,
        from_custodian: str | None,
        to_custodian: str | None,
        location: str | None,
        purpose: str | None,
        notes: str | None,
        related_event_id: str | None,
    ) -> CustodyEventRecord:
        CaseService().get(session, principal, case_id)
        if not principal.can(Permission.CUSTODY_REVIEW):
            raise CaseAccessDeniedError("The current user cannot record custody events.")
        if event_type == "transferred":
            if not evidence_file_id or not from_custodian or not to_custodian or not purpose:
                raise CustodyError("Transfers require evidence, from/to custodians, and purpose.")
            if from_custodian.strip() == to_custodian.strip():
                raise CustodyError("Transfer custodians must be different.")
        if event_type == "amendment":
            if not related_event_id or not notes:
                raise CustodyError("Amendments require a related event and correction notes.")
            related = session.get(CustodyEventRecord, related_event_id)
            if related is None or related.case_id != case_id:
                raise CustodyError("The amended custody event does not belong to this case.")
        return self._append(
            session,
            case_id=case_id,
            actor_id=principal.user_id,
            event_type=event_type,
            evidence_file_id=evidence_file_id,
            report_id=None,
            from_custodian=from_custodian,
            to_custodian=to_custodian,
            location=location,
            purpose=purpose,
            notes=notes,
            related_event_id=related_event_id,
        )

    def append_automatic(
        self,
        session: Session,
        *,
        case_id: str,
        actor_id: str,
        event_type: Literal["evidence_registered", "integrity_verified", "integrity_exception"],
        evidence_file_id: str,
        purpose: str,
    ) -> CustodyEventRecord:
        return self._append(
            session,
            case_id=case_id,
            actor_id=actor_id,
            event_type=event_type,
            evidence_file_id=evidence_file_id,
            report_id=None,
            from_custodian=None,
            to_custodian=None,
            location=None,
            purpose=purpose,
            notes=None,
            related_event_id=None,
        )

    def append_report_generated(
        self,
        session: Session,
        *,
        case_id: str,
        actor_id: str,
        report_id: str,
        purpose: str,
    ) -> CustodyEventRecord:
        return self._append(
            session,
            case_id=case_id,
            actor_id=actor_id,
            event_type="report_generated",
            evidence_file_id=None,
            report_id=report_id,
            from_custodian=None,
            to_custodian=None,
            location=None,
            purpose=purpose,
            notes=None,
            related_event_id=None,
        )

    def append_evidence_source(
        self,
        session: Session,
        *,
        case_id: str,
        actor_id: str,
        event_type: Literal[
            "evidence_source_registered",
            "source_integrity_verified",
            "working_copy_verified",
            "parser_completed",
            "parser_failed",
            "integrity_exception",
        ],
        evidence_source_id: str,
        parser_run_id: str | None = None,
        purpose: str,
    ) -> CustodyEventRecord:
        """Append custody history for an imported master, its copy, or derived analysis."""
        return self._append(
            session,
            case_id=case_id,
            actor_id=actor_id,
            event_type=event_type,
            evidence_file_id=None,
            report_id=None,
            from_custodian=None,
            to_custodian=None,
            location=None,
            purpose=purpose,
            notes=None,
            related_event_id=None,
            evidence_source_id=evidence_source_id,
            parser_run_id=parser_run_id,
        )

    def list(
        self, session: Session, principal: Principal, case_id: str
    ) -> list[CustodyEventRecord]:
        CaseService().get(session, principal, case_id)
        if not principal.can(Permission.CUSTODY_REVIEW):
            raise CaseAccessDeniedError("The current user cannot view custody history.")
        return list(
            session.scalars(
                select(CustodyEventRecord)
                .where(CustodyEventRecord.case_id == case_id)
                .order_by(CustodyEventRecord.sequence)
            )
        )

    def verify_chain(
        self, session: Session, principal: Principal, case_id: str
    ) -> tuple[bool, int | None]:
        records = self.list(session, principal, case_id)
        previous_hash = GENESIS_HASH
        for expected_sequence, record in enumerate(records, 1):
            expected_hash = _custody_hash(record, previous_hash)
            if (
                record.sequence != expected_sequence
                or record.previous_hash != previous_hash
                or record.event_hash != expected_hash
            ):
                return False, record.sequence
            previous_hash = record.event_hash
        return True, None

    def _append(
        self,
        session: Session,
        *,
        case_id: str,
        actor_id: str,
        event_type: CustodyEventType,
        evidence_file_id: str | None,
        report_id: str | None,
        from_custodian: str | None,
        to_custodian: str | None,
        location: str | None,
        purpose: str | None,
        notes: str | None,
        related_event_id: str | None,
        evidence_source_id: str | None = None,
        parser_run_id: str | None = None,
    ) -> CustodyEventRecord:
        if evidence_file_id:
            evidence = session.get(AcquiredEvidenceFileRecord, evidence_file_id)
            if evidence is None or evidence.case_id != case_id:
                raise CustodyError("The custody evidence does not belong to this case.")
        if report_id:
            report = session.get(ReportRecord, report_id)
            if report is None or report.case_id != case_id:
                raise CustodyError("The custody report does not belong to this case.")
        if evidence_source_id:
            source = session.get(EvidenceSourceRecord, evidence_source_id)
            if source is None or source.case_id != case_id:
                raise CustodyError("The custody evidence source does not belong to this case.")
        if parser_run_id:
            run = session.get(EvidenceParserRunRecord, parser_run_id)
            if (
                run is None
                or run.case_id != case_id
                or run.evidence_source_id != evidence_source_id
            ):
                raise CustodyError(
                    "The custody parser run does not belong to this evidence source."
                )
        previous = session.scalar(
            select(CustodyEventRecord)
            .where(CustodyEventRecord.case_id == case_id)
            .order_by(CustodyEventRecord.sequence.desc())
            .limit(1)
        )
        sequence = (previous.sequence + 1) if previous else 1
        previous_hash = previous.event_hash if previous else GENESIS_HASH
        created_at = datetime.now(UTC)
        record = CustodyEventRecord(
            id=str(uuid4()),
            case_id=case_id,
            evidence_file_id=evidence_file_id,
            evidence_source_id=evidence_source_id,
            parser_run_id=parser_run_id,
            report_id=report_id,
            actor_id=actor_id,
            sequence=sequence,
            event_type=event_type,
            from_custodian=_text(from_custodian, 255),
            to_custodian=_text(to_custodian, 255),
            location=_text(location, 255),
            purpose=_text(purpose, 1000),
            notes=_text(notes, 2000),
            related_event_id=related_event_id,
            previous_hash=previous_hash,
            event_hash="",
            created_at=created_at,
        )
        record.event_hash = _custody_hash(record, previous_hash)
        session.add(record)
        session.flush()
        AuditService().append(
            session,
            case_id=case_id,
            actor_id=actor_id,
            event_type=f"custody.{event_type}",
            object_type="custody_event",
            object_id=record.id,
            detail={"custody_hash": record.event_hash, "sequence": sequence},
            created_at=created_at,
        )
        session.flush()
        return record


def _custody_hash(record: CustodyEventRecord, previous_hash: str) -> str:
    payload = {
        "actor_id": record.actor_id,
        "case_id": record.case_id,
        "created_at": _iso(record.created_at),
        "event_type": record.event_type,
        "evidence_file_id": record.evidence_file_id,
        "from_custodian": record.from_custodian,
        "id": record.id,
        "location": record.location,
        "notes": record.notes,
        "purpose": record.purpose,
        "related_event_id": record.related_event_id,
        "sequence": record.sequence,
        "to_custodian": record.to_custodian,
    }
    if record.report_id is not None:
        payload["report_id"] = record.report_id
    if record.evidence_source_id is not None:
        payload["evidence_source_id"] = record.evidence_source_id
    if record.parser_run_id is not None:
        payload["parser_run_id"] = record.parser_run_id
    canonical = _canonical_json(payload)
    return sha256((previous_hash + canonical).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _iso(value: datetime) -> str:
    current = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return current.isoformat()


def _text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > limit:
        raise CustodyError(f"Custody text must contain between 1 and {limit} characters.")
    return normalized
