"""Durable custody/audit checkpoint exports for independent external anchoring."""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from forensix_forensic.storage import EvidenceStore
from forensix_server import __version__
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseInvalidStateError, CaseService
from forensix_server.custody import AuditService, CustodyService
from forensix_server.db import (
    AuditLogRecord,
    CustodyCheckpointRecord,
    CustodyEventRecord,
    Database,
)

CHECKPOINT_SCHEMA_VERSION = "1.0.0"


class CustodyCheckpointError(CaseInvalidStateError):
    code = "CUSTODY_CHECKPOINT_INVALID"


class CustodyCheckpointNotFoundError(CustodyCheckpointError):
    code = "CUSTODY_CHECKPOINT_NOT_FOUND"


class CustodyCheckpointIntegrityError(CustodyCheckpointError):
    code = "CUSTODY_CHECKPOINT_INTEGRITY_FAILED"


@dataclass(frozen=True, slots=True)
class CustodyCheckpointContent:
    record: CustodyCheckpointRecord
    path: Path


class CustodyCheckpointService:
    """Seal a verified point-in-time chain snapshot without claiming external anchoring."""

    def create(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
    ) -> CustodyCheckpointRecord:
        self._require_export_permission(principal)
        checkpoint_id = str(uuid4())
        created_at = datetime.now(UTC)
        with database.session() as session:
            case = CaseService().get(session, principal, case_id)
            custody_valid, custody_broken = CustodyService().verify_chain(
                session, principal, case_id
            )
            audit_valid, audit_broken = AuditService().verify(session, principal)
            if not custody_valid:
                raise CustodyCheckpointIntegrityError(
                    f"Custody chain verification failed at sequence {custody_broken}."
                )
            if not audit_valid:
                raise CustodyCheckpointIntegrityError(
                    f"Audit chain verification failed at sequence {audit_broken}."
                )
            custody = CustodyService().list(session, principal, case_id)
            audits = AuditService().list(session, principal, limit=None)
            case_audits = [item for item in audits if item.case_id == case_id]
            audit_head = audits[-1] if audits else None
            payload = {
                "anchor_status": "not_externally_anchored",
                "audit_checkpoint": {
                    "case_entries": [_audit_payload(item) for item in case_audits],
                    "global_head_hash": audit_head.entry_hash if audit_head else None,
                    "global_sequence": audit_head.sequence if audit_head else 0,
                    "verified_before_export": True,
                },
                "case": {
                    "case_number": case.case_number,
                    "id": case.id,
                    "status": case.status,
                    "title": case.title,
                },
                "checkpoint_id": checkpoint_id,
                "created_at": _iso(created_at),
                "created_by": principal.user_id,
                "custody_chain": {
                    "events": [_custody_payload(item) for item in custody],
                    "head_hash": custody[-1].event_hash if custody else None,
                    "record_count": len(custody),
                    "verified_before_export": True,
                },
                "limitations": [
                    "This file is hash sealed but has not been externally timestamped or signed.",
                    "The audit head predates the audit event recording this export.",
                    "Independent preservation or publication of the SHA-256 is required "
                    "for anchoring.",
                ],
                "schema_version": CHECKPOINT_SCHEMA_VERSION,
                "tool": {"name": "ForensiX", "version": __version__},
            }
            content = _canonical_bytes(payload)
            safe_case = re.sub(r"[^A-Za-z0-9._-]", "_", case.case_number)
            filename = f"ForensiX_{safe_case}_CustodyCheckpoint_{checkpoint_id[:8]}.json"
            store = EvidenceStore(database.data_dir / "evidence")
            with store.open_writer(
                f"custody-checkpoints/{case_id}/{checkpoint_id}/checkpoint.json"
            ) as writer:
                writer.write(content)
                stored = writer.seal()
            record = CustodyCheckpointRecord(
                id=checkpoint_id,
                case_id=case_id,
                created_by=principal.user_id,
                custody_record_count=len(custody),
                custody_head_hash=custody[-1].event_hash if custody else None,
                audit_sequence=audit_head.sequence if audit_head else 0,
                audit_head_hash=audit_head.entry_hash if audit_head else None,
                filename=filename,
                storage_key=stored.storage_key,
                size_bytes=stored.size_bytes,
                sha256=stored.sha256,
                schema_version=CHECKPOINT_SCHEMA_VERSION,
                created_at=created_at,
            )
            session.add(record)
            session.flush()
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="custody_checkpoint.created",
                object_type="custody_checkpoint",
                object_id=checkpoint_id,
                detail={
                    "anchor_status": "not_externally_anchored",
                    "audit_head_hash": record.audit_head_hash,
                    "audit_sequence": record.audit_sequence,
                    "custody_head_hash": record.custody_head_hash,
                    "sha256": record.sha256,
                },
                created_at=created_at,
            )
            session.flush()
            return record

    def list(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
    ) -> list[CustodyCheckpointRecord]:
        self._require_export_permission(principal)
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            return list(
                session.scalars(
                    select(CustodyCheckpointRecord)
                    .where(CustodyCheckpointRecord.case_id == case_id)
                    .order_by(
                        CustodyCheckpointRecord.created_at.desc(),
                        CustodyCheckpointRecord.id.desc(),
                    )
                )
            )

    def content(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        checkpoint_id: str,
    ) -> CustodyCheckpointContent:
        self._require_export_permission(principal)
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            record = session.get(CustodyCheckpointRecord, checkpoint_id)
            if record is None or record.case_id != case_id:
                raise CustodyCheckpointNotFoundError(
                    "The requested custody checkpoint does not exist in this case."
                )
            store = EvidenceStore(database.data_dir / "evidence")
            if not store.verify(record.storage_key, record.sha256):
                raise CustodyCheckpointIntegrityError(
                    "The custody checkpoint no longer matches its recorded SHA-256."
                )
            path = store.resolve(record.storage_key, require_file=True)
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="custody_checkpoint.downloaded",
                object_type="custody_checkpoint",
                object_id=checkpoint_id,
                detail={"sha256": record.sha256},
                created_at=datetime.now(UTC),
            )
            return CustodyCheckpointContent(record=record, path=path)

    @staticmethod
    def _require_export_permission(principal: Principal) -> None:
        if not (principal.can(Permission.CUSTODY_REVIEW) and principal.can(Permission.AUDIT_VIEW)):
            raise CaseAccessDeniedError(
                "Custody checkpoint export requires custody-review and audit-view permissions."
            )


def _custody_payload(record: CustodyEventRecord) -> dict[str, Any]:
    return {
        "actor_id": record.actor_id,
        "case_id": record.case_id,
        "created_at": _iso(record.created_at),
        "event_hash": record.event_hash,
        "event_type": record.event_type,
        "evidence_file_id": record.evidence_file_id,
        "evidence_source_id": record.evidence_source_id,
        "from_custodian": record.from_custodian,
        "id": record.id,
        "location": record.location,
        "notes": record.notes,
        "parser_run_id": record.parser_run_id,
        "previous_hash": record.previous_hash,
        "purpose": record.purpose,
        "related_event_id": record.related_event_id,
        "report_id": record.report_id,
        "sequence": record.sequence,
        "to_custodian": record.to_custodian,
    }


def _audit_payload(record: AuditLogRecord) -> dict[str, Any]:
    return {
        "actor_id": record.actor_id,
        "case_id": record.case_id,
        "created_at": _iso(record.created_at),
        "detail": json.loads(record.detail_json),
        "entry_hash": record.entry_hash,
        "event_type": record.event_type,
        "id": record.id,
        "object_id": record.object_id,
        "object_type": record.object_type,
        "previous_hash": record.previous_hash,
        "sequence": record.sequence,
    }


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _iso(value: datetime) -> str:
    current = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return current.isoformat()
