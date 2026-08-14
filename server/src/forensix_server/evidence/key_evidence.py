"""Unified, auditable findings board across both normalized artifact families."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.custody import AuditService
from forensix_server.db import (
    AnalystNoteRecord,
    ArtifactRecord,
    ArtifactTagRecord,
    EvidenceSourceArtifactRecord,
    KeyEvidenceRecord,
    TagRecord,
)

from .service import ArtifactError

KeyEvidenceTargetType = Literal["artifact", "source_artifact"]
KeyEvidencePriority = Literal["critical", "high", "normal"]


@dataclass(frozen=True, slots=True)
class KeyEvidenceItem:
    id: str
    case_id: str
    target_type: KeyEvidenceTargetType
    target_id: str
    category: str
    subtype: str
    title: str
    summary: str
    source_locator: str
    status: str
    confidence: str
    event_time: datetime | None
    integrity_hash: str
    parser_id: str
    parser_version: str
    size_bytes: int | None
    priority: KeyEvidencePriority
    reason: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    tags: list[str]
    note_count: int
    latest_note: str | None


@dataclass(frozen=True, slots=True)
class KeyEvidenceList:
    items: list[KeyEvidenceItem]
    total: int
    priority_counts: dict[str, int]
    category_facets: dict[str, int]


class KeyEvidenceService:
    def list(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        query: str | None = None,
        priority: KeyEvidencePriority | None = None,
        category: str | None = None,
    ) -> KeyEvidenceList:
        CaseService().get(session, principal, case_id)
        normalized_query = query.strip().casefold() if query else None
        records = list(
            session.scalars(
                select(KeyEvidenceRecord)
                .where(
                    KeyEvidenceRecord.case_id == case_id,
                    KeyEvidenceRecord.removed_at.is_(None),
                )
                .order_by(KeyEvidenceRecord.updated_at.desc(), KeyEvidenceRecord.id)
            )
        )
        items = [self._hydrate(session, record) for record in records]
        if priority:
            items = [item for item in items if item.priority == priority]
        if category:
            items = [item for item in items if item.category == category]
        if normalized_query:
            items = [
                item
                for item in items
                if normalized_query
                in " ".join(
                    (
                        item.title,
                        item.summary,
                        item.reason or "",
                        item.source_locator,
                        " ".join(item.tags),
                        item.latest_note or "",
                    )
                ).casefold()
            ]
        items.sort(key=lambda item: (_priority_rank(item.priority), -_timestamp(item.updated_at)))
        priority_counts: dict[str, int] = {"critical": 0, "high": 0, "normal": 0}
        category_facets: dict[str, int] = {}
        for item in items:
            priority_counts[item.priority] += 1
            category_facets[item.category] = category_facets.get(item.category, 0) + 1
        return KeyEvidenceList(
            items=items,
            total=len(items),
            priority_counts=priority_counts,
            category_facets=dict(
                sorted(category_facets.items(), key=lambda entry: (-entry[1], entry[0]))
            ),
        )

    def promote(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        target_type: KeyEvidenceTargetType,
        target_id: str,
        priority: KeyEvidencePriority,
        reason: str | None,
    ) -> KeyEvidenceItem:
        self._require_write(session, principal, case_id)
        self._target(session, case_id, target_type, target_id)
        target_column = (
            KeyEvidenceRecord.artifact_id
            if target_type == "artifact"
            else KeyEvidenceRecord.source_artifact_id
        )
        record = session.scalar(select(KeyEvidenceRecord).where(target_column == target_id))
        now = datetime.now(UTC)
        normalized_reason = _optional_text(reason, 2000)
        if record is None:
            record = KeyEvidenceRecord(
                case_id=case_id,
                target_type=target_type,
                artifact_id=target_id if target_type == "artifact" else None,
                source_artifact_id=target_id if target_type == "source_artifact" else None,
                created_by=principal.user_id,
                priority=priority,
                reason=normalized_reason,
                created_at=now,
                updated_at=now,
            )
            session.add(record)
        else:
            if record.case_id != case_id or record.target_type != target_type:
                raise ArtifactError("The key-evidence target belongs to another case.")
            record.created_by = principal.user_id
            record.priority = priority
            record.reason = normalized_reason
            record.updated_at = now
            record.removed_at = None
        session.flush()
        self._audit(
            session,
            principal,
            case_id,
            record,
            "key_evidence_promoted",
            now,
            {"priority": priority, "target_type": target_type},
        )
        session.flush()
        return self._hydrate(session, record)

    def remove(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        finding_id: str,
    ) -> None:
        self._require_write(session, principal, case_id)
        record = session.get(KeyEvidenceRecord, finding_id)
        if record is None or record.case_id != case_id:
            raise ArtifactError("The requested key-evidence finding does not exist.")
        if record.removed_at is not None:
            return
        now = datetime.now(UTC)
        record.removed_at = now
        record.updated_at = now
        self._audit(
            session,
            principal,
            case_id,
            record,
            "key_evidence_removed",
            now,
            {"target_type": record.target_type},
        )
        session.flush()

    @staticmethod
    def _require_write(session: Session, principal: Principal, case_id: str) -> None:
        CaseService().get(session, principal, case_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot curate key evidence.")

    @staticmethod
    def _target(
        session: Session,
        case_id: str,
        target_type: KeyEvidenceTargetType,
        target_id: str,
    ) -> ArtifactRecord | EvidenceSourceArtifactRecord:
        target: ArtifactRecord | EvidenceSourceArtifactRecord | None
        if target_type == "artifact":
            target = session.get(ArtifactRecord, target_id)
        else:
            target = session.get(EvidenceSourceArtifactRecord, target_id)
        if target is None or target.case_id != case_id:
            raise ArtifactError("The selected key-evidence target does not exist in this case.")
        return target

    def _hydrate(self, session: Session, record: KeyEvidenceRecord) -> KeyEvidenceItem:
        target_id = record.artifact_id or record.source_artifact_id
        if target_id is None:
            raise ArtifactError("The key-evidence target reference is invalid.")
        target_type = cast(KeyEvidenceTargetType, record.target_type)
        target = self._target(session, record.case_id, target_type, target_id)
        tags: list[str] = []
        note_count = 0
        latest_note: str | None = None
        event_time: datetime | None
        if isinstance(target, ArtifactRecord):
            tags = list(
                session.scalars(
                    select(TagRecord.name)
                    .join(ArtifactTagRecord, ArtifactTagRecord.tag_id == TagRecord.id)
                    .where(ArtifactTagRecord.artifact_id == target.id)
                    .order_by(TagRecord.normalized_name)
                )
            )
            notes = list(
                session.scalars(
                    select(AnalystNoteRecord)
                    .where(AnalystNoteRecord.artifact_id == target.id)
                    .order_by(AnalystNoteRecord.created_at.desc(), AnalystNoteRecord.id.desc())
                )
            )
            note_count = len(notes)
            latest_note = notes[0].body if notes else None
            category = target.category
            subtype = target.subtype
            title = target.title
            summary = target.summary
            source_locator = target.source_relative_path
            status = target.status
            confidence = target.timestamp_confidence
            event_time = target.collected_at
            integrity_hash = target.primary_sha256
            parser_id = target.parser_id
            parser_version = target.parser_version
            size_bytes = target.size_bytes
        else:
            category = target.category
            subtype = target.subtype
            title = target.title
            summary = target.summary
            source_locator = target.source_locator
            status = target.status
            confidence = target.confidence
            event_time = target.event_time
            integrity_hash = target.artifact_hash
            parser_id = target.parser_id
            parser_version = target.parser_version
            size_bytes = None
        return KeyEvidenceItem(
            id=record.id,
            case_id=record.case_id,
            target_type=target_type,
            target_id=target_id,
            category=category,
            subtype=subtype,
            title=title,
            summary=summary,
            source_locator=source_locator,
            status=status,
            confidence=confidence,
            event_time=event_time,
            integrity_hash=integrity_hash,
            parser_id=parser_id,
            parser_version=parser_version,
            size_bytes=size_bytes,
            priority=cast(KeyEvidencePriority, record.priority),
            reason=record.reason,
            created_by=record.created_by,
            created_at=record.created_at,
            updated_at=record.updated_at,
            tags=tags,
            note_count=note_count,
            latest_note=latest_note,
        )

    @staticmethod
    def _audit(
        session: Session,
        principal: Principal,
        case_id: str,
        record: KeyEvidenceRecord,
        event_type: str,
        created_at: datetime,
        detail: dict[str, object],
    ) -> None:
        AuditService().append(
            session,
            case_id=case_id,
            actor_id=principal.user_id,
            event_type=event_type,
            object_type="key_evidence",
            object_id=record.id,
            detail=detail,
            created_at=created_at,
        )


def _optional_text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    normalized = " ".join(value.strip().split())
    if len(normalized) > limit:
        raise ArtifactError(f"Text cannot exceed {limit} characters.")
    return normalized or None


def _priority_rank(priority: KeyEvidencePriority) -> int:
    return {"critical": 0, "high": 1, "normal": 2}[priority]


def _timestamp(value: datetime) -> float:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.timestamp()
