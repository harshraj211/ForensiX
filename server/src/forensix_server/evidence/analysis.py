"""Case-authorized annotations kept separate from immutable source artifacts."""

import re
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError
from forensix_server.custody import AuditService
from forensix_server.db import (
    AnalystNoteRecord,
    ArtifactRecord,
    ArtifactTagRecord,
    BookmarkRecord,
    TagRecord,
)

from .service import ArtifactError, ArtifactService


class AnalysisService:
    def bookmark(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        artifact_id: str,
        *,
        reason: str | None = None,
    ) -> BookmarkRecord:
        artifact = self._writable_artifact(session, principal, case_id, artifact_id)
        normalized_reason = _optional_text(reason, 1000)
        record = session.scalar(
            select(BookmarkRecord).where(
                BookmarkRecord.artifact_id == artifact.id,
                BookmarkRecord.user_id == principal.user_id,
            )
        )
        now = datetime.now(UTC)
        if record is None:
            record = BookmarkRecord(
                artifact_id=artifact.id,
                case_id=case_id,
                user_id=principal.user_id,
                reason=normalized_reason,
                created_at=now,
            )
            session.add(record)
        else:
            record.reason = normalized_reason
            record.removed_at = None
        self._audit(session, principal, artifact, "artifact_bookmarked", now)
        session.flush()
        return record

    def remove_bookmark(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        artifact_id: str,
    ) -> BookmarkRecord | None:
        artifact = self._writable_artifact(session, principal, case_id, artifact_id)
        record = session.scalar(
            select(BookmarkRecord).where(
                BookmarkRecord.artifact_id == artifact.id,
                BookmarkRecord.user_id == principal.user_id,
            )
        )
        if record is None or record.removed_at is not None:
            return record
        now = datetime.now(UTC)
        record.removed_at = now
        self._audit(session, principal, artifact, "artifact_bookmark_removed", now)
        session.flush()
        return record

    def add_tag(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        artifact_id: str,
        name: str,
    ) -> TagRecord:
        artifact = self._writable_artifact(session, principal, case_id, artifact_id)
        display_name, normalized = _tag_name(name)
        tag = session.scalar(
            select(TagRecord).where(
                TagRecord.case_id == case_id,
                TagRecord.normalized_name == normalized,
            )
        )
        now = datetime.now(UTC)
        if tag is None:
            tag = TagRecord(
                case_id=case_id,
                name=display_name,
                normalized_name=normalized,
                created_by=principal.user_id,
                created_at=now,
            )
            session.add(tag)
            session.flush()
        association = session.scalar(
            select(ArtifactTagRecord).where(
                ArtifactTagRecord.artifact_id == artifact.id,
                ArtifactTagRecord.tag_id == tag.id,
            )
        )
        if association is None:
            session.add(
                ArtifactTagRecord(
                    artifact_id=artifact.id,
                    tag_id=tag.id,
                    added_by=principal.user_id,
                    created_at=now,
                )
            )
            self._audit(
                session,
                principal,
                artifact,
                "artifact_tag_added",
                now,
                {"tag": normalized},
            )
        session.flush()
        return tag

    def add_note(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        artifact_id: str,
        body: str,
        *,
        supersedes_id: str | None = None,
    ) -> AnalystNoteRecord:
        artifact = self._writable_artifact(session, principal, case_id, artifact_id)
        normalized_body = _required_text(body, 4000)
        if supersedes_id:
            superseded = session.get(AnalystNoteRecord, supersedes_id)
            if superseded is None or superseded.artifact_id != artifact.id:
                raise ArtifactError("The superseded note does not belong to this artifact.")
        now = datetime.now(UTC)
        note = AnalystNoteRecord(
            artifact_id=artifact.id,
            case_id=case_id,
            author_id=principal.user_id,
            body=normalized_body,
            supersedes_id=supersedes_id,
            created_at=now,
        )
        session.add(note)
        session.flush()
        self._audit(
            session,
            principal,
            artifact,
            "analyst_note_amended" if supersedes_id else "analyst_note_added",
            now,
            {"note_id": note.id, "supersedes_id": supersedes_id},
        )
        session.flush()
        return note

    def annotations(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        artifact_id: str,
    ) -> tuple[BookmarkRecord | None, list[TagRecord], list[AnalystNoteRecord]]:
        artifact = ArtifactService().get(session, principal, case_id, artifact_id)
        bookmark = session.scalar(
            select(BookmarkRecord).where(
                BookmarkRecord.artifact_id == artifact.id,
                BookmarkRecord.user_id == principal.user_id,
                BookmarkRecord.removed_at.is_(None),
            )
        )
        tags = list(
            session.scalars(
                select(TagRecord)
                .join(ArtifactTagRecord, ArtifactTagRecord.tag_id == TagRecord.id)
                .where(ArtifactTagRecord.artifact_id == artifact.id)
                .order_by(TagRecord.normalized_name)
            )
        )
        notes = list(
            session.scalars(
                select(AnalystNoteRecord)
                .where(AnalystNoteRecord.artifact_id == artifact.id)
                .order_by(AnalystNoteRecord.created_at, AnalystNoteRecord.id)
            )
        )
        return bookmark, tags, notes

    @staticmethod
    def _writable_artifact(
        session: Session, principal: Principal, case_id: str, artifact_id: str
    ) -> ArtifactRecord:
        artifact = ArtifactService().get(session, principal, case_id, artifact_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot annotate evidence.")
        return artifact

    @staticmethod
    def _audit(
        session: Session,
        principal: Principal,
        artifact: ArtifactRecord,
        event_type: str,
        created_at: datetime,
        detail: dict[str, object] | None = None,
    ) -> None:
        AuditService().append(
            session,
            case_id=artifact.case_id,
            actor_id=principal.user_id,
            event_type=event_type,
            object_type="artifact",
            object_id=artifact.id,
            detail=detail or {},
            created_at=created_at,
        )


def _required_text(value: str, limit: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > limit:
        raise ArtifactError(f"Text must contain 1 to {limit} characters.")
    return normalized


def _optional_text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if len(normalized) > limit:
        raise ArtifactError(f"Text cannot exceed {limit} characters.")
    return normalized or None


def _tag_name(value: str) -> tuple[str, str]:
    display = " ".join(value.strip().split())
    normalized = display.casefold()
    if not display or len(display) > 64 or not re.fullmatch(r"[\w .-]+", display, re.UNICODE):
        raise ArtifactError("Tags must contain 1 to 64 letters, numbers, spaces, dots, or dashes.")
    return display, normalized
