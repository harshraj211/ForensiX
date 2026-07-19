"""Deterministic, metadata-only artifact normalization and SQLite FTS5 search."""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseInvalidStateError, CaseService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionInventoryItemRecord,
    ArtifactRecord,
)

ARTIFACT_SCHEMA_VERSION = "1.0.0"
PARSER_ID = "generic_file_metadata"
PARSER_VERSION = "1.0.0"
ARTIFACT_CATEGORIES = frozenset({"image", "video", "audio", "document", "archive", "other"})
ARTIFACT_STATUSES = frozenset(
    {"active", "deleted", "recovered", "partial", "corrupted", "unverified"}
)

_MIME_BY_EXTENSION = {
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "gif": "image/gif",
    "webp": "image/webp",
    "heic": "image/heic",
    "heif": "image/heif",
    "mp4": "video/mp4",
    "mkv": "video/x-matroska",
    "webm": "video/webm",
    "mov": "video/quicktime",
    "3gp": "video/3gpp",
    "mp3": "audio/mpeg",
    "m4a": "audio/mp4",
    "aac": "audio/aac",
    "wav": "audio/wav",
    "ogg": "audio/ogg",
    "flac": "audio/flac",
    "pdf": "application/pdf",
    "txt": "text/plain",
    "csv": "text/csv",
    "json": "application/json",
    "xml": "application/xml",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt": "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "zip": "application/zip",
    "7z": "application/x-7z-compressed",
    "rar": "application/vnd.rar",
    "tar": "application/x-tar",
    "gz": "application/gzip",
}
_ARCHIVE_EXTENSIONS = frozenset({"zip", "7z", "rar", "tar", "gz"})
_DOCUMENT_EXTENSIONS = frozenset(
    {"pdf", "txt", "csv", "json", "xml", "doc", "docx", "xls", "xlsx", "ppt", "pptx"}
)


class ArtifactError(CaseInvalidStateError):
    code = "ARTIFACT_INVALID"


class ArtifactQueryError(ArtifactError):
    code = "ARTIFACT_QUERY_INVALID"


@dataclass(frozen=True, slots=True)
class ArtifactSearchResult:
    items: list[ArtifactRecord]
    total: int
    category_facets: dict[str, int]
    duplicate_counts: dict[str, int]


class ArtifactService:
    """Normalizes sealed file metadata without opening or parsing evidence content."""

    def ensure_search_index(self, session: Session) -> None:
        session.execute(
            text(
                "CREATE VIRTUAL TABLE IF NOT EXISTS artifact_search USING fts5("
                "artifact_id UNINDEXED, case_id UNINDEXED, title, summary, source_name, "
                "tokenize='unicode61 remove_diacritics 2')"
            )
        )

    def normalize_completed(
        self,
        session: Session,
        evidence: AcquiredEvidenceFileRecord,
        source_relative_path: str,
    ) -> ArtifactRecord:
        if (
            evidence.status != "completed"
            or evidence.size_bytes is None
            or evidence.sha256 is None
            or evidence.completed_at is None
        ):
            raise ArtifactError("Only a completed, hashed evidence file can be normalized.")
        self.ensure_search_index(session)
        existing = session.scalar(
            select(ArtifactRecord).where(ArtifactRecord.evidence_file_id == evidence.id)
        )
        if existing is not None:
            self._index(session, existing)
            return existing

        source = PurePosixPath(source_relative_path)
        title = source.name[:512] or "Unnamed acquired file"
        extension = source.suffix.lower().removeprefix(".")[:16] or None
        detected_mime = _MIME_BY_EXTENSION.get(extension or "", "application/octet-stream")
        category = _category(extension, detected_mime)
        inventory_item = session.get(AcquisitionInventoryItemRecord, evidence.inventory_item_id)
        if inventory_item is None:
            raise ArtifactError("The source inventory metadata is unavailable.")
        source_modified_at = (
            _aware_utc(inventory_item.modified_at)
            if inventory_item.modified_at is not None
            else None
        )
        provenance = {
            "acquired_by": evidence.acquired_by,
            "device_id": evidence.device_id,
            "evidence_file_id": evidence.id,
            "file_sha256": evidence.sha256,
            "inventory_id": evidence.inventory_id,
            "inventory_item_id": evidence.inventory_item_id,
            "job_id": evidence.job_id,
            "manifest_sha256": evidence.manifest_hash,
            "plan_id": evidence.plan_id,
            "source_path_hash": evidence.source_path_hash,
            "source_root_id": evidence.source_root_id,
            "storage_key": evidence.storage_key,
            "tool_version": evidence.tool_version,
            "validation_state": evidence.validation_state,
            "inventory_source_size_bytes": inventory_item.size_bytes,
            "source_modified_time_raw": inventory_item.modified_time_raw,
            "source_modified_at": (
                source_modified_at.isoformat() if source_modified_at is not None else None
            ),
            "source_timestamp_source": inventory_item.timestamp_source,
            "source_timestamp_confidence": inventory_item.timestamp_confidence,
        }
        metadata = {
            "classification_basis": "filename_extension_only",
            "content_parsed": False,
            "declared_extension": extension,
            "limitations": [
                "Media type was mapped from the filename extension and was not content-sniffed.",
                "No hostile evidence content was opened or rendered during normalization.",
                "Android stat modification time depends on the device clock and "
                "filesystem metadata.",
            ],
            "source_timestamp": {
                "original_epoch_seconds": inventory_item.modified_time_raw,
                "normalized_utc": (
                    source_modified_at.isoformat() if source_modified_at is not None else None
                ),
                "source": inventory_item.timestamp_source,
                "confidence": inventory_item.timestamp_confidence,
                "precision": "second" if inventory_item.modified_at is not None else None,
            },
            "inventory_size_matches_acquired_size": (
                inventory_item.size_bytes == evidence.size_bytes
                if inventory_item.size_bytes is not None
                else None
            ),
            "source_modified_after_collection": (
                source_modified_at > _aware_utc(evidence.completed_at)
                if source_modified_at is not None
                else None
            ),
        }
        artifact = ArtifactRecord(
            evidence_file_id=evidence.id,
            case_id=evidence.case_id,
            device_id=evidence.device_id,
            job_id=evidence.job_id,
            category=category,
            subtype="file",
            title=title,
            summary=f"{category.title()} file acquired from approved shared storage.",
            source_relative_path=source_relative_path,
            source_path_hash=evidence.source_path_hash,
            extension=extension,
            detected_mime=detected_mime,
            size_bytes=evidence.size_bytes,
            status="active",
            primary_sha256=evidence.sha256,
            parser_id=PARSER_ID,
            parser_version=PARSER_VERSION,
            timestamp_confidence="high",
            collected_at=evidence.completed_at,
            provenance_json=_canonical_json(provenance),
            metadata_json=_canonical_json(metadata),
            schema_version=ARTIFACT_SCHEMA_VERSION,
        )
        session.add(artifact)
        session.flush()
        self._index(session, artifact)
        return artifact

    def backfill_completed(self, session: Session) -> int:
        self.ensure_search_index(session)
        rows = session.execute(
            select(AcquiredEvidenceFileRecord, AcquisitionInventoryItemRecord.relative_path)
            .join(
                AcquisitionInventoryItemRecord,
                AcquisitionInventoryItemRecord.id == AcquiredEvidenceFileRecord.inventory_item_id,
            )
            .where(AcquiredEvidenceFileRecord.status == "completed")
        ).all()
        created = 0
        for evidence, source_relative_path in rows:
            existing = session.scalar(
                select(ArtifactRecord.id).where(ArtifactRecord.evidence_file_id == evidence.id)
            )
            self.normalize_completed(session, evidence, source_relative_path)
            created += existing is None
        session.flush()
        return created

    def search(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        query: str | None = None,
        category: str | None = None,
        status: str | None = None,
        extension: str | None = None,
        duplicate_only: bool = False,
        min_size: int | None = None,
        max_size: int | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> ArtifactSearchResult:
        CaseService().get(session, principal, case_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot analyze case evidence.")
        if category is not None and category not in ARTIFACT_CATEGORIES:
            raise ArtifactQueryError("The artifact category filter is unsupported.")
        if status is not None and status not in ARTIFACT_STATUSES:
            raise ArtifactQueryError("The artifact status filter is unsupported.")
        normalized_extension = _normalize_extension(extension)
        self.ensure_search_index(session)

        conditions = [ArtifactRecord.case_id == case_id]
        if category:
            conditions.append(ArtifactRecord.category == category)
        if status:
            conditions.append(ArtifactRecord.status == status)
        if normalized_extension:
            conditions.append(ArtifactRecord.extension == normalized_extension)
        if min_size is not None:
            conditions.append(ArtifactRecord.size_bytes >= min_size)
        if max_size is not None:
            conditions.append(ArtifactRecord.size_bytes <= max_size)
        if min_size is not None and max_size is not None and min_size > max_size:
            raise ArtifactQueryError("The minimum size cannot exceed the maximum size.")
        if duplicate_only:
            duplicate_hashes = (
                select(ArtifactRecord.primary_sha256)
                .where(ArtifactRecord.case_id == case_id)
                .group_by(ArtifactRecord.primary_sha256)
                .having(func.count(ArtifactRecord.id) > 1)
            )
            conditions.append(ArtifactRecord.primary_sha256.in_(duplicate_hashes))

        statement = select(ArtifactRecord).where(*conditions)
        count_statement = select(func.count(ArtifactRecord.id)).where(*conditions)
        if query and query.strip():
            compiled = _compile_fts_query(query)
            fts_filter = text(
                "artifacts.id IN (SELECT artifact_id FROM artifact_search "
                "WHERE artifact_search MATCH :artifact_query)"
            )
            statement = statement.where(fts_filter).params(artifact_query=compiled)
            count_statement = count_statement.where(fts_filter).params(artifact_query=compiled)
        items = list(
            session.scalars(
                statement.order_by(ArtifactRecord.collected_at.desc(), ArtifactRecord.id.desc())
                .offset(offset)
                .limit(limit)
            )
        )
        total = session.scalar(count_statement) or 0
        facets = {
            item_category: count
            for item_category, count in session.execute(
                select(ArtifactRecord.category, func.count(ArtifactRecord.id))
                .where(ArtifactRecord.case_id == case_id)
                .group_by(ArtifactRecord.category)
            ).all()
        }
        hashes = {item.primary_sha256 for item in items}
        duplicate_counts = {
            sha256: count
            for sha256, count in session.execute(
                select(ArtifactRecord.primary_sha256, func.count(ArtifactRecord.id))
                .where(
                    ArtifactRecord.case_id == case_id,
                    ArtifactRecord.primary_sha256.in_(hashes),
                )
                .group_by(ArtifactRecord.primary_sha256)
            ).all()
        }
        return ArtifactSearchResult(
            items=items,
            total=total,
            category_facets=facets,
            duplicate_counts=duplicate_counts,
        )

    def duplicate_count(self, session: Session, case_id: str, sha256: str) -> int:
        return int(
            session.scalar(
                select(func.count(ArtifactRecord.id)).where(
                    ArtifactRecord.case_id == case_id,
                    ArtifactRecord.primary_sha256 == sha256,
                )
            )
            or 0
        )

    def get(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        artifact_id: str,
    ) -> ArtifactRecord:
        CaseService().get(session, principal, case_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot analyze case evidence.")
        artifact = session.get(ArtifactRecord, artifact_id)
        if artifact is None or artifact.case_id != case_id:
            raise ArtifactError("The requested artifact is not available in this case.")
        return artifact

    def _index(self, session: Session, artifact: ArtifactRecord) -> None:
        session.execute(
            text("DELETE FROM artifact_search WHERE artifact_id = :artifact_id"),
            {"artifact_id": artifact.id},
        )
        session.execute(
            text(
                "INSERT INTO artifact_search "
                "(artifact_id, case_id, title, summary, source_name) "
                "VALUES (:artifact_id, :case_id, :title, :summary, :source_name)"
            ),
            {
                "artifact_id": artifact.id,
                "case_id": artifact.case_id,
                "title": artifact.title,
                "summary": artifact.summary,
                "source_name": artifact.source_relative_path,
            },
        )


def _category(extension: str | None, detected_mime: str) -> str:
    if extension in _ARCHIVE_EXTENSIONS:
        return "archive"
    if extension in _DOCUMENT_EXTENSIONS:
        return "document"
    for prefix in ("image", "video", "audio"):
        if detected_mime.startswith(f"{prefix}/"):
            return prefix
    return "other"


def _normalize_extension(extension: str | None) -> str | None:
    if extension is None or not extension.strip():
        return None
    normalized = extension.strip().lower().removeprefix(".")
    if not re.fullmatch(r"[a-z0-9]{1,16}", normalized):
        raise ArtifactQueryError("The artifact extension filter is invalid.")
    return normalized


def _compile_fts_query(query: str) -> str:
    if len(query) > 256:
        raise ArtifactQueryError("The evidence search query cannot exceed 256 characters.")
    terms = re.findall(r"\w+", query.lower(), flags=re.UNICODE)
    if not terms:
        raise ArtifactQueryError("The evidence search query must contain searchable text.")
    if len(terms) > 8 or any(len(term) > 64 for term in terms):
        raise ArtifactQueryError("The evidence search query is too complex.")
    return " AND ".join(f'"{term}"' for term in terms)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
