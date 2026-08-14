"""Deterministic timeline materialization from explicit normalized timestamp claims."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionInventoryItemRecord,
    ArtifactRecord,
    EvidenceSourceArtifactRecord,
    EvidenceSourceTimelineEventRecord,
    MediaAnalysisRecord,
    TimelineEventRecord,
)

TIMELINE_BUILDER_VERSION = "1.1.0"
MEDIA_CAPTURE_TIMESTAMP_TYPE = "media_exif_captured_at"


@dataclass(frozen=True, slots=True)
class TimelineSearchResult:
    items: list[TimelineEventRecord | EvidenceSourceTimelineEventRecord]
    total: int
    category_facets: dict[str, int]


class TimelineService:
    """Materializes only known claims; it never invents device-side file times."""

    def materialize(self, session: Session, artifact: ArtifactRecord) -> TimelineEventRecord:
        existing = session.scalar(
            select(TimelineEventRecord).where(
                TimelineEventRecord.artifact_id == artifact.id,
                TimelineEventRecord.timestamp_type == "acquisition_collected_at",
            )
        )
        if existing is not None:
            self._materialize_source_modified(session, artifact)
            return existing
        event_time = _aware_utc(artifact.collected_at)
        category = "media" if artifact.category in {"image", "video", "audio"} else "file"
        summary = f"ForensiX collected {artifact.title}."
        payload = {
            "artifact_id": artifact.id,
            "builder_version": TIMELINE_BUILDER_VERSION,
            "case_id": artifact.case_id,
            "category": category,
            "confidence": "high",
            "event_time": event_time.isoformat(),
            "job_id": artifact.job_id,
            "original_time": event_time.isoformat(),
            "precision": "microsecond",
            "summary": summary,
            "timestamp_type": "acquisition_collected_at",
            "timezone_basis": "UTC recorded by acquisition workstation",
        }
        record = TimelineEventRecord(
            case_id=artifact.case_id,
            artifact_id=artifact.id,
            job_id=artifact.job_id,
            category=category,
            timestamp_type="acquisition_collected_at",
            event_time=event_time,
            original_time=event_time.isoformat(),
            timezone_basis="UTC recorded by acquisition workstation",
            precision="microsecond",
            confidence="high",
            summary=summary,
            builder_version=TIMELINE_BUILDER_VERSION,
            event_hash=sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
        )
        session.add(record)
        session.flush()
        self._materialize_source_modified(session, artifact)
        return record

    def materialize_source_artifact(
        self, session: Session, artifact: EvidenceSourceArtifactRecord
    ) -> EvidenceSourceTimelineEventRecord | None:
        """Materialize a parser timestamp without pretending it came from ADB acquisition."""
        if artifact.event_time is None:
            return None
        existing = session.scalar(
            select(EvidenceSourceTimelineEventRecord).where(
                EvidenceSourceTimelineEventRecord.source_artifact_id == artifact.id,
                EvidenceSourceTimelineEventRecord.timestamp_type == "parsed_artifact_event_time",
            )
        )
        if existing is not None:
            return existing
        event_time = _aware_utc(artifact.event_time)
        category = _source_category(artifact.category)
        summary = f"{artifact.title}: {artifact.summary}"
        payload = {
            "builder_version": TIMELINE_BUILDER_VERSION,
            "case_id": artifact.case_id,
            "category": category,
            "confidence": artifact.confidence,
            "event_time": event_time.isoformat(),
            "parser_run_id": artifact.parser_run_id,
            "source_artifact_id": artifact.id,
            "summary": summary,
            "timestamp_type": "parsed_artifact_event_time",
            "timezone_basis": "UTC normalized by the versioned artifact parser",
        }
        record = EvidenceSourceTimelineEventRecord(
            case_id=artifact.case_id,
            source_artifact_id=artifact.id,
            parser_run_id=artifact.parser_run_id,
            category=category,
            timestamp_type="parsed_artifact_event_time",
            event_time=event_time,
            original_time=event_time.isoformat(),
            timezone_basis="UTC normalized by the versioned artifact parser",
            precision="second",
            confidence=artifact.confidence,
            summary=summary[:1000],
            builder_version=TIMELINE_BUILDER_VERSION,
            event_hash=sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
        )
        session.add(record)
        session.flush()
        return record

    def materialize_media_capture(
        self,
        session: Session,
        artifact: ArtifactRecord,
        media: MediaAnalysisRecord,
    ) -> TimelineEventRecord | None:
        """Materialize an EXIF capture-time event only when the raw string parses cleanly.

        EXIF timestamps carry no timezone offset, so the event is marked confidence=low
        and timezone_basis states the ambiguity explicitly. Returns None when
        captured_at_raw is absent or unparseable — never invents a time.
        """
        if media.captured_at_raw is None:
            return None
        event_time = _parse_exif_datetime(media.captured_at_raw)
        if event_time is None:
            return None
        existing = session.scalar(
            select(TimelineEventRecord).where(
                TimelineEventRecord.artifact_id == artifact.id,
                TimelineEventRecord.timestamp_type == MEDIA_CAPTURE_TIMESTAMP_TYPE,
            )
        )
        if existing is not None:
            return existing
        summary = f"EXIF capture time recorded in {artifact.title}."
        payload = {
            "artifact_id": artifact.id,
            "builder_version": TIMELINE_BUILDER_VERSION,
            "case_id": artifact.case_id,
            "category": "media",
            "confidence": "low",
            "event_time": event_time.isoformat(),
            "job_id": artifact.job_id,
            "original_time": media.captured_at_raw,
            "precision": "second",
            "summary": summary,
            "timestamp_type": MEDIA_CAPTURE_TIMESTAMP_TYPE,
            "timezone_basis": "UTC assumed; EXIF timestamp carries no timezone offset",
        }
        record = TimelineEventRecord(
            case_id=artifact.case_id,
            artifact_id=artifact.id,
            job_id=artifact.job_id,
            category="media",
            timestamp_type=MEDIA_CAPTURE_TIMESTAMP_TYPE,
            event_time=event_time,
            original_time=media.captured_at_raw,
            timezone_basis="UTC assumed; EXIF timestamp carries no timezone offset",
            precision="second",
            confidence="low",
            summary=summary,
            builder_version=TIMELINE_BUILDER_VERSION,
            event_hash=sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
        )
        session.add(record)
        session.flush()
        return record

    @staticmethod
    def _materialize_source_modified(
        session: Session, artifact: ArtifactRecord
    ) -> TimelineEventRecord | None:
        existing = session.scalar(
            select(TimelineEventRecord).where(
                TimelineEventRecord.artifact_id == artifact.id,
                TimelineEventRecord.timestamp_type == "source_file_modified_at",
            )
        )
        if existing is not None:
            return existing
        evidence = session.get(AcquiredEvidenceFileRecord, artifact.evidence_file_id)
        item = (
            session.get(AcquisitionInventoryItemRecord, evidence.inventory_item_id)
            if evidence is not None
            else None
        )
        if (
            item is None
            or item.modified_at is None
            or item.modified_time_raw is None
            or item.timestamp_source != "android_stat_mtime_epoch"
        ):
            return None
        event_time = _aware_utc(item.modified_at)
        category = "media" if artifact.category in {"image", "video", "audio"} else "file"
        source_after_collection = event_time > _aware_utc(artifact.collected_at)
        confidence = "low" if source_after_collection else item.timestamp_confidence or "medium"
        summary = f"Android shared storage reported {artifact.title} as modified."
        if source_after_collection:
            summary += (
                " The source time is after workstation collection and may reflect clock skew."
            )
        payload = {
            "artifact_id": artifact.id,
            "builder_version": TIMELINE_BUILDER_VERSION,
            "case_id": artifact.case_id,
            "category": category,
            "confidence": confidence,
            "event_time": event_time.isoformat(),
            "job_id": artifact.job_id,
            "original_time": item.modified_time_raw,
            "precision": "second",
            "summary": summary,
            "timestamp_type": "source_file_modified_at",
            "timezone_basis": "UTC derived from Unix epoch reported by Android stat",
        }
        record = TimelineEventRecord(
            case_id=artifact.case_id,
            artifact_id=artifact.id,
            job_id=artifact.job_id,
            category=category,
            timestamp_type="source_file_modified_at",
            event_time=event_time,
            original_time=item.modified_time_raw,
            timezone_basis="UTC derived from Unix epoch reported by Android stat",
            precision="second",
            confidence=confidence,
            summary=summary,
            builder_version=TIMELINE_BUILDER_VERSION,
            event_hash=sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
        )
        session.add(record)
        session.flush()
        return record

    def backfill(self, session: Session) -> int:
        artifacts = list(session.scalars(select(ArtifactRecord)))
        created = 0
        for artifact in artifacts:
            exists = session.scalar(
                select(TimelineEventRecord.id).where(
                    TimelineEventRecord.artifact_id == artifact.id,
                    TimelineEventRecord.timestamp_type == "acquisition_collected_at",
                )
            )
            self.materialize(session, artifact)
            created += exists is None
        source_artifacts = list(session.scalars(select(EvidenceSourceArtifactRecord)))
        for source_artifact in source_artifacts:
            if source_artifact.event_time is None:
                continue
            exists = session.scalar(
                select(EvidenceSourceTimelineEventRecord.id).where(
                    EvidenceSourceTimelineEventRecord.source_artifact_id == source_artifact.id,
                    EvidenceSourceTimelineEventRecord.timestamp_type
                    == "parsed_artifact_event_time",
                )
            )
            self.materialize_source_artifact(session, source_artifact)
            created += exists is None
        analyses = list(
            session.scalars(
                select(MediaAnalysisRecord).where(
                    MediaAnalysisRecord.status == "analyzed",
                    MediaAnalysisRecord.captured_at_raw.is_not(None),
                )
            )
        )
        for media in analyses:
            media_artifact = session.get(ArtifactRecord, media.artifact_id)
            if media_artifact is None:
                continue
            exists = session.scalar(
                select(TimelineEventRecord.id).where(
                    TimelineEventRecord.artifact_id == media.artifact_id,
                    TimelineEventRecord.timestamp_type == MEDIA_CAPTURE_TIMESTAMP_TYPE,
                )
            )
            self.materialize_media_capture(session, media_artifact, media)
            created += exists is None
        return created

    def search(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        category: str | None = None,
        confidence: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> TimelineSearchResult:
        CaseService().get(session, principal, case_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot analyze the case timeline.")
        conditions = [TimelineEventRecord.case_id == case_id]
        source_conditions = [EvidenceSourceTimelineEventRecord.case_id == case_id]
        if category:
            conditions.append(TimelineEventRecord.category == category)
            source_conditions.append(EvidenceSourceTimelineEventRecord.category == category)
        if confidence:
            conditions.append(TimelineEventRecord.confidence == confidence)
            source_conditions.append(EvidenceSourceTimelineEventRecord.confidence == confidence)
        if from_time:
            conditions.append(TimelineEventRecord.event_time >= _aware_utc(from_time))
            source_conditions.append(
                EvidenceSourceTimelineEventRecord.event_time >= _aware_utc(from_time)
            )
        if to_time:
            conditions.append(TimelineEventRecord.event_time <= _aware_utc(to_time))
            source_conditions.append(
                EvidenceSourceTimelineEventRecord.event_time <= _aware_utc(to_time)
            )
        combined: list[TimelineEventRecord | EvidenceSourceTimelineEventRecord] = [
            *session.scalars(select(TimelineEventRecord).where(*conditions)),
            *session.scalars(select(EvidenceSourceTimelineEventRecord).where(*source_conditions)),
        ]
        combined.sort(
            key=lambda item: (_aware_utc(item.event_time), item.id),
            reverse=True,
        )
        facets: dict[str, int] = {}
        for model in (TimelineEventRecord, EvidenceSourceTimelineEventRecord):
            for category_name, count in session.execute(
                select(model.category, func.count(model.id))
                .where(model.case_id == case_id)
                .group_by(model.category)
            ).all():
                facets[category_name] = facets.get(category_name, 0) + count
        return TimelineSearchResult(
            items=combined[offset : offset + limit],
            total=len(combined),
            category_facets=facets,
        )


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_exif_datetime(raw: str) -> datetime | None:
    """Parse the EXIF 'YYYY:MM:DD HH:MM:SS' form; return None on any deviation.

    EXIF times have no timezone; the parsed value is tagged UTC by convention with the
    ambiguity recorded in the event's timezone_basis. Anything not matching the exact
    EXIF grammar yields None so no timestamp is invented.
    """
    candidate = raw.strip()
    try:
        parsed = datetime.strptime(candidate, "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _source_category(category: str) -> str:
    return {
        "contact": "communication",
        "communication": "communication",
        "application": "application",
        "location": "location",
        "system": "system",
        "file": "file",
    }.get(category, "system")
