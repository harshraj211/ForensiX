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
    TimelineEventRecord,
)

TIMELINE_BUILDER_VERSION = "1.1.0"


@dataclass(frozen=True, slots=True)
class TimelineSearchResult:
    items: list[TimelineEventRecord]
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
        if category:
            conditions.append(TimelineEventRecord.category == category)
        if confidence:
            conditions.append(TimelineEventRecord.confidence == confidence)
        if from_time:
            conditions.append(TimelineEventRecord.event_time >= _aware_utc(from_time))
        if to_time:
            conditions.append(TimelineEventRecord.event_time <= _aware_utc(to_time))
        items = list(
            session.scalars(
                select(TimelineEventRecord)
                .where(*conditions)
                .order_by(TimelineEventRecord.event_time.desc(), TimelineEventRecord.id.desc())
                .offset(offset)
                .limit(limit)
            )
        )
        total = session.scalar(select(func.count(TimelineEventRecord.id)).where(*conditions)) or 0
        facets = {
            category_name: count
            for category_name, count in session.execute(
                select(TimelineEventRecord.category, func.count(TimelineEventRecord.id))
                .where(TimelineEventRecord.case_id == case_id)
                .group_by(TimelineEventRecord.category)
            ).all()
        }
        return TimelineSearchResult(items=items, total=total, category_facets=facets)


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
