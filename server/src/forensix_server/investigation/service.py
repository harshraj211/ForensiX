"""Read-only aggregation for the case investigation command center."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from forensix_server.auth import Principal
from forensix_server.cases import CaseService
from forensix_server.custody import CustodyService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    ArtifactRecord,
    BookmarkRecord,
    CaseDeviceRecord,
    CaseEventRecord,
    CustodyEventRecord,
    EvidenceSourceArtifactRecord,
    EvidenceSourceRecord,
    EvidenceSourceTimelineEventRecord,
    EvidenceSourceVerificationRecord,
    EvidenceVerificationRecord,
    JobRecord,
    KeyEvidenceRecord,
    ReportRecord,
    ReportReviewEventRecord,
    TimelineEventRecord,
)

AttentionSeverity = Literal["critical", "warning", "info"]
ActivityKind = Literal["case", "acquisition", "custody", "evidence", "report"]
NextAction = Literal[
    "detect_device",
    "create_acquisition_plan",
    "monitor_acquisition",
    "acquire_evidence",
    "index_evidence",
    "review_evidence",
    "generate_report",
    "review_report",
    "continue_analysis",
]

ACTIVE_JOB_STATES = ("created", "validating", "ready", "running", "paused", "cancelling")
ATTENTION_JOB_STATES = ("interrupted", "failed")
COMPLETED_JOB_STATES = ("completed", "verified")


@dataclass(frozen=True, slots=True)
class CommandCenterJobs:
    total: int
    active: int
    completed: int
    attention_required: int


@dataclass(frozen=True, slots=True)
class CommandCenterEvidence:
    acquired_files: int
    sealed_sources: int
    normalized_artifacts: int
    imported_artifacts: int
    total_artifacts: int
    total_size_bytes: int
    bookmarked_artifacts: int
    category_facets: dict[str, int]


@dataclass(frozen=True, slots=True)
class CommandCenterIntegrity:
    custody_chain_valid: bool
    custody_event_count: int
    verification_exceptions: int
    verified_observations: int


@dataclass(frozen=True, slots=True)
class CommandCenterAttention:
    code: str
    severity: AttentionSeverity
    title: str
    detail: str


@dataclass(frozen=True, slots=True)
class CommandCenterActivity:
    kind: ActivityKind
    title: str
    detail: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class CommandCenterSummary:
    case_id: str
    generated_at: datetime
    device_count: int
    jobs: CommandCenterJobs
    evidence: CommandCenterEvidence
    integrity: CommandCenterIntegrity
    timeline_event_count: int
    report_count: int
    reports_pending_review: int
    next_action: NextAction
    attention: list[CommandCenterAttention]
    recent_activity: list[CommandCenterActivity]


class InvestigationCommandCenterService:
    """Build a truthful, case-authorized operational summary from persisted records."""

    def summarize(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
    ) -> CommandCenterSummary:
        case = CaseService().get(session, principal, case_id)
        device_count = _count(session, CaseDeviceRecord, CaseDeviceRecord.case_id == case_id)

        job_total = _count(session, JobRecord, JobRecord.case_id == case_id)
        active_jobs = _count(
            session,
            JobRecord,
            JobRecord.case_id == case_id,
            JobRecord.state.in_(ACTIVE_JOB_STATES),
        )
        completed_jobs = _count(
            session,
            JobRecord,
            JobRecord.case_id == case_id,
            JobRecord.state.in_(COMPLETED_JOB_STATES),
        )
        attention_jobs = _count(
            session,
            JobRecord,
            JobRecord.case_id == case_id,
            JobRecord.state.in_(ATTENTION_JOB_STATES),
        )

        acquired_files = _count(
            session,
            AcquiredEvidenceFileRecord,
            AcquiredEvidenceFileRecord.case_id == case_id,
            AcquiredEvidenceFileRecord.status == "completed",
        )
        sealed_sources = _count(
            session,
            EvidenceSourceRecord,
            EvidenceSourceRecord.case_id == case_id,
            EvidenceSourceRecord.status == "sealed",
        )
        normalized_artifacts = _count(
            session,
            ArtifactRecord,
            ArtifactRecord.case_id == case_id,
        )
        imported_artifacts = _count(
            session,
            EvidenceSourceArtifactRecord,
            EvidenceSourceArtifactRecord.case_id == case_id,
        )
        total_size = int(
            session.scalar(
                select(func.coalesce(func.sum(AcquiredEvidenceFileRecord.size_bytes), 0)).where(
                    AcquiredEvidenceFileRecord.case_id == case_id,
                    AcquiredEvidenceFileRecord.status == "completed",
                )
            )
            or 0
        )
        total_size += int(
            session.scalar(
                select(func.coalesce(func.sum(EvidenceSourceRecord.size_bytes), 0)).where(
                    EvidenceSourceRecord.case_id == case_id,
                    EvidenceSourceRecord.status == "sealed",
                )
            )
            or 0
        )
        legacy_bookmarks = _count(
            session,
            BookmarkRecord,
            BookmarkRecord.case_id == case_id,
            BookmarkRecord.removed_at.is_(None),
        )
        key_evidence_count = _count(
            session,
            KeyEvidenceRecord,
            KeyEvidenceRecord.case_id == case_id,
            KeyEvidenceRecord.removed_at.is_(None),
        )
        bookmarks = key_evidence_count or legacy_bookmarks
        category_facets = _category_facets(session, case_id)

        custody_count = _count(
            session,
            CustodyEventRecord,
            CustodyEventRecord.case_id == case_id,
        )
        custody_valid, _ = CustodyService().verify_chain(session, principal, case_id)
        evidence_mismatches = _count(
            session,
            EvidenceVerificationRecord,
            EvidenceVerificationRecord.case_id == case_id,
            EvidenceVerificationRecord.status != "verified",
        )
        source_mismatches = _count(
            session,
            EvidenceSourceVerificationRecord,
            EvidenceSourceVerificationRecord.case_id == case_id,
            EvidenceSourceVerificationRecord.status != "verified",
        )
        verified_observations = _count(
            session,
            EvidenceVerificationRecord,
            EvidenceVerificationRecord.case_id == case_id,
            EvidenceVerificationRecord.status == "verified",
        ) + _count(
            session,
            EvidenceSourceVerificationRecord,
            EvidenceSourceVerificationRecord.case_id == case_id,
            EvidenceSourceVerificationRecord.status == "verified",
        )

        timeline_count = _count(
            session,
            TimelineEventRecord,
            TimelineEventRecord.case_id == case_id,
        ) + _count(
            session,
            EvidenceSourceTimelineEventRecord,
            EvidenceSourceTimelineEventRecord.case_id == case_id,
        )
        report_count = _count(session, ReportRecord, ReportRecord.case_id == case_id)
        reviewed_report_ids = select(ReportReviewEventRecord.report_id).where(
            ReportReviewEventRecord.case_id == case_id
        )
        pending_reports = _count(
            session,
            ReportRecord,
            ReportRecord.case_id == case_id,
            ReportRecord.id.not_in(reviewed_report_ids),
        )

        verification_exceptions = evidence_mismatches + source_mismatches
        attention = _attention_items(
            case_status=case.status,
            attention_jobs=attention_jobs,
            custody_valid=custody_valid,
            verification_exceptions=verification_exceptions,
            pending_reports=pending_reports,
            artifact_count=normalized_artifacts + imported_artifacts,
        )
        next_action = _next_action(
            device_count=device_count,
            job_total=job_total,
            active_jobs=active_jobs,
            acquired_files=acquired_files,
            sealed_sources=sealed_sources,
            artifact_count=normalized_artifacts + imported_artifacts,
            bookmarks=bookmarks,
            report_count=report_count,
            pending_reports=pending_reports,
        )

        return CommandCenterSummary(
            case_id=case_id,
            generated_at=datetime.now(UTC),
            device_count=device_count,
            jobs=CommandCenterJobs(
                total=job_total,
                active=active_jobs,
                completed=completed_jobs,
                attention_required=attention_jobs,
            ),
            evidence=CommandCenterEvidence(
                acquired_files=acquired_files,
                sealed_sources=sealed_sources,
                normalized_artifacts=normalized_artifacts,
                imported_artifacts=imported_artifacts,
                total_artifacts=normalized_artifacts + imported_artifacts,
                total_size_bytes=total_size,
                bookmarked_artifacts=bookmarks,
                category_facets=category_facets,
            ),
            integrity=CommandCenterIntegrity(
                custody_chain_valid=custody_valid,
                custody_event_count=custody_count,
                verification_exceptions=verification_exceptions,
                verified_observations=verified_observations,
            ),
            timeline_event_count=timeline_count,
            report_count=report_count,
            reports_pending_review=pending_reports,
            next_action=next_action,
            attention=attention,
            recent_activity=_recent_activity(session, case_id),
        )


def _count(
    session: Session,
    model: type[object],
    *criteria: ColumnElement[bool],
) -> int:
    query = select(func.count()).select_from(model)
    if criteria:
        query = query.where(*criteria)
    return int(session.scalar(query) or 0)


def _category_facets(session: Session, case_id: str) -> dict[str, int]:
    facets: dict[str, int] = {}
    for category, count in session.execute(
        select(ArtifactRecord.category, func.count())
        .where(ArtifactRecord.case_id == case_id)
        .group_by(ArtifactRecord.category)
    ):
        facets[str(category)] = int(count)
    for category, count in session.execute(
        select(EvidenceSourceArtifactRecord.category, func.count())
        .where(EvidenceSourceArtifactRecord.case_id == case_id)
        .group_by(EvidenceSourceArtifactRecord.category)
    ):
        key = str(category)
        facets[key] = facets.get(key, 0) + int(count)
    return dict(sorted(facets.items(), key=lambda item: (-item[1], item[0])))


def _attention_items(
    *,
    case_status: str,
    attention_jobs: int,
    custody_valid: bool,
    verification_exceptions: int,
    pending_reports: int,
    artifact_count: int,
) -> list[CommandCenterAttention]:
    items: list[CommandCenterAttention] = []
    if not custody_valid:
        items.append(
            CommandCenterAttention(
                code="CUSTODY_CHAIN_INVALID",
                severity="critical",
                title="Custody chain requires review",
                detail="The persisted custody chain did not pass hash-chain verification.",
            )
        )
    if verification_exceptions:
        items.append(
            CommandCenterAttention(
                code="INTEGRITY_EXCEPTION",
                severity="critical",
                title="Evidence integrity exception",
                detail=f"{verification_exceptions} verification observation(s) require review.",
            )
        )
    if attention_jobs:
        items.append(
            CommandCenterAttention(
                code="ACQUISITION_ATTENTION",
                severity="warning",
                title="Acquisition follow-up needed",
                detail=f"{attention_jobs} interrupted or failed job(s) retain diagnostic history.",
            )
        )
    if pending_reports:
        items.append(
            CommandCenterAttention(
                code="REPORT_REVIEW_PENDING",
                severity="warning",
                title="Report review pending",
                detail=f"{pending_reports} preliminary report(s) have no recorded review decision.",
            )
        )
    if artifact_count == 0:
        items.append(
            CommandCenterAttention(
                code="NO_NORMALIZED_ARTIFACTS",
                severity="info",
                title="No searchable artifacts yet",
                detail=(
                    "Acquire or parse evidence to populate analysis, timeline, and "
                    "correlation views."
                ),
            )
        )
    if case_status in {"closed", "archived"}:
        items.append(
            CommandCenterAttention(
                code="CASE_READ_ONLY",
                severity="info",
                title="Case is in a review state",
                detail=(
                    "Collection actions are restricted until an authorized user reopens "
                    "the case."
                ),
            )
        )
    return items


def _next_action(
    *,
    device_count: int,
    job_total: int,
    active_jobs: int,
    acquired_files: int,
    sealed_sources: int,
    artifact_count: int,
    bookmarks: int,
    report_count: int,
    pending_reports: int,
) -> NextAction:
    if device_count == 0 and sealed_sources == 0:
        return "detect_device"
    if active_jobs:
        return "monitor_acquisition"
    if job_total == 0 and sealed_sources == 0:
        return "create_acquisition_plan"
    if acquired_files == 0 and sealed_sources == 0:
        return "acquire_evidence"
    if artifact_count == 0:
        return "index_evidence"
    if bookmarks == 0:
        return "review_evidence"
    if report_count == 0:
        return "generate_report"
    if pending_reports:
        return "review_report"
    return "continue_analysis"


def _recent_activity(session: Session, case_id: str) -> list[CommandCenterActivity]:
    activities: list[CommandCenterActivity] = []
    case_events = session.scalars(
        select(CaseEventRecord)
        .where(CaseEventRecord.case_id == case_id)
        .order_by(CaseEventRecord.created_at.desc())
        .limit(5)
    )
    activities.extend(
        CommandCenterActivity(
            kind="case",
            title=event.event_type.replace("_", " ").title(),
            detail=event.safe_detail or "Case lifecycle event recorded.",
            occurred_at=event.created_at,
        )
        for event in case_events
    )

    jobs = session.scalars(
        select(JobRecord)
        .where(JobRecord.case_id == case_id)
        .order_by(JobRecord.updated_at.desc())
        .limit(5)
    )
    activities.extend(
        CommandCenterActivity(
            kind="acquisition",
            title=f"{job.job_type.replace('_', ' ').title()} · {job.state}",
            detail=job.current_step or job.error_message or "Durable job state updated.",
            occurred_at=job.updated_at,
        )
        for job in jobs
    )

    custody_events = session.scalars(
        select(CustodyEventRecord)
        .where(CustodyEventRecord.case_id == case_id)
        .order_by(CustodyEventRecord.created_at.desc())
        .limit(5)
    )
    activities.extend(
        CommandCenterActivity(
            kind="custody",
            title=event.event_type.replace("_", " ").title(),
            detail=event.purpose or event.notes or f"Custody event #{event.sequence} recorded.",
            occurred_at=event.created_at,
        )
        for event in custody_events
    )

    sources = session.scalars(
        select(EvidenceSourceRecord)
        .where(EvidenceSourceRecord.case_id == case_id)
        .order_by(EvidenceSourceRecord.created_at.desc())
        .limit(5)
    )
    activities.extend(
        CommandCenterActivity(
            kind="evidence",
            title=f"Evidence source {source.status}",
            detail=source.display_name,
            occurred_at=source.sealed_at or source.created_at,
        )
        for source in sources
    )

    reports = session.scalars(
        select(ReportRecord)
        .where(ReportRecord.case_id == case_id)
        .order_by(ReportRecord.generated_at.desc())
        .limit(5)
    )
    activities.extend(
        CommandCenterActivity(
            kind="report",
            title="Preliminary report generated",
            detail=report.title,
            occurred_at=report.generated_at,
        )
        for report in reports
    )
    return sorted(activities, key=_activity_timestamp, reverse=True)[:8]


def _activity_timestamp(item: CommandCenterActivity) -> float:
    occurred_at = item.occurred_at
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=UTC)
    return occurred_at.timestamp()
