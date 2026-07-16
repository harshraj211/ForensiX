"""Case-authorized preparation and observation of durable acquisition jobs."""

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal
from forensix_server.cases import (
    CaseAccessDeniedError,
    CaseInvalidStateError,
    CaseNotFoundError,
    CaseService,
    CaseStatus,
)
from forensix_server.db import CaseEventRecord, JobEventRecord, JobRecord
from forensix_server.jobs import JobService, JobState, JobType

from .service import AcquisitionPlanService


class AcquisitionJobNotFoundError(CaseNotFoundError):
    code = "ACQUISITION_JOB_NOT_FOUND"


class AcquisitionJobInvalidStateError(CaseInvalidStateError):
    code = "ACQUISITION_JOB_INVALID"


class AcquisitionExecutionService:
    """Creates one idempotent, non-executing durable job for an immutable plan."""

    def prepare(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        plan_id: str,
        *,
        now: datetime | None = None,
    ) -> tuple[JobRecord, bool]:
        case = CaseService().get(session, principal, case_id)
        if not principal.can(Permission.ACQUISITIONS_OPERATE):
            raise CaseAccessDeniedError("The current user cannot prepare acquisition jobs.")
        plan = AcquisitionPlanService().get(session, principal, case_id, plan_id)

        existing = session.scalar(select(JobRecord).where(JobRecord.plan_id == plan.id))
        if existing is not None:
            return existing, False

        if case.status in {CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value}:
            raise AcquisitionJobInvalidStateError(
                "Acquisition jobs cannot be prepared for a closed or archived case."
            )
        current_time = _as_utc(now or datetime.now(UTC))
        if current_time > _as_utc(plan.readiness_expires_at):
            raise AcquisitionJobInvalidStateError(
                "The plan readiness snapshot is stale; reassess and create a new plan."
            )

        jobs = JobService()
        job = jobs.create(
            session,
            JobType.ACQUISITION,
            resume_supported=True,
            owner_id=principal.user_id,
            case_id=case_id,
            plan_id=plan.id,
        )
        jobs.transition(session, job.id, JobState.VALIDATING)
        jobs.update_progress(
            session,
            job.id,
            5,
            current_step="Immutable plan validated; awaiting bounded executor",
            checkpoint={
                "phase": "prepared",
                "plan_hash": plan.plan_hash,
                "plan_id": plan.id,
                "schema_version": plan.schema_version,
            },
        )
        jobs.transition(session, job.id, JobState.READY)
        session.add(
            CaseEventRecord(
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="acquisition_job_prepared",
                safe_detail=f"job_id={job.id};plan_id={plan.id}",
                created_at=current_time,
            )
        )
        session.flush()
        return job, True

    def list_for_case(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[JobRecord], int]:
        CaseService().get(session, principal, case_id)
        filters = (
            JobRecord.case_id == case_id,
            JobRecord.job_type == JobType.ACQUISITION.value,
        )
        total = session.scalar(select(func.count()).select_from(JobRecord).where(*filters)) or 0
        jobs = list(
            session.scalars(
                select(JobRecord)
                .where(*filters)
                .order_by(JobRecord.created_at.desc(), JobRecord.id)
                .offset(offset)
                .limit(limit)
            )
        )
        return jobs, total

    def get(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> JobRecord:
        CaseService().get(session, principal, case_id)
        job = session.get(JobRecord, job_id)
        if (
            job is None
            or job.case_id != case_id
            or job.job_type != JobType.ACQUISITION.value
            or job.plan_id is None
        ):
            raise AcquisitionJobNotFoundError("The requested acquisition job does not exist.")
        return job

    def cancel(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> JobRecord:
        if not principal.can(Permission.ACQUISITIONS_OPERATE):
            raise CaseAccessDeniedError("The current user cannot cancel acquisition jobs.")
        job = self.get(session, principal, case_id, job_id)
        before = (job.state, job.cancellation_requested)
        updated = JobService().request_cancellation(session, job.id)
        if before != (updated.state, updated.cancellation_requested):
            session.add(
                CaseEventRecord(
                    case_id=case_id,
                    actor_id=principal.user_id,
                    event_type="acquisition_job_cancelled",
                    safe_detail=f"job_id={job.id};state={updated.state}",
                )
            )
            session.flush()
        return updated

    def list_events(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> list[JobEventRecord]:
        self.get(session, principal, case_id, job_id)
        return JobService().list_events(session, job_id)


def job_checkpoint(job: JobRecord) -> dict[str, Any] | None:
    if job.checkpoint_json is None:
        return None
    value = json.loads(job.checkpoint_json)
    return value if isinstance(value, dict) else None


def event_checkpoint(event: JobEventRecord) -> dict[str, Any] | None:
    if event.checkpoint_json is None:
        return None
    value = json.loads(event.checkpoint_json)
    return value if isinstance(value, dict) else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
