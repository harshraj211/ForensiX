"""Transaction-scoped service for durable local jobs and append-only progress events."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_server.db.models import JobEventRecord, JobRecord

from .domain import (
    ACTIVE_STATES,
    RESTART_INTERRUPTABLE_STATES,
    TERMINAL_STATES,
    JobState,
    JobType,
    require_transition,
)


class JobNotFoundError(LookupError):
    def __init__(self, job_id: str) -> None:
        super().__init__(f"Job {job_id!r} was not found.")
        self.job_id = job_id


class JobService:
    """Mutates jobs only through validated, versioned state operations."""

    def create(
        self,
        session: Session,
        job_type: JobType,
        *,
        resume_supported: bool = False,
        owner_id: str | None = None,
        case_id: str | None = None,
        plan_id: str | None = None,
    ) -> JobRecord:
        job = JobRecord(
            id=str(uuid4()),
            owner_id=owner_id,
            case_id=case_id,
            plan_id=plan_id,
            job_type=job_type.value,
            state=JobState.CREATED.value,
            progress_percent=0,
            cancellation_requested=False,
            resume_supported=resume_supported,
            last_event_sequence=1,
        )
        session.add(job)
        session.flush()
        session.add(
            JobEventRecord(
                job_id=job.id,
                sequence=1,
                event_type="job_created",
                state=job.state,
                progress_percent=job.progress_percent,
                created_at=job.created_at,
            )
        )
        session.flush()
        return job

    def get(self, session: Session, job_id: str) -> JobRecord:
        job = session.get(JobRecord, job_id)
        if job is None:
            raise JobNotFoundError(job_id)
        return job

    def transition(
        self,
        session: Session,
        job_id: str,
        requested: JobState,
        *,
        error_code: str | None = None,
        error_message: str | None = None,
        result_reference: str | None = None,
        event_type: str = "state_changed",
    ) -> JobRecord:
        job = self.get(session, job_id)
        current = JobState(job.state)
        require_transition(current, requested)
        now = datetime.now(UTC)

        if requested is JobState.FAILED and not error_code:
            raise ValueError("failed jobs require a stable error_code")
        if requested is JobState.RUNNING and job.started_at is None:
            job.started_at = now
        if requested in TERMINAL_STATES:
            job.completed_at = now
        if requested in {JobState.COMPLETED, JobState.VERIFIED}:
            job.progress_percent = 100

        job.state = requested.value
        job.error_code = error_code
        job.error_message = error_message
        job.result_reference = result_reference or job.result_reference
        self._touch(job, now)
        self._append_event(
            session,
            job,
            event_type,
            safe_detail=f"from={current.value};to={requested.value}",
            now=now,
        )
        session.flush()
        return job

    def update_progress(
        self,
        session: Session,
        job_id: str,
        progress_percent: int,
        *,
        current_step: str | None = None,
        current_module: str | None = None,
        checkpoint: Mapping[str, object] | None = None,
    ) -> JobRecord:
        job = self.get(session, job_id)
        state = JobState(job.state)
        if state not in ACTIVE_STATES:
            raise ValueError(f"progress cannot be updated while a job is {state.value}")
        if not 0 <= progress_percent <= 100:
            raise ValueError("progress_percent must be between 0 and 100")
        if progress_percent < job.progress_percent:
            raise ValueError("job progress cannot decrease")

        encoded_checkpoint = _canonical_checkpoint(checkpoint) if checkpoint is not None else None
        job.progress_percent = progress_percent
        job.current_step = current_step
        job.current_module = current_module
        if encoded_checkpoint is not None:
            job.checkpoint_json = encoded_checkpoint
        now = datetime.now(UTC)
        self._touch(job, now)
        self._append_event(session, job, "progress_updated", now=now)
        session.flush()
        return job

    def request_cancellation(self, session: Session, job_id: str) -> JobRecord:
        job = self.get(session, job_id)
        state = JobState(job.state)
        if state in TERMINAL_STATES:
            return job

        if job.cancellation_requested:
            return job

        job.cancellation_requested = True
        if state in {JobState.CREATED, JobState.READY, JobState.PAUSED, JobState.INTERRUPTED}:
            return self.transition(
                session, job_id, JobState.CANCELLED, event_type="cancellation_requested"
            )
        if state in ACTIVE_STATES and state is not JobState.CANCELLING:
            return self.transition(
                session, job_id, JobState.CANCELLING, event_type="cancellation_requested"
            )

        return job

    def list_events(self, session: Session, job_id: str) -> list[JobEventRecord]:
        self.get(session, job_id)
        return list(
            session.scalars(
                select(JobEventRecord)
                .where(JobEventRecord.job_id == job_id)
                .order_by(JobEventRecord.sequence)
            )
        )

    def recover_after_restart(self, session: Session) -> list[JobRecord]:
        recoverable_values = tuple(state.value for state in RESTART_INTERRUPTABLE_STATES)
        jobs = list(
            session.scalars(select(JobRecord).where(JobRecord.state.in_(recoverable_values)))
        )
        for job in jobs:
            job.state = JobState.INTERRUPTED.value
            job.error_code = "BACKEND_RESTARTED"
            job.error_message = "The local backend restarted before this job completed."
            now = datetime.now(UTC)
            self._touch(job, now)
            self._append_event(
                session,
                job,
                "job_interrupted",
                safe_detail="reason=backend_restart",
                now=now,
            )
        session.flush()
        return jobs

    @staticmethod
    def _touch(job: JobRecord, now: datetime | None = None) -> None:
        job.updated_at = now or datetime.now(UTC)

    @staticmethod
    def _append_event(
        session: Session,
        job: JobRecord,
        event_type: str,
        *,
        safe_detail: str | None = None,
        now: datetime | None = None,
    ) -> JobEventRecord:
        if not event_type or len(event_type) > 32:
            raise ValueError("event_type must contain 1 to 32 characters")
        if safe_detail is not None and len(safe_detail) > 255:
            raise ValueError("safe_detail cannot exceed 255 characters")
        job.last_event_sequence += 1
        # Flush the versioned parent before the event insert so a stale writer
        # fails with StaleDataError instead of racing on the sequence constraint.
        session.flush([job])
        event = JobEventRecord(
            job_id=job.id,
            sequence=job.last_event_sequence,
            event_type=event_type,
            state=job.state,
            progress_percent=job.progress_percent,
            current_step=job.current_step,
            current_module=job.current_module,
            checkpoint_json=job.checkpoint_json,
            safe_detail=safe_detail,
            created_at=now or datetime.now(UTC),
        )
        session.add(event)
        return event


def _canonical_checkpoint(checkpoint: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(
            dict(checkpoint), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError) as error:
        raise ValueError("checkpoint must be JSON serializable") from error
    if len(encoded.encode("utf-8")) > 8_192:
        raise ValueError("checkpoint cannot exceed 8192 bytes")
    return encoded
