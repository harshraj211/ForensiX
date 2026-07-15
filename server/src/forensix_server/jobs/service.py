"""Transaction-scoped service for durable local jobs."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_server.db.models import JobRecord

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
    ) -> JobRecord:
        job = JobRecord(
            job_type=job_type.value,
            state=JobState.CREATED.value,
            resume_supported=resume_supported,
        )
        session.add(job)
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
    ) -> JobRecord:
        job = self.get(session, job_id)
        state = JobState(job.state)
        if state not in ACTIVE_STATES:
            raise ValueError(f"progress cannot be updated while a job is {state.value}")
        if not 0 <= progress_percent <= 100:
            raise ValueError("progress_percent must be between 0 and 100")
        if progress_percent < job.progress_percent:
            raise ValueError("job progress cannot decrease")

        job.progress_percent = progress_percent
        job.current_step = current_step
        job.current_module = current_module
        self._touch(job)
        session.flush()
        return job

    def request_cancellation(self, session: Session, job_id: str) -> JobRecord:
        job = self.get(session, job_id)
        state = JobState(job.state)
        if state in TERMINAL_STATES:
            return job

        job.cancellation_requested = True
        if state in {JobState.CREATED, JobState.READY, JobState.PAUSED, JobState.INTERRUPTED}:
            return self.transition(session, job_id, JobState.CANCELLED)
        if state in ACTIVE_STATES and state is not JobState.CANCELLING:
            return self.transition(session, job_id, JobState.CANCELLING)

        self._touch(job)
        session.flush()
        return job

    def recover_after_restart(self, session: Session) -> list[JobRecord]:
        recoverable_values = tuple(state.value for state in RESTART_INTERRUPTABLE_STATES)
        jobs = list(
            session.scalars(select(JobRecord).where(JobRecord.state.in_(recoverable_values)))
        )
        for job in jobs:
            job.state = JobState.INTERRUPTED.value
            job.error_code = "BACKEND_RESTARTED"
            job.error_message = "The local backend restarted before this job completed."
            self._touch(job)
        session.flush()
        return jobs

    @staticmethod
    def _touch(job: JobRecord, now: datetime | None = None) -> None:
        job.updated_at = now or datetime.now(UTC)
