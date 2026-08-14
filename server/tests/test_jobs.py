from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from forensix_server.db import Database, JobEventRecord
from forensix_server.jobs import JobService, JobState, JobTransitionError, JobType


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    database_path = tmp_path / "jobs.db"
    database = Database(f"sqlite:///{database_path.as_posix()}", tmp_path)
    database.initialize()
    with database.session() as active_session:
        yield active_session
    database.dispose()


def test_job_follows_validated_acquisition_lifecycle(session: Session) -> None:
    service = JobService()
    job = service.create(session, JobType.ACQUISITION, resume_supported=True)

    service.transition(session, job.id, JobState.VALIDATING)
    service.update_progress(session, job.id, 5, current_step="Checking device readiness")
    service.transition(session, job.id, JobState.READY)
    service.transition(session, job.id, JobState.RUNNING)
    service.update_progress(
        session,
        job.id,
        60,
        current_step="Hashing sealed evidence",
        current_module="shared-storage",
    )
    service.transition(session, job.id, JobState.COMPLETED, result_reference="manifest-1")
    service.transition(session, job.id, JobState.VERIFYING)
    verified = service.transition(session, job.id, JobState.VERIFIED)

    assert verified.state == JobState.VERIFIED.value
    assert verified.progress_percent == 100
    assert verified.started_at is not None
    assert verified.completed_at is not None
    assert verified.result_reference == "manifest-1"
    assert verified.version == 9


def test_job_rejects_invalid_transition(session: Session) -> None:
    service = JobService()
    job = service.create(session, JobType.ACQUISITION)

    with pytest.raises(JobTransitionError):
        service.transition(session, job.id, JobState.RUNNING)


def test_progress_is_monotonic_and_only_allowed_while_active(session: Session) -> None:
    service = JobService()
    job = service.create(session, JobType.HASHING)
    service.transition(session, job.id, JobState.VALIDATING)
    service.update_progress(session, job.id, 40)

    with pytest.raises(ValueError, match="cannot decrease"):
        service.update_progress(session, job.id, 39)

    service.transition(session, job.id, JobState.READY)
    with pytest.raises(ValueError, match="cannot be updated"):
        service.update_progress(session, job.id, 50)


def test_progress_persists_bounded_checkpoint_and_append_only_events(session: Session) -> None:
    service = JobService()
    job = service.create(session, JobType.ACQUISITION, resume_supported=True)
    service.transition(session, job.id, JobState.VALIDATING)
    service.update_progress(
        session,
        job.id,
        15,
        current_step="Validating plan",
        current_module="device_metadata",
        checkpoint={"phase": "validation", "completed_modules": 0},
    )

    events = service.list_events(session, job.id)

    assert [event.sequence for event in events] == [1, 2, 3]
    assert [event.event_type for event in events] == [
        "job_created",
        "state_changed",
        "progress_updated",
    ]
    assert events[-1].checkpoint_json == '{"completed_modules":0,"phase":"validation"}'
    assert session.query(JobEventRecord).count() == 3


def test_checkpoint_rejects_unbounded_or_non_json_values(session: Session) -> None:
    service = JobService()
    job = service.create(session, JobType.ACQUISITION)
    service.transition(session, job.id, JobState.VALIDATING)

    with pytest.raises(ValueError, match="JSON serializable"):
        service.update_progress(session, job.id, 1, checkpoint={"invalid": object()})
    with pytest.raises(ValueError, match="8192"):
        service.update_progress(session, job.id, 1, checkpoint={"oversized": "x" * 9_000})


def test_active_job_cancellation_is_cooperative_and_idempotent(session: Session) -> None:
    service = JobService()
    job = service.create(session, JobType.ACQUISITION)
    service.transition(session, job.id, JobState.VALIDATING)
    service.transition(session, job.id, JobState.READY)
    service.transition(session, job.id, JobState.RUNNING)

    cancelling = service.request_cancellation(session, job.id)
    repeated = service.request_cancellation(session, job.id)

    assert cancelling.state == JobState.CANCELLING.value
    assert repeated.state == JobState.CANCELLING.value
    assert repeated.cancellation_requested is True


def test_not_started_job_cancels_immediately(session: Session) -> None:
    service = JobService()
    job = service.create(session, JobType.REPORT)

    cancelled = service.request_cancellation(session, job.id)

    assert cancelled.state == JobState.CANCELLED.value
    assert cancelled.completed_at is not None


def test_completed_job_ignores_late_cancellation_request(session: Session) -> None:
    service = JobService()
    job = service.create(session, JobType.REPORT)
    service.transition(session, job.id, JobState.VALIDATING)
    service.transition(session, job.id, JobState.READY)
    service.transition(session, job.id, JobState.RUNNING)
    service.transition(session, job.id, JobState.COMPLETED)

    completed = service.request_cancellation(session, job.id)

    assert completed.state == JobState.COMPLETED.value
    assert completed.cancellation_requested is False


def test_failed_job_requires_stable_error_code(session: Session) -> None:
    service = JobService()
    job = service.create(session, JobType.PARSING)
    service.transition(session, job.id, JobState.VALIDATING)

    with pytest.raises(ValueError, match="error_code"):
        service.transition(session, job.id, JobState.FAILED)


def test_restart_marks_only_active_jobs_interrupted(session: Session) -> None:
    service = JobService()
    running = service.create(session, JobType.ACQUISITION, resume_supported=True)
    service.transition(session, running.id, JobState.VALIDATING)
    service.transition(session, running.id, JobState.READY)
    service.transition(session, running.id, JobState.RUNNING)
    ready = service.create(session, JobType.REPORT)
    service.transition(session, ready.id, JobState.VALIDATING)
    service.transition(session, ready.id, JobState.READY)

    recovered = service.recover_after_restart(session)

    assert [job.id for job in recovered] == [running.id]
    assert running.state == JobState.INTERRUPTED.value
    assert running.error_code == "BACKEND_RESTARTED"
    assert ready.state == JobState.READY.value
    assert service.list_events(session, running.id)[-1].event_type == "job_interrupted"


def test_job_version_detects_concurrent_state_update(tmp_path: Path) -> None:
    database_path = tmp_path / "concurrency.db"
    database = Database(f"sqlite:///{database_path.as_posix()}", tmp_path)
    database.initialize()
    service = JobService()

    with Session(database.engine) as creator:
        created = service.create(creator, JobType.ACQUISITION)
        job_id = created.id
        creator.commit()

    with Session(database.engine) as first, Session(database.engine) as stale:
        first_job = service.get(first, job_id)
        stale_job = service.get(stale, job_id)
        assert first_job.version == stale_job.version == 1
        service.transition(first, job_id, JobState.VALIDATING)
        first.commit()

        with pytest.raises(StaleDataError):
            service.transition(stale, job_id, JobState.VALIDATING)

    database.dispose()


def test_priority_scheduler_reorders_items_on_low_battery() -> None:
    from types import SimpleNamespace

    from forensix_server.jobs.domain import PriorityScheduler

    # Mock items with relative_path
    i1 = SimpleNamespace(id="1", relative_path="documents/report.pdf")
    i2 = SimpleNamespace(id="2", relative_path="contacts2.db")
    i3 = SimpleNamespace(id="3", relative_path="packages.xml")

    items = [i1, i2, i3]

    assert [i.id for i in PriorityScheduler.prioritize_inventory_items(items, None)] == [
        "1",
        "2",
        "3",
    ]
    assert [i.id for i in PriorityScheduler.prioritize_inventory_items(items, 50)] == [
        "1",
        "2",
        "3",
    ]

    prioritized = PriorityScheduler.prioritize_inventory_items(items, 15)
    assert [i.id for i in prioritized] == ["2", "3", "1"]
