"""Explicit state graph for durable local jobs."""

from enum import StrEnum


class JobType(StrEnum):
    DEVICE_ASSESSMENT = "device_assessment"
    ACQUISITION = "acquisition"
    PARSING = "parsing"
    INDEXING = "indexing"
    HASHING = "hashing"
    TIMELINE = "timeline"
    REPORT = "report"
    EXPORT = "export"
    HASH_VERIFICATION = "hash_verification"


class JobState(StrEnum):
    CREATED = "created"
    VALIDATING = "validating"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    FAILED = "failed"
    COMPLETED = "completed"
    VERIFYING = "verifying"
    VERIFIED = "verified"


ALLOWED_TRANSITIONS: dict[JobState, frozenset[JobState]] = {
    JobState.CREATED: frozenset({JobState.VALIDATING, JobState.CANCELLED}),
    JobState.VALIDATING: frozenset(
        {JobState.READY, JobState.CANCELLING, JobState.INTERRUPTED, JobState.FAILED}
    ),
    JobState.READY: frozenset({JobState.RUNNING, JobState.CANCELLED}),
    JobState.RUNNING: frozenset(
        {
            JobState.PAUSED,
            JobState.CANCELLING,
            JobState.INTERRUPTED,
            JobState.FAILED,
            JobState.COMPLETED,
        }
    ),
    JobState.PAUSED: frozenset(
        {JobState.RUNNING, JobState.CANCELLING, JobState.CANCELLED, JobState.INTERRUPTED}
    ),
    JobState.CANCELLING: frozenset({JobState.CANCELLED, JobState.INTERRUPTED, JobState.FAILED}),
    JobState.CANCELLED: frozenset(),
    JobState.INTERRUPTED: frozenset({JobState.VALIDATING, JobState.CANCELLED}),
    JobState.FAILED: frozenset(),
    JobState.COMPLETED: frozenset({JobState.VERIFYING}),
    JobState.VERIFYING: frozenset({JobState.CANCELLING, JobState.VERIFIED, JobState.FAILED}),
    JobState.VERIFIED: frozenset(),
}

ACTIVE_STATES = frozenset(
    {
        JobState.VALIDATING,
        JobState.RUNNING,
        JobState.CANCELLING,
        JobState.VERIFYING,
    }
)
RESTART_INTERRUPTABLE_STATES = ACTIVE_STATES
TERMINAL_STATES = frozenset(
    {JobState.CANCELLED, JobState.FAILED, JobState.COMPLETED, JobState.VERIFIED}
)


class JobTransitionError(ValueError):
    def __init__(self, current: JobState, requested: JobState) -> None:
        super().__init__(f"Job cannot transition from {current.value} to {requested.value}.")
        self.current = current
        self.requested = requested


def can_transition(current: JobState, requested: JobState) -> bool:
    return requested in ALLOWED_TRANSITIONS[current]


def require_transition(current: JobState, requested: JobState) -> None:
    if not can_transition(current, requested):
        raise JobTransitionError(current, requested)
