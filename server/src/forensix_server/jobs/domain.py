"""Explicit state graph for durable local jobs."""

from enum import StrEnum
from typing import Protocol, TypeVar


class PrioritizableInventoryItem(Protocol):
    relative_path: str


InventoryItemT = TypeVar("InventoryItemT", bound=PrioritizableInventoryItem)


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
    JobState.READY: frozenset({JobState.VALIDATING, JobState.RUNNING, JobState.CANCELLED}),
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


class PriorityScheduler:
    """Reorders acquisition tasks based on device capability (e.g., low battery)."""

    @staticmethod
    def prioritize_inventory_items(
        items: list[InventoryItemT], battery_level: int | None
    ) -> list[InventoryItemT]:
        if battery_level is None or battery_level >= 20:
            return items

        def priority_score(item: InventoryItemT) -> int:
            path = str(item.relative_path).lower()
            if "device_info" in path or "metadata" in path:
                return 10
            if "contacts" in path:
                return 20
            if "calllog" in path:
                return 30
            if "mmssms" in path or "telephony" in path:
                return 40
            if "packages" in path or "inventory" in path:
                return 50
            if path.endswith((".jpg", ".jpeg", ".png", ".mp4", ".gif", ".webp")):
                return 60
            return 100

        return sorted(items, key=lambda i: (priority_score(i), i.relative_path))
