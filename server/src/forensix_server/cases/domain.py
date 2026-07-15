"""Case status and membership vocabulary."""

from enum import StrEnum


class CaseStatus(StrEnum):
    OPEN = "open"
    ACTIVE = "active"
    CLOSED = "closed"
    ARCHIVED = "archived"


class CaseAccessLevel(StrEnum):
    OWNER = "owner"
    INVESTIGATOR = "investigator"
    ANALYST = "analyst"
    SUPERVISOR = "supervisor"
    REVIEWER = "reviewer"


ALLOWED_CASE_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset({CaseStatus.ACTIVE, CaseStatus.CLOSED}),
    CaseStatus.ACTIVE: frozenset({CaseStatus.CLOSED}),
    CaseStatus.CLOSED: frozenset({CaseStatus.ACTIVE, CaseStatus.ARCHIVED}),
    CaseStatus.ARCHIVED: frozenset(),
}
