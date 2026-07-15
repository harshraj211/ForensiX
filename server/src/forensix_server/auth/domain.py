"""Authentication identities and explicit RBAC permissions."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class RoleName(StrEnum):
    ADMINISTRATOR = "administrator"
    INVESTIGATOR = "investigator"
    ANALYST = "analyst"
    SUPERVISOR = "supervisor"
    REVIEWER = "reviewer"


class Permission(StrEnum):
    USERS_MANAGE = "users:manage"
    SETTINGS_MANAGE = "settings:manage"
    AUDIT_VIEW = "audit:view"
    CASES_CREATE = "cases:create"
    CASES_READ = "cases:read"
    CASES_MANAGE = "cases:manage"
    DEVICES_OPERATE = "devices:operate"
    ACQUISITIONS_OPERATE = "acquisitions:operate"
    EVIDENCE_ANALYZE = "evidence:analyze"
    REPORTS_GENERATE = "reports:generate"
    REPORTS_APPROVE = "reports:approve"
    CUSTODY_REVIEW = "custody:review"


ROLE_PERMISSIONS: dict[RoleName, frozenset[Permission]] = {
    RoleName.ADMINISTRATOR: frozenset(Permission),
    RoleName.INVESTIGATOR: frozenset(
        {
            Permission.CASES_CREATE,
            Permission.CASES_READ,
            Permission.CASES_MANAGE,
            Permission.DEVICES_OPERATE,
            Permission.ACQUISITIONS_OPERATE,
            Permission.EVIDENCE_ANALYZE,
            Permission.REPORTS_GENERATE,
            Permission.CUSTODY_REVIEW,
        }
    ),
    RoleName.ANALYST: frozenset(
        {
            Permission.CASES_READ,
            Permission.EVIDENCE_ANALYZE,
            Permission.REPORTS_GENERATE,
            Permission.CUSTODY_REVIEW,
        }
    ),
    RoleName.SUPERVISOR: frozenset(
        {
            Permission.CASES_READ,
            Permission.CASES_MANAGE,
            Permission.EVIDENCE_ANALYZE,
            Permission.REPORTS_GENERATE,
            Permission.REPORTS_APPROVE,
            Permission.CUSTODY_REVIEW,
            Permission.AUDIT_VIEW,
        }
    ),
    RoleName.REVIEWER: frozenset({Permission.CASES_READ, Permission.CUSTODY_REVIEW}),
}


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: str
    username: str
    display_name: str
    roles: frozenset[RoleName]
    permissions: frozenset[Permission]

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    session_id: str
    principal: Principal
    csrf_hash: str
    expires_at: datetime


ROLE_DESCRIPTIONS: dict[RoleName, str] = {
    RoleName.ADMINISTRATOR: "Manages users, security settings, and system administration.",
    RoleName.INVESTIGATOR: "Creates cases and performs controlled device acquisitions.",
    RoleName.ANALYST: "Analyzes evidence, timelines, notes, tags, and preliminary reports.",
    RoleName.SUPERVISOR: "Reviews cases, custody, audit history, and report approval.",
    RoleName.REVIEWER: "Reads approved case material and custody information.",
}
