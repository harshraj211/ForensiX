"""Transaction-scoped case service with object-level authorization."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal, RoleName
from forensix_server.db.models import (
    CaseEventRecord,
    CaseMemberRecord,
    CaseRecord,
    UserRecord,
)

from .domain import ALLOWED_CASE_TRANSITIONS, CaseAccessLevel, CaseStatus


class CaseError(RuntimeError):
    code = "CASE_ERROR"


class CaseNotFoundError(CaseError):
    code = "CASE_NOT_FOUND"


class CaseAccessDeniedError(CaseError):
    code = "CASE_ACCESS_DENIED"


class CaseInvalidStateError(CaseError):
    code = "CASE_INVALID_STATE"


class CaseVersionConflictError(CaseError):
    code = "CASE_VERSION_CONFLICT"


class CaseMemberError(CaseError):
    code = "CASE_MEMBER_INVALID"


class CaseService:
    def create(
        self,
        session: Session,
        principal: Principal,
        *,
        title: str,
        description: str | None = None,
        legal_authority: str | None = None,
    ) -> CaseRecord:
        self._require_permission(principal, Permission.CASES_CREATE)
        now = datetime.now(UTC)
        case = CaseRecord(
            case_number=_case_number(now),
            title=_required_text(title, "title", 255),
            description=_optional_text(description, "description", 10_000),
            legal_authority=_optional_text(legal_authority, "legal_authority", 2_000),
            status=CaseStatus.OPEN.value,
            created_by=principal.user_id,
            created_at=now,
            updated_at=now,
        )
        session.add(case)
        session.flush()
        session.add(
            CaseMemberRecord(
                case_id=case.id,
                user_id=principal.user_id,
                access_level=CaseAccessLevel.OWNER.value,
                assigned_at=now,
                assigned_by=principal.user_id,
            )
        )
        self._event(
            session,
            case_id=case.id,
            actor_id=principal.user_id,
            event_type="case_created",
            to_status=CaseStatus.OPEN.value,
        )
        session.flush()
        return case

    def list_accessible(
        self,
        session: Session,
        principal: Principal,
        *,
        offset: int = 0,
        limit: int = 50,
        status: CaseStatus | None = None,
    ) -> tuple[list[CaseRecord], int]:
        self._require_permission(principal, Permission.CASES_READ)
        query = select(CaseRecord)
        count_query = select(func.count()).select_from(CaseRecord)
        if not self._is_administrator(principal):
            query = query.join(CaseMemberRecord).where(
                CaseMemberRecord.user_id == principal.user_id
            )
            count_query = count_query.join(CaseMemberRecord).where(
                CaseMemberRecord.user_id == principal.user_id
            )
        if status is not None:
            query = query.where(CaseRecord.status == status.value)
            count_query = count_query.where(CaseRecord.status == status.value)
        total = session.scalar(count_query) or 0
        cases = list(
            session.scalars(
                query.order_by(CaseRecord.updated_at.desc()).offset(offset).limit(limit)
            )
        )
        return cases, total

    def get(self, session: Session, principal: Principal, case_id: str) -> CaseRecord:
        self._require_case_access(session, principal, case_id, Permission.CASES_READ)
        case = session.get(CaseRecord, case_id)
        if case is None:
            raise CaseNotFoundError("The requested case does not exist.")
        return case

    def update(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        expected_version: int,
        title: str | None = None,
        description: str | None = None,
        legal_authority: str | None = None,
    ) -> CaseRecord:
        case = self._get_manageable(session, principal, case_id)
        if case.status in {CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value}:
            raise CaseInvalidStateError("Closed or archived cases cannot be edited.")
        if case.version != expected_version:
            raise CaseVersionConflictError("The case was modified by another operation.")
        if title is not None:
            case.title = _required_text(title, "title", 255)
        if description is not None:
            case.description = _optional_text(description, "description", 10_000)
        if legal_authority is not None:
            case.legal_authority = _optional_text(legal_authority, "legal_authority", 2_000)
        case.updated_at = datetime.now(UTC)
        self._event(
            session,
            case_id=case.id,
            actor_id=principal.user_id,
            event_type="case_updated",
            safe_detail=f"expected_version={expected_version}",
        )
        session.flush()
        return case

    def transition(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        requested: CaseStatus,
        expected_version: int,
    ) -> CaseRecord:
        case = self._get_manageable(session, principal, case_id)
        current = CaseStatus(case.status)
        if case.version != expected_version:
            raise CaseVersionConflictError("The case was modified by another operation.")
        if requested not in ALLOWED_CASE_TRANSITIONS[current]:
            raise CaseInvalidStateError(
                f"Case cannot transition from {current.value} to {requested.value}."
            )
        if (
            requested in {CaseStatus.ACTIVE, CaseStatus.ARCHIVED}
            and current is CaseStatus.CLOSED
            and not principal.roles.intersection({RoleName.ADMINISTRATOR, RoleName.SUPERVISOR})
        ):
            raise CaseAccessDeniedError(
                "Only an administrator or supervisor can reopen or archive a closed case."
            )
        now = datetime.now(UTC)
        case.status = requested.value
        case.updated_at = now
        case.closed_at = now if requested is CaseStatus.CLOSED else None
        self._event(
            session,
            case_id=case.id,
            actor_id=principal.user_id,
            event_type="case_status_changed",
            from_status=current.value,
            to_status=requested.value,
        )
        session.flush()
        return case

    def list_members(
        self, session: Session, principal: Principal, case_id: str
    ) -> list[CaseMemberRecord]:
        self._require_case_access(session, principal, case_id, Permission.CASES_READ)
        return list(
            session.scalars(
                select(CaseMemberRecord)
                .where(CaseMemberRecord.case_id == case_id)
                .order_by(CaseMemberRecord.assigned_at)
            )
        )

    def list_events(
        self, session: Session, principal: Principal, case_id: str
    ) -> list[CaseEventRecord]:
        self._require_case_access(session, principal, case_id, Permission.CASES_READ)
        return list(
            session.scalars(
                select(CaseEventRecord)
                .where(CaseEventRecord.case_id == case_id)
                .order_by(CaseEventRecord.created_at, CaseEventRecord.id)
            )
        )

    def add_member(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        user_id: str,
        access_level: CaseAccessLevel,
    ) -> CaseMemberRecord:
        self._require_membership_manager(session, principal, case_id)
        user = session.get(UserRecord, user_id)
        if user is None or not user.is_active:
            raise CaseMemberError("The selected user is unavailable.")
        existing = session.get(CaseMemberRecord, (case_id, user_id))
        now = datetime.now(UTC)
        if existing is None:
            existing = CaseMemberRecord(
                case_id=case_id,
                user_id=user_id,
                access_level=access_level.value,
                assigned_at=now,
                assigned_by=principal.user_id,
            )
            session.add(existing)
            event_type = "case_member_added"
        else:
            existing.access_level = access_level.value
            existing.assigned_at = now
            existing.assigned_by = principal.user_id
            event_type = "case_member_updated"
        self._event(
            session,
            case_id=case_id,
            actor_id=principal.user_id,
            event_type=event_type,
            safe_detail=f"user_id={user_id};access={access_level.value}",
        )
        session.flush()
        return existing

    def remove_member(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        user_id: str,
    ) -> None:
        case = self._require_membership_manager(session, principal, case_id)
        member = session.get(CaseMemberRecord, (case_id, user_id))
        if member is None:
            raise CaseMemberError("The selected user is not a case member.")
        if user_id == case.created_by:
            raise CaseMemberError("The case creator cannot be removed from the case.")
        session.delete(member)
        self._event(
            session,
            case_id=case_id,
            actor_id=principal.user_id,
            event_type="case_member_removed",
            safe_detail=f"user_id={user_id}",
        )
        session.flush()

    def _get_manageable(self, session: Session, principal: Principal, case_id: str) -> CaseRecord:
        self._require_case_access(session, principal, case_id, Permission.CASES_MANAGE)
        case = session.get(CaseRecord, case_id)
        if case is None:
            raise CaseNotFoundError("The requested case does not exist.")
        return case

    def _require_membership_manager(
        self, session: Session, principal: Principal, case_id: str
    ) -> CaseRecord:
        case = self._get_manageable(session, principal, case_id)
        if self._is_administrator(principal):
            return case
        membership = session.get(CaseMemberRecord, (case_id, principal.user_id))
        if membership is None or membership.access_level not in {
            CaseAccessLevel.OWNER.value,
            CaseAccessLevel.SUPERVISOR.value,
        }:
            raise CaseAccessDeniedError(
                "Only a case owner, case supervisor, or administrator can manage membership."
            )
        return case

    def _require_case_access(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        permission: Permission,
    ) -> None:
        self._require_permission(principal, permission)
        case_exists = session.get(CaseRecord, case_id)
        if case_exists is None:
            raise CaseNotFoundError("The requested case does not exist.")
        if self._is_administrator(principal):
            return
        membership = session.get(CaseMemberRecord, (case_id, principal.user_id))
        if membership is None:
            raise CaseAccessDeniedError("The current user is not assigned to this case.")

    @staticmethod
    def _require_permission(principal: Principal, permission: Permission) -> None:
        if not principal.can(permission):
            raise CaseAccessDeniedError("The current user lacks the required case permission.")

    @staticmethod
    def _is_administrator(principal: Principal) -> bool:
        return RoleName.ADMINISTRATOR in principal.roles

    @staticmethod
    def _event(
        session: Session,
        *,
        case_id: str,
        actor_id: str,
        event_type: str,
        from_status: str | None = None,
        to_status: str | None = None,
        safe_detail: str | None = None,
    ) -> None:
        session.add(
            CaseEventRecord(
                case_id=case_id,
                actor_id=actor_id,
                event_type=event_type,
                from_status=from_status,
                to_status=to_status,
                safe_detail=safe_detail,
            )
        )


def _case_number(now: datetime) -> str:
    return f"FX-{now.year}-{uuid4().hex[:8].upper()}"


def _required_text(value: str, field: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"{field} must contain between 1 and {maximum} characters")
    return normalized


def _optional_text(value: str | None, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if len(normalized) > maximum:
        raise ValueError(f"{field} cannot exceed {maximum} characters")
    return normalized or None
