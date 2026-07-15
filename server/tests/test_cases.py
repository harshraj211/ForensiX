from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_server.auth.domain import ROLE_PERMISSIONS, Principal, RoleName
from forensix_server.cases import (
    CaseAccessDeniedError,
    CaseAccessLevel,
    CaseInvalidStateError,
    CaseMemberError,
    CaseService,
    CaseStatus,
    CaseVersionConflictError,
)
from forensix_server.db import CaseEventRecord, CaseMemberRecord, Database, UserRecord


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    database_path = tmp_path / "cases.db"
    database = Database(f"sqlite:///{database_path.as_posix()}", tmp_path)
    database.initialize()
    with database.session() as active_session:
        yield active_session
    database.dispose()


def _user(session: Session, username: str) -> UserRecord:
    user = UserRecord(
        username=username,
        display_name=username.replace(".", " ").title(),
        password_hash="$argon2id$test-placeholder",
    )
    session.add(user)
    session.flush()
    return user


def _principal(user: UserRecord, role: RoleName) -> Principal:
    return Principal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        roles=frozenset({role}),
        permissions=ROLE_PERMISSIONS[role],
    )


def test_create_case_assigns_owner_and_append_only_event(session: Session) -> None:
    service = CaseService()
    creator = _principal(_user(session, "case.owner"), RoleName.INVESTIGATOR)

    case = service.create(
        session,
        creator,
        title="Controlled Android examination",
        description="Known test device",
        legal_authority="Internal validation authorization",
    )

    member = session.get(CaseMemberRecord, (case.id, creator.user_id))
    event = session.scalar(select(CaseEventRecord))
    assert case.case_number.startswith("FX-")
    assert case.status == CaseStatus.OPEN.value
    assert member is not None
    assert member.access_level == CaseAccessLevel.OWNER.value
    assert event is not None
    assert event.event_type == "case_created"


def test_nonmember_cannot_read_case(session: Session) -> None:
    service = CaseService()
    creator = _principal(_user(session, "case.owner"), RoleName.INVESTIGATOR)
    outsider = _principal(_user(session, "case.outsider"), RoleName.ANALYST)
    case = service.create(session, creator, title="Restricted case")

    with pytest.raises(CaseAccessDeniedError):
        service.get(session, outsider, case.id)


def test_administrator_can_list_all_cases_without_membership(session: Session) -> None:
    service = CaseService()
    creator = _principal(_user(session, "case.owner"), RoleName.INVESTIGATOR)
    administrator = _principal(_user(session, "system.admin"), RoleName.ADMINISTRATOR)
    service.create(session, creator, title="Case one")
    service.create(session, creator, title="Case two")

    cases, total = service.list_accessible(session, administrator)

    assert total == 2
    assert {case.title for case in cases} == {"Case one", "Case two"}


def test_case_update_requires_expected_version(session: Session) -> None:
    service = CaseService()
    creator = _principal(_user(session, "case.owner"), RoleName.INVESTIGATOR)
    case = service.create(session, creator, title="Original title")

    updated = service.update(
        session,
        creator,
        case.id,
        expected_version=1,
        title="Updated title",
    )

    assert updated.title == "Updated title"
    assert updated.version == 2
    with pytest.raises(CaseVersionConflictError):
        service.update(
            session,
            creator,
            case.id,
            expected_version=1,
            title="Stale update",
        )


def test_case_lifecycle_enforces_transition_graph_and_reopen_role(session: Session) -> None:
    service = CaseService()
    investigator = _principal(_user(session, "case.owner"), RoleName.INVESTIGATOR)
    case = service.create(session, investigator, title="Lifecycle case")
    active = service.transition(
        session,
        investigator,
        case.id,
        requested=CaseStatus.ACTIVE,
        expected_version=1,
    )
    closed = service.transition(
        session,
        investigator,
        case.id,
        requested=CaseStatus.CLOSED,
        expected_version=active.version,
    )

    with pytest.raises(CaseAccessDeniedError):
        service.transition(
            session,
            investigator,
            case.id,
            requested=CaseStatus.ACTIVE,
            expected_version=closed.version,
        )
    with pytest.raises(CaseInvalidStateError):
        service.transition(
            session,
            investigator,
            case.id,
            requested=CaseStatus.OPEN,
            expected_version=closed.version,
        )


def test_owner_can_add_member_but_creator_cannot_be_removed(session: Session) -> None:
    service = CaseService()
    creator = _principal(_user(session, "case.owner"), RoleName.INVESTIGATOR)
    analyst = _user(session, "case.analyst")
    case = service.create(session, creator, title="Membership case")

    membership = service.add_member(
        session,
        creator,
        case.id,
        user_id=analyst.id,
        access_level=CaseAccessLevel.ANALYST,
    )
    service.remove_member(session, creator, case.id, user_id=analyst.id)

    assert membership.access_level == CaseAccessLevel.ANALYST.value
    assert session.get(CaseMemberRecord, (case.id, analyst.id)) is None
    with pytest.raises(CaseMemberError):
        service.remove_member(session, creator, case.id, user_id=creator.user_id)


def test_closed_case_cannot_be_edited(session: Session) -> None:
    service = CaseService()
    creator = _principal(_user(session, "case.owner"), RoleName.INVESTIGATOR)
    case = service.create(session, creator, title="Closed case")
    closed = service.transition(
        session,
        creator,
        case.id,
        requested=CaseStatus.CLOSED,
        expected_version=1,
    )

    with pytest.raises(CaseInvalidStateError):
        service.update(
            session,
            creator,
            case.id,
            expected_version=closed.version,
            title="Should fail",
        )
