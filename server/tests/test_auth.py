from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_server.auth import (
    AuthService,
    BootstrapAlreadyCompleteError,
    PasswordPolicyError,
    Permission,
    RoleName,
)
from forensix_server.config import Settings
from forensix_server.db import AuthEventRecord, AuthSessionRecord, Database, UserRecord

PASSWORD = "StrongPass!2026"


@pytest.fixture
def auth_context(tmp_path: Path) -> Iterator[tuple[Database, AuthService]]:
    database_path = tmp_path / "auth.db"
    database = Database(f"sqlite:///{database_path.as_posix()}", tmp_path)
    database.initialize()
    settings = Settings(
        environment="test",
        data_dir=tmp_path,
        login_max_failures=3,
        login_lockout_minutes=10,
    )
    service = AuthService(settings)
    with database.session() as session:
        service.ensure_roles(session)
    yield database, service
    database.dispose()


def _bootstrap(database: Database, service: AuthService) -> str:
    with database.session() as session:
        issued = service.bootstrap_administrator(
            session,
            username="Admin.User",
            display_name="Primary Administrator",
            password=PASSWORD,
        )
    return issued.session_token


def test_bootstrap_creates_argon2id_administrator_and_hashed_session(
    auth_context: tuple[Database, AuthService],
) -> None:
    database, service = auth_context

    token = _bootstrap(database, service)

    with database.session() as session:
        user = session.scalar(select(UserRecord))
        auth_session = session.scalar(select(AuthSessionRecord))
        events = list(session.scalars(select(AuthEventRecord)))
        authenticated = service.authenticate(session, token)
    assert user is not None
    assert user.username == "admin.user"
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash
    assert auth_session is not None
    assert auth_session.token_hash != token
    assert authenticated is not None
    assert authenticated.principal.roles == frozenset({RoleName.ADMINISTRATOR})
    assert authenticated.principal.can(Permission.USERS_MANAGE)
    assert events[0].username_hash != "admin.user"


def test_bootstrap_is_single_use(auth_context: tuple[Database, AuthService]) -> None:
    database, service = auth_context
    _bootstrap(database, service)

    with database.session() as session, pytest.raises(BootstrapAlreadyCompleteError):
        service.bootstrap_administrator(
            session,
            username="second.admin",
            display_name="Second Administrator",
            password=PASSWORD,
        )


@pytest.mark.parametrize(
    "password",
    ["short", "alllowercasepassword", "ALLUPPERCASE2026", "NoNumbersOrSymbol"],
)
def test_password_policy_rejects_weak_passwords(
    auth_context: tuple[Database, AuthService], password: str
) -> None:
    database, service = auth_context

    with database.session() as session, pytest.raises(PasswordPolicyError):
        service.bootstrap_administrator(
            session,
            username="admin.user",
            display_name="Administrator",
            password=password,
        )


def test_failed_logins_lock_account_without_storing_attempted_password(
    auth_context: tuple[Database, AuthService],
) -> None:
    database, service = auth_context
    _bootstrap(database, service)

    for _ in range(3):
        with database.session() as session:
            assert service.login(session, username="admin.user", password="WrongPass!2026") is None

    with database.session() as session:
        user = session.scalar(select(UserRecord))
        assert user is not None
        assert user.failed_login_count == 3
        assert user.locked_until is not None
        assert service.login(session, username="admin.user", password=PASSWORD) is None


def test_login_session_csrf_rotation_and_revocation(
    auth_context: tuple[Database, AuthService],
) -> None:
    database, service = auth_context
    _bootstrap(database, service)

    with database.session() as session:
        issued = service.login(session, username="ADMIN.USER", password=PASSWORD)
    assert issued is not None

    with database.session() as session:
        authenticated = service.authenticate(session, issued.session_token)
    assert authenticated is not None
    assert not service.verify_csrf(authenticated, "wrong-token")
    assert service.verify_csrf(authenticated, issued.csrf_token)

    with database.session() as session:
        rotated = service.rotate(session, authenticated, issued.csrf_token)
    assert rotated is not None
    with database.session() as session:
        assert service.authenticate(session, issued.session_token) is None
        new_authenticated = service.authenticate(session, rotated.session_token)
    assert new_authenticated is not None

    with database.session() as session:
        assert service.revoke(session, new_authenticated, rotated.csrf_token)
    with database.session() as session:
        assert service.authenticate(session, rotated.session_token) is None


def test_expired_session_is_rejected(auth_context: tuple[Database, AuthService]) -> None:
    database, service = auth_context
    token = _bootstrap(database, service)

    with Session(database.engine) as session:
        record = session.scalar(select(AuthSessionRecord))
        assert record is not None
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    with database.session() as session:
        assert service.authenticate(session, token) is None
