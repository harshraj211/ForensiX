"""Argon2id credentials, opaque sessions, lockout, and RBAC persistence."""

import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensix_server.config import Settings
from forensix_server.db.models import (
    AuthEventRecord,
    AuthSessionRecord,
    RoleRecord,
    UserRecord,
    UserRoleRecord,
)

from .domain import (
    ROLE_DESCRIPTIONS,
    ROLE_PERMISSIONS,
    AuthenticatedSession,
    Principal,
    RoleName,
)

_USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash("ForensiX-dummy-credential-not-a-user")


class BootstrapAlreadyCompleteError(RuntimeError):
    pass


class PasswordPolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IssuedSession:
    session_token: str
    csrf_token: str
    expires_at: datetime
    principal: Principal


class AuthService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def ensure_roles(self, session: Session) -> None:
        existing = set(session.scalars(select(RoleRecord.name)))
        for role_name, description in ROLE_DESCRIPTIONS.items():
            if role_name.value not in existing:
                session.add(RoleRecord(name=role_name.value, description=description))
        session.flush()

    def bootstrap_required(self, session: Session) -> bool:
        return session.scalar(select(func.count()).select_from(UserRecord)) == 0

    def bootstrap_administrator(
        self,
        session: Session,
        *,
        username: str,
        display_name: str,
        password: str,
    ) -> IssuedSession:
        if not self.bootstrap_required(session):
            raise BootstrapAlreadyCompleteError("The first administrator already exists.")

        normalized_username = self.normalize_username(username)
        normalized_display_name = display_name.strip()
        if not 1 <= len(normalized_display_name) <= 128:
            raise ValueError("display_name must contain between 1 and 128 characters")
        self.validate_password(password)
        self.ensure_roles(session)
        now = datetime.now(UTC)
        user = UserRecord(
            username=normalized_username,
            display_name=normalized_display_name,
            password_hash=_PASSWORD_HASHER.hash(password),
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(user)
        session.flush()
        administrator = session.scalar(
            select(RoleRecord).where(RoleRecord.name == RoleName.ADMINISTRATOR.value)
        )
        if administrator is None:  # defensive invariant after ensure_roles
            raise RuntimeError("administrator role seed is unavailable")
        session.add(UserRoleRecord(user_id=user.id, role_id=administrator.id))
        self._record_event(
            session,
            username=normalized_username,
            user_id=user.id,
            event_type="bootstrap",
            outcome="success",
        )
        session.flush()
        return self._issue_session(session, user, now)

    def login(self, session: Session, *, username: str, password: str) -> IssuedSession | None:
        normalized_username = self._normalize_username_for_lookup(username)
        user = session.scalar(select(UserRecord).where(UserRecord.username == normalized_username))
        password_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH
        password_valid = self._verify_password(password_hash, password)
        now = datetime.now(UTC)

        if user is None:
            self._record_event(
                session,
                username=normalized_username,
                user_id=None,
                event_type="login",
                outcome="failure",
                safe_detail="invalid_credentials",
            )
            session.flush()
            return None

        locked_until = _as_utc(user.locked_until) if user.locked_until is not None else None
        is_locked = locked_until is not None and locked_until > now
        if not password_valid or not user.is_active or is_locked:
            if not is_locked:
                user.failed_login_count += 1
                if user.failed_login_count >= self._settings.login_max_failures:
                    user.locked_until = now + timedelta(
                        minutes=self._settings.login_lockout_minutes
                    )
            user.updated_at = now
            self._record_event(
                session,
                username=user.username,
                user_id=user.id,
                event_type="login",
                outcome="failure",
                safe_detail="account_unavailable" if is_locked else "invalid_credentials",
            )
            session.flush()
            return None

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        user.updated_at = now
        if _PASSWORD_HASHER.check_needs_rehash(user.password_hash):
            user.password_hash = _PASSWORD_HASHER.hash(password)
            user.password_changed_at = now
        self._record_event(
            session,
            username=user.username,
            user_id=user.id,
            event_type="login",
            outcome="success",
        )
        session.flush()
        return self._issue_session(session, user, now)

    def authenticate(
        self, session: Session, session_token: str | None
    ) -> AuthenticatedSession | None:
        if not session_token:
            return None
        now = datetime.now(UTC)
        record = session.scalar(
            select(AuthSessionRecord).where(
                AuthSessionRecord.token_hash == _secret_hash(session_token)
            )
        )
        if record is None or record.revoked_at is not None or _as_utc(record.expires_at) <= now:
            return None
        user = session.get(UserRecord, record.user_id)
        if user is None or not user.is_active:
            return None

        record.last_seen_at = now
        principal = self._principal(session, user)
        session.flush()
        return AuthenticatedSession(
            session_id=record.id,
            principal=principal,
            csrf_hash=record.csrf_hash,
            expires_at=_as_utc(record.expires_at),
        )

    def revoke(
        self,
        session: Session,
        authenticated: AuthenticatedSession,
        csrf_token: str,
    ) -> bool:
        if not self.verify_csrf(authenticated, csrf_token):
            return False
        record = session.get(AuthSessionRecord, authenticated.session_id)
        if record is None or record.revoked_at is not None:
            return False
        record.revoked_at = datetime.now(UTC)
        self._record_event(
            session,
            username=authenticated.principal.username,
            user_id=authenticated.principal.user_id,
            event_type="logout",
            outcome="success",
        )
        session.flush()
        return True

    def rotate(
        self,
        session: Session,
        authenticated: AuthenticatedSession,
        csrf_token: str,
    ) -> IssuedSession | None:
        if not self.verify_csrf(authenticated, csrf_token):
            return None
        record = session.get(AuthSessionRecord, authenticated.session_id)
        user = session.get(UserRecord, authenticated.principal.user_id)
        if record is None or user is None or record.revoked_at is not None:
            return None
        now = datetime.now(UTC)
        record.revoked_at = now
        issued = self._issue_session(session, user, now)
        self._record_event(
            session,
            username=user.username,
            user_id=user.id,
            event_type="refresh",
            outcome="success",
        )
        session.flush()
        return issued

    @staticmethod
    def verify_csrf(authenticated: AuthenticatedSession, csrf_token: str | None) -> bool:
        return bool(
            csrf_token
            and secrets.compare_digest(
                authenticated.csrf_hash,
                _secret_hash(csrf_token),
            )
        )

    @staticmethod
    def normalize_username(username: str) -> str:
        normalized = username.strip().lower()
        if not _USERNAME_PATTERN.fullmatch(normalized):
            raise ValueError(
                "username must start with a letter and use 3-64 lowercase letters, digits, "
                "dot, dash, or underscore"
            )
        return normalized

    @staticmethod
    def validate_password(password: str) -> None:
        if not 12 <= len(password) <= 128:
            raise PasswordPolicyError("password must contain between 12 and 128 characters")
        classes = sum(
            (
                any(character.islower() for character in password),
                any(character.isupper() for character in password),
                any(character.isdigit() for character in password),
                any(not character.isalnum() for character in password),
            )
        )
        if classes < 3:
            raise PasswordPolicyError(
                "password must contain at least three of lowercase, uppercase, number, and symbol"
            )

    def _issue_session(
        self,
        session: Session,
        user: UserRecord,
        now: datetime,
    ) -> IssuedSession:
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(minutes=self._settings.session_ttl_minutes)
        record = AuthSessionRecord(
            user_id=user.id,
            token_hash=_secret_hash(session_token),
            csrf_hash=_secret_hash(csrf_token),
            created_at=now,
            expires_at=expires_at,
            last_seen_at=now,
        )
        session.add(record)
        session.flush()
        return IssuedSession(
            session_token=session_token,
            csrf_token=csrf_token,
            expires_at=expires_at,
            principal=self._principal(session, user),
        )

    @staticmethod
    def _principal(session: Session, user: UserRecord) -> Principal:
        role_names = session.scalars(
            select(RoleRecord.name)
            .join(UserRoleRecord, UserRoleRecord.role_id == RoleRecord.id)
            .where(UserRoleRecord.user_id == user.id)
        )
        roles = frozenset(RoleName(role_name) for role_name in role_names)
        permissions = frozenset(
            permission for role in roles for permission in ROLE_PERMISSIONS[role]
        )
        return Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=roles,
            permissions=permissions,
        )

    @staticmethod
    def _record_event(
        session: Session,
        *,
        username: str,
        user_id: str | None,
        event_type: str,
        outcome: str,
        safe_detail: str | None = None,
    ) -> None:
        session.add(
            AuthEventRecord(
                user_id=user_id,
                username_hash=_secret_hash(username),
                event_type=event_type,
                outcome=outcome,
                safe_detail=safe_detail,
            )
        )

    @staticmethod
    def _normalize_username_for_lookup(username: str) -> str:
        normalized = username.strip().lower()
        return normalized[:64]

    @staticmethod
    def _verify_password(password_hash: str, password: str) -> bool:
        try:
            return _PASSWORD_HASHER.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


def _secret_hash(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
