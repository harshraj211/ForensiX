"""Composition helpers for API dependencies."""

import secrets
from typing import Annotated, cast

from fastapi import Cookie, Depends, Header, Request, status

from forensix_api.errors import ApiSecurityError
from forensix_forensic.adb import (
    AdbBinaryResolver,
    AdbClient,
    SubprocessAdbRunner,
    SystemAdbClient,
)
from forensix_server.auth import AuthenticatedSession, AuthService, Permission
from forensix_server.config import Settings
from forensix_server.db import Database

SESSION_COOKIE = "forensix_session"
CSRF_COOKIE = "forensix_csrf"


def get_settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def get_database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def get_auth_service(request: Request) -> AuthService:
    return cast(AuthService, request.app.state.auth_service)


def get_authenticated_session(
    database: Annotated[Database, Depends(get_database)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> AuthenticatedSession:
    with database.session() as session:
        authenticated = auth_service.authenticate(session, session_token)
    if authenticated is None:
        raise ApiSecurityError(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "A valid local ForensiX session is required.",
        )
    return authenticated


def require_csrf_session(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
    csrf_header: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> AuthenticatedSession:
    if (
        not csrf_cookie
        or not csrf_header
        or not secrets.compare_digest(csrf_cookie, csrf_header)
        or not auth_service.verify_csrf(authenticated, csrf_header)
    ):
        raise ApiSecurityError(
            status.HTTP_403_FORBIDDEN,
            "CSRF_VALIDATION_FAILED",
            "The request CSRF token is missing or invalid.",
        )
    return authenticated


def require_device_operator(
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
) -> AuthenticatedSession:
    if not authenticated.principal.can(Permission.DEVICES_OPERATE):
        raise ApiSecurityError(
            status.HTTP_403_FORBIDDEN,
            "PERMISSION_DENIED",
            "The current user cannot operate Android devices.",
        )
    return authenticated


def get_adb_client(request: Request) -> AdbClient:
    injected = cast(AdbClient | None, request.app.state.adb_client)
    if injected is not None:
        return injected
    settings: Settings = request.app.state.settings
    adb_path = AdbBinaryResolver(settings.adb_path).resolve()
    return SystemAdbClient(SubprocessAdbRunner(adb_path))
