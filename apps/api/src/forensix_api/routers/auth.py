"""Offline bootstrap, login, session rotation, and logout endpoints."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response, status

from forensix_api.dependencies import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    get_auth_service,
    get_authenticated_session,
    get_database,
    get_settings,
    require_csrf_session,
)
from forensix_api.errors import ApiSecurityError
from forensix_api.schemas import (
    ApiErrorResponse,
    AuthBootstrapRequest,
    AuthBootstrapStatusResponse,
    AuthLoginRequest,
    AuthSessionResponse,
    AuthUserResponse,
)
from forensix_server.auth import (
    AuthenticatedSession,
    AuthService,
    BootstrapAlreadyCompleteError,
    PasswordPolicyError,
    Principal,
)
from forensix_server.auth.service import IssuedSession
from forensix_server.config import Settings
from forensix_server.db import Database

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


@router.get("/bootstrap-status", response_model=AuthBootstrapStatusResponse)
def bootstrap_status(
    database: Annotated[Database, Depends(get_database)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> AuthBootstrapStatusResponse:
    with database.session() as session:
        required = auth_service.bootstrap_required(session)
    return AuthBootstrapStatusResponse(bootstrap_required=required)


@router.post(
    "/bootstrap",
    response_model=AuthSessionResponse,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"model": ApiErrorResponse}, 422: {"model": ApiErrorResponse}},
)
def bootstrap_administrator(
    request: AuthBootstrapRequest,
    response: Response,
    database: Annotated[Database, Depends(get_database)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthSessionResponse:
    try:
        with database.session() as session:
            issued = auth_service.bootstrap_administrator(
                session,
                username=request.username,
                display_name=request.display_name,
                password=request.password,
            )
    except BootstrapAlreadyCompleteError as error:
        raise ApiSecurityError(409, "BOOTSTRAP_ALREADY_COMPLETE", str(error)) from error
    except (PasswordPolicyError, ValueError) as error:
        raise ApiSecurityError(422, "INVALID_BOOTSTRAP_INPUT", str(error)) from error
    _set_auth_cookies(response, issued, settings)
    return _session_response(issued)


@router.post(
    "/login",
    response_model=AuthSessionResponse,
    responses={401: {"model": ApiErrorResponse}},
)
def login(
    request: AuthLoginRequest,
    response: Response,
    database: Annotated[Database, Depends(get_database)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthSessionResponse:
    with database.session() as session:
        issued = auth_service.login(
            session,
            username=request.username,
            password=request.password,
        )
    if issued is None:
        raise ApiSecurityError(
            status.HTTP_401_UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "The username or password is invalid, or the account is unavailable.",
        )
    _set_auth_cookies(response, issued, settings)
    return _session_response(issued)


@router.get(
    "/me",
    response_model=AuthUserResponse,
    responses={401: {"model": ApiErrorResponse}},
)
def current_user(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
) -> AuthUserResponse:
    return _user_response(authenticated.principal)


@router.post(
    "/refresh",
    response_model=AuthSessionResponse,
    responses={401: {"model": ApiErrorResponse}, 403: {"model": ApiErrorResponse}},
)
def refresh(
    response: Response,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings)],
    csrf_token: Annotated[str, Header(alias="X-CSRF-Token")],
) -> AuthSessionResponse:
    with database.session() as session:
        issued = auth_service.rotate(session, authenticated, csrf_token)
    if issued is None:
        raise ApiSecurityError(
            status.HTTP_401_UNAUTHORIZED,
            "SESSION_REFRESH_FAILED",
            "The local session could not be refreshed.",
        )
    _set_auth_cookies(response, issued, settings)
    return _session_response(issued)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={401: {"model": ApiErrorResponse}, 403: {"model": ApiErrorResponse}},
)
def logout(
    response: Response,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    csrf_token: Annotated[str, Header(alias="X-CSRF-Token")],
) -> None:
    with database.session() as session:
        revoked = auth_service.revoke(session, authenticated, csrf_token)
    if not revoked:
        raise ApiSecurityError(
            status.HTTP_401_UNAUTHORIZED,
            "SESSION_REVOCATION_FAILED",
            "The local session could not be revoked.",
        )
    response.delete_cookie(SESSION_COOKIE, path="/api/v1")
    response.delete_cookie(CSRF_COOKIE, path="/api/v1")


def _set_auth_cookies(response: Response, issued: IssuedSession, settings: Settings) -> None:
    max_age = max(0, int((issued.expires_at - datetime.now(UTC)).total_seconds()))
    response.set_cookie(
        SESSION_COOKIE,
        issued.session_token,
        max_age=max_age,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        path="/api/v1",
    )
    response.set_cookie(
        CSRF_COOKIE,
        issued.csrf_token,
        max_age=max_age,
        httponly=False,
        secure=settings.secure_cookies,
        samesite="strict",
        path="/api/v1",
    )


def _session_response(issued: IssuedSession) -> AuthSessionResponse:
    return AuthSessionResponse(
        user=_user_response(issued.principal),
        expires_at=issued.expires_at,
        csrf_token=issued.csrf_token,
    )


def _user_response(principal: Principal) -> AuthUserResponse:
    return AuthUserResponse(
        user_id=principal.user_id,
        username=principal.username,
        display_name=principal.display_name,
        roles=sorted(role.value for role in principal.roles),
        permissions=sorted(permission.value for permission in principal.permissions),
    )
