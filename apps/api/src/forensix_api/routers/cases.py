"""Case lifecycle and membership endpoints."""

import json
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from forensix_api.dependencies import (
    get_authenticated_session,
    get_database,
    require_csrf_session,
)
from forensix_api.schemas import (
    ApiErrorResponse,
    CaseCreateRequest,
    CaseDeviceAssessmentResponse,
    CaseDeviceResponse,
    CaseEventResponse,
    CaseListResponse,
    CaseMemberRequest,
    CaseMemberResponse,
    CaseResponse,
    CaseTransitionRequest,
    CaseUpdateRequest,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseService, CaseStatus
from forensix_server.db import Database

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


@router.get("", response_model=CaseListResponse, responses={401: {"model": ApiErrorResponse}})
def list_cases(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    case_status: Annotated[CaseStatus | None, Query(alias="status")] = None,
) -> CaseListResponse:
    with database.session() as session:
        items, total = CaseService().list_accessible(
            session,
            authenticated.principal,
            offset=offset,
            limit=limit,
            status=case_status,
        )
        responses = [CaseResponse.model_validate(item) for item in items]
    return CaseListResponse(items=responses, total=total, offset=offset, limit=limit)


@router.post(
    "",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    responses={401: {"model": ApiErrorResponse}, 403: {"model": ApiErrorResponse}},
)
def create_case(
    request: CaseCreateRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CaseResponse:
    with database.session() as session:
        case = CaseService().create(
            session,
            authenticated.principal,
            title=request.title,
            description=request.description,
            legal_authority=request.legal_authority,
        )
        response = CaseResponse.model_validate(case)
    return response


@router.get(
    "/{case_id}",
    response_model=CaseResponse,
    responses={
        401: {"model": ApiErrorResponse},
        403: {"model": ApiErrorResponse},
        404: {"model": ApiErrorResponse},
    },
)
def get_case(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CaseResponse:
    with database.session() as session:
        case = CaseService().get(session, authenticated.principal, case_id)
        response = CaseResponse.model_validate(case)
    return response


@router.patch(
    "/{case_id}",
    response_model=CaseResponse,
    responses={
        401: {"model": ApiErrorResponse},
        403: {"model": ApiErrorResponse},
        404: {"model": ApiErrorResponse},
        409: {"model": ApiErrorResponse},
    },
)
def update_case(
    case_id: str,
    request: CaseUpdateRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CaseResponse:
    with database.session() as session:
        case = CaseService().update(
            session,
            authenticated.principal,
            case_id,
            expected_version=request.expected_version,
            title=request.title,
            description=request.description,
            legal_authority=request.legal_authority,
        )
        response = CaseResponse.model_validate(case)
    return response


@router.post(
    "/{case_id}/transition",
    response_model=CaseResponse,
    responses={
        401: {"model": ApiErrorResponse},
        403: {"model": ApiErrorResponse},
        404: {"model": ApiErrorResponse},
        409: {"model": ApiErrorResponse},
    },
)
def transition_case(
    case_id: str,
    request: CaseTransitionRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CaseResponse:
    with database.session() as session:
        case = CaseService().transition(
            session,
            authenticated.principal,
            case_id,
            requested=request.status,
            expected_version=request.expected_version,
        )
        response = CaseResponse.model_validate(case)
    return response


@router.get("/{case_id}/members", response_model=list[CaseMemberResponse])
def list_case_members(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[CaseMemberResponse]:
    with database.session() as session:
        members = CaseService().list_members(session, authenticated.principal, case_id)
        return [CaseMemberResponse.model_validate(member) for member in members]


@router.post(
    "/{case_id}/members",
    response_model=CaseMemberResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_case_member(
    case_id: str,
    request: CaseMemberRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CaseMemberResponse:
    with database.session() as session:
        member = CaseService().add_member(
            session,
            authenticated.principal,
            case_id,
            user_id=request.user_id,
            access_level=request.access_level,
        )
        response = CaseMemberResponse.model_validate(member)
    return response


@router.delete("/{case_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_case_member(
    case_id: str,
    user_id: str,
    response: Response,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> None:
    with database.session() as session:
        CaseService().remove_member(
            session,
            authenticated.principal,
            case_id,
            user_id=user_id,
        )
    response.status_code = status.HTTP_204_NO_CONTENT


@router.get("/{case_id}/events", response_model=list[CaseEventResponse])
def list_case_events(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[CaseEventResponse]:
    with database.session() as session:
        events = CaseService().list_events(session, authenticated.principal, case_id)
        return [CaseEventResponse.model_validate(event) for event in events]


@router.get("/{case_id}/devices", response_model=list[CaseDeviceResponse])
def list_case_devices(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[CaseDeviceResponse]:
    with database.session() as session:
        devices = CaseDeviceService().list_devices(session, authenticated.principal, case_id)
        return [CaseDeviceResponse.model_validate(device) for device in devices]


@router.get("/{case_id}/devices/{device_id}", response_model=CaseDeviceResponse)
def get_case_device(
    case_id: str,
    device_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CaseDeviceResponse:
    with database.session() as session:
        device = CaseDeviceService().get_device(
            session, authenticated.principal, case_id, device_id
        )
        return CaseDeviceResponse.model_validate(device)


@router.get(
    "/{case_id}/devices/{device_id}/assessments",
    response_model=list[CaseDeviceAssessmentResponse],
)
def list_case_device_assessments(
    case_id: str,
    device_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[CaseDeviceAssessmentResponse]:
    with database.session() as session:
        assessments = CaseDeviceService().list_assessments(
            session, authenticated.principal, case_id, device_id
        )
        return [
            CaseDeviceAssessmentResponse(
                id=assessment.id,
                case_id=assessment.case_id,
                device_id=assessment.device_id,
                assessed_by=assessment.assessed_by,
                **json.loads(assessment.snapshot_json),
            )
            for assessment in assessments
        ]
