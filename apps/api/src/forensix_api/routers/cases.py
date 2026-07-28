"""Case lifecycle and membership endpoints."""

import json
from dataclasses import asdict
from typing import Annotated, Literal, TypedDict

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import select

from forensix_api.dependencies import (
    get_authenticated_session,
    get_database,
    require_csrf_session,
)
from forensix_api.schemas import (
    AcquisitionCompletenessResponse,
    AcquisitionPlanCreateRequest,
    AcquisitionPlanListResponse,
    AcquisitionPlanResponse,
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
    CommandCenterActivityResponse,
    CommandCenterAttentionResponse,
    CommandCenterEvidenceResponse,
    CommandCenterIntegrityResponse,
    CommandCenterJobsResponse,
    CommandCenterResponse,
    CompletenessItem,
)
from forensix_server.acquisitions import (
    AcquisitionModule,
    AcquisitionPlanService,
    AcquisitionScope,
    plan_limitations,
    plan_modules,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseService, CaseStatus
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionInventoryItemRecord,
    AcquisitionPlanRecord,
    Database,
)
from forensix_server.investigation import InvestigationCommandCenterService

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])

CompletenessStatus = Literal["captured", "partial", "blocked", "failed", "not_present"]


class _CompletenessCategory(TypedDict):
    keywords: list[str]
    status: CompletenessStatus
    reason: str | None


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


@router.get("/{case_id}/command-center", response_model=CommandCenterResponse)
def get_command_center(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CommandCenterResponse:
    with database.session() as session:
        summary = InvestigationCommandCenterService().summarize(
            session, authenticated.principal, case_id
        )
        return CommandCenterResponse(
            case_id=summary.case_id,
            generated_at=summary.generated_at,
            device_count=summary.device_count,
            jobs=CommandCenterJobsResponse(**asdict(summary.jobs)),
            evidence=CommandCenterEvidenceResponse(**asdict(summary.evidence)),
            integrity=CommandCenterIntegrityResponse(**asdict(summary.integrity)),
            timeline_event_count=summary.timeline_event_count,
            report_count=summary.report_count,
            reports_pending_review=summary.reports_pending_review,
            next_action=summary.next_action,
            attention=[
                CommandCenterAttentionResponse(**asdict(item)) for item in summary.attention
            ],
            recent_activity=[
                CommandCenterActivityResponse(**asdict(item)) for item in summary.recent_activity
            ],
        )


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


@router.get(
    "/{case_id}/acquisition-plans",
    response_model=AcquisitionPlanListResponse,
)
def list_acquisition_plans(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> AcquisitionPlanListResponse:
    with database.session() as session:
        plans, total = AcquisitionPlanService().list_for_case(
            session,
            authenticated.principal,
            case_id,
            offset=offset,
            limit=limit,
        )
        items = [_plan_response(plan) for plan in plans]
    return AcquisitionPlanListResponse(
        items=items,
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post(
    "/{case_id}/acquisition-plans",
    response_model=AcquisitionPlanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_acquisition_plan(
    case_id: str,
    request: AcquisitionPlanCreateRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> AcquisitionPlanResponse:
    with database.session() as session:
        plan = AcquisitionPlanService().create(
            session,
            authenticated.principal,
            case_id,
            device_id=request.device_id,
            assessment_id=request.assessment_id,
            scope=request.scope,
            requested_modules=tuple(request.modules),
            limitations_acknowledged=request.limitations_acknowledged,
        )
        return _plan_response(plan)


@router.get(
    "/{case_id}/acquisition-plans/{plan_id}",
    response_model=AcquisitionPlanResponse,
)
def get_acquisition_plan(
    case_id: str,
    plan_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> AcquisitionPlanResponse:
    with database.session() as session:
        plan = AcquisitionPlanService().get(session, authenticated.principal, case_id, plan_id)
        return _plan_response(plan)


def _plan_response(plan: AcquisitionPlanRecord) -> AcquisitionPlanResponse:
    return AcquisitionPlanResponse(
        id=plan.id,
        case_id=plan.case_id,
        device_id=plan.device_id,
        assessment_id=plan.assessment_id,
        created_by=plan.created_by,
        scope=AcquisitionScope(plan.scope),
        status="ready",
        modules=[AcquisitionModule(module) for module in plan_modules(plan)],
        limitations=plan_limitations(plan),
        snapshot_hash=plan.snapshot_hash,
        plan_hash=plan.plan_hash,
        schema_version=plan.schema_version,
        readiness_assessed_at=plan.readiness_assessed_at,
        readiness_expires_at=plan.readiness_expires_at,
        created_at=plan.created_at,
    )


@router.get("/{case_id}/completeness", response_model=AcquisitionCompletenessResponse)
def get_case_completeness(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> AcquisitionCompletenessResponse:
    with database.session() as session:
        CaseService().get(session, authenticated.principal, case_id)

        query = select(
            AcquiredEvidenceFileRecord.status,
            AcquiredEvidenceFileRecord.error_message,
            AcquisitionInventoryItemRecord.relative_path,
        ).join(
            AcquisitionInventoryItemRecord,
            AcquiredEvidenceFileRecord.inventory_item_id == AcquisitionInventoryItemRecord.id,
        ).where(AcquiredEvidenceFileRecord.case_id == case_id)

        results = session.execute(query).all()

        categories: dict[str, _CompletenessCategory] = {
            "Device Info": {
                "keywords": ["device_info", "metadata"],
                "status": "not_present",
                "reason": None,
            },
            "Contacts": {"keywords": ["contacts2.db"], "status": "not_present", "reason": None},
            "Call Logs": {"keywords": ["calllog.db"], "status": "not_present", "reason": None},
            "SMS": {
                "keywords": ["mmssms.db", "telephony.db"],
                "status": "not_present",
                "reason": None,
            },
            "App Inventory": {
                "keywords": ["packages.xml", "inventory"],
                "status": "not_present",
                "reason": None,
            },
            "Media": {
                "keywords": [".jpg", ".png", ".mp4", ".jpeg"],
                "status": "not_present",
                "reason": None,
            },
        }

        for r_status, r_error, r_path in results:
            path_lower = r_path.lower()
            for data in categories.values():
                if any(kw in path_lower for kw in data["keywords"]):
                    if r_status == "completed":
                        data["status"] = "captured"
                    elif r_status == "failed" and data["status"] != "captured":
                        data["status"] = "failed"
                        data["reason"] = r_error
                    break

        items = [
            CompletenessItem(
                artifact=category,
                status=data["status"],
                reason=data["reason"],
            )
            for category, data in categories.items()
        ]

        return AcquisitionCompletenessResponse(case_id=case_id, items=items)
