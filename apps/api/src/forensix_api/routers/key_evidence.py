"""Case-wide key-evidence curation across both artifact families."""

from dataclasses import asdict
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Response, status

from forensix_api.dependencies import (
    get_authenticated_session,
    get_database,
    require_csrf_session,
)
from forensix_api.schemas import (
    KeyEvidenceItemResponse,
    KeyEvidenceListResponse,
    KeyEvidencePromoteRequest,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database
from forensix_server.evidence import (
    KeyEvidenceService,
)

router = APIRouter(prefix="/api/v1/cases/{case_id}/key-evidence", tags=["key-evidence"])


@router.get("", response_model=KeyEvidenceListResponse)
def list_key_evidence(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    query: Annotated[str | None, Query(alias="q", max_length=256)] = None,
    priority: Literal["critical", "high", "normal"] | None = None,
    category: Annotated[str | None, Query(max_length=64)] = None,
) -> KeyEvidenceListResponse:
    with database.session() as session:
        result = KeyEvidenceService().list(
            session,
            authenticated.principal,
            case_id,
            query=query,
            priority=priority,
            category=category,
        )
        return KeyEvidenceListResponse(
            items=[KeyEvidenceItemResponse(**asdict(item)) for item in result.items],
            total=result.total,
            priority_counts=result.priority_counts,
            category_facets=result.category_facets,
        )


@router.post(
    "",
    response_model=KeyEvidenceItemResponse,
    status_code=status.HTTP_201_CREATED,
)
def promote_key_evidence(
    case_id: str,
    request: KeyEvidencePromoteRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> KeyEvidenceItemResponse:
    with database.session() as session:
        item = KeyEvidenceService().promote(
            session,
            authenticated.principal,
            case_id,
            target_type=request.target_type,
            target_id=request.target_id,
            priority=request.priority,
            reason=request.reason,
        )
        return KeyEvidenceItemResponse(**asdict(item))


@router.delete("/{finding_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_key_evidence(
    case_id: str,
    finding_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> Response:
    with database.session() as session:
        KeyEvidenceService().remove(
            session,
            authenticated.principal,
            case_id,
            finding_id,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
