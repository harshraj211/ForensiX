"""Case-scoped, deterministic investigation storyboard."""

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends

from forensix_api.dependencies import get_authenticated_session, get_database
from forensix_api.schemas import InvestigationStoryboardResponse
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database
from forensix_server.investigation import InvestigationStoryboardService

router = APIRouter(prefix="/api/v1/cases/{case_id}/storyboard", tags=["storyboard"])


@router.get("", response_model=InvestigationStoryboardResponse)
def get_storyboard(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> InvestigationStoryboardResponse:
    with database.session() as session:
        storyboard = InvestigationStoryboardService().build(
            session,
            authenticated.principal,
            case_id,
        )
    return InvestigationStoryboardResponse(**asdict(storyboard))
