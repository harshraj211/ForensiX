"""Export and Vault endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from forensix_api.dependencies import get_authenticated_session, get_database
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database
from forensix_server.custody_exports.case_uco import CaseUcoExporter

router = APIRouter(prefix="/api/v1/cases", tags=["exports"])


@router.get("/{case_id}/exports/uco", response_class=JSONResponse)
def export_case_uco(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> dict:
    """Export case data in CASE/UCO JSON-LD format."""
    with database.session() as session:
        exporter = CaseUcoExporter(session, authenticated.principal, case_id)
        return exporter.export()
