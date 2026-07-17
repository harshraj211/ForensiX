"""Versioned preliminary report generation and verified downloads."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, status
from fastapi.responses import FileResponse

from forensix_api.dependencies import (
    get_authenticated_session,
    get_database,
    require_csrf_session,
)
from forensix_api.schemas import ReportOutputResponse, ReportResponse
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database
from forensix_server.reporting import ReportBundle, ReportService

router = APIRouter(tags=["reports"])


@router.get("/api/v1/cases/{case_id}/reports", response_model=list[ReportResponse])
def list_reports(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[ReportResponse]:
    with database.session() as session:
        return [
            _response(bundle)
            for bundle in ReportService().list(session, authenticated.principal, case_id)
        ]


@router.post(
    "/api/v1/cases/{case_id}/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
)
def generate_report(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ReportResponse:
    return _response(ReportService().generate(database, authenticated.principal, case_id))


@router.get("/api/v1/cases/{case_id}/reports/{report_id}", response_model=ReportResponse)
def get_report(
    case_id: str,
    report_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ReportResponse:
    with database.session() as session:
        return _response(ReportService().get(session, authenticated.principal, case_id, report_id))


@router.get("/api/v1/cases/{case_id}/reports/{report_id}/download/{output_format}")
def download_report(
    case_id: str,
    report_id: str,
    output_format: Literal["pdf", "json", "csv"],
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> FileResponse:
    content = ReportService().content(
        database, authenticated.principal, case_id, report_id, output_format
    )
    return FileResponse(
        content.path,
        media_type=content.output.media_type,
        filename=content.output.filename,
        headers={
            "Cache-Control": "no-store, private",
            "Content-Security-Policy": "sandbox; default-src 'none'",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Content-Type-Options": "nosniff",
            "X-ForensiX-Output-SHA256": content.output.sha256,
        },
    )


def _response(bundle: ReportBundle) -> ReportResponse:
    report = bundle.report
    return ReportResponse(
        id=report.id,
        case_id=report.case_id,
        generated_by=report.generated_by,
        report_type="preliminary",
        status="available",
        title=report.title,
        schema_version=report.schema_version,
        template_version=report.template_version,
        snapshot_size_bytes=report.snapshot_size_bytes,
        snapshot_sha256=report.snapshot_sha256,
        generated_at=report.generated_at,
        outputs=[ReportOutputResponse.model_validate(item) for item in bundle.outputs],
    )
