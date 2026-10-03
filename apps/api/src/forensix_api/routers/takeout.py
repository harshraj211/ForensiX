"""Compatibility endpoint; Takeout now uses sealed sources and versioned parsers."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import func, select

from forensix_api.dependencies import get_database, require_csrf_session
from forensix_forensic.extractors.cloud.exports import CloudExportError
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database, EvidenceSourceTimelineEventRecord
from forensix_server.evidence_twin.cloud_exports import CloudExportService

router = APIRouter(prefix="/api/v1/cases", tags=["takeout"])


@router.post("/{case_id}/takeout/import")
def import_takeout(
    case_id: str,
    file: Annotated[UploadFile, File()],
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> dict[str, int | str]:
    try:
        source, run, _ = CloudExportService().import_stream(
            database,
            authenticated.principal,
            case_id,
            file.file,
            source_name=file.filename or "takeout.zip",
            provider="google",
        )
    except CloudExportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        file.file.close()
    with database.session() as session:
        count = (
            session.scalar(
                select(func.count())
                .select_from(EvidenceSourceTimelineEventRecord)
                .where(EvidenceSourceTimelineEventRecord.parser_run_id == run.id)
            )
            or 0
        )
    return {
        "imported_events": count,
        "evidence_source_id": source.id,
        "parser_run_id": run.id,
        "status": run.status,
    }
