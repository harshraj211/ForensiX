"""Case-scoped deterministic timeline endpoint."""

from datetime import datetime
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Query

from forensix_api.dependencies import get_authenticated_session, get_database
from forensix_api.schemas import TimelineEventResponse, TimelineSearchResponse
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database, TimelineEventRecord
from forensix_server.evidence import TimelineService

router = APIRouter(prefix="/api/v1/cases/{case_id}/timeline", tags=["timeline"])


@router.get("", response_model=TimelineSearchResponse)
def search_timeline(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    category: Literal[
        "device",
        "file",
        "media",
        "communication",
        "application",
        "location",
        "system",
        "acquisition",
        "custody",
    ]
    | None = None,
    confidence: Literal["low", "medium", "high"] | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> TimelineSearchResponse:
    with database.session() as session:
        result = TimelineService().search(
            session,
            authenticated.principal,
            case_id,
            category=category,
            confidence=confidence,
            from_time=from_time,
            to_time=to_time,
            offset=offset,
            limit=limit,
        )
        items = [_response(record) for record in result.items]
    return TimelineSearchResponse(
        items=items,
        total=result.total,
        offset=offset,
        limit=limit,
        category_facets=result.category_facets,
    )


def _response(record: TimelineEventRecord) -> TimelineEventResponse:
    return TimelineEventResponse(
        id=record.id,
        case_id=record.case_id,
        artifact_id=record.artifact_id,
        job_id=record.job_id,
        category=cast(
            Literal[
                "device",
                "file",
                "media",
                "communication",
                "application",
                "location",
                "system",
                "acquisition",
                "custody",
            ],
            record.category,
        ),
        timestamp_type=record.timestamp_type,
        event_time=record.event_time,
        original_time=record.original_time,
        timezone_basis=record.timezone_basis,
        precision=record.precision,
        confidence=record.confidence,
        summary=record.summary,
        builder_version=record.builder_version,
        event_hash=record.event_hash,
    )
