"""Case-scoped deterministic timeline endpoint."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from heapq import merge
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from forensix_api.dependencies import get_authenticated_session, get_database
from forensix_api.schemas import TimelineEventResponse, TimelineSearchResponse
from forensix_server.auth import AuthenticatedSession, Permission
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.db import (
    Database,
    EvidenceSourceTimelineEventRecord,
    TimelineEventRecord,
)
from forensix_server.evidence import TimelineService

router = APIRouter(prefix="/api/v1/cases/{case_id}/timeline", tags=["timeline"])


@router.get("/export.ndjson")
def export_timeline(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> StreamingResponse:
    """Export every normalized claim with its provenance hash in stable newest-first order."""
    # Authorize before returning a lazy response, so access errors remain normal HTTP errors.
    with database.session() as session:
        CaseService().get(session, authenticated.principal, case_id)
        if not authenticated.principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot analyze the case timeline.")

    def lines() -> Iterator[str]:
        with database.session() as session:
            native = session.scalars(
                select(TimelineEventRecord)
                .where(TimelineEventRecord.case_id == case_id)
                .order_by(TimelineEventRecord.event_time.desc(), TimelineEventRecord.id.desc())
                .execution_options(yield_per=500)
            )
            imported = session.scalars(
                select(EvidenceSourceTimelineEventRecord)
                .where(EvidenceSourceTimelineEventRecord.case_id == case_id)
                .order_by(
                    EvidenceSourceTimelineEventRecord.event_time.desc(),
                    EvidenceSourceTimelineEventRecord.id.desc(),
                )
                .execution_options(yield_per=500)
            )
            native_items: Iterator[TimelineEventRecord | EvidenceSourceTimelineEventRecord] = iter(
                native
            )
            imported_items: Iterator[TimelineEventRecord | EvidenceSourceTimelineEventRecord] = (
                iter(imported)
            )
            for record in merge(
                native_items,
                imported_items,
                key=_event_key,
                reverse=True,
            ):
                yield (
                    json.dumps(
                        _response(record).model_dump(mode="json"),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                )

    return StreamingResponse(
        lines(),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="forensix-timeline-{case_id}.ndjson"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


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


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _event_key(
    record: TimelineEventRecord | EvidenceSourceTimelineEventRecord,
) -> tuple[datetime, str]:
    return _utc(record.event_time), record.id


def _response(
    record: TimelineEventRecord | EvidenceSourceTimelineEventRecord,
) -> TimelineEventResponse:
    if isinstance(record, EvidenceSourceTimelineEventRecord):
        artifact_id = None
        source_artifact_id = record.source_artifact_id
        job_id = None
        parser_run_id = record.parser_run_id
    else:
        artifact_id = record.artifact_id
        source_artifact_id = None
        job_id = record.job_id
        parser_run_id = None
    return TimelineEventResponse(
        id=record.id,
        case_id=record.case_id,
        artifact_id=artifact_id,
        source_artifact_id=source_artifact_id,
        job_id=job_id,
        parser_run_id=parser_run_id,
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
