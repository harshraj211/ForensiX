"""Case-authorized normalized evidence search and metadata detail endpoints."""

import json
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Query, Response, status

from forensix_api.dependencies import (
    get_authenticated_session,
    get_database,
    require_csrf_session,
)
from forensix_api.schemas import (
    AnalystNoteRequest,
    AnalystNoteResponse,
    ArtifactAnnotationsResponse,
    ArtifactResponse,
    ArtifactSearchResponse,
    BookmarkRequest,
    BookmarkResponse,
    TagRequest,
    TagResponse,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import (
    AnalystNoteRecord,
    ArtifactRecord,
    BookmarkRecord,
    Database,
    TagRecord,
)
from forensix_server.evidence import AnalysisService, ArtifactService

router = APIRouter(prefix="/api/v1/cases/{case_id}/artifacts", tags=["artifacts"])


@router.get("", response_model=ArtifactSearchResponse)
def search_artifacts(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    query: Annotated[str | None, Query(alias="q", max_length=256)] = None,
    category: Literal["image", "video", "audio", "document", "archive", "other"] | None = None,
    artifact_status: Annotated[
        Literal["active", "deleted", "recovered", "partial", "corrupted", "unverified"] | None,
        Query(alias="status"),
    ] = None,
    extension: Annotated[str | None, Query(max_length=17)] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> ArtifactSearchResponse:
    with database.session() as session:
        result = ArtifactService().search(
            session,
            authenticated.principal,
            case_id,
            query=query,
            category=category,
            status=artifact_status,
            extension=extension,
            offset=offset,
            limit=limit,
        )
        items = [_artifact_response(item) for item in result.items]
    return ArtifactSearchResponse(
        items=items,
        total=result.total,
        offset=offset,
        limit=limit,
        category_facets=result.category_facets,
    )


@router.get("/{artifact_id}", response_model=ArtifactResponse)
def get_artifact(
    case_id: str,
    artifact_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ArtifactResponse:
    with database.session() as session:
        record = ArtifactService().get(session, authenticated.principal, case_id, artifact_id)
        return _artifact_response(record)


@router.get("/{artifact_id}/annotations", response_model=ArtifactAnnotationsResponse)
def get_annotations(
    case_id: str,
    artifact_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ArtifactAnnotationsResponse:
    with database.session() as session:
        bookmark, tags, notes = AnalysisService().annotations(
            session, authenticated.principal, case_id, artifact_id
        )
        return _annotations_response(bookmark, tags, notes)


@router.post(
    "/{artifact_id}/bookmark",
    response_model=BookmarkResponse,
    status_code=status.HTTP_201_CREATED,
)
def bookmark_artifact(
    case_id: str,
    artifact_id: str,
    request: BookmarkRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> BookmarkResponse:
    with database.session() as session:
        record = AnalysisService().bookmark(
            session,
            authenticated.principal,
            case_id,
            artifact_id,
            reason=request.reason,
        )
        return _bookmark_response(record)


@router.delete("/{artifact_id}/bookmark", status_code=status.HTTP_204_NO_CONTENT)
def remove_artifact_bookmark(
    case_id: str,
    artifact_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> Response:
    with database.session() as session:
        AnalysisService().remove_bookmark(session, authenticated.principal, case_id, artifact_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{artifact_id}/tags", response_model=TagResponse, status_code=status.HTTP_201_CREATED)
def add_artifact_tag(
    case_id: str,
    artifact_id: str,
    request: TagRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> TagResponse:
    with database.session() as session:
        record = AnalysisService().add_tag(
            session, authenticated.principal, case_id, artifact_id, request.name
        )
        return _tag_response(record)


@router.post(
    "/{artifact_id}/notes",
    response_model=AnalystNoteResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_artifact_note(
    case_id: str,
    artifact_id: str,
    request: AnalystNoteRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> AnalystNoteResponse:
    with database.session() as session:
        record = AnalysisService().add_note(
            session,
            authenticated.principal,
            case_id,
            artifact_id,
            request.body,
            supersedes_id=request.supersedes_id,
        )
        return _note_response(record)


def _artifact_response(record: ArtifactRecord) -> ArtifactResponse:
    category = cast(
        Literal["image", "video", "audio", "document", "archive", "other"],
        record.category,
    )
    status = cast(
        Literal["active", "deleted", "recovered", "partial", "corrupted", "unverified"],
        record.status,
    )
    return ArtifactResponse(
        id=record.id,
        evidence_file_id=record.evidence_file_id,
        case_id=record.case_id,
        device_id=record.device_id,
        job_id=record.job_id,
        category=category,
        subtype=record.subtype,
        title=record.title,
        summary=record.summary,
        source_relative_path=record.source_relative_path,
        source_path_hash=record.source_path_hash,
        extension=record.extension,
        detected_mime=record.detected_mime,
        size_bytes=record.size_bytes,
        status=status,
        primary_sha256=record.primary_sha256,
        parser_id=record.parser_id,
        parser_version=record.parser_version,
        timestamp_confidence=record.timestamp_confidence,
        collected_at=record.collected_at,
        provenance=_json_object(record.provenance_json),
        metadata=_json_object(record.metadata_json),
        schema_version=record.schema_version,
        created_at=record.created_at,
    )


def _json_object(value: str) -> dict[str, Any]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise RuntimeError("Normalized artifact JSON must be an object.")
    return cast(dict[str, Any], parsed)


def _annotations_response(
    bookmark: BookmarkRecord | None,
    tags: list[TagRecord],
    notes: list[AnalystNoteRecord],
) -> ArtifactAnnotationsResponse:
    return ArtifactAnnotationsResponse(
        bookmark=_bookmark_response(bookmark) if bookmark else None,
        tags=[_tag_response(tag) for tag in tags],
        notes=[_note_response(note) for note in notes],
    )


def _bookmark_response(record: BookmarkRecord) -> BookmarkResponse:
    return BookmarkResponse(
        id=record.id,
        artifact_id=record.artifact_id,
        user_id=record.user_id,
        reason=record.reason,
        created_at=record.created_at,
    )


def _tag_response(record: TagRecord) -> TagResponse:
    return TagResponse(
        id=record.id,
        name=record.name,
        created_by=record.created_by,
        created_at=record.created_at,
    )


def _note_response(record: AnalystNoteRecord) -> AnalystNoteResponse:
    return AnalystNoteResponse(
        id=record.id,
        artifact_id=record.artifact_id,
        author_id=record.author_id,
        body=record.body,
        supersedes_id=record.supersedes_id,
        created_at=record.created_at,
    )
