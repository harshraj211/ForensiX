"""Case-authorized normalized evidence search and metadata detail endpoints."""

import json
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Query

from forensix_api.dependencies import get_authenticated_session, get_database
from forensix_api.schemas import ArtifactResponse, ArtifactSearchResponse
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import ArtifactRecord, Database
from forensix_server.evidence import ArtifactService

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
