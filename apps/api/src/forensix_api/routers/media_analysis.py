"""Case-authorized media analysis endpoints (perceptual hash, EXIF/GPS, OCR, labels)."""

import json
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Query, status

from forensix_api.dependencies import (
    get_authenticated_session,
    get_database,
    require_csrf_session,
)
from forensix_api.schemas import (
    MediaAnalysisBackfillResponse,
    MediaAnalysisListResponse,
    MediaAnalysisResponse,
    MediaDetectionLabel,
    MediaFaceClusterListResponse,
    MediaFaceClusterResponse,
    MediaFaceClusterRunResponse,
    MediaFaceEmbeddingResponse,
    SimilarMediaItem,
    SimilarMediaResponse,
    VisualSimilarMediaItem,
    VisualSimilarMediaResponse,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import (
    Database,
    MediaAnalysisRecord,
    MediaFaceClusterRecord,
    MediaFaceEmbeddingRecord,
)
from forensix_server.media import MediaAnalysisService, MediaFaceClusteringService

router = APIRouter(prefix="/api/v1/cases/{case_id}/media", tags=["media-analysis"])


@router.get("/analyses", response_model=MediaAnalysisListResponse)
def list_analyses(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    media_kind: Annotated[Literal["image", "video", "audio"] | None, Query()] = None,
    gps_only: bool = False,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> MediaAnalysisListResponse:
    with database.session() as session:
        items, total = MediaAnalysisService().list_for_case(
            session,
            authenticated.principal,
            case_id,
            media_kind=media_kind,
            gps_only=gps_only,
            offset=offset,
            limit=limit,
        )
        return MediaAnalysisListResponse(
            items=[_analysis_response(item) for item in items],
            total=total,
            offset=offset,
            limit=limit,
        )


@router.get("/faces/clusters", response_model=MediaFaceClusterListResponse)
def list_face_clusters(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> MediaFaceClusterListResponse:
    with database.session() as session:
        clusters, embeddings = MediaFaceClusteringService().list_clusters(
            session, authenticated.principal, case_id
        )
        embeddings_by_cluster: dict[str, list[MediaFaceEmbeddingRecord]] = {}
        for embedding in embeddings:
            if embedding.cluster_key is None:
                continue
            embeddings_by_cluster.setdefault(embedding.cluster_key, []).append(embedding)
        return MediaFaceClusterListResponse(
            clusters=[
                _face_cluster_response(cluster, embeddings_by_cluster.get(cluster.cluster_key, []))
                for cluster in clusters
            ],
            total_clusters=len(clusters),
            total_embeddings=len(embeddings),
        )


@router.post(
    "/faces/clusters/rebuild",
    response_model=MediaFaceClusterRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def rebuild_face_clusters(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> MediaFaceClusterRunResponse:
    result = MediaFaceClusteringService().rebuild(database, authenticated.principal, case_id)
    return MediaFaceClusterRunResponse(embeddings=result.embeddings, clusters=result.clusters)


@router.get("/artifacts/{artifact_id}", response_model=MediaAnalysisResponse | None)
def get_analysis(
    case_id: str,
    artifact_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> MediaAnalysisResponse | None:
    with database.session() as session:
        record = MediaAnalysisService().get_status(
            session, authenticated.principal, case_id, artifact_id
        )
        return _analysis_response(record) if record is not None else None


@router.post(
    "/analyses/backfill",
    response_model=MediaAnalysisBackfillResponse,
    status_code=status.HTTP_201_CREATED,
)
def analyze_pending_media(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> MediaAnalysisBackfillResponse:
    result = MediaAnalysisService().backfill_unprocessed(
        database,
        authenticated.principal,
        case_id=case_id,
        limit=limit,
    )
    return MediaAnalysisBackfillResponse(
        analyzed=result.analyzed,
        unsupported=result.unsupported,
        failed=result.failed,
        skipped_existing=result.skipped_existing,
    )


@router.post(
    "/artifacts/{artifact_id}",
    response_model=MediaAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
)
def analyze_artifact(
    case_id: str,
    artifact_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> MediaAnalysisResponse:
    record = MediaAnalysisService().analyze(database, authenticated.principal, case_id, artifact_id)
    return _analysis_response(record)


@router.get("/artifacts/{artifact_id}/similar", response_model=SimilarMediaResponse)
def find_similar(
    case_id: str,
    artifact_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    max_distance: Annotated[int, Query(ge=0, le=64)] = 10,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> SimilarMediaResponse:
    with database.session() as session:
        base, matches = MediaAnalysisService().find_similar(
            session,
            authenticated.principal,
            case_id,
            artifact_id,
            max_distance=max_distance,
            limit=limit,
        )
        return SimilarMediaResponse(
            base=_analysis_response(base),
            matches=[
                SimilarMediaItem(
                    distance=match.distance, analysis=_analysis_response(match.analysis)
                )
                for match in matches
            ],
            max_distance=max_distance,
        )


@router.get(
    "/artifacts/{artifact_id}/visual-similar",
    response_model=VisualSimilarMediaResponse,
)
def find_visual_similar(
    case_id: str,
    artifact_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    max_distance: Annotated[float, Query(ge=0.0, le=2.0)] = 0.35,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> VisualSimilarMediaResponse:
    with database.session() as session:
        base, matches = MediaAnalysisService().find_visual_similar(
            session,
            authenticated.principal,
            case_id,
            artifact_id,
            max_distance=max_distance,
            limit=limit,
        )
        return VisualSimilarMediaResponse(
            base=_analysis_response(base),
            matches=[
                VisualSimilarMediaItem(
                    distance=match.distance,
                    embedding_model=match.embedding_model,
                    analysis=_analysis_response(match.analysis),
                )
                for match in matches
            ],
            max_distance=max_distance,
        )


def _analysis_response(record: MediaAnalysisRecord) -> MediaAnalysisResponse:
    media_kind = cast(Literal["image", "video", "audio"], record.media_kind)
    analysis_status = cast(Literal["analyzed", "unsupported", "rejected", "failed"], record.status)
    ocr_status = cast(
        Literal["not_attempted", "completed", "unavailable", "empty"], record.ocr_status
    )
    return MediaAnalysisResponse(
        id=record.id,
        artifact_id=record.artifact_id,
        case_id=record.case_id,
        media_kind=media_kind,
        status=analysis_status,
        detected_mime=record.detected_mime,
        width=record.width,
        height=record.height,
        perceptual_hash=record.perceptual_hash,
        captured_at_raw=record.captured_at_raw,
        camera_make=record.camera_make,
        camera_model=record.camera_model,
        gps_present=record.gps_present,
        gps_latitude=record.gps_latitude,
        gps_longitude=record.gps_longitude,
        exif=_json_object(record.exif_json),
        ocr_status=ocr_status,
        ocr_engine=record.ocr_engine,
        ocr_text=record.ocr_text,
        detections=[MediaDetectionLabel(**label) for label in _json_array(record.detection_json)],
        detector_maturity=record.detector_maturity,
        error_code=record.error_code,
        error_message=record.error_message,
        analysis_hash=record.analysis_hash,
        worker_version=record.worker_version,
        analyzed_at=record.analyzed_at,
    )


def _face_cluster_response(
    record: MediaFaceClusterRecord, members: list[MediaFaceEmbeddingRecord]
) -> MediaFaceClusterResponse:
    return MediaFaceClusterResponse(
        id=record.id,
        case_id=record.case_id,
        cluster_key=record.cluster_key,
        label=record.label,
        member_count=record.member_count,
        centroid=_json_float_array(record.centroid_json),
        member_ids=_json_array(record.member_ids_json),
        algorithm=record.algorithm,
        cluster_hash=record.cluster_hash,
        created_by=record.created_by,
        created_at=record.created_at,
        members=[_face_embedding_response(member) for member in members],
    )


def _face_embedding_response(record: MediaFaceEmbeddingRecord) -> MediaFaceEmbeddingResponse:
    return MediaFaceEmbeddingResponse(
        id=record.id,
        case_id=record.case_id,
        artifact_id=record.artifact_id,
        media_analysis_id=record.media_analysis_id,
        face_index=record.face_index,
        embedding_model=record.embedding_model,
        embedding=_json_float_array(record.embedding_json),
        region=_json_float_object(record.region_json),
        cluster_key=record.cluster_key,
        embedding_hash=record.embedding_hash,
        created_at=record.created_at,
    )


def _json_object(value: str) -> dict[str, Any]:
    parsed = json.loads(value)
    return cast(dict[str, Any], parsed) if isinstance(parsed, dict) else {}


def _json_array(value: str) -> list[dict[str, Any]]:
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _json_float_array(value: str) -> list[float]:
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        return []
    return [float(item) for item in parsed if isinstance(item, (int, float))]


def _json_float_object(value: str) -> dict[str, float]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        return {}
    return {str(key): float(item) for key, item in parsed.items() if isinstance(item, (int, float))}
