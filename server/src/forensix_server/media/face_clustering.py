"""Case-level face embedding and grouping over media analysis detections."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.db import (
    Database,
    MediaAnalysisRecord,
    MediaFaceClusterRecord,
    MediaFaceEmbeddingRecord,
)

FACE_CLUSTER_ALGORITHM = "face-region-geometry-v1"
FACE_EMBEDDING_MODEL = "detector-region-geometry-v1"
FACE_CLUSTER_DISTANCE = 0.18


@dataclass(frozen=True, slots=True)
class FaceClusterRunResult:
    embeddings: int
    clusters: int


class MediaFaceClusteringService:
    """Builds deterministic case-local person groups from detected face regions."""

    def list_clusters(
        self, session: Session, principal: Principal, case_id: str
    ) -> tuple[list[MediaFaceClusterRecord], list[MediaFaceEmbeddingRecord]]:
        self._require_analyze(session, principal, case_id)
        clusters = list(
            session.scalars(
                select(MediaFaceClusterRecord)
                .where(MediaFaceClusterRecord.case_id == case_id)
                .order_by(MediaFaceClusterRecord.member_count.desc(), MediaFaceClusterRecord.label)
            )
        )
        embeddings = list(
            session.scalars(
                select(MediaFaceEmbeddingRecord)
                .where(MediaFaceEmbeddingRecord.case_id == case_id)
                .order_by(MediaFaceEmbeddingRecord.cluster_key, MediaFaceEmbeddingRecord.face_index)
            )
        )
        return clusters, embeddings

    def rebuild(
        self, database: Database, principal: Principal, case_id: str
    ) -> FaceClusterRunResult:
        with database.session() as session:
            self._require_analyze(session, principal, case_id)
            analyses = list(
                session.scalars(
                    select(MediaAnalysisRecord)
                    .where(
                        MediaAnalysisRecord.case_id == case_id,
                        MediaAnalysisRecord.status == "analyzed",
                    )
                    .order_by(MediaAnalysisRecord.analyzed_at.asc(), MediaAnalysisRecord.id.asc())
                )
            )
            session.execute(
                delete(MediaFaceClusterRecord).where(MediaFaceClusterRecord.case_id == case_id)
            )
            session.execute(
                delete(MediaFaceEmbeddingRecord).where(MediaFaceEmbeddingRecord.case_id == case_id)
            )
            candidates = _embedding_candidates(analyses)
            grouped = _cluster_candidates(candidates)
            embedding_count = 0
            for cluster_index, cluster in enumerate(grouped, start=1):
                cluster_key = f"person-{cluster_index:03d}"
                for candidate in cluster:
                    session.add(_embedding_record(candidate, cluster_key))
                    embedding_count += 1
                cluster_record = _cluster_record(
                    case_id=case_id,
                    cluster_key=cluster_key,
                    label=f"Person Group {cluster_index}",
                    candidates=cluster,
                    actor_id=principal.user_id,
                )
                session.add(cluster_record)
            session.flush()
            return FaceClusterRunResult(embeddings=embedding_count, clusters=len(grouped))

    @staticmethod
    def _require_analyze(session: Session, principal: Principal, case_id: str) -> None:
        CaseService().get(session, principal, case_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot analyze case media.")


@dataclass(frozen=True, slots=True)
class _FaceCandidate:
    case_id: str
    artifact_id: str
    media_analysis_id: str
    face_index: int
    region: dict[str, float]
    embedding: list[float]


def _embedding_candidates(analyses: list[MediaAnalysisRecord]) -> list[_FaceCandidate]:
    candidates: list[_FaceCandidate] = []
    for analysis in analyses:
        detections = _json_array(analysis.detection_json)
        face_index = 0
        for detection in detections:
            if not str(detection.get("label", "")).startswith("face_region"):
                continue
            region = _region(detection.get("region"))
            if region is None:
                continue
            embedding = _embedding_from_detection(detection, region, analysis)
            candidates.append(
                _FaceCandidate(
                    case_id=analysis.case_id,
                    artifact_id=analysis.artifact_id,
                    media_analysis_id=analysis.id,
                    face_index=face_index,
                    region=region,
                    embedding=embedding,
                )
            )
            face_index += 1
    return candidates


def _cluster_candidates(candidates: list[_FaceCandidate]) -> list[list[_FaceCandidate]]:
    clusters: list[list[_FaceCandidate]] = []
    centroids: list[list[float]] = []
    for candidate in candidates:
        best_index: int | None = None
        best_distance = float("inf")
        for index, centroid in enumerate(centroids):
            distance = _distance(candidate.embedding, centroid)
            if distance < best_distance:
                best_distance = distance
                best_index = index
        if best_index is None or best_distance > FACE_CLUSTER_DISTANCE:
            clusters.append([candidate])
            centroids.append(candidate.embedding)
        else:
            clusters[best_index].append(candidate)
            centroids[best_index] = _centroid([item.embedding for item in clusters[best_index]])
    return clusters


def _embedding_record(candidate: _FaceCandidate, cluster_key: str) -> MediaFaceEmbeddingRecord:
    embedding_json = _canonical_json(candidate.embedding)
    region_json = _canonical_json(candidate.region)
    material = "|".join(
        (
            candidate.case_id,
            candidate.artifact_id,
            candidate.media_analysis_id,
            str(candidate.face_index),
            embedding_json,
            region_json,
            cluster_key,
        )
    )
    return MediaFaceEmbeddingRecord(
        case_id=candidate.case_id,
        artifact_id=candidate.artifact_id,
        media_analysis_id=candidate.media_analysis_id,
        face_index=candidate.face_index,
        embedding_model=FACE_EMBEDDING_MODEL,
        embedding_json=embedding_json,
        region_json=region_json,
        cluster_key=cluster_key,
        embedding_hash=hashlib.sha256(material.encode("utf-8")).hexdigest(),
    )


def _cluster_record(
    *,
    case_id: str,
    cluster_key: str,
    label: str,
    candidates: list[_FaceCandidate],
    actor_id: str,
) -> MediaFaceClusterRecord:
    centroid = _centroid([candidate.embedding for candidate in candidates])
    member_ids = [
        {
            "artifact_id": candidate.artifact_id,
            "media_analysis_id": candidate.media_analysis_id,
            "face_index": candidate.face_index,
        }
        for candidate in candidates
    ]
    centroid_json = _canonical_json(centroid)
    member_ids_json = _canonical_json(member_ids)
    material = "|".join(
        (case_id, cluster_key, centroid_json, member_ids_json, FACE_CLUSTER_ALGORITHM)
    )
    return MediaFaceClusterRecord(
        case_id=case_id,
        cluster_key=cluster_key,
        label=label,
        member_count=len(candidates),
        centroid_json=centroid_json,
        member_ids_json=member_ids_json,
        algorithm=FACE_CLUSTER_ALGORITHM,
        cluster_hash=hashlib.sha256(material.encode("utf-8")).hexdigest(),
        created_by=actor_id,
    )


def _embedding_from_detection(
    detection: dict[str, Any], region: dict[str, float], analysis: MediaAnalysisRecord
) -> list[float]:
    details = detection.get("details")
    if isinstance(details, dict) and isinstance(details.get("embedding"), list):
        values = [float(value) for value in details["embedding"] if isinstance(value, (int, float))]
        if values:
            return _normalize(values[:128])
    x = region["x"]
    y = region["y"]
    width = region["width"]
    height = region["height"]
    center_x = x + width / 2
    center_y = y + height / 2
    area = width * height
    aspect = width / height if height else 0.0
    source_seed = int(
        hashlib.sha256((analysis.perceptual_hash or analysis.analysis_hash).encode()).hexdigest()[
            :8
        ],
        16,
    )
    seed_feature = (source_seed % 10_000) / 10_000
    return _normalize([center_x, center_y, width, height, area, aspect, seed_feature])


def _region(value: Any) -> dict[str, float] | None:
    if not isinstance(value, dict):
        return None
    keys = ("x", "y", "width", "height")
    parsed: dict[str, float] = {}
    for key in keys:
        item = value.get(key)
        if not isinstance(item, (int, float)):
            return None
        parsed[key] = round(float(item), 6)
    return parsed


def _centroid(vectors: list[list[float]]) -> list[float]:
    if not vectors:
        return []
    width = max(len(vector) for vector in vectors)
    padded = [vector + [0.0] * (width - len(vector)) for vector in vectors]
    return [
        round(sum(vector[index] for vector in padded) / len(padded), 6) for index in range(width)
    ]


def _distance(left: list[float], right: list[float]) -> float:
    width = max(len(left), len(right))
    lpad = left + [0.0] * (width - len(left))
    rpad = right + [0.0] * (width - len(right))
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(lpad, rpad, strict=True)))


def _normalize(values: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in values)) or 1.0
    return [round(value / norm, 6) for value in values]


def _json_array(value: str) -> list[dict[str, Any]]:
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        return []
    return [cast(dict[str, Any], item) for item in parsed if isinstance(item, dict)]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
