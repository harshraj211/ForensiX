from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionInventoryItemRecord,
    AcquisitionInventoryRecord,
    AcquisitionPlanRecord,
    ArtifactRecord,
    CaseDeviceAssessmentRecord,
    CaseDeviceRecord,
    Database,
    JobRecord,
    MediaAnalysisRecord,
    MediaFaceClusterRecord,
    MediaFaceEmbeddingRecord,
    MediaVisualEmbeddingRecord,
    UserRecord,
)
from forensix_server.media import MediaAnalysisService
from forensix_server.media.face_clustering import MediaFaceClusteringService


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'faces.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal(database: Database) -> Principal:
    with database.session() as session:
        user = UserRecord(
            username="face.cluster.operator",
            display_name="Face Cluster Operator",
            password_hash="$argon2id$test-placeholder",
        )
        session.add(user)
        session.flush()
        return Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({RoleName.INVESTIGATOR}),
            permissions=ROLE_PERMISSIONS[RoleName.INVESTIGATOR],
        )


def _case_graph(database: Database, principal: Principal) -> tuple[str, str, str, str, str]:
    now = datetime(2026, 9, 30, 8, 0, tzinfo=UTC)
    with database.session() as session:
        case = CaseService().create(session, principal, title="Face grouping case")
        device = CaseDeviceRecord(
            case_id=case.id,
            serial_hash=_sha("serial"),
            serial_suffix="1234",
            manufacturer="Google",
            model="Pixel Test",
            registered_by=principal.user_id,
        )
        session.add(device)
        session.flush()
        assessment = CaseDeviceAssessmentRecord(
            case_id=case.id,
            device_id=device.id,
            assessed_by=principal.user_id,
            assessed_at=now,
            package_count=0,
            assessor_version="test",
            snapshot_json="{}",
        )
        session.add(assessment)
        session.flush()
        plan = AcquisitionPlanRecord(
            case_id=case.id,
            device_id=device.id,
            assessment_id=assessment.id,
            created_by=principal.user_id,
            scope="image_files",
            status="ready",
            modules_json="[]",
            limitations_json="[]",
            snapshot_hash=_sha("snapshot"),
            plan_hash=_sha("plan"),
            schema_version="1.0.0",
            readiness_assessed_at=now,
            readiness_expires_at=now + timedelta(hours=1),
        )
        session.add(plan)
        session.flush()
        job = JobRecord(
            owner_id=principal.user_id,
            case_id=case.id,
            plan_id=plan.id,
            job_type="acquisition",
            state="completed",
            progress_percent=100,
            started_at=now,
            completed_at=now,
        )
        session.add(job)
        session.flush()
        inventory = AcquisitionInventoryRecord(
            job_id=job.id,
            case_id=case.id,
            plan_id=plan.id,
            device_id=device.id,
            created_by=principal.user_id,
            root_id="media",
            display_path="/sdcard/DCIM",
            status="completed",
            discovered_count=3,
            persisted_count=3,
            skipped_count=0,
            max_items=10,
            max_depth=2,
            manifest_hash=_sha("inventory"),
            started_at=now,
            completed_at=now,
        )
        session.add(inventory)
        session.flush()
        return case.id, device.id, plan.id, job.id, inventory.id


def _add_media_analysis(
    database: Database,
    principal: Principal,
    *,
    case_id: str,
    device_id: str,
    plan_id: str,
    job_id: str,
    inventory_id: str,
    ordinal: int,
    embedding: list[float],
) -> tuple[str, str]:
    now = datetime(2026, 9, 30, 8, ordinal, tzinfo=UTC)
    path = f"DCIM/Camera/face-{ordinal}.jpg"
    with database.session() as session:
        item = AcquisitionInventoryItemRecord(
            inventory_id=inventory_id,
            ordinal=ordinal,
            relative_path=path,
            path_hash=_sha(path),
            extension="jpg",
            size_bytes=4096,
            timestamp_confidence="medium",
        )
        session.add(item)
        session.flush()
        evidence = AcquiredEvidenceFileRecord(
            inventory_id=inventory_id,
            inventory_item_id=item.id,
            job_id=job_id,
            case_id=case_id,
            plan_id=plan_id,
            device_id=device_id,
            acquired_by=principal.user_id,
            status="completed",
            source_root_id="media",
            source_path_hash=item.path_hash,
            storage_key=f"cases/{case_id}/raw/face-{ordinal}.jpg",
            manifest_storage_key=f"cases/{case_id}/manifests/face-{ordinal}.json",
            size_bytes=4096,
            sha256=_sha(f"evidence-{ordinal}"),
            manifest_hash=_sha(f"manifest-{ordinal}"),
            transfer_limit_bytes=1_000_000,
            tool_version="test",
            validation_state="not_physically_validated",
            started_at=now,
            completed_at=now,
        )
        session.add(evidence)
        session.flush()
        artifact = ArtifactRecord(
            evidence_file_id=evidence.id,
            case_id=case_id,
            device_id=device_id,
            job_id=job_id,
            category="image",
            subtype="media",
            title=f"Face {ordinal}",
            summary="Image with detected face region",
            source_relative_path=path,
            source_path_hash=item.path_hash,
            extension="jpg",
            detected_mime="image/jpeg",
            size_bytes=4096,
            status="active",
            primary_sha256=evidence.sha256 or _sha(f"artifact-{ordinal}"),
            parser_id="test.media",
            parser_version="1.0.0",
            timestamp_confidence="high",
            collected_at=now,
            provenance_json="{}",
            metadata_json="{}",
            schema_version="1.0.0",
        )
        session.add(artifact)
        session.flush()
        detection = {
            "label": "face_region",
            "confidence": 0.91,
            "basis": "test_fixture",
            "status": "completed",
            "region": {"x": 0.1 * ordinal, "y": 0.2, "width": 0.2, "height": 0.2},
            "details": {"index": 0, "embedding": embedding},
        }
        analysis = MediaAnalysisRecord(
            artifact_id=artifact.id,
            evidence_file_id=evidence.id,
            case_id=case_id,
            analyzed_by=principal.user_id,
            media_kind="image",
            status="analyzed",
            detected_mime="image/jpeg",
            width=640,
            height=480,
            perceptual_hash=f"{ordinal:016x}",
            gps_present=False,
            exif_json="{}",
            ocr_status="not_attempted",
            detection_json=json.dumps([detection], sort_keys=True),
            detector_maturity="local_ml",
            analysis_hash=_sha(f"analysis-{ordinal}"),
            worker_version="test",
            analyzed_at=now,
        )
        session.add(analysis)
        session.flush()
        return artifact.id, analysis.id


def test_rebuild_face_clusters_groups_detected_regions(database: Database) -> None:
    principal = _principal(database)
    case_id, device_id, plan_id, job_id, inventory_id = _case_graph(database, principal)
    _add_media_analysis(
        database,
        principal,
        case_id=case_id,
        device_id=device_id,
        plan_id=plan_id,
        job_id=job_id,
        inventory_id=inventory_id,
        ordinal=1,
        embedding=[1.0, 0.0, 0.0],
    )
    _add_media_analysis(
        database,
        principal,
        case_id=case_id,
        device_id=device_id,
        plan_id=plan_id,
        job_id=job_id,
        inventory_id=inventory_id,
        ordinal=2,
        embedding=[0.99, 0.01, 0.0],
    )
    _add_media_analysis(
        database,
        principal,
        case_id=case_id,
        device_id=device_id,
        plan_id=plan_id,
        job_id=job_id,
        inventory_id=inventory_id,
        ordinal=3,
        embedding=[0.0, 1.0, 0.0],
    )

    result = MediaFaceClusteringService().rebuild(database, principal, case_id)

    assert result.embeddings == 3
    assert result.clusters == 2
    with database.session() as session:
        clusters, embeddings = MediaFaceClusteringService().list_clusters(
            session, principal, case_id
        )
        member_counts = sorted(cluster.member_count for cluster in clusters)
        assert member_counts == [1, 2]
        assert len(embeddings) == 3
        assert {embedding.embedding_model for embedding in embeddings} == {
            "detector-region-geometry-v1"
        }
        assert all(json.loads(embedding.region_json)["width"] == 0.2 for embedding in embeddings)
        assert session.query(MediaFaceClusterRecord).count() == 2
        assert session.query(MediaFaceEmbeddingRecord).count() == 3

    rerun = MediaFaceClusteringService().rebuild(database, principal, case_id)

    assert rerun.embeddings == 3
    assert rerun.clusters == 2
    with database.session() as session:
        assert session.query(MediaFaceClusterRecord).count() == 2
        assert session.query(MediaFaceEmbeddingRecord).count() == 3


def test_find_visual_similar_uses_gallery_embeddings(database: Database) -> None:
    principal = _principal(database)
    case_id, device_id, plan_id, job_id, inventory_id = _case_graph(database, principal)
    first_artifact, first_analysis = _add_media_analysis(
        database,
        principal,
        case_id=case_id,
        device_id=device_id,
        plan_id=plan_id,
        job_id=job_id,
        inventory_id=inventory_id,
        ordinal=1,
        embedding=[1.0, 0.0, 0.0],
    )
    _, second_analysis = _add_media_analysis(
        database,
        principal,
        case_id=case_id,
        device_id=device_id,
        plan_id=plan_id,
        job_id=job_id,
        inventory_id=inventory_id,
        ordinal=2,
        embedding=[0.99, 0.01, 0.0],
    )
    _, third_analysis = _add_media_analysis(
        database,
        principal,
        case_id=case_id,
        device_id=device_id,
        plan_id=plan_id,
        job_id=job_id,
        inventory_id=inventory_id,
        ordinal=3,
        embedding=[0.0, 1.0, 0.0],
    )
    vectors = {
        first_analysis: [1.0, 0.0, 0.0],
        second_analysis: [0.99, 0.01, 0.0],
        third_analysis: [0.0, 1.0, 0.0],
    }
    with database.session() as session:
        for analysis_id, vector in vectors.items():
            analysis = session.get(MediaAnalysisRecord, analysis_id)
            assert analysis is not None
            session.add(
                MediaVisualEmbeddingRecord(
                    case_id=case_id,
                    artifact_id=analysis.artifact_id,
                    media_analysis_id=analysis.id,
                    embedding_model="clip-test.onnx",
                    embedding_json=json.dumps(vector),
                    dimension_count=len(vector),
                    embedding_hash=_sha(f"visual-{analysis.id}"),
                )
            )

    with database.session() as session:
        base, matches = MediaAnalysisService().find_visual_similar(
            session,
            principal,
            case_id,
            first_artifact,
            max_distance=0.02,
            limit=10,
        )

    assert base.id == first_analysis
    assert [match.analysis.id for match in matches] == [second_analysis]
    assert matches[0].embedding_model == "clip-test.onnx"
    assert matches[0].distance < 0.001
