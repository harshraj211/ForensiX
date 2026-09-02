"""Tests for enterprise GeoLocationAnalyticsService and SocialGraphAnalyticsService."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import (
    Database,
    EvidenceParserRunRecord,
    EvidenceSourceArtifactRecord,
    EvidenceSourceInspectionRecord,
    UserRecord,
)
from forensix_server.evidence_twin import EvidenceTwinService
from forensix_server.investigation import (
    GeoLocationAnalyticsService,
    SocialGraphAnalyticsService,
)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'analytics.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_fixture_ids(database: Database) -> tuple[Principal, str, str, str, str]:
    with database.session() as session:
        user = UserRecord(
            username="analyst",
            display_name="Senior Analyst",
            password_hash="$argon2id$placeholder",
        )
        session.add(user)
        session.flush()
        principal = Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({RoleName.INVESTIGATOR}),
            permissions=ROLE_PERMISSIONS[RoleName.INVESTIGATOR],
        )
        case_id = CaseService().create(session, principal, title="Analytics Case").id

    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(b"DUMMY_SOURCE_CONTENT_12345"),
        source_name="device_dump.tar",
    )
    copy = EvidenceTwinService().create_working_copy(database, principal, case_id, source.id)

    with database.session() as session:
        now = datetime.now(UTC)
        inspection = EvidenceSourceInspectionRecord(
            evidence_source_id=source.id,
            working_copy_id=copy.id,
            case_id=case_id,
            inspected_by=principal.user_id,
            detected_type="sqlite",
            confidence="high",
            encryption_state="not_detected",
            signature_json="{}",
            warnings_json="[]",
            detector_version="1.0",
            inspection_hash="a" * 64,
            inspected_at=now,
        )
        session.add(inspection)
        session.flush()

        run = EvidenceParserRunRecord(
            evidence_source_id=source.id,
            working_copy_id=copy.id,
            inspection_id=inspection.id,
            case_id=case_id,
            executed_by=principal.user_id,
            parser_id="android.location.records",
            parser_version="1.0.0",
            status="completed",
            artifact_count=2,
            source_sha256="0" * 64,
            input_locator="locator.db",
            input_sha256="0" * 64,
            run_hash="b" * 64,
            started_at=now,
            completed_at=now,
        )
        session.add(run)
        session.flush()
        return principal, case_id, source.id, copy.id, run.id


def test_geolocation_analytics_service(database: Database) -> None:
    principal, case_id, src_id, copy_id, run_id = _principal_and_fixture_ids(database)

    with database.session() as session:
        # Add a location observation artifact
        art1 = EvidenceSourceArtifactRecord(
            case_id=case_id,
            evidence_source_id=src_id,
            working_copy_id=copy_id,
            parser_run_id=run_id,
            category="location",
            subtype="location_observation",
            title="GPS Fix 1",
            summary="GPS Fix 1 summary",
            confidence="high",
            status="active",
            source_locator="gps_1",
            parser_id="android.test",
            parser_version="1.0.0",
            provenance_json="{}",
            artifact_hash="1" * 64,
            event_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            metadata_json=json.dumps(
                {"latitude": 37.7749, "longitude": -122.4194, "application": "gps"}
            ),
        )
        # Add a Wi-Fi profile with coordinates
        art2 = EvidenceSourceArtifactRecord(
            case_id=case_id,
            evidence_source_id=src_id,
            working_copy_id=copy_id,
            parser_run_id=run_id,
            category="location",
            subtype="wifi_profile",
            title="Wi-Fi: HQ",
            summary="Wi-Fi HQ summary",
            confidence="high",
            status="active",
            source_locator="wifi_1",
            parser_id="android.test",
            parser_version="1.0.0",
            provenance_json="{}",
            artifact_hash="2" * 64,
            event_time=datetime(2024, 1, 1, 13, 0, 0, tzinfo=UTC),
            metadata_json=json.dumps(
                {"latitude": 37.7800, "longitude": -122.4200, "application": "wifi"}
            ),
        )
        session.add_all([art1, art2])
        session.commit()

        service = GeoLocationAnalyticsService(session, principal)
        result = service.get_case_geolocation(case_id)

    assert result.case_id == case_id
    assert result.total_points == 2
    assert result.bounding_box is not None
    assert result.bounding_box["min_lat"] <= 37.7749
    assert result.bounding_box["max_lat"] >= 37.7800
    assert len(result.clusters_summary) > 0
    assert result.providers_summary["gps"] == 1
    assert result.providers_summary["wifi"] == 1


def test_social_graph_analytics_service(database: Database) -> None:
    principal, case_id, src_id, copy_id, run_id = _principal_and_fixture_ids(database)

    with database.session() as session:
        # Add outgoing WhatsApp message
        msg1 = EvidenceSourceArtifactRecord(
            case_id=case_id,
            evidence_source_id=src_id,
            working_copy_id=copy_id,
            parser_run_id=run_id,
            category="communication",
            subtype="whatsapp_message",
            title="WhatsApp outgoing: suspect_bob",
            summary="Meet me at noon",
            confidence="high",
            status="active",
            source_locator="wa_1",
            parser_id="android.test",
            parser_version="1.0.0",
            provenance_json="{}",
            artifact_hash="3" * 64,
            event_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            metadata_json=json.dumps(
                {
                    "resolved_sender": "suspect_bob",
                    "from_me": 1,
                    "direction": "outgoing",
                    "application": "whatsapp",
                }
            ),
        )
        # Add incoming Signal message
        msg2 = EvidenceSourceArtifactRecord(
            case_id=case_id,
            evidence_source_id=src_id,
            working_copy_id=copy_id,
            parser_run_id=run_id,
            category="communication",
            subtype="signal_message",
            title="Signal incoming: +15550001111",
            summary="Package secured",
            confidence="high",
            status="active",
            source_locator="sig_1",
            parser_id="android.test",
            parser_version="1.0.0",
            provenance_json="{}",
            artifact_hash="4" * 64,
            event_time=datetime(2024, 1, 1, 12, 5, 0, tzinfo=UTC),
            metadata_json=json.dumps(
                {
                    "address": "+15550001111",
                    "from_me": 0,
                    "direction": "incoming",
                    "application": "signal",
                }
            ),
        )
        session.add_all([msg1, msg2])
        session.commit()

        service = SocialGraphAnalyticsService(session, principal)
        result = service.get_case_social_graph(case_id)

    assert result.case_id == case_id
    assert result.total_nodes >= 3  # Device Owner, suspect_bob, +15550001111
    assert result.total_edges >= 2
    assert any(n["id"] == "suspect_bob" for n in result.nodes)
    assert any(n["id"] == "+15550001111" for n in result.nodes)
    assert result.channels_summary["whatsapp"] == 1
    assert result.channels_summary["signal"] == 1
