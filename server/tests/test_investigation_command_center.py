from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import (
    CaseDeviceRecord,
    Database,
    EvidenceSourceRecord,
    EvidenceSourceVerificationRecord,
    JobRecord,
    ReportRecord,
    UserRecord,
)
from forensix_server.investigation import InvestigationCommandCenterService


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    database = Database(f"sqlite:///{(tmp_path / 'command-center.db').as_posix()}", tmp_path)
    database.initialize()
    with database.session() as active_session:
        yield active_session
    database.dispose()


def _principal(session: Session) -> Principal:
    user = UserRecord(
        username="command.center",
        display_name="Command Center Examiner",
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


def test_empty_case_recommends_device_detection(session: Session) -> None:
    principal = _principal(session)
    case = CaseService().create(session, principal, title="Empty command-center case")

    summary = InvestigationCommandCenterService().summarize(session, principal, case.id)

    assert summary.device_count == 0
    assert summary.evidence.total_artifacts == 0
    assert summary.integrity.custody_chain_valid is True
    assert summary.next_action == "detect_device"
    assert [item.code for item in summary.attention] == ["NO_NORMALIZED_ARTIFACTS"]
    assert summary.recent_activity[0].title == "Case Created"


def test_summary_surfaces_persisted_metrics_and_attention(session: Session) -> None:
    principal = _principal(session)
    case = CaseService().create(session, principal, title="Populated command-center case")
    now = datetime.now(UTC)
    device = CaseDeviceRecord(
        case_id=case.id,
        serial_hash="a" * 64,
        serial_suffix="1234",
        manufacturer="Google",
        model="Pixel Test",
        android_version="15",
        sdk_level=35,
        registered_by=principal.user_id,
        first_seen_at=now,
        last_seen_at=now,
    )
    session.add(device)
    session.flush()
    session.add(
        JobRecord(
            owner_id=principal.user_id,
            case_id=case.id,
            job_type="acquisition",
            state="failed",
            progress_percent=35,
            current_step="Reading approved path metadata",
            error_code="DEVICE_DISCONNECTED",
            error_message="The controlled test transport disconnected.",
            created_at=now,
            updated_at=now,
        )
    )
    source = EvidenceSourceRecord(
        case_id=case.id,
        device_id=device.id,
        created_by=principal.user_id,
        source_type="imported_file",
        acquisition_level="logical",
        status="sealed",
        display_name="Controlled extraction",
        source_name="controlled.zip",
        container_format="zip",
        sealed_storage_key="command-center/source.bin",
        chunks_storage_key="command-center/chunks.json",
        manifest_storage_key="command-center/manifest.json",
        size_bytes=4096,
        sha256="b" * 64,
        chunks_sha256="c" * 64,
        manifest_sha256="d" * 64,
        chunk_size_bytes=1_048_576,
        chunk_count=1,
        read_only_applied=True,
        validation_state="sealed",
        limitations_json="[]",
        tool_version="0.1.0",
        sealed_at=now,
        created_at=now,
    )
    session.add(source)
    session.flush()
    session.add(
        EvidenceSourceVerificationRecord(
            evidence_source_id=source.id,
            case_id=case.id,
            verified_by=principal.user_id,
            target_type="master",
            status="verified",
            expected_sha256=source.sha256,
            observed_sha256=source.sha256,
            size_bytes=source.size_bytes,
            verification_hash="e" * 64,
            tool_version="0.1.0",
            verified_at=now,
        )
    )
    session.add(
        ReportRecord(
            case_id=case.id,
            generated_by=principal.user_id,
            report_type="preliminary",
            status="available",
            title="Preliminary controlled report",
            schema_version="1.0",
            template_version="1.0",
            redaction_profile="full",
            snapshot_storage_key="command-center/report.json",
            snapshot_size_bytes=1024,
            snapshot_sha256="f" * 64,
            generated_at=now,
        )
    )
    session.flush()

    summary = InvestigationCommandCenterService().summarize(session, principal, case.id)

    assert summary.device_count == 1
    assert summary.jobs.attention_required == 1
    assert summary.evidence.sealed_sources == 1
    assert summary.evidence.total_size_bytes == 4096
    assert summary.integrity.verified_observations == 1
    assert summary.report_count == 1
    assert summary.reports_pending_review == 1
    assert summary.next_action == "index_evidence"
    assert {item.code for item in summary.attention} == {
        "ACQUISITION_ATTENTION",
        "REPORT_REVIEW_PENDING",
        "NO_NORMALIZED_ARTIFACTS",
    }
