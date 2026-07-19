import json
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from sqlalchemy import select

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import (
    AuditLogRecord,
    Database,
    EvidenceRecoveryAssessmentRecord,
    UserRecord,
)
from forensix_server.evidence_twin import EvidenceRecoveryAssessmentService, EvidenceTwinService


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'recovery.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="recovery.examiner",
            display_name="Recovery Examiner",
            password_hash="$argon2id$test-placeholder",
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
        case_id = CaseService().create(session, principal, title="Recovery assessment case").id
        return principal, case_id


def _sqlite_header(freelist_pages: int) -> bytes:
    header = bytearray(100)
    header[:16] = b"SQLite format 3\x00"
    header[16:18] = (4096).to_bytes(2, "big")
    header[28:32] = (20).to_bytes(4, "big")
    header[32:36] = (7 if freelist_pages else 0).to_bytes(4, "big")
    header[36:40] = freelist_pages.to_bytes(4, "big")
    return bytes(header)


def test_direct_sqlite_assessment_is_immutable_and_audited(database: Database) -> None:
    principal, case_id = _principal_and_case(database)
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_sqlite_header(3)),
        source_name="messages.db",
    )
    working_copy = EvidenceTwinService().create_working_copy(
        database, principal, case_id, source.id
    )
    service = EvidenceRecoveryAssessmentService()

    assessment = service.assess(database, principal, case_id, source.id, working_copy.id)
    repeated = service.assess(database, principal, case_id, source.id, working_copy.id)

    assert repeated.id == assessment.id
    assert assessment.maturity == "experimental"
    assert assessment.status == "candidate_regions_observed"
    assert assessment.candidate_region_count == 3
    result = json.loads(assessment.result_json)
    assert result["candidates"][0]["source_kind"] == "sqlite_database"
    assert "not recovered records" in result["limitations"][0]
    with database.session() as session:
        rows = list(session.scalars(select(EvidenceRecoveryAssessmentRecord)))
        audit = session.scalar(
            select(AuditLogRecord).where(
                AuditLogRecord.event_type == "experimental_recovery_assessed"
            )
        )
    assert len(rows) == 1
    assert audit is not None


def test_archive_assessment_finds_wal_without_calling_frames_deleted(
    database: Database,
) -> None:
    principal, case_id = _principal_and_case(database)
    wal = bytearray(32)
    wal[:4] = b"\x37\x7f\x06\x82"
    wal[8:12] = (1024).to_bytes(4, "big")
    archive_buffer = BytesIO()
    with ZipFile(archive_buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("data/messages.db-wal", wal + bytes(24 + 1024))
        archive.writestr("data/readme.txt", "controlled fixture")
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(archive_buffer.getvalue()),
        source_name="filesystem.zip",
    )
    working_copy = EvidenceTwinService().create_working_copy(
        database, principal, case_id, source.id
    )

    assessment = EvidenceRecoveryAssessmentService().assess(
        database, principal, case_id, source.id, working_copy.id
    )

    result = json.loads(assessment.result_json)
    assert assessment.candidate_region_count == 1
    assert len(result["candidates"]) == 1
    assert result["candidates"][0]["source_kind"] == "sqlite_wal"
    assert "none are labeled deleted" in result["candidates"][0]["limitations"][0]
