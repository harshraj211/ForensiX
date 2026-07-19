from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import pytest
from sqlalchemy import select

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.db import (
    AuditLogRecord,
    Database,
    EvidenceSourceChunkRecord,
    EvidenceSourceRecord,
    EvidenceSourceVerificationRecord,
    EvidenceWorkingCopyRecord,
    UserRecord,
)
from forensix_server.evidence_twin import EvidenceTwinError, EvidenceTwinService

MIB = 1024 * 1024


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'twin.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal(database: Database, role: RoleName = RoleName.INVESTIGATOR) -> Principal:
    with database.session() as session:
        user = UserRecord(
            username=f"twin.{role.value}",
            display_name="Evidence Twin Operator",
            password_hash="$argon2id$test-placeholder",
        )
        session.add(user)
        session.flush()
        return Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({role}),
            permissions=ROLE_PERMISSIONS[role],
        )


def _case(database: Database, principal: Principal) -> str:
    with database.session() as session:
        return CaseService().create(session, principal, title="Evidence Twin case").id


def test_stream_import_seals_master_chunks_manifest_and_verified_working_copy(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id = _case(database, principal)
    payload = b"A" * MIB + b"B" * MIB + b"final-chunk"
    service = EvidenceTwinService()

    source = service.import_stream(
        database,
        principal,
        case_id,
        BytesIO(payload),
        source_name=r"C:\examiner\capture.raw",
        display_name="Controlled physical image",
        declared_size_bytes=len(payload),
        chunk_size_bytes=MIB,
    )
    verification = service.verify_master(database, principal, case_id, source.id)
    working_copy = service.create_working_copy(database, principal, case_id, source.id)

    assert source.status == "sealed"
    assert source.source_name == "capture.raw"
    assert source.container_format == "raw"
    assert source.acquisition_level == "filesystem"
    assert source.size_bytes == len(payload)
    assert source.chunk_count == 3
    assert source.sha256 is not None and len(source.sha256) == 64
    assert source.chunks_sha256 is not None and len(source.chunks_sha256) == 64
    assert source.manifest_sha256 is not None and len(source.manifest_sha256) == 64
    assert source.read_only_applied is True
    assert verification.status == "verified"
    assert working_copy.status == "ready"
    assert working_copy.observed_sha256 == source.sha256
    evidence_root = database.data_dir / "evidence"
    assert (evidence_root / Path(source.sealed_storage_key or "missing")).read_bytes() == payload
    assert (evidence_root / Path(working_copy.storage_key)).read_bytes() == payload
    assert source.sealed_storage_key != working_copy.storage_key
    chunk_lines = (
        (evidence_root / Path(source.chunks_storage_key or "missing"))
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert len(chunk_lines) == 3
    with database.session() as session:
        chunks = list(
            session.scalars(
                select(EvidenceSourceChunkRecord).order_by(EvidenceSourceChunkRecord.ordinal)
            )
        )
        copies = list(session.scalars(select(EvidenceWorkingCopyRecord)))
        verifications = list(session.scalars(select(EvidenceSourceVerificationRecord)))
        audits = list(session.scalars(select(AuditLogRecord).order_by(AuditLogRecord.sequence)))
    assert [chunk.offset_bytes for chunk in chunks] == [0, MIB, 2 * MIB]
    assert [chunk.size_bytes for chunk in chunks] == [MIB, MIB, len(b"final-chunk")]
    assert len(copies) == 1
    assert [record.status for record in verifications] == ["verified", "verified"]
    assert [record.sequence for record in audits] == list(range(1, len(audits) + 1))


def test_master_verification_detects_post_seal_corruption(database: Database) -> None:
    principal = _principal(database)
    case_id = _case(database, principal)
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(b"known evidence bytes"),
        source_name="capture.dd",
    )
    master_path = database.data_dir / "evidence" / Path(source.sealed_storage_key or "missing")
    master_path.chmod(0o600)
    master_path.write_bytes(b"modified evidence bytes")

    verification = EvidenceTwinService().verify_master(database, principal, case_id, source.id)

    assert verification.status == "mismatch"
    assert verification.expected_sha256 == source.sha256
    assert verification.observed_sha256 != source.sha256


def test_empty_import_is_failed_without_becoming_sealed(database: Database) -> None:
    principal = _principal(database)
    case_id = _case(database, principal)

    with pytest.raises(EvidenceTwinError, match="empty"):
        EvidenceTwinService().import_stream(
            database, principal, case_id, BytesIO(), source_name="empty.img"
        )

    with database.session() as session:
        source = session.scalar(select(EvidenceSourceRecord))
    assert source is not None
    assert source.status == "failed"
    assert source.sealed_storage_key is None


def test_reviewer_cannot_import_evidence(database: Database) -> None:
    owner = _principal(database)
    case_id = _case(database, owner)
    reviewer = _principal(database, RoleName.REVIEWER)

    with pytest.raises(CaseAccessDeniedError):
        EvidenceTwinService().import_stream(
            database, reviewer, case_id, BytesIO(b"evidence"), source_name="capture.img"
        )
