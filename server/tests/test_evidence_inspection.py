from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import Database, UserRecord
from forensix_server.evidence_twin import EvidenceInspectionService, EvidenceTwinService


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'inspection.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="inspection.owner",
            display_name="Inspection Owner",
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
        case_id = CaseService().create(session, principal, title="Inspection case").id
        return principal, case_id


def _inspect(database: Database, payload: bytes, filename: str):
    principal, case_id = _principal_and_case(database)
    source = EvidenceTwinService().import_stream(
        database, principal, case_id, BytesIO(payload), source_name=filename
    )
    copy = EvidenceTwinService().create_working_copy(database, principal, case_id, source.id)
    record = EvidenceInspectionService().inspect_working_copy(
        database, principal, case_id, source.id, copy.id
    )
    repeated = EvidenceInspectionService().inspect_working_copy(
        database, principal, case_id, source.id, copy.id
    )
    assert repeated.id == record.id
    return record


def test_zip_is_detected_from_signature_not_filename(database: Database) -> None:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("data/contacts2.db", b"known fixture")

    record = _inspect(database, buffer.getvalue(), "misleading.raw")

    assert record.detected_type == "zip"
    assert record.confidence == "high"
    assert record.encryption_state == "not_detected"


def test_sqlite_header_is_detected(database: Database) -> None:
    record = _inspect(database, b"SQLite format 3\x00" + b"\x00" * 4096, "unknown.bin")

    assert record.detected_type == "sqlite"
    assert record.encryption_state == "not_detected"


@pytest.mark.parametrize(
    ("offset", "magic", "expected"),
    [
        (0, b"\x3a\xff\x26\xed", "android_sparse"),
        (1080, b"\x53\xef", "ext4"),
        (1024, b"\x10\x20\xf5\xf2", "f2fs"),
    ],
)
def test_android_image_signatures_do_not_claim_decryption(
    database: Database, offset: int, magic: bytes, expected: str
) -> None:
    payload = bytearray(4096)
    payload[offset : offset + len(magic)] = magic

    record = _inspect(database, bytes(payload), "capture.raw")

    assert record.detected_type == expected
    assert record.encryption_state == "unknown"
    assert "decrypt" not in record.signature_json.casefold()
    assert "does not prove" in record.warnings_json
