import json
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

from sqlalchemy import select

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import (
    AuditLogRecord,
    Database,
    EvidenceRecoveryCarvingRecord,
    UserRecord,
)
from forensix_server.evidence_twin import EvidenceRecoveryCarvingService, EvidenceTwinService


def _database(tmp_path: Path) -> Iterator[Database]:
    database = Database(f"sqlite:///{(tmp_path / 'recovery-carving.db').as_posix()}", tmp_path)
    database.initialize()
    yield database
    database.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="carving.examiner",
            display_name="Carving Examiner",
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
        case_id = CaseService().create(session, principal, title="Recovery carving case").id
        return principal, case_id


def _sqlite_fixture() -> bytes:
    header = bytearray(100)
    header[:16] = b"SQLite format 3\x00"
    header[16:18] = (4096).to_bytes(2, "big")
    header[28:32] = (1).to_bytes(4, "big")
    return bytes(header) + (b"\x00" * 200) + b"deleted chat lead 2026 case 42"


def test_fragment_scan_is_bounded_immutable_and_audited(tmp_path: Path) -> None:
    database = next(_database(tmp_path))
    try:
        principal, case_id = _principal_and_case(database)
        source = EvidenceTwinService().import_stream(
            database,
            principal,
            case_id,
            BytesIO(_sqlite_fixture()),
            source_name="messages.db",
        )
        working_copy = EvidenceTwinService().create_working_copy(
            database, principal, case_id, source.id
        )

        service = EvidenceRecoveryCarvingService()
        run = service.carve(database, principal, case_id, source.id, working_copy.id)
        repeated = service.carve(database, principal, case_id, source.id, working_copy.id)

        assert repeated.id == run.id
        assert run.status == "candidate_fragments_observed"
        assert run.fragment_count >= 1
        assert len(run.run_hash) == 64
        result = json.loads(run.result_json)
        assert result["fragments"]
        assert "not verified deleted records" in result["limitations"][0]
        assert any(
            "deleted chat lead" in fragment["content_preview"] for fragment in result["fragments"]
        )
        with database.session() as session:
            rows = list(session.scalars(select(EvidenceRecoveryCarvingRecord)))
            audit = session.scalar(
                select(AuditLogRecord).where(
                    AuditLogRecord.event_type == "experimental_recovery_fragment_scan_completed"
                )
            )
        assert len(rows) == 1
        assert audit is not None
    finally:
        database.dispose()
