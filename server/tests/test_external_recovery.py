import json
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

from sqlalchemy import select

from forensix_forensic.integrations import PhotoRecExecution, PhotoRecOutputFile
from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import (
    AuditLogRecord,
    Database,
    EvidenceExternalRecoveryRunRecord,
    UserRecord,
)
from forensix_server.evidence_twin import EvidenceExternalRecoveryService, EvidenceTwinService


class _PhotoRecStub:
    def recover(self, source_path: Path, output_root: Path) -> PhotoRecExecution:
        assert source_path.is_file()
        recovered = output_root / "recovered.1"
        recovered.mkdir(parents=True)
        output = recovered / "f0000001.jpg"
        output.write_bytes(b"recovered candidate")
        return PhotoRecExecution(
            version="7.2-test",
            executable_sha256="a" * 64,
            command=("photorec", "/cmd", "verified-working-copy", "search"),
            exit_code=0,
            output_files=(
                PhotoRecOutputFile(
                    relative_path="recovered.1/f0000001.jpg",
                    size_bytes=output.stat().st_size,
                    sha256="b" * 64,
                ),
            ),
            output_total_bytes=output.stat().st_size,
            console_summary="Recovered 1 file",
        )


def _database(tmp_path: Path) -> Iterator[Database]:
    database = Database(f"sqlite:///{(tmp_path / 'external-recovery.db').as_posix()}", tmp_path)
    database.initialize()
    yield database
    database.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="external.recovery.examiner",
            display_name="External Recovery Examiner",
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
        case_id = CaseService().create(session, principal, title="External recovery case").id
        return principal, case_id


def _ext4_fixture() -> bytes:
    payload = bytearray(1082)
    payload[1080:1082] = b"\x53\xef"
    return bytes(payload)


def test_external_recovery_is_working_copy_scoped_and_audited(tmp_path: Path) -> None:
    database = next(_database(tmp_path))
    try:
        principal, case_id = _principal_and_case(database)
        source = EvidenceTwinService().import_stream(
            database,
            principal,
            case_id,
            BytesIO(_ext4_fixture()),
            source_name="userdata.raw",
        )
        working_copy = EvidenceTwinService().create_working_copy(
            database, principal, case_id, source.id
        )

        run = EvidenceExternalRecoveryService().run(
            database,
            principal,
            case_id,
            source.id,
            working_copy.id,
            _PhotoRecStub(),  # type: ignore[arg-type]
        )
        repeated = EvidenceExternalRecoveryService().run(
            database,
            principal,
            case_id,
            source.id,
            working_copy.id,
            _PhotoRecStub(),  # type: ignore[arg-type]
        )

        assert repeated.id == run.id
        assert run.status == "completed"
        assert run.recovered_file_count == 1
        result = json.loads(run.result_json)
        assert result["output_files"][0]["relative_path"] == "recovered.1/f0000001.jpg"
        assert "not a proof" in result["limitations"][0]
        with database.session() as session:
            rows = list(session.scalars(select(EvidenceExternalRecoveryRunRecord)))
            audit = session.scalar(
                select(AuditLogRecord).where(
                    AuditLogRecord.event_type == "experimental_external_recovery_completed"
                )
            )
        assert len(rows) == 1
        assert audit is not None
    finally:
        database.dispose()
