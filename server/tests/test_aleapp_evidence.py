import sys
from collections.abc import Iterator
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from sqlalchemy import select

from forensix_forensic.integrations import AleappConfiguration, AleappRunner
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import (
    Database,
    EvidenceParserRunRecord,
    EvidenceToolOutputRecord,
    UserRecord,
)
from forensix_server.evidence_twin import AleappEvidenceService, EvidenceTwinService


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'aleapp.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="aleapp.examiner",
            display_name="ALEAPP Examiner",
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
        case_id = CaseService().create(session, principal, title="ALEAPP case").id
        return principal, case_id


def _zip_payload() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("data/system/users/0/settings_secure.xml", "known fixture")
    return buffer.getvalue()


def _runner(tmp_path: Path) -> AleappRunner:
    program = tmp_path / "aleapp.py"
    program.write_text(
        """
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('-t')
parser.add_argument('-i')
parser.add_argument('-o')
args = parser.parse_args()
output = Path(args.o)
output.mkdir(parents=True, exist_ok=True)
(output / 'report.tsv').write_text('artifact\\tvalue\\nFixture\\tKnown\\n', encoding='utf-8')
print('ALEAPP fixture complete')
""",
        encoding="utf-8",
    )
    return AleappRunner(
        AleappConfiguration(
            program_path=program,
            python_executable=Path(sys.executable),
            expected_sha256=sha256(program.read_bytes()).hexdigest(),
            release_label="v2026.1.0-test",
            timeout_seconds=5,
        )
    )


def test_aleapp_outputs_are_sealed_and_persisted(database: Database, tmp_path: Path) -> None:
    principal, case_id = _principal_and_case(database)
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_zip_payload()),
        source_name="filesystem.zip",
    )
    copy = EvidenceTwinService().create_working_copy(database, principal, case_id, source.id)
    runner = _runner(tmp_path)

    result = AleappEvidenceService().run(database, principal, case_id, source.id, copy.id, runner)
    repeated = AleappEvidenceService().run(database, principal, case_id, source.id, copy.id, runner)

    assert result.run.status == "completed"
    assert result.run.parser_id == "external.aleapp"
    assert result.run.parser_version == "v2026.1.0-test"
    assert len(result.outputs) == 1
    assert result.outputs[0].relative_path == "report.tsv"
    assert repeated.run.id == result.run.id
    store = EvidenceStore(database.data_dir / "evidence")
    assert store.verify(result.outputs[0].storage_key, result.outputs[0].sha256)
    with database.session() as session:
        assert len(list(session.scalars(select(EvidenceParserRunRecord)))) == 1
        assert len(list(session.scalars(select(EvidenceToolOutputRecord)))) == 1
