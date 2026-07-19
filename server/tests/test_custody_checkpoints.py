import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.custody_exports import (
    CustodyCheckpointIntegrityError,
    CustodyCheckpointService,
)
from forensix_server.db import Database, UserRecord


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'checkpoint.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="checkpoint.supervisor",
            display_name="Checkpoint Supervisor",
            password_hash="$argon2id$test-placeholder",
        )
        session.add(user)
        session.flush()
        principal = Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({RoleName.ADMINISTRATOR}),
            permissions=ROLE_PERMISSIONS[RoleName.ADMINISTRATOR],
        )
        case = CaseService().create(session, principal, title="Checkpoint known-answer case")
        return principal, case.id


def test_checkpoint_is_sealed_and_refuses_tampered_download(database: Database) -> None:
    principal, case_id = _principal_and_case(database)
    service = CustodyCheckpointService()

    record = service.create(database, principal, case_id)
    content = service.content(database, principal, case_id, record.id)
    payload = json.loads(content.path.read_text(encoding="utf-8"))

    assert record.custody_record_count == 0
    assert record.audit_sequence == 0
    assert record.audit_head_hash is None
    assert len(record.sha256) == 64
    assert payload["checkpoint_id"] == record.id
    assert payload["anchor_status"] == "not_externally_anchored"
    assert payload["audit_checkpoint"]["global_head_hash"] == record.audit_head_hash
    assert payload["custody_chain"]["events"] == []

    content.path.write_bytes(b"tampered checkpoint")
    with pytest.raises(CustodyCheckpointIntegrityError, match="SHA-256"):
        service.content(database, principal, case_id, record.id)
