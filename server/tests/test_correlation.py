import sqlite3
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import pytest

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import Database, UserRecord
from forensix_server.evidence import CorrelationService
from forensix_server.evidence_twin import EvidenceExaminationService, EvidenceTwinService


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'correlation.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def test_correlation_graph_links_explicit_contact_entities_deterministically(
    database: Database, tmp_path: Path
) -> None:
    principal, case_id = _principal_and_case(database)
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_contacts_database(tmp_path / "contacts2.db")),
        source_name="contacts2.db",
    )
    copy = EvidenceTwinService().create_working_copy(database, principal, case_id, source.id)
    EvidenceExaminationService().run_native_parsers(
        database, principal, case_id, source.id, copy.id
    )

    with database.session() as session:
        first = CorrelationService().build(session, principal, case_id)
        second = CorrelationService().build(session, principal, case_id)

    assert first.graph_hash == second.graph_hash
    assert any(
        node.node_type == "identity" and node.label == "Known Contact" for node in first.nodes
    )
    assert any(node.node_type == "phone" and node.label == "+15551234567" for node in first.nodes)
    assert any(edge.relation == "derived_from" for edge in first.edges)
    assert any(edge.relation == "mentions" for edge in first.edges)
    assert first.truncated is False


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="correlator",
            display_name="Correlation Examiner",
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
        case_id = CaseService().create(session, principal, title="Correlation case").id
        return principal, case_id


def _contacts_database(path: Path) -> bytes:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, deleted INTEGER);
        CREATE TABLE data (
            _id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER,
            data1 TEXT, data2 TEXT, data3 TEXT
        );
        INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/name');
        INSERT INTO mimetypes VALUES (2, 'vnd.android.cursor.item/phone_v2');
        INSERT INTO raw_contacts VALUES (10, 0);
        INSERT INTO data VALUES (1, 10, 1, 'Known Contact', NULL, NULL);
        INSERT INTO data VALUES (2, 10, 2, '+15551234567', '2', 'Mobile');
        """
    )
    connection.commit()
    connection.close()
    return path.read_bytes()
