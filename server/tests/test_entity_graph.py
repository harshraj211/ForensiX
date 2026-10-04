"""Tests for Cross-Source Entity Graph correlation and link analysis."""

import sqlite3
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import pytest

from forensix_server.auth.domain import ROLE_PERMISSIONS, Principal, RoleName
from forensix_server.cases import CaseService
from forensix_server.db import Database, UserRecord
from forensix_server.evidence_twin import EvidenceExaminationService, EvidenceTwinService
from forensix_server.evidence_twin.entity_graph import EntityGraphService


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'entity_graph.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="graph_examiner",
            display_name="Graph Examiner",
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
        case_id = CaseService().create(session, principal, title="Entity Graph Test Case").id
        return principal, case_id


def _contacts_database(path: Path) -> bytes:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE raw_contacts ("
        "_id INTEGER PRIMARY KEY, account_name TEXT, account_type TEXT, deleted INTEGER)"
    )
    conn.execute("CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT)")
    conn.execute(
        "CREATE TABLE data ("
        "_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER, "
        "data1 TEXT, data2 TEXT, data3 TEXT)"
    )

    conn.execute(
        "INSERT INTO raw_contacts (_id, account_name, account_type, deleted) "
        "VALUES (1, 'user@gmail.com', 'com.google', 0)"
    )
    conn.execute("INSERT INTO mimetypes (_id, mimetype) VALUES (1, 'vnd.android.cursor.item/name')")
    conn.execute(
        "INSERT INTO mimetypes (_id, mimetype) VALUES (2, 'vnd.android.cursor.item/phone_v2')"
    )
    conn.execute(
        "INSERT INTO mimetypes (_id, mimetype) VALUES (3, 'vnd.android.cursor.item/email_v2')"
    )

    conn.execute(
        "INSERT INTO data (_id, raw_contact_id, mimetype_id, data1, data2, data3) "
        "VALUES (1, 1, 1, 'Target Subject', 'Target', 'Subject')"
    )
    conn.execute(
        "INSERT INTO data (_id, raw_contact_id, mimetype_id, data1, data2, data3) "
        "VALUES (2, 1, 2, '+15550009999', '2', NULL)"
    )
    conn.execute(
        "INSERT INTO data (_id, raw_contact_id, mimetype_id, data1, data2, data3) "
        "VALUES (3, 1, 3, 'target@darknet.org', '1', NULL)"
    )
    conn.commit()
    conn.close()
    return path.read_bytes()


def _sms_database(path: Path) -> bytes:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE sms (_id INTEGER PRIMARY KEY, date INTEGER, type INTEGER, "
        "address TEXT, body TEXT)"
    )
    conn.execute(
        "INSERT INTO sms (_id, date, type, address, body) "
        "VALUES (1, 1693824000000, 1, '+15550009999', 'Meet at coordinates')"
    )
    conn.commit()
    conn.close()
    return path.read_bytes()


def test_entity_graph_service_correlation(database: Database, tmp_path: Path) -> None:
    principal, case_id = _principal_and_case(database)

    # 1. Ingest contacts database
    src_contacts = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_contacts_database(tmp_path / "contacts2.db")),
        source_name="contacts2.db",
    )
    wc_contacts = EvidenceTwinService().create_working_copy(
        database, principal, case_id, src_contacts.id
    )
    EvidenceExaminationService().run_native_parsers(
        database, principal, case_id, src_contacts.id, wc_contacts.id
    )

    # 2. Ingest SMS database
    src_sms = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_sms_database(tmp_path / "mmssms.db")),
        source_name="mmssms.db",
    )
    wc_sms = EvidenceTwinService().create_working_copy(database, principal, case_id, src_sms.id)
    EvidenceExaminationService().run_native_parsers(
        database, principal, case_id, src_sms.id, wc_sms.id
    )

    # 3. Build cross-source entity graph
    graph = EntityGraphService().build_graph(database, principal, case_id)
    assert graph["case_id"] == case_id
    assert graph["total_nodes"] >= 4
    assert graph["total_edges"] >= 3

    node_types = {n["node_type"] for n in graph["nodes"]}
    assert "person" in node_types
    assert "phone" in node_types
    assert "email" in node_types

    edge_relations = {e["relation"] for e in graph["edges"]}
    assert "HAS_PHONE" in edge_relations
    assert "HAS_EMAIL" in edge_relations
    assert "COMMUNICATED_WITH" in edge_relations
