import sqlite3
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import pytest
from sqlalchemy import select

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import AuditLogRecord, Database, UserRecord
from forensix_server.evidence import KeyEvidenceService
from forensix_server.evidence_twin import EvidenceExaminationService, EvidenceTwinService


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'key-evidence.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="key.evidence.examiner",
            display_name="Key Evidence Examiner",
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
        case_id = CaseService().create(session, principal, title="Key evidence case").id
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
        INSERT INTO data VALUES (1, 10, 1, 'Priority Contact', NULL, NULL);
        INSERT INTO data VALUES (2, 10, 2, '+15551234567', '2', 'Mobile');
        """
    )
    connection.commit()
    connection.close()
    return path.read_bytes()


def test_parsed_source_artifact_can_be_curated_and_removed(
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
    working_copy = EvidenceTwinService().create_working_copy(
        database, principal, case_id, source.id
    )
    parsed = (
        EvidenceExaminationService()
        .run_native_parsers(database, principal, case_id, source.id, working_copy.id)[0]
        .artifacts[0]
    )

    with database.session() as session:
        finding = KeyEvidenceService().promote(
            session,
            principal,
            case_id,
            target_type="source_artifact",
            target_id=parsed.id,
            priority="critical",
            reason="Known number connects this extraction to the primary subject.",
        )

        assert finding.target_type == "source_artifact"
        assert finding.title == "Priority Contact"
        assert finding.category == "contact"
        assert finding.priority == "critical"
        assert finding.parser_id == "android.contacts_provider"
        finding_id = finding.id

    with database.session() as session:
        results = KeyEvidenceService().list(
            session, principal, case_id, query="primary subject", priority="critical"
        )
        audit_types = set(session.scalars(select(AuditLogRecord.event_type)))

        assert results.total == 1
        assert results.items[0].id == finding_id
        assert results.priority_counts == {"critical": 1, "high": 0, "normal": 0}
        assert results.category_facets == {"contact": 1}
        assert "key_evidence_promoted" in audit_types

    with database.session() as session:
        KeyEvidenceService().remove(session, principal, case_id, finding_id)

    with database.session() as session:
        assert KeyEvidenceService().list(session, principal, case_id).total == 0
        audit_types = set(session.scalars(select(AuditLogRecord.event_type)))
        assert "key_evidence_removed" in audit_types
