import json
import sqlite3
import tarfile
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import pytest
from sqlalchemy import select

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import (
    AuditLogRecord,
    CustodyEventRecord,
    Database,
    EvidenceParserRunRecord,
    EvidenceSourceArtifactRecord,
    EvidenceSourceTimelineEventRecord,
    UserRecord,
)
from forensix_server.evidence_twin import (
    EvidenceExaminationService,
    EvidenceTwinError,
    EvidenceTwinService,
)
from forensix_server.reporting import ReportService


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'examination.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="examiner",
            display_name="Evidence Examiner",
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
        case_id = CaseService().create(session, principal, title="Parser case").id
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


def test_native_parser_results_are_persisted_with_provenance(
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

    results = EvidenceExaminationService().run_native_parsers(
        database, principal, case_id, source.id, working_copy.id
    )
    repeated = EvidenceExaminationService().run_native_parsers(
        database, principal, case_id, source.id, working_copy.id
    )

    assert len(results) == 1
    assert results[0].run.parser_id == "android.contacts_provider"
    assert results[0].run.status == "completed"
    assert results[0].run.artifact_count == 1
    assert results[0].artifacts[0].title == "Known Contact"
    assert results[0].artifacts[0].source_locator == "raw_contacts:10"
    assert repeated[0].run.id == results[0].run.id
    with database.session() as session:
        assert len(list(session.scalars(select(EvidenceParserRunRecord)))) == 1
        assert len(list(session.scalars(select(EvidenceSourceArtifactRecord)))) == 1
        audit_types = set(session.scalars(select(AuditLogRecord.event_type)))
        custody_types = list(
            session.scalars(
                select(CustodyEventRecord.event_type).order_by(CustodyEventRecord.sequence)
            )
        )
        assert "evidence_parser_completed" in audit_types
        assert custody_types.count("parser_completed") == 1
        assert session.scalar(select(EvidenceSourceTimelineEventRecord.id)) is None


def test_sms_parser_materializes_imported_source_timeline_claim(
    database: Database, tmp_path: Path
) -> None:
    principal, case_id = _principal_and_case(database)
    path = tmp_path / "mmssms.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE sms (_id INTEGER PRIMARY KEY, date INTEGER, type INTEGER,
                          address TEXT, body TEXT);
        INSERT INTO sms VALUES (7, 1700000000000, 1, '+15550001111', 'Known message');
        """
    )
    connection.commit()
    connection.close()
    source = EvidenceTwinService().import_stream(
        database, principal, case_id, BytesIO(path.read_bytes()), source_name="mmssms.db"
    )
    working_copy = EvidenceTwinService().create_working_copy(
        database, principal, case_id, source.id
    )

    result = EvidenceExaminationService().run_native_parsers(
        database,
        principal,
        case_id,
        source.id,
        working_copy.id,
        parser_ids=("android.telephony.sms",),
    )[0]

    with database.session() as session:
        timeline = session.scalar(select(EvidenceSourceTimelineEventRecord))
    assert timeline is not None
    assert timeline.source_artifact_id == result.artifacts[0].id
    assert timeline.parser_run_id == result.run.id
    assert timeline.category == "communication"
    assert timeline.timestamp_type == "parsed_artifact_event_time"

    report = ReportService().generate(database, principal, case_id)
    json_output = next(item for item in report.outputs if item.format == "json")
    report_payload = json.loads(
        (database.data_dir / "evidence" / json_output.storage_key).read_text(encoding="utf-8")
    )
    assert report_payload["evidence_sources"][0]["sha256"] == source.sha256
    assert report_payload["evidence_sources"][0]["working_copies"][0]["status"] == "ready"
    assert report_payload["evidence_sources"][0]["parser_runs"][0]["parser_id"] == (
        "android.telephony.sms"
    )
    assert report_payload["imported_artifacts"][0]["subtype"] == "sms"
    assert report_payload["timeline"][0]["source_artifact_id"] == result.artifacts[0].id


def test_incompatible_parser_selection_is_rejected(database: Database, tmp_path: Path) -> None:
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

    with pytest.raises(EvidenceTwinError, match="not compatible"):
        EvidenceExaminationService().run_native_parsers(
            database,
            principal,
            case_id,
            source.id,
            working_copy.id,
            parser_ids=("android.telephony.sms",),
        )


def test_native_parsers_safely_examine_sqlite_members_in_rooted_tar(
    database: Database, tmp_path: Path
) -> None:
    principal, case_id = _principal_and_case(database)
    contacts = _contacts_database(tmp_path / "rooted-contacts2.db")
    archive_buffer = BytesIO()
    member_name = (
        "data/user_de/0/com.android.providers.contacts/databases/contacts2.db"
    )
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        member = tarfile.TarInfo(member_name)
        member.size = len(contacts)
        archive.addfile(member, BytesIO(contacts))
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(archive_buffer.getvalue()),
        source_name="android_providers.tar",
    )
    working_copy = EvidenceTwinService().create_working_copy(
        database, principal, case_id, source.id
    )

    results = EvidenceExaminationService().run_native_parsers(
        database, principal, case_id, source.id, working_copy.id
    )
    repeated = EvidenceExaminationService().run_native_parsers(
        database, principal, case_id, source.id, working_copy.id
    )

    assert len(results) == 1
    assert results[0].run.parser_id == "android.contacts_provider"
    assert results[0].run.input_locator == member_name
    assert len(results[0].run.input_sha256) == 64
    assert results[0].artifacts[0].title == "Known Contact"
    provenance = json.loads(results[0].artifacts[0].provenance_json)
    assert provenance["input_locator"] == member_name
    assert provenance["input_sha256"] == results[0].run.input_sha256
    assert repeated[0].run.id == results[0].run.id
    extraction_parent = database.data_dir / "work" / "archive-examination"
    assert not extraction_parent.exists() or not any(extraction_parent.iterdir())
