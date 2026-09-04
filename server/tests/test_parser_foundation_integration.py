import json
import sqlite3
from collections.abc import Iterator
from datetime import datetime
from io import BytesIO
from pathlib import Path

import pytest

from forensix_forensic.evidence_io import (
    BaseEvidenceParser,
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    ParserRegistry,
    SafeSQLiteReader,
)
from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import (
    Database,
    UserRecord,
)
from forensix_server.evidence_twin import (
    EvidenceExaminationService,
    EvidenceTwinService,
)
from forensix_server.jobs import JobState, JobType


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'foundation.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="foundation_examiner",
            display_name="Foundation Examiner",
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
        case_id = CaseService().create(session, principal, title="Foundation Test Case").id
        return principal, case_id


def _rich_test_database(path: Path) -> bytes:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE chat_messages (
            id INTEGER PRIMARY KEY,
            sender TEXT,
            recipient TEXT,
            body TEXT,
            ocr_text TEXT,
            sent_at TEXT
        );
        INSERT INTO chat_messages VALUES (
            1,
            'alice@investigation.internal',
            '+15559876543',
            'Confidential blueprint meeting scheduled for tomorrow morning.',
            'Whiteboard sketch showing project architecture diagram.',
            '2026-03-15T09:30:00Z'
        );
        """
    )
    connection.commit()
    connection.close()
    return path.read_bytes()


class RichTestParser(BaseEvidenceParser):
    metadata = ParserMetadata(
        parser_id="test.rich_parser",
        name="Rich Evidence Parser",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"chat_messages"}),
        source_path_hints=("rich_evidence",),
        maturity="validated",
        access_level="filesystem",
        supported_artifact_types=("chat_message",),
        description="Extracts test chat messages with rich content, OCR, and metadata",
    )

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        del context
        rows = reader.execute_select(
            "SELECT id, sender, recipient, body, ocr_text, sent_at FROM chat_messages"
        )
        artifacts = []
        for row in rows:
            artifacts.append(
                ParsedArtifact(
                    category="communication",
                    subtype="chat_message",
                    title=f"Message from {row['sender']}",
                    summary="Confidential project kickoff discussion",
                    event_time=datetime.fromisoformat(str(row["sent_at"])),
                    source_locator=f"chat_messages:{row['id']}",
                    status="active",
                    confidence="high",
                    content=str(row["body"]),
                    metadata={
                        "sender": str(row["sender"]),
                        "recipient": str(row["recipient"]),
                        "ocr_text": str(row["ocr_text"]),
                        "body": str(row["body"]),
                    },
                )
            )
        return artifacts


def test_fts5_full_text_search_across_content_and_metadata(
    database: Database, tmp_path: Path
) -> None:
    principal, case_id = _principal_and_case(database)
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_rich_test_database(tmp_path / "rich_evidence.db")),
        source_name="rich_evidence.db",
    )
    working_copy = EvidenceTwinService().create_working_copy(
        database, principal, case_id, source.id
    )

    custom_registry = ParserRegistry()
    rich_parser = RichTestParser()
    custom_registry.register(rich_parser)

    # Execute parser with custom registry
    results = EvidenceExaminationService().run_native_parsers(
        database,
        principal,
        case_id,
        source.id,
        working_copy.id,
        registry=custom_registry,
    )
    assert len(results) == 1
    assert results[0].run.parser_id == "test.rich_parser"
    assert results[0].run.status == "completed"
    assert results[0].run.artifact_count == 1

    # 1. Search by message body text
    body_res = EvidenceExaminationService().search_source_artifacts(
        database, principal, case_id, query="Confidential blueprint"
    )
    assert body_res.total == 1
    assert body_res.items[0].title == "Message from alice@investigation.internal"

    # 2. Search by OCR extracted text
    ocr_res = EvidenceExaminationService().search_source_artifacts(
        database, principal, case_id, query="Whiteboard architecture"
    )
    assert ocr_res.total == 1
    assert ocr_res.items[0].id == body_res.items[0].id

    # 3. Search by metadata (phone / email)
    phone_res = EvidenceExaminationService().search_source_artifacts(
        database, principal, case_id, query="+15559876543"
    )
    assert phone_res.total == 1

    email_res = EvidenceExaminationService().search_source_artifacts(
        database, principal, case_id, query="alice"
    )
    assert email_res.total == 1

    # 4. Search by summary
    summary_res = EvidenceExaminationService().search_source_artifacts(
        database, principal, case_id, query="kickoff discussion"
    )
    assert summary_res.total == 1

    # 5. Non-matching query
    miss_res = EvidenceExaminationService().search_source_artifacts(
        database, principal, case_id, query="nonexistentterm"
    )
    assert miss_res.total == 0


def test_background_parser_job_lifecycle(database: Database, tmp_path: Path) -> None:
    principal, case_id = _principal_and_case(database)
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_rich_test_database(tmp_path / "rich_evidence2.db")),
        source_name="rich_evidence2.db",
    )
    working_copy = EvidenceTwinService().create_working_copy(
        database, principal, case_id, source.id
    )

    custom_registry = ParserRegistry()
    custom_registry.register(RichTestParser())

    service = EvidenceExaminationService()

    # 1. Prepare job
    job = service.prepare_parser_job(database, principal, case_id, source.id, working_copy.id)
    assert job.job_type == JobType.PARSING.value
    assert job.state == JobState.READY.value
    assert job.progress_percent == 5
    assert job.checkpoint_json is not None
    checkpoint = json.loads(job.checkpoint_json)
    assert checkpoint["case_id"] == case_id
    assert checkpoint["source_id"] == source.id
    assert checkpoint["working_copy_id"] == working_copy.id

    # 2. Query job
    fetched_job = service.get_parser_job(database, principal, case_id, job.id)
    assert fetched_job.id == job.id

    # 3. Execute job
    results = service.execute_parser_job(database, principal, job.id, registry=custom_registry)
    assert len(results) == 1
    assert results[0].run.status == "completed"

    # Verify job state after completion
    completed_job = service.get_parser_job(database, principal, case_id, job.id)
    assert completed_job.state == JobState.COMPLETED.value
    assert completed_job.progress_percent == 100
    assert completed_job.result_reference == "artifacts:1"


def test_background_parser_job_cancellation(database: Database, tmp_path: Path) -> None:
    principal, case_id = _principal_and_case(database)
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_rich_test_database(tmp_path / "rich_evidence3.db")),
        source_name="rich_evidence3.db",
    )
    working_copy = EvidenceTwinService().create_working_copy(
        database, principal, case_id, source.id
    )

    service = EvidenceExaminationService()
    job = service.prepare_parser_job(database, principal, case_id, source.id, working_copy.id)

    # Cancel job
    cancelled_job = service.cancel_parser_job(database, principal, case_id, job.id)
    assert cancelled_job.cancellation_requested is True


def test_strengthened_parser_provenance(database: Database, tmp_path: Path) -> None:
    principal, case_id = _principal_and_case(database)
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_rich_test_database(tmp_path / "rich_evidence4.db")),
        source_name="rich_evidence4.db",
    )
    working_copy = EvidenceTwinService().create_working_copy(
        database, principal, case_id, source.id
    )

    custom_registry = ParserRegistry()
    custom_registry.register(RichTestParser())

    results = EvidenceExaminationService().run_native_parsers(
        database,
        principal,
        case_id,
        source.id,
        working_copy.id,
        registry=custom_registry,
    )

    assert len(results) == 1
    run = results[0].run
    assert run.run_hash != ""
    assert len(run.run_hash) == 64
    assert run.parser_id == "test.rich_parser"
    assert run.parser_version == "1.0.0"
    assert run.artifact_count == 1

    artifact = results[0].artifacts[0]
    prov = json.loads(artifact.provenance_json)
    assert prov["parser_id"] == "test.rich_parser"
    assert prov["parser_version"] == "1.0.0"
    assert prov["source_locator"] == "chat_messages:1"
    assert prov["confidence"] == "high"
    assert prov["status"] == "active"
    assert prov["parser_maturity"] == "validated"
    assert prov["access_level"] == "filesystem"
    assert prov["input_sha256"] != ""
