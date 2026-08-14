import sqlite3
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import pytest

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.db import Database, UserRecord
from forensix_server.evidence import KeyEvidenceService
from forensix_server.evidence_twin import EvidenceExaminationService, EvidenceTwinService
from forensix_server.investigation import InvestigationStoryboardService


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'storyboard.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="storyboard.examiner",
            display_name="Storyboard Examiner",
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
        case_id = CaseService().create(session, principal, title="Storyboard case").id
        return principal, case_id


def _sms_database(path: Path) -> bytes:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE sms (
            _id INTEGER PRIMARY KEY,
            date INTEGER,
            type INTEGER,
            address TEXT,
            body TEXT
        );
        INSERT INTO sms VALUES (
            7,
            1700000000000,
            1,
            '+15550001111',
            'Known message linked to the primary subject'
        );
        """
    )
    connection.commit()
    connection.close()
    return path.read_bytes()


def test_storyboard_links_key_evidence_timeline_and_explicit_entities(
    database: Database,
    tmp_path: Path,
) -> None:
    principal, case_id = _principal_and_case(database)
    source = EvidenceTwinService().import_stream(
        database,
        principal,
        case_id,
        BytesIO(_sms_database(tmp_path / "mmssms.db")),
        source_name="mmssms.db",
    )
    working_copy = EvidenceTwinService().create_working_copy(
        database,
        principal,
        case_id,
        source.id,
    )
    parsed = (
        EvidenceExaminationService()
        .run_native_parsers(
            database,
            principal,
            case_id,
            source.id,
            working_copy.id,
            parser_ids=("android.telephony.sms",),
        )[0]
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
            reason="Message directly names the working investigation subject.",
        )

    with database.session() as session:
        storyboard = InvestigationStoryboardService().build(
            session,
            principal,
            case_id,
        )
        repeated = InvestigationStoryboardService().build(
            session,
            principal,
            case_id,
        )

    assert storyboard.metrics.key_findings == 1
    assert storyboard.metrics.critical_findings == 1
    assert storyboard.metrics.timeline_claims == 1
    assert storyboard.metrics.linked_moments == 1
    assert storyboard.metrics.relationship_leads >= 1
    assert storyboard.findings[0].id == finding.id
    assert storyboard.findings[0].timeline_event_ids == (storyboard.moments[0].id,)
    assert "phone: +15550001111" in storyboard.findings[0].related_entities
    assert any(
        lead.entity_type == "phone" and lead.label == "+15550001111" for lead in storyboard.leads
    )
    assert storyboard.moments[0].key_evidence_linked is True
    assert storyboard.moments[0].finding_ids == (finding.id,)
    assert storyboard.gaps == ()
    assert all(len(value) == 64 for value in storyboard.source_hashes.values())
    assert storyboard.snapshot_hash == repeated.snapshot_hash
    assert len(storyboard.snapshot_hash) == 64


def test_storyboard_exposes_actionable_gaps_without_inventing_evidence(
    database: Database,
) -> None:
    principal, case_id = _principal_and_case(database)

    with database.session() as session:
        storyboard = InvestigationStoryboardService().build(
            session,
            principal,
            case_id,
        )

    assert storyboard.metrics.key_findings == 0
    assert storyboard.metrics.timeline_claims == 0
    assert storyboard.findings == ()
    assert storyboard.moments == ()
    assert storyboard.leads == ()
    assert {gap.code for gap in storyboard.gaps} == {
        "NO_KEY_EVIDENCE",
        "NO_TIMELINE_CLAIMS",
    }
    assert "0 key finding(s)" in storyboard.overview
    assert len(storyboard.snapshot_hash) == 64
