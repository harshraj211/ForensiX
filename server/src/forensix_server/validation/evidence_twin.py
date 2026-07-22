"""Sealed known-answer validation of the complete Evidence Twin workflow."""

from __future__ import annotations

import hashlib
import json
import platform
import sqlite3
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from forensix_forensic.storage import EvidenceStore
from forensix_forensic.validation import (
    ValidationCheck,
    ValidationEnvironment,
    ValidationOutcome,
    ValidationStatus,
)
from forensix_server import __version__
from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.custody import AuditService, CustodyService
from forensix_server.db import (
    AuditLogRecord,
    CustodyEventRecord,
    Database,
    EvidenceSourceArtifactRecord,
    EvidenceSourceTimelineEventRecord,
    UserRecord,
)
from forensix_server.evidence_twin import (
    EvidenceExaminationService,
    EvidenceInspectionService,
    EvidenceTwinService,
    ParserExecutionResult,
)
from forensix_server.reporting import ReportService

EXPECTED_PARSER_COUNTS = {
    "android.call_log": 1,
    "android.contacts_provider": 1,
    "android.telephony.mms": 1,
    "android.telephony.sms": 1,
}


class EvidenceTwinValidationReport(BaseModel):
    """Redacted end-to-end known-answer result with no raw artifact content."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = "forensix-evidence-twin-validation/1.0"
    run_id: str = Field(min_length=36, max_length=36)
    started_at: datetime
    completed_at: datetime
    tool_version: str = Field(min_length=1, max_length=64)
    profile: Literal["sqlite_provider_known_answer"]
    outcome: ValidationOutcome
    environment: ValidationEnvironment
    fixture_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    evidence_source_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    chunk_ledger_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    manifest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    working_copy_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    report_output_sha256: dict[str, str] = Field(default_factory=dict)
    checks: tuple[ValidationCheck, ...]
    limitations: tuple[str, ...]


class SealedEvidenceTwinValidationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    report: EvidenceTwinValidationReport
    canonical_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


def run_evidence_twin_validation(workspace: Path) -> SealedEvidenceTwinValidationReport:
    """Execute an isolated known-answer workflow and return an integrity-sealed result."""
    started_at = datetime.now(UTC)
    checks: list[ValidationCheck] = []
    fixture_sha256: str | None = None
    source_sha256: str | None = None
    chunk_ledger_sha256: str | None = None
    manifest_sha256: str | None = None
    working_copy_sha256: str | None = None
    report_output_sha256: dict[str, str] = {}
    workspace.mkdir(parents=True, exist_ok=True)
    database = Database(
        f"sqlite:///{(workspace / 'validation.db').as_posix()}",
        workspace,
    )
    try:
        database.initialize()
        principal, case_id = _principal_and_case(database)
        fixture = _provider_fixture(workspace / "provider-known-answer.db")
        fixture_sha256 = hashlib.sha256(fixture).hexdigest()
        checks.append(
            _check(
                "fixture_created",
                ValidationStatus.SUCCEEDED,
                "The controlled provider database fixture was created and hashed.",
                size_bytes=len(fixture),
                expected_parser_count=len(EXPECTED_PARSER_COUNTS),
            )
        )

        twin = EvidenceTwinService()
        source = twin.import_stream(
            database,
            principal,
            case_id,
            BytesIO(fixture),
            source_name="provider-known-answer.db",
            display_name="Controlled Android provider known-answer source",
            declared_size_bytes=len(fixture),
        )
        source_sha256 = source.sha256
        chunk_ledger_sha256 = source.chunks_sha256
        manifest_sha256 = source.manifest_sha256
        source_valid = (
            source.status == "sealed"
            and source.sha256 == fixture_sha256
            and source.chunk_count >= 1
            and source.chunks_sha256 is not None
            and source.manifest_sha256 is not None
        )
        checks.append(
            _check(
                "source_sealing",
                _status(source_valid),
                "The imported master, fixed chunk ledger, and canonical manifest were sealed.",
                whole_hash_matches=source.sha256 == fixture_sha256,
                chunk_count=source.chunk_count,
                read_only_applied=source.read_only_applied,
            )
        )

        master_verification = twin.verify_master(database, principal, case_id, source.id)
        working_copy = twin.create_working_copy(database, principal, case_id, source.id)
        copy_verification = twin.verify_working_copy(
            database,
            principal,
            case_id,
            source.id,
            working_copy.id,
        )
        working_copy_sha256 = working_copy.observed_sha256
        copy_valid = (
            master_verification.status == "verified"
            and working_copy.status == "ready"
            and copy_verification.status == "verified"
            and working_copy.observed_sha256 == source.sha256
        )
        checks.append(
            _check(
                "working_copy_integrity",
                _status(copy_valid),
                "A separate examination copy was created and independently re-hashed.",
                master_verified=master_verification.status == "verified",
                copy_verified=copy_verification.status == "verified",
                hash_matches=working_copy.observed_sha256 == source.sha256,
            )
        )

        inspection = EvidenceInspectionService().inspect_working_copy(
            database,
            principal,
            case_id,
            source.id,
            working_copy.id,
        )
        checks.append(
            _check(
                "signature_inspection",
                _status(inspection.detected_type == "sqlite"),
                "The working copy was classified from bounded file signatures.",
                detected_type=inspection.detected_type,
            )
        )

        results = EvidenceExaminationService().run_native_parsers(
            database,
            principal,
            case_id,
            source.id,
            working_copy.id,
            parser_ids=tuple(EXPECTED_PARSER_COUNTS),
        )
        observed_counts = {result.run.parser_id: result.run.artifact_count for result in results}
        parser_valid = observed_counts == EXPECTED_PARSER_COUNTS and _known_answers_match(results)
        checks.append(
            _check(
                "provider_parsers",
                _status(parser_valid),
                "Contacts, SMS, MMS, and call-log parsers matched controlled expectations.",
                parser_count=len(results),
                artifact_count=sum(observed_counts.values()),
                known_answers_match=parser_valid,
            )
        )

        with database.session() as session:
            artifact_count = (
                session.scalar(select(func.count(EvidenceSourceArtifactRecord.id))) or 0
            )
            timeline = list(session.scalars(select(EvidenceSourceTimelineEventRecord)))
            custody = list(session.scalars(select(CustodyEventRecord)))
            audits = list(session.scalars(select(AuditLogRecord)))
            custody_valid, _ = CustodyService().verify_chain(session, principal, case_id)
            audit_valid, _ = AuditService().verify(session, principal)
        timeline_valid = (
            len(timeline) == 3
            and all(len(item.event_hash) == 64 for item in timeline)
            and all(item.timestamp_type == "parsed_artifact_event_time" for item in timeline)
        )
        checks.append(
            _check(
                "normalization_timeline",
                _status(artifact_count == 4 and timeline_valid),
                "Normalized artifacts and timestamp-bearing timeline claims were materialized.",
                artifact_count=artifact_count,
                timeline_count=len(timeline),
                timeline_hashes_valid=timeline_valid,
            )
        )
        checks.append(
            _check(
                "custody_audit_chains",
                _status(custody_valid and audit_valid),
                "Evidence operations produced independently verifiable custody and audit chains.",
                custody_valid=custody_valid,
                custody_events=len(custody),
                audit_valid=audit_valid,
                audit_events=len(audits),
            )
        )

        report_bundle = ReportService().generate(database, principal, case_id)
        store = EvidenceStore(database.data_dir / "evidence")
        outputs_valid = all(
            store.verify(item.storage_key, item.sha256) for item in report_bundle.outputs
        )
        report_output_sha256 = {item.format: item.sha256 for item in report_bundle.outputs}
        json_output = next(item for item in report_bundle.outputs if item.format == "json")
        report_payload = json.loads(
            store.resolve(json_output.storage_key, require_file=True).read_text(encoding="utf-8")
        )
        report_valid = (
            outputs_valid
            and set(report_output_sha256) == {"csv", "json", "pdf"}
            and len(report_payload["imported_artifacts"]) == 4
            and len(report_payload["timeline"]) == 3
            and report_payload["evidence_sources"][0]["sha256"] == source.sha256
        )
        checks.append(
            _check(
                "report_integrity",
                _status(report_valid),
                "The preliminary PDF, JSON, and CSV outputs were sealed and re-verified.",
                output_count=len(report_bundle.outputs),
                outputs_verified=outputs_valid,
                snapshot_contains_known_counts=report_valid,
            )
        )
    except Exception as error:  # A failed validation must still yield a sealed redacted record.
        checks.append(
            _check(
                "validation_runtime",
                ValidationStatus.FAIL,
                "The Evidence Twin validation stopped safely after an operational error.",
                error_type=type(error).__name__,
            )
        )
    finally:
        database.dispose()

    validation_report = EvidenceTwinValidationReport(
        run_id=str(uuid4()),
        started_at=started_at,
        completed_at=datetime.now(UTC),
        tool_version=__version__,
        profile="sqlite_provider_known_answer",
        outcome=_outcome(checks),
        environment=ValidationEnvironment(
            operating_system=platform.system() or "unknown",
            operating_system_release=platform.release() or "unknown",
            machine=platform.machine() or "unknown",
            python_version=platform.python_version(),
        ),
        fixture_sha256=fixture_sha256,
        evidence_source_sha256=source_sha256,
        chunk_ledger_sha256=chunk_ledger_sha256,
        manifest_sha256=manifest_sha256,
        working_copy_sha256=working_copy_sha256,
        report_output_sha256=report_output_sha256,
        checks=tuple(checks),
        limitations=(
            (
                "This synthetic known-answer run is software validation, not physical-device "
                "validation."
            ),
            "The fixture contains no production, personal, or case evidence.",
            "Passing parser fixtures do not prove coverage across Android or application versions.",
            "Evidentiary admissibility requires agency validation, procedures, and review.",
        ),
    )
    return SealedEvidenceTwinValidationReport(
        report=validation_report,
        canonical_sha256=_report_digest(validation_report),
    )


def verify_evidence_twin_validation(sealed: SealedEvidenceTwinValidationReport) -> bool:
    return _report_digest(sealed.report) == sealed.canonical_sha256


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="evidence.twin.validator",
            display_name="Evidence Twin Validator",
            password_hash="$argon2id$validation-placeholder",  # noqa: S106
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
        case = CaseService().create(
            session,
            principal,
            title="Evidence Twin controlled known-answer validation",
            legal_authority="Synthetic software validation",
        )
        return principal, case.id


def _provider_fixture(path: Path) -> bytes:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE raw_contacts (
            _id INTEGER PRIMARY KEY, deleted INTEGER, account_name TEXT, account_type TEXT
        );
        CREATE TABLE data (
            _id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER,
            data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT
        );
        INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/name');
        INSERT INTO mimetypes VALUES (2, 'vnd.android.cursor.item/phone_v2');
        INSERT INTO raw_contacts VALUES (10, 0, 'known-answer', 'forensix.validation');
        INSERT INTO data VALUES (1, 10, 1, 'Known Contact', NULL, NULL, NULL);
        INSERT INTO data VALUES (2, 10, 2, '+15550000001', '2', 'Mobile', NULL);

        CREATE TABLE sms (
            _id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER,
            date_sent INTEGER, read INTEGER, seen INTEGER, type INTEGER, body TEXT,
            service_center TEXT, sub_id INTEGER, creator TEXT
        );
        INSERT INTO sms VALUES (
            1, 7, '+15550000002', 1704067200000, 1704067200000, 1, 1, 1,
            'Known SMS', NULL, 1, 'forensix.validation'
        );
        CREATE TABLE pdu (
            _id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, date_sent INTEGER,
            msg_box INTEGER, read INTEGER, seen INTEGER, sub TEXT, ct_t TEXT
        );
        CREATE TABLE part (
            _id INTEGER PRIMARY KEY, mid INTEGER, ct TEXT, text TEXT, _data TEXT,
            name TEXT, fn TEXT, cid TEXT, cl TEXT
        );
        CREATE TABLE addr (msg_id INTEGER, address TEXT, type INTEGER, charset INTEGER);
        INSERT INTO pdu VALUES (
            2, 8, 1704067200, 1704067200, 1, 1, 1, 'Known Subject',
            'application/vnd.wap.multipart.related'
        );
        INSERT INTO part VALUES (
            20, 2, 'text/plain', 'Known MMS', NULL, NULL, NULL, NULL, NULL
        );
        INSERT INTO addr VALUES (2, '+15550000003', 137, 106);

        CREATE TABLE calls (
            _id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER,
            type INTEGER, name TEXT, geocoded_location TEXT
        );
        INSERT INTO calls VALUES (
            1, '+15550000004', 1704067200000, 42, 2, 'Known Caller', 'Known Location'
        );
        """
    )
    connection.commit()
    connection.close()
    return path.read_bytes()


def _known_answers_match(results: list[ParserExecutionResult]) -> bool:
    artifacts: dict[str, list[EvidenceSourceArtifactRecord]] = {}
    for result in results:
        artifacts[result.run.parser_id] = list(result.artifacts)
    return (
        artifacts["android.contacts_provider"][0].title == "Known Contact"
        and artifacts["android.telephony.sms"][0].summary == "Known SMS"
        and artifacts["android.telephony.mms"][0].summary == "Known MMS"
        and artifacts["android.call_log"][0].summary == "Duration 42 second(s)"
    )


def _check(
    check_id: str,
    status: ValidationStatus,
    summary: str,
    **observed: str | int | bool | None,
) -> ValidationCheck:
    return ValidationCheck(check_id=check_id, status=status, summary=summary, observed=observed)


def _status(value: bool) -> ValidationStatus:
    return ValidationStatus.SUCCEEDED if value else ValidationStatus.FAIL


def _outcome(checks: list[ValidationCheck]) -> ValidationOutcome:
    statuses = {check.status for check in checks}
    if ValidationStatus.FAIL in statuses:
        return ValidationOutcome.FAILED
    if ValidationStatus.SKIPPED in statuses:
        return ValidationOutcome.INCOMPLETE
    if ValidationStatus.WARNING in statuses:
        return ValidationOutcome.PASSED_WITH_WARNINGS
    return ValidationOutcome.PASSED


def _report_digest(report: EvidenceTwinValidationReport) -> str:
    payload = report.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
