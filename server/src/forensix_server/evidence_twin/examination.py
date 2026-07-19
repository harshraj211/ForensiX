"""Case-authorized execution of trusted parsers against verified working copies."""

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sqlalchemy import select

from forensix_forensic.android_artifacts import android_parser_registry
from forensix_forensic.evidence_io import (
    EvidenceParser,
    ParsedArtifact,
    ParserContext,
    ParserRegistry,
    ParserRegistryError,
    SafeSQLiteReader,
)
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError
from forensix_server.custody import AuditService, CustodyService
from forensix_server.db import (
    Database,
    EvidenceParserRunRecord,
    EvidenceSourceArtifactRecord,
    EvidenceWorkingCopyRecord,
)
from forensix_server.evidence import TimelineService

from .inspection import EvidenceInspectionService
from .service import EvidenceTwinError, EvidenceTwinIntegrityError, EvidenceTwinService


@dataclass(frozen=True, slots=True)
class ParserExecutionResult:
    run: EvidenceParserRunRecord
    artifacts: tuple[EvidenceSourceArtifactRecord, ...]


class EvidenceExaminationService:
    """Runs only built-in registered parsers and appends immutable normalized output."""

    def run_native_parsers(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
        *,
        parser_ids: tuple[str, ...] | None = None,
    ) -> list[ParserExecutionResult]:
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot execute evidence parsers.")
        source = EvidenceTwinService().get_source(database, principal, case_id, source_id)
        verification = EvidenceTwinService().verify_working_copy(
            database, principal, case_id, source_id, working_copy_id
        )
        if verification.status != "verified":
            raise EvidenceTwinIntegrityError(
                "The working copy failed integrity verification and was not parsed."
            )
        inspection = EvidenceInspectionService().inspect_working_copy(
            database, principal, case_id, source_id, working_copy_id
        )
        if inspection.detected_type != "sqlite":
            raise EvidenceTwinError(
                "Native Android provider parsers currently require a direct SQLite working copy."
            )
        with database.session() as session:
            working_copy = session.get(EvidenceWorkingCopyRecord, working_copy_id)
            assert working_copy is not None
        store = EvidenceStore(database.data_dir / "evidence")
        path = store.resolve(working_copy.storage_key, require_file=True)
        context = ParserContext(
            case_id=case_id,
            evidence_source_id=source_id,
            working_copy_id=working_copy_id,
            source_sha256=working_copy.expected_source_sha256,
            source_label=source.source_name,
        )
        registry = android_parser_registry()
        with SafeSQLiteReader(path) as reader:
            compatible = {
                parser.metadata.parser_id: parser
                for parser in registry.compatible(reader.table_names())
            }
            selected = self._select_parsers(registry, compatible, parser_ids)
            return [
                self._execute_parser(
                    database,
                    principal,
                    inspection.id,
                    context,
                    parser,
                    reader,
                )
                for parser in selected
            ]

    def list_runs(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
    ) -> list[EvidenceParserRunRecord]:
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            return list(
                session.scalars(
                    select(EvidenceParserRunRecord)
                    .where(
                        EvidenceParserRunRecord.case_id == case_id,
                        EvidenceParserRunRecord.evidence_source_id == source_id,
                    )
                    .order_by(EvidenceParserRunRecord.completed_at, EvidenceParserRunRecord.id)
                )
            )

    def list_artifacts(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
    ) -> list[EvidenceSourceArtifactRecord]:
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            return list(
                session.scalars(
                    select(EvidenceSourceArtifactRecord)
                    .where(
                        EvidenceSourceArtifactRecord.case_id == case_id,
                        EvidenceSourceArtifactRecord.evidence_source_id == source_id,
                    )
                    .order_by(
                        EvidenceSourceArtifactRecord.event_time,
                        EvidenceSourceArtifactRecord.created_at,
                        EvidenceSourceArtifactRecord.id,
                    )
                )
            )

    @staticmethod
    def _select_parsers(
        registry: ParserRegistry,
        compatible: dict[str, EvidenceParser],
        parser_ids: tuple[str, ...] | None,
    ) -> tuple[EvidenceParser, ...]:
        if parser_ids is None:
            return tuple(compatible.values())
        if len(parser_ids) != len(set(parser_ids)) or len(parser_ids) > 20:
            raise EvidenceTwinError("Parser selection contains duplicates or exceeds policy.")
        selected: list[EvidenceParser] = []
        for parser_id in parser_ids:
            try:
                registry.get(parser_id)
            except ParserRegistryError as error:
                raise EvidenceTwinError(str(error)) from error
            if parser_id not in compatible:
                raise EvidenceTwinError(
                    f"Parser '{parser_id}' is not compatible with this SQLite schema."
                )
            selected.append(compatible[parser_id])
        return tuple(selected)

    def _execute_parser(
        self,
        database: Database,
        principal: Principal,
        inspection_id: str,
        context: ParserContext,
        parser: EvidenceParser,
        reader: SafeSQLiteReader,
    ) -> ParserExecutionResult:
        existing = self._existing_result(database, context.working_copy_id, parser)
        if existing is not None:
            return existing
        started_at = datetime.now(UTC)
        try:
            parsed = parser.parse(reader, context)
            return self._persist_success(
                database, principal, inspection_id, context, parser, parsed, started_at
            )
        except Exception as error:
            return self._persist_failure(
                database, principal, inspection_id, context, parser, error, started_at
            )

    @staticmethod
    def _existing_result(
        database: Database, working_copy_id: str, parser: EvidenceParser
    ) -> ParserExecutionResult | None:
        with database.session() as session:
            run = session.scalar(
                select(EvidenceParserRunRecord).where(
                    EvidenceParserRunRecord.working_copy_id == working_copy_id,
                    EvidenceParserRunRecord.parser_id == parser.metadata.parser_id,
                    EvidenceParserRunRecord.parser_version == parser.metadata.version,
                )
            )
            if run is None:
                return None
            artifacts = tuple(
                session.scalars(
                    select(EvidenceSourceArtifactRecord)
                    .where(EvidenceSourceArtifactRecord.parser_run_id == run.id)
                    .order_by(
                        EvidenceSourceArtifactRecord.created_at, EvidenceSourceArtifactRecord.id
                    )
                )
            )
            return ParserExecutionResult(run=run, artifacts=artifacts)

    def _persist_success(
        self,
        database: Database,
        principal: Principal,
        inspection_id: str,
        context: ParserContext,
        parser: EvidenceParser,
        parsed: list[ParsedArtifact],
        started_at: datetime,
    ) -> ParserExecutionResult:
        completed_at = datetime.now(UTC)
        artifacts_payload = [self._artifact_payload(context, parser, item) for item in parsed]
        artifact_hashes = [
            sha256(_canonical_json(item).encode()).hexdigest() for item in artifacts_payload
        ]
        run_payload = {
            "artifact_hashes": artifact_hashes,
            "completed_at": completed_at.isoformat(),
            "parser_id": parser.metadata.parser_id,
            "parser_version": parser.metadata.version,
            "source_sha256": context.source_sha256,
            "started_at": started_at.isoformat(),
            "status": "completed",
            "working_copy_id": context.working_copy_id,
        }
        run = EvidenceParserRunRecord(
            evidence_source_id=context.evidence_source_id,
            working_copy_id=context.working_copy_id,
            inspection_id=inspection_id,
            case_id=context.case_id,
            executed_by=principal.user_id,
            parser_id=parser.metadata.parser_id,
            parser_version=parser.metadata.version,
            status="completed",
            artifact_count=len(parsed),
            source_sha256=context.source_sha256,
            run_hash=sha256(_canonical_json(run_payload).encode()).hexdigest(),
            error_code=None,
            error_message=None,
            started_at=started_at,
            completed_at=completed_at,
        )
        with database.session() as session:
            session.add(run)
            session.flush()
            records = [
                EvidenceSourceArtifactRecord(
                    parser_run_id=run.id,
                    evidence_source_id=context.evidence_source_id,
                    working_copy_id=context.working_copy_id,
                    case_id=context.case_id,
                    category=item.category,
                    subtype=item.subtype,
                    title=_bounded(item.title, 512, "artifact title"),
                    summary=_bounded(item.summary, 2000, "artifact summary"),
                    event_time=item.event_time,
                    source_locator=_bounded(item.source_locator, 1024, "source locator"),
                    status=item.status,
                    confidence=item.confidence,
                    parser_id=parser.metadata.parser_id,
                    parser_version=parser.metadata.version,
                    metadata_json=_canonical_json(_json_safe(item.metadata)),
                    provenance_json=_canonical_json(payload["provenance"]),
                    artifact_hash=artifact_hash,
                    created_at=completed_at,
                )
                for item, payload, artifact_hash in zip(
                    parsed, artifacts_payload, artifact_hashes, strict=True
                )
            ]
            session.add_all(records)
            session.flush()
            timeline_service = TimelineService()
            for record in records:
                timeline_service.materialize_source_artifact(session, record)
            AuditService().append(
                session,
                case_id=context.case_id,
                actor_id=principal.user_id,
                event_type="evidence_parser_completed",
                object_type="evidence_parser_run",
                object_id=run.id,
                detail={
                    "artifact_count": len(records),
                    "parser_id": parser.metadata.parser_id,
                    "run_hash": run.run_hash,
                },
                created_at=completed_at,
            )
            CustodyService().append_evidence_source(
                session,
                case_id=context.case_id,
                actor_id=principal.user_id,
                event_type="parser_completed",
                evidence_source_id=context.evidence_source_id,
                parser_run_id=run.id,
                purpose=(
                    f"Versioned parser {parser.metadata.parser_id} completed with "
                    f"{len(records)} normalized artifact(s); run hash {run.run_hash}."
                ),
            )
            session.flush()
            return ParserExecutionResult(run=run, artifacts=tuple(records))

    @staticmethod
    def _persist_failure(
        database: Database,
        principal: Principal,
        inspection_id: str,
        context: ParserContext,
        parser: EvidenceParser,
        error: Exception,
        started_at: datetime,
    ) -> ParserExecutionResult:
        completed_at = datetime.now(UTC)
        error_code = getattr(error, "code", "EVIDENCE_PARSER_FAILED")
        payload = {
            "completed_at": completed_at.isoformat(),
            "error_code": error_code,
            "parser_id": parser.metadata.parser_id,
            "parser_version": parser.metadata.version,
            "source_sha256": context.source_sha256,
            "started_at": started_at.isoformat(),
            "status": "failed",
            "working_copy_id": context.working_copy_id,
        }
        run = EvidenceParserRunRecord(
            evidence_source_id=context.evidence_source_id,
            working_copy_id=context.working_copy_id,
            inspection_id=inspection_id,
            case_id=context.case_id,
            executed_by=principal.user_id,
            parser_id=parser.metadata.parser_id,
            parser_version=parser.metadata.version,
            status="failed",
            artifact_count=0,
            source_sha256=context.source_sha256,
            run_hash=sha256(_canonical_json(payload).encode()).hexdigest(),
            error_code=str(error_code)[:64],
            error_message=str(error)[:1000],
            started_at=started_at,
            completed_at=completed_at,
        )
        with database.session() as session:
            session.add(run)
            session.flush()
            AuditService().append(
                session,
                case_id=context.case_id,
                actor_id=principal.user_id,
                event_type="evidence_parser_failed",
                object_type="evidence_parser_run",
                object_id=run.id,
                detail={"error_code": error_code, "parser_id": parser.metadata.parser_id},
                created_at=completed_at,
            )
            CustodyService().append_evidence_source(
                session,
                case_id=context.case_id,
                actor_id=principal.user_id,
                event_type="parser_failed",
                evidence_source_id=context.evidence_source_id,
                parser_run_id=run.id,
                purpose=(
                    f"Versioned parser {parser.metadata.parser_id} failed with "
                    f"error code {error_code}; no normalized artifacts were accepted."
                ),
            )
            session.flush()
            return ParserExecutionResult(run=run, artifacts=())

    @staticmethod
    def _artifact_payload(
        context: ParserContext, parser: EvidenceParser, artifact: ParsedArtifact
    ) -> dict[str, Any]:
        return {
            "artifact": {
                "category": artifact.category,
                "confidence": artifact.confidence,
                "event_time": artifact.event_time.isoformat() if artifact.event_time else None,
                "metadata": _json_safe(artifact.metadata),
                "source_locator": artifact.source_locator,
                "status": artifact.status,
                "subtype": artifact.subtype,
                "summary": artifact.summary,
                "title": artifact.title,
            },
            "provenance": {
                "case_id": context.case_id,
                "evidence_source_id": context.evidence_source_id,
                "parser_id": parser.metadata.parser_id,
                "parser_version": parser.metadata.version,
                "source_label": context.source_label,
                "source_sha256": context.source_sha256,
                "working_copy_id": context.working_copy_id,
            },
        }


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


def _bounded(value: str, limit: int, label: str) -> str:
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > limit:
        raise EvidenceTwinError(f"The parser produced an invalid {label}.")
    return normalized


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
