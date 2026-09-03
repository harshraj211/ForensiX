"""Case-authorized execution of trusted parsers against verified working copies."""

import base64
import contextlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from forensix_forensic.android_artifacts import (
    android_document_parser_registry,
    android_parser_registry,
)
from forensix_forensic.evidence_io import (
    ArchivePolicy,
    DocumentEvidenceParser,
    DocumentParserRegistry,
    EvidenceParser,
    ExtractedArchiveMember,
    ParsedArtifact,
    ParserContext,
    ParserRegistry,
    ParserRegistryError,
    SafeArchiveExtractor,
    SafeSQLiteError,
    SafeSQLiteReader,
)
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.custody import AuditService, CustodyService
from forensix_server.db import (
    Database,
    EvidenceParserRunRecord,
    EvidenceSourceArtifactRecord,
    EvidenceWorkingCopyRecord,
    JobRecord,
)
from forensix_server.evidence import TimelineService
from forensix_server.jobs import (
    JobService,
    JobState,
    JobType,
)

from .inspection import EvidenceInspectionService
from .service import (
    EvidenceTwinError,
    EvidenceTwinIntegrityError,
    EvidenceTwinService,
)


@dataclass(frozen=True, slots=True)
class ParserExecutionResult:
    run: EvidenceParserRunRecord
    artifacts: tuple[EvidenceSourceArtifactRecord, ...]


@dataclass(frozen=True, slots=True)
class SourceArtifactSearchResult:
    items: list[EvidenceSourceArtifactRecord]
    total: int
    offset: int
    limit: int
    category_facets: dict[str, int]


SOURCE_ARTIFACT_CATEGORIES = frozenset(
    {"contact", "communication", "application", "location", "system", "file"}
)
SOURCE_ARTIFACT_STATUSES = frozenset(
    {"active", "deleted", "recovered", "partial", "corrupted", "unverified"}
)
MAX_SEARCH_QUERY_LENGTH = 256
_INSERT_SOURCE_ARTIFACT_SEARCH = (
    "INSERT INTO source_artifact_search "
    "(artifact_id, case_id, category, subtype, title, summary, content, metadata) "
    "VALUES (:artifact_id, :case_id, :category, :subtype, :title, :summary, :content, :metadata)"
)


type VersionedParser = EvidenceParser | DocumentEvidenceParser


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
        registry: ParserRegistry | None = None,
        document_registry: DocumentParserRegistry | None = None,
        job_id: str | None = None,
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
            input_locator="working_copy",
            input_sha256=working_copy.expected_source_sha256,
        )
        active_registry = registry or android_parser_registry()
        active_document_registry = document_registry or android_document_parser_registry()
        if inspection.detected_type in {"zip", "tar"}:
            return self._run_archive_parsers(
                database,
                principal,
                inspection.id,
                context,
                path,
                active_registry,
                active_document_registry,
                parser_ids,
                job_id=job_id,
            )
        if inspection.detected_type != "sqlite":
            compatible_documents = {
                parser.metadata.parser_id: parser
                for parser in active_document_registry.compatible(source.source_name)
            }
            selected_documents = self._select_document_parsers(
                active_registry, active_document_registry, compatible_documents, parser_ids
            )
            if selected_documents:
                doc_results: list[ParserExecutionResult] = []
                for i, doc_parser in enumerate(selected_documents):
                    if job_id and self._is_job_cancelled(database, job_id):
                        break
                    doc_results.append(
                        self._execute_document_parser(
                            database, principal, inspection.id, context, doc_parser, path
                        )
                    )
                    if job_id:
                        progress = min(95, 20 + int(70 * (i + 1) / len(selected_documents)))
                        self._report_job_progress(
                            database,
                            job_id,
                            progress,
                            f"Parsed document with {doc_parser.metadata.name}",
                            doc_parser.metadata.parser_id,
                        )
                return doc_results
            raise EvidenceTwinError(
                "Native Android parsers require SQLite, a supported bounded document, or a "
                "safely extractable archive."
            )
        with SafeSQLiteReader(path) as reader:
            compatible = {
                parser.metadata.parser_id: parser
                for parser in active_registry.compatible(
                    reader.table_names(), source_locator=source.source_name
                )
            }
            selected = self._select_parsers(active_registry, compatible, parser_ids)
            results: list[ParserExecutionResult] = []
            for i, parser in enumerate(selected):
                if job_id and self._is_job_cancelled(database, job_id):
                    break
                results.append(
                    self._execute_parser(
                        database,
                        principal,
                        inspection.id,
                        context,
                        parser,
                        reader,
                    )
                )
                if job_id:
                    progress = min(95, 20 + int(70 * (i + 1) / len(selected)))
                    self._report_job_progress(
                        database,
                        job_id,
                        progress,
                        f"Parsed schema with {parser.metadata.name}",
                        parser.metadata.parser_id,
                    )
            return results

    def _run_archive_parsers(
        self,
        database: Database,
        principal: Principal,
        inspection_id: str,
        base_context: ParserContext,
        archive_path: Path,
        registry: ParserRegistry,
        document_registry: DocumentParserRegistry,
        parser_ids: tuple[str, ...] | None,
        job_id: str | None = None,
    ) -> list[ParserExecutionResult]:
        requested = self._validate_parser_ids(registry, document_registry, parser_ids)
        workspace = _new_archive_workspace(database.data_dir)
        store = EvidenceStore(workspace)
        matched: set[str] = set()
        results: list[ParserExecutionResult] = []
        try:
            members = SafeArchiveExtractor(
                ArchivePolicy(
                    max_members=256,
                    max_member_bytes=512 * 1024 * 1024,
                    max_total_bytes=1024 * 1024 * 1024,
                    max_path_depth=20,
                )
            ).extract(archive_path, store, "members")
            candidates = _sqlite_archive_candidates(members)
            document_candidates = _document_archive_candidates(members, document_registry)
            if not candidates and not document_candidates:
                raise EvidenceTwinError(
                    "No bounded supported database or configuration member was found in the "
                    "archive."
                )
            scheduled: list[tuple[ExtractedArchiveMember, tuple[EvidenceParser, ...]]] = []
            scheduled_documents: list[
                tuple[ExtractedArchiveMember, tuple[DocumentEvidenceParser, ...]]
            ] = []
            readable_sqlite_count = 0
            for member in candidates:
                member_path = store.resolve(member.storage_key, require_file=True)
                try:
                    with SafeSQLiteReader(member_path) as reader:
                        readable_sqlite_count += 1
                        compatible = {
                            parser.metadata.parser_id: parser
                            for parser in registry.compatible(
                                reader.table_names(), source_locator=member.original_name
                            )
                        }
                        selected = tuple(
                            parser
                            for parser_id, parser in compatible.items()
                            if requested is None or parser_id in requested
                        )
                        matched.update(parser.metadata.parser_id for parser in selected)
                        if selected:
                            scheduled.append((member, selected))
                except SafeSQLiteError:
                    # Application databases may be SQLCipher-encrypted or merely use a .db suffix.
                    # They are never opened with fallback credentials or mutating recovery flags.
                    continue
            for member in document_candidates:
                selected_documents = tuple(
                    parser
                    for parser in document_registry.compatible(member.original_name)
                    if requested is None or parser.metadata.parser_id in requested
                )
                matched.update(parser.metadata.parser_id for parser in selected_documents)
                if selected_documents:
                    scheduled_documents.append((member, selected_documents))
            if candidates and readable_sqlite_count == 0 and not scheduled_documents:
                raise EvidenceTwinError(
                    "Database-like archive members were encrypted, opaque, or not valid SQLite; "
                    "ForensiX does not bypass application encryption."
                )
            if requested is not None and matched != requested:
                missing = ", ".join(sorted(requested - matched))
                raise EvidenceTwinError(
                    f"Selected parser(s) were not compatible with archive members: {missing}."
                )
            if not scheduled and not scheduled_documents:
                raise EvidenceTwinError(
                    "The archive contained readable inputs but no compatible Android schema."
                )
            total_tasks = sum(len(parsers) for _, parsers in scheduled) + sum(
                len(parsers) for _, parsers in scheduled_documents
            )
            completed_tasks = 0

            for member, selected in scheduled:
                if job_id and self._is_job_cancelled(database, job_id):
                    break
                member_path = store.resolve(member.storage_key, require_file=True)
                with SafeSQLiteReader(member_path) as reader:
                    context = ParserContext(
                        case_id=base_context.case_id,
                        evidence_source_id=base_context.evidence_source_id,
                        working_copy_id=base_context.working_copy_id,
                        source_sha256=base_context.source_sha256,
                        source_label=f"{base_context.source_label}:{member.original_name}",
                        input_locator=member.original_name,
                        input_sha256=member.sha256,
                    )
                    for parser in selected:
                        if job_id and self._is_job_cancelled(database, job_id):
                            break
                        results.append(
                            self._execute_parser(
                                database,
                                principal,
                                inspection_id,
                                context,
                                parser,
                                reader,
                            )
                        )
                        completed_tasks += 1
                        if job_id:
                            progress = min(95, 20 + int(70 * completed_tasks / max(total_tasks, 1)))
                            self._report_job_progress(
                                database,
                                job_id,
                                progress,
                                f"Parsed {member.original_name} with {parser.metadata.name}",
                                parser.metadata.parser_id,
                            )
            for member, selected_documents in scheduled_documents:
                if job_id and self._is_job_cancelled(database, job_id):
                    break
                member_path = store.resolve(member.storage_key, require_file=True)
                context = ParserContext(
                    case_id=base_context.case_id,
                    evidence_source_id=base_context.evidence_source_id,
                    working_copy_id=base_context.working_copy_id,
                    source_sha256=base_context.source_sha256,
                    source_label=f"{base_context.source_label}:{member.original_name}",
                    input_locator=member.original_name,
                    input_sha256=member.sha256,
                )
                for parser in selected_documents:
                    if job_id and self._is_job_cancelled(database, job_id):
                        break
                    results.append(
                        self._execute_document_parser(
                            database,
                            principal,
                            inspection_id,
                            context,
                            parser,
                            member_path,
                        )
                    )
                    completed_tasks += 1
                    if job_id:
                        progress = min(95, 20 + int(70 * completed_tasks / max(total_tasks, 1)))
                        self._report_job_progress(
                            database,
                            job_id,
                            progress,
                            f"Parsed document {member.original_name} with {parser.metadata.name}",
                            parser.metadata.parser_id,
                        )
            return results
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

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

    def search_source_artifacts(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        *,
        query: str | None = None,
        category: str | None = None,
        status: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> SourceArtifactSearchResult:
        """Search parsed artifacts across every sealed source in a case at once.

        Matching utilizes SQLite FTS5 full-text search across content (message bodies,
        OCR text, raw text), metadata (senders, recipients, phone numbers, app IDs),
        summaries, and titles, with ILIKE substring fallback.
        """
        if category is not None and category not in SOURCE_ARTIFACT_CATEGORIES:
            raise EvidenceTwinError("The artifact category filter is unsupported.")
        if status is not None and status not in SOURCE_ARTIFACT_STATUSES:
            raise EvidenceTwinError("The artifact status filter is unsupported.")
        normalized_query = (query or "").strip()
        if len(normalized_query) > MAX_SEARCH_QUERY_LENGTH:
            raise EvidenceTwinError("The artifact search query cannot exceed 256 characters.")
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            if not principal.can(Permission.EVIDENCE_ANALYZE):
                raise CaseAccessDeniedError("The current user cannot analyze case evidence.")
            ensure_source_artifact_search_index(session)

            conditions = [EvidenceSourceArtifactRecord.case_id == case_id]
            if category:
                conditions.append(EvidenceSourceArtifactRecord.category == category)
            if status:
                conditions.append(EvidenceSourceArtifactRecord.status == status)

            facet_conditions = [EvidenceSourceArtifactRecord.case_id == case_id]
            params: dict[str, Any] = {}

            if normalized_query:
                like = f"%{_escape_like(normalized_query)}%"
                try:
                    fts_query = _compile_source_fts_query(normalized_query)
                    params["fts_query"] = fts_query
                    fts_filter = text(
                        "evidence_source_artifacts.id IN ("
                        "SELECT artifact_id FROM source_artifact_search "
                        "WHERE source_artifact_search MATCH :fts_query"
                        ")"
                    )
                    search_filter = or_(
                        fts_filter,
                        EvidenceSourceArtifactRecord.title.ilike(like, escape="\\"),
                        EvidenceSourceArtifactRecord.summary.ilike(like, escape="\\"),
                        EvidenceSourceArtifactRecord.subtype.ilike(like, escape="\\"),
                        EvidenceSourceArtifactRecord.metadata_json.ilike(like, escape="\\"),
                    )
                except Exception:
                    search_filter = or_(
                        EvidenceSourceArtifactRecord.title.ilike(like, escape="\\"),
                        EvidenceSourceArtifactRecord.summary.ilike(like, escape="\\"),
                        EvidenceSourceArtifactRecord.subtype.ilike(like, escape="\\"),
                        EvidenceSourceArtifactRecord.metadata_json.ilike(like, escape="\\"),
                    )
                conditions.append(search_filter)
                facet_conditions.append(search_filter)

            count_stmt = select(func.count(EvidenceSourceArtifactRecord.id)).where(*conditions)
            if params:
                count_stmt = count_stmt.params(**params)
            total = int(session.scalar(count_stmt) or 0)

            select_stmt = (
                select(EvidenceSourceArtifactRecord)
                .where(*conditions)
                .order_by(
                    EvidenceSourceArtifactRecord.event_time.desc().nulls_last(),
                    EvidenceSourceArtifactRecord.created_at.desc(),
                    EvidenceSourceArtifactRecord.id.desc(),
                )
                .offset(max(offset, 0))
                .limit(max(1, min(limit, 200)))
            )
            if params:
                select_stmt = select_stmt.params(**params)
            items = list(session.scalars(select_stmt))

            facet_stmt = (
                select(
                    EvidenceSourceArtifactRecord.category,
                    func.count(EvidenceSourceArtifactRecord.id),
                )
                .where(*facet_conditions)
                .group_by(EvidenceSourceArtifactRecord.category)
            )
            if params:
                facet_stmt = facet_stmt.params(**params)
            facets = {
                facet_category: int(count)
                for facet_category, count in session.execute(facet_stmt).all()
            }
        return SourceArtifactSearchResult(
            items=items,
            total=total,
            offset=max(offset, 0),
            limit=max(1, min(limit, 200)),
            category_facets=facets,
        )

    def prepare_parser_job(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
        *,
        parser_ids: tuple[str, ...] | None = None,
    ) -> JobRecord:
        """Create and validate a durable background parsing job without blocking HTTP requests."""
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
        with database.session() as session:
            job_service = JobService()
            job = job_service.create(
                session,
                JobType.PARSING,
                owner_id=principal.user_id,
                case_id=case_id,
                resume_supported=False,
            )
            job_service.transition(session, job.id, JobState.VALIDATING)
            job_service.update_progress(
                session,
                job.id,
                5,
                current_step="Validated working copy and parser readiness",
                checkpoint={
                    "case_id": case_id,
                    "source_id": source_id,
                    "source_name": source.source_name,
                    "working_copy_id": working_copy_id,
                    "inspection_id": inspection.id,
                    "detected_type": inspection.detected_type,
                    "parser_ids": list(parser_ids) if parser_ids else None,
                },
            )
            job_service.transition(session, job.id, JobState.READY)
            session.commit()
            return job

    def execute_parser_job(
        self,
        database: Database,
        principal: Principal,
        job_id: str,
        *,
        registry: ParserRegistry | None = None,
        document_registry: DocumentParserRegistry | None = None,
    ) -> list[ParserExecutionResult]:
        """Execute a prepared background parsing job with progress and cancellation tracking."""
        with database.session() as session:
            job = JobService().get(session, job_id)
            if job.state != JobState.READY.value:
                raise EvidenceTwinError(f"Job {job_id} cannot run from state {job.state}.")
            checkpoint = _load_checkpoint(job)
            case_id = checkpoint.get("case_id") or job.case_id
            source_id = checkpoint.get("source_id")
            working_copy_id = checkpoint.get("working_copy_id")
            parser_ids_raw = checkpoint.get("parser_ids")
            parser_ids = tuple(parser_ids_raw) if parser_ids_raw else None

            JobService().transition(session, job_id, JobState.RUNNING)
            JobService().update_progress(
                session,
                job_id,
                10,
                current_step="Forensic parser job running",
                current_module="evidence_examination",
            )
            session.commit()

        try:
            results = self.run_native_parsers(
                database,
                principal,
                case_id,
                source_id,
                working_copy_id,
                parser_ids=parser_ids,
                registry=registry,
                document_registry=document_registry,
                job_id=job_id,
            )
            with database.session() as session:
                current_job = JobService().get(session, job_id)
                if current_job.cancellation_requested:
                    JobService().transition(
                        session,
                        job_id,
                        JobState.CANCELLED,
                        result_reference="cancelled",
                        event_type="parser_job_cancelled",
                    )
                else:
                    total_artifacts = sum(r.run.artifact_count for r in results)
                    JobService().update_progress(
                        session,
                        job_id,
                        100,
                        current_step=f"Completed parsing: {total_artifacts} artifact(s) normalized",
                        current_module="evidence_examination",
                    )
                    JobService().transition(
                        session,
                        job_id,
                        JobState.COMPLETED,
                        result_reference=f"artifacts:{total_artifacts}",
                        event_type="parser_job_completed",
                    )
                session.commit()
            return results
        except Exception as error:
            with database.session() as session:
                JobService().transition(
                    session,
                    job_id,
                    JobState.FAILED,
                    error_code="PARSER_EXECUTION_FAILED",
                    error_message=str(error)[:1000],
                    event_type="parser_job_failed",
                )
                session.commit()
            raise

    def get_parser_job(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> JobRecord:
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            if not principal.can(Permission.EVIDENCE_ANALYZE):
                raise CaseAccessDeniedError("The current user cannot view parser jobs.")
            job = JobService().get(session, job_id)
            if job.case_id != case_id:
                raise EvidenceTwinError("The requested parser job does not belong to this case.")
            return job

    def cancel_parser_job(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> JobRecord:
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            if not principal.can(Permission.EVIDENCE_ANALYZE):
                raise CaseAccessDeniedError("The current user cannot cancel parser jobs.")
            job = JobService().request_cancellation(session, job_id)
            session.commit()
            return job

    @staticmethod
    def _is_job_cancelled(database: Database, job_id: str | None) -> bool:
        if not job_id:
            return False
        with database.session() as session:
            job = session.get(JobRecord, job_id)
            return bool(job and job.cancellation_requested)

    @staticmethod
    def _report_job_progress(
        database: Database,
        job_id: str | None,
        progress_percent: int,
        step: str,
        module: str | None = None,
    ) -> None:
        if not job_id:
            return
        with database.session() as session:
            try:
                JobService().update_progress(
                    session,
                    job_id,
                    progress_percent,
                    current_step=step,
                    current_module=module,
                )
                session.commit()
            except Exception:
                session.rollback()

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

    @staticmethod
    def _validate_parser_ids(
        registry: ParserRegistry,
        document_registry: DocumentParserRegistry,
        parser_ids: tuple[str, ...] | None,
    ) -> set[str] | None:
        if parser_ids is None:
            return None
        if len(parser_ids) != len(set(parser_ids)) or len(parser_ids) > 20:
            raise EvidenceTwinError("Parser selection contains duplicates or exceeds policy.")
        for parser_id in parser_ids:
            try:
                registry.get(parser_id)
            except ParserRegistryError as error:
                try:
                    document_registry.get(parser_id)
                except ParserRegistryError:
                    raise EvidenceTwinError(str(error)) from error
        return set(parser_ids)

    @staticmethod
    def _select_document_parsers(
        registry: ParserRegistry,
        document_registry: DocumentParserRegistry,
        compatible: dict[str, DocumentEvidenceParser],
        parser_ids: tuple[str, ...] | None,
    ) -> tuple[DocumentEvidenceParser, ...]:
        if parser_ids is None:
            return tuple(compatible.values())
        EvidenceExaminationService._validate_parser_ids(registry, document_registry, parser_ids)
        selected: list[DocumentEvidenceParser] = []
        for parser_id in parser_ids:
            if parser_id not in compatible:
                raise EvidenceTwinError(
                    f"Parser '{parser_id}' is not compatible with this document."
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
        existing = self._existing_result(
            database, context.working_copy_id, context.input_locator, parser
        )
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

    def _execute_document_parser(
        self,
        database: Database,
        principal: Principal,
        inspection_id: str,
        context: ParserContext,
        parser: DocumentEvidenceParser,
        path: Path,
    ) -> ParserExecutionResult:
        existing = self._existing_result(
            database, context.working_copy_id, context.input_locator, parser
        )
        if existing is not None:
            return existing
        started_at = datetime.now(UTC)
        try:
            parsed = parser.parse(path, context)
            return self._persist_success(
                database, principal, inspection_id, context, parser, parsed, started_at
            )
        except Exception as error:
            return self._persist_failure(
                database, principal, inspection_id, context, parser, error, started_at
            )

    @staticmethod
    def _existing_result(
        database: Database,
        working_copy_id: str,
        input_locator: str,
        parser: VersionedParser,
    ) -> ParserExecutionResult | None:
        with database.session() as session:
            run = session.scalar(
                select(EvidenceParserRunRecord).where(
                    EvidenceParserRunRecord.working_copy_id == working_copy_id,
                    EvidenceParserRunRecord.input_locator == input_locator,
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
        parser: VersionedParser,
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
            "input_locator": context.input_locator,
            "input_sha256": context.input_sha256 or context.source_sha256,
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
            input_locator=_bounded(context.input_locator, 1024, "parser input locator"),
            input_sha256=context.input_sha256 or context.source_sha256,
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
            ensure_source_artifact_search_index(session)
            for item, record in zip(parsed, records, strict=True):
                content_text, metadata_text = _extract_searchable_content(item, item.metadata)
                session.execute(
                    text("DELETE FROM source_artifact_search WHERE artifact_id = :artifact_id"),
                    {"artifact_id": record.id},
                )
                session.execute(
                    text(_INSERT_SOURCE_ARTIFACT_SEARCH),
                    {
                        "artifact_id": record.id,
                        "case_id": record.case_id,
                        "category": record.category,
                        "subtype": record.subtype,
                        "title": record.title,
                        "summary": record.summary,
                        "content": content_text,
                        "metadata": metadata_text,
                    },
                )
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
                    "input_locator": context.input_locator,
                    "input_sha256": context.input_sha256 or context.source_sha256,
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
        parser: VersionedParser,
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
            "input_locator": context.input_locator,
            "input_sha256": context.input_sha256 or context.source_sha256,
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
            input_locator=_bounded(context.input_locator, 1024, "parser input locator"),
            input_sha256=context.input_sha256 or context.source_sha256,
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
        context: ParserContext, parser: VersionedParser, artifact: ParsedArtifact
    ) -> dict[str, Any]:
        artifact_data: dict[str, Any] = {
            "category": artifact.category,
            "confidence": artifact.confidence,
            "event_time": artifact.event_time.isoformat() if artifact.event_time else None,
            "metadata": _json_safe(artifact.metadata),
            "source_locator": artifact.source_locator,
            "status": artifact.status,
            "subtype": artifact.subtype,
            "summary": artifact.summary,
            "title": artifact.title,
        }
        if artifact.content:
            artifact_data["content"] = artifact.content
        return {
            "artifact": artifact_data,
            "provenance": {
                "case_id": context.case_id,
                "evidence_source_id": context.evidence_source_id,
                "parser_id": parser.metadata.parser_id,
                "parser_version": parser.metadata.version,
                "source_label": context.source_label,
                "source_sha256": context.source_sha256,
                "input_locator": context.input_locator,
                "input_sha256": context.input_sha256 or context.source_sha256,
                "working_copy_id": context.working_copy_id,
                "source_locator": artifact.source_locator,
                "confidence": artifact.confidence,
                "status": artifact.status,
                "parser_maturity": parser.metadata.maturity,
                "access_level": parser.metadata.access_level,
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


def _new_archive_workspace(data_dir: Path) -> Path:
    parent = (data_dir / "work" / "archive-examination").resolve()
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.is_symlink() or not parent.is_dir():
        raise EvidenceTwinError("The archive examination workspace is unsafe.")
    workspace = (parent / str(uuid4())).resolve()
    if workspace.parent != parent:
        raise EvidenceTwinError("The archive examination workspace path is invalid.")
    return workspace


def _sqlite_archive_candidates(
    members: list[ExtractedArchiveMember],
) -> tuple[ExtractedArchiveMember, ...]:
    candidates = tuple(
        member
        for member in members
        if len(member.original_name) <= 1024
        and Path(member.original_name).suffix.casefold() in {".db", ".sqlite", ".sqlite3"}
    )
    if len(candidates) > 32:
        raise EvidenceTwinError("The archive exceeds the SQLite candidate-count limit.")
    return candidates


def _escape_like(value: str) -> str:
    """Escape LIKE/ILIKE wildcards so user text matches literally under escape='\\'."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _document_archive_candidates(
    members: list[ExtractedArchiveMember], registry: DocumentParserRegistry
) -> tuple[ExtractedArchiveMember, ...]:
    candidates = tuple(
        member
        for member in members
        if len(member.original_name) <= 1024 and registry.compatible(member.original_name)
    )
    if len(candidates) > 64:
        raise EvidenceTwinError("The archive exceeds the document candidate-count limit.")
    return candidates


def _load_checkpoint(job: JobRecord) -> dict[str, Any]:
    if not job.checkpoint_json:
        return {}
    try:
        data = json.loads(job.checkpoint_json)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def ensure_source_artifact_search_index(session: Session) -> None:
    session.execute(
        text(
            "CREATE VIRTUAL TABLE IF NOT EXISTS source_artifact_search USING fts5("
            "artifact_id UNINDEXED, "
            "case_id UNINDEXED, "
            "category UNINDEXED, "
            "subtype UNINDEXED, "
            "title, "
            "summary, "
            "content, "
            "metadata, "
            "tokenize='unicode61 remove_diacritics 2')"
        )
    )
    try:
        indexed_count = (
            session.execute(text("SELECT count(*) FROM source_artifact_search")).scalar() or 0
        )
        total_artifacts = (
            session.execute(text("SELECT count(*) FROM evidence_source_artifacts")).scalar() or 0
        )
        if total_artifacts > 0 and indexed_count == 0:
            rows = session.execute(
                select(
                    EvidenceSourceArtifactRecord.id,
                    EvidenceSourceArtifactRecord.case_id,
                    EvidenceSourceArtifactRecord.category,
                    EvidenceSourceArtifactRecord.subtype,
                    EvidenceSourceArtifactRecord.title,
                    EvidenceSourceArtifactRecord.summary,
                    EvidenceSourceArtifactRecord.metadata_json,
                )
            ).all()
            for row in rows:
                meta = {}
                with contextlib.suppress(Exception):
                    meta = json.loads(row.metadata_json)
                c_text, m_text = _extract_searchable_content(None, meta)
                session.execute(
                    text(_INSERT_SOURCE_ARTIFACT_SEARCH),
                    {
                        "artifact_id": row.id,
                        "case_id": row.case_id,
                        "category": row.category,
                        "subtype": row.subtype,
                        "title": row.title,
                        "summary": row.summary,
                        "content": c_text,
                        "metadata": m_text,
                    },
                )
            session.flush()
    except Exception:  # noqa: BLE001, S110
        pass


def _extract_searchable_content(
    item: ParsedArtifact | None, metadata_dict: dict[str, Any]
) -> tuple[str, str]:
    content_parts: list[str] = []
    if item is not None and getattr(item, "content", None):
        content_parts.append(str(item.content).strip())

    for key in (
        "body",
        "text",
        "message",
        "snippet",
        "content",
        "note_text",
        "transcription",
        "ocr_text",
        "ocr",
        "extracted_text",
        "subject",
        "document_text",
    ):
        val = metadata_dict.get(key)
        if isinstance(val, str) and val.strip():
            content_parts.append(val.strip())
        elif isinstance(val, (list, tuple)):
            for v in val:
                if isinstance(v, str) and v.strip():
                    content_parts.append(v.strip())

    meta_parts: list[str] = []
    for key in (
        "sender",
        "sender_name",
        "recipient",
        "recipient_name",
        "participants",
        "phone",
        "phone_number",
        "number",
        "address",
        "email",
        "package_name",
        "app_name",
        "app_id",
        "url",
        "file_name",
        "filename",
        "account_id",
        "ssid",
        "bssid",
        "device_name",
    ):
        val = metadata_dict.get(key)
        if isinstance(val, str) and val.strip():
            meta_parts.append(val.strip())
        elif isinstance(val, (list, tuple)):
            for v in val:
                if isinstance(v, str) and v.strip():
                    meta_parts.append(v.strip())

    return " ".join(content_parts), " ".join(meta_parts)


def _compile_source_fts_query(query: str) -> str:
    if len(query) > MAX_SEARCH_QUERY_LENGTH:
        raise EvidenceTwinError("The artifact search query cannot exceed 256 characters.")
    terms = re.findall(r"\w+", query.lower(), flags=re.UNICODE)
    if not terms:
        raise EvidenceTwinError("The artifact search query must contain searchable text.")
    if len(terms) > 12 or any(len(term) > 64 for term in terms):
        raise EvidenceTwinError("The artifact search query is too complex.")
    return " AND ".join(f"{term}*" for term in terms)
