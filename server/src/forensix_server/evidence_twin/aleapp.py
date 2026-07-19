"""Persisted ALEAPP execution over verified ZIP/TAR Evidence Twin copies."""

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal
from uuid import uuid4

from sqlalchemy import select

from forensix_forensic.integrations import AleappDiagnostic, AleappOutputFile, AleappRunner
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError
from forensix_server.custody import AuditService, CustodyService
from forensix_server.db import (
    Database,
    EvidenceParserRunRecord,
    EvidenceToolOutputRecord,
    EvidenceWorkingCopyRecord,
)

from .inspection import EvidenceInspectionService
from .service import EvidenceTwinError, EvidenceTwinIntegrityError, EvidenceTwinService


@dataclass(frozen=True, slots=True)
class AleappExecutionRecord:
    run: EvidenceParserRunRecord
    outputs: tuple[EvidenceToolOutputRecord, ...]


class AleappEvidenceService:
    parser_id = "external.aleapp"

    @staticmethod
    def diagnose(runner: AleappRunner | None) -> AleappDiagnostic:
        if runner is None:
            return AleappDiagnostic(
                available=False,
                hash_verified=False,
                release_label="not_configured",
                program_path="",
                observed_sha256=None,
                message=(
                    "ALEAPP is optional and not configured. Set a local program path and pinned "
                    "SHA-256 before use."
                ),
            )
        return runner.diagnose()

    def run(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
        runner: AleappRunner,
    ) -> AleappExecutionRecord:
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot run external evidence parsers.")
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        verification = EvidenceTwinService().verify_working_copy(
            database, principal, case_id, source_id, working_copy_id
        )
        if verification.status != "verified":
            raise EvidenceTwinIntegrityError(
                "The working copy failed integrity verification and was not sent to ALEAPP."
            )
        inspection = EvidenceInspectionService().inspect_working_copy(
            database, principal, case_id, source_id, working_copy_id
        )
        if inspection.detected_type not in {"zip", "tar"}:
            raise EvidenceTwinError(
                "ALEAPP integration currently accepts signature-verified ZIP or TAR sources."
            )
        diagnostic = runner.diagnose()
        if not diagnostic.available or not diagnostic.hash_verified:
            raise EvidenceTwinError(diagnostic.message)
        existing = self._existing(database, working_copy_id, diagnostic.release_label)
        if existing is not None:
            return existing
        with database.session() as session:
            working_copy = session.get(EvidenceWorkingCopyRecord, working_copy_id)
            assert working_copy is not None
        store = EvidenceStore(database.data_dir / "evidence")
        input_path = store.resolve(working_copy.storage_key, require_file=True)
        run_id = str(uuid4())
        workspace_parent = database.data_dir / "workspaces" / "aleapp"
        workspace_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        run_workspace = workspace_parent / run_id
        run_workspace.mkdir(mode=0o700)
        started_at = datetime.now(UTC)
        input_type: Literal["zip", "tar"] = "zip" if inspection.detected_type == "zip" else "tar"
        try:
            result = runner.run(
                input_path,
                run_workspace / "output",
                run_workspace,
                input_type=input_type,
            )
            completed_at = datetime.now(UTC)
            if result.exit_code != 0:
                return self._persist_failure(
                    database,
                    principal,
                    run_id,
                    inspection.id,
                    case_id,
                    source_id,
                    working_copy,
                    result.release_label,
                    result.program_sha256,
                    result.exit_code,
                    started_at,
                    completed_at,
                )
            outputs = self._seal_outputs(
                store,
                run_workspace / "output",
                run_id,
                case_id,
                source_id,
                working_copy_id,
                result.outputs,
                completed_at,
            )
            payload = {
                "completed_at": completed_at.isoformat(),
                "exit_code": result.exit_code,
                "input_type": result.input_type,
                "output_hashes": [item.sha256 for item in outputs],
                "program_sha256": result.program_sha256,
                "release_label": result.release_label,
                "source_sha256": working_copy.expected_source_sha256,
                "started_at": started_at.isoformat(),
                "stderr_sha256": sha256(result.stderr.encode()).hexdigest(),
                "stdout_sha256": sha256(result.stdout.encode()).hexdigest(),
                "working_copy_id": working_copy_id,
            }
            run = EvidenceParserRunRecord(
                id=run_id,
                evidence_source_id=source_id,
                working_copy_id=working_copy_id,
                inspection_id=inspection.id,
                case_id=case_id,
                executed_by=principal.user_id,
                parser_id=self.parser_id,
                parser_version=result.release_label,
                status="completed",
                artifact_count=0,
                source_sha256=working_copy.expected_source_sha256,
                input_locator="working_copy",
                input_sha256=working_copy.expected_source_sha256,
                run_hash=sha256(_canonical_json(payload).encode()).hexdigest(),
                error_code=None,
                error_message=None,
                started_at=started_at,
                completed_at=completed_at,
            )
            with database.session() as session:
                session.add(run)
                session.add_all(outputs)
                session.flush()
                AuditService().append(
                    session,
                    case_id=case_id,
                    actor_id=principal.user_id,
                    event_type="aleapp_completed",
                    object_type="evidence_parser_run",
                    object_id=run.id,
                    detail={
                        "output_count": len(outputs),
                        "program_sha256": result.program_sha256,
                        "release_label": result.release_label,
                        "run_hash": run.run_hash,
                    },
                    created_at=completed_at,
                )
                CustodyService().append_evidence_source(
                    session,
                    case_id=case_id,
                    actor_id=principal.user_id,
                    event_type="parser_completed",
                    evidence_source_id=source_id,
                    parser_run_id=run.id,
                    purpose=(
                        f"Pinned ALEAPP {result.release_label} completed and sealed "
                        f"{len(outputs)} derived output(s); run hash {run.run_hash}."
                    ),
                )
                session.flush()
            return AleappExecutionRecord(run=run, outputs=outputs)
        finally:
            shutil.rmtree(run_workspace, ignore_errors=True)

    def list_outputs(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
    ) -> list[EvidenceToolOutputRecord]:
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            return list(
                session.scalars(
                    select(EvidenceToolOutputRecord)
                    .where(
                        EvidenceToolOutputRecord.case_id == case_id,
                        EvidenceToolOutputRecord.evidence_source_id == source_id,
                    )
                    .order_by(EvidenceToolOutputRecord.created_at, EvidenceToolOutputRecord.id)
                )
            )

    @staticmethod
    def _existing(
        database: Database, working_copy_id: str, release_label: str
    ) -> AleappExecutionRecord | None:
        with database.session() as session:
            run = session.scalar(
                select(EvidenceParserRunRecord).where(
                    EvidenceParserRunRecord.working_copy_id == working_copy_id,
                    EvidenceParserRunRecord.parser_id == AleappEvidenceService.parser_id,
                    EvidenceParserRunRecord.parser_version == release_label,
                )
            )
            if run is None:
                return None
            outputs = tuple(
                session.scalars(
                    select(EvidenceToolOutputRecord)
                    .where(EvidenceToolOutputRecord.parser_run_id == run.id)
                    .order_by(EvidenceToolOutputRecord.relative_path)
                )
            )
            return AleappExecutionRecord(run=run, outputs=outputs)

    @staticmethod
    def _seal_outputs(
        store: EvidenceStore,
        output_directory: Path,
        run_id: str,
        case_id: str,
        source_id: str,
        working_copy_id: str,
        outputs: tuple[AleappOutputFile, ...],
        created_at: datetime,
    ) -> tuple[EvidenceToolOutputRecord, ...]:
        records: list[EvidenceToolOutputRecord] = []
        resolved_output = output_directory.resolve(strict=True)
        for ordinal, output in enumerate(outputs):
            relative_path = output.relative_path
            expected_sha256 = output.sha256
            if not relative_path or len(relative_path) > 1024:
                raise EvidenceTwinError("ALEAPP produced an invalid relative output path.")
            source_path = output_directory.joinpath(*relative_path.split("/")).resolve(strict=True)
            try:
                source_path.relative_to(resolved_output)
            except ValueError as error:
                raise EvidenceTwinError("ALEAPP output escaped its workspace.") from error
            digest = sha256(relative_path.encode()).hexdigest()[:20]
            storage_key = (
                f"c/{case_id[:8]}/tw/{source_id}/tools/{run_id}/output-{ordinal:06d}-{digest}.bin"
            )
            with source_path.open("rb") as input_stream, store.open_writer(storage_key) as writer:
                while data := input_stream.read(1024 * 1024):
                    writer.write(data)
                stored = writer.seal()
            if stored.sha256 != expected_sha256:
                raise EvidenceTwinIntegrityError(
                    "An ALEAPP output changed before it could be sealed."
                )
            records.append(
                EvidenceToolOutputRecord(
                    parser_run_id=run_id,
                    evidence_source_id=source_id,
                    working_copy_id=working_copy_id,
                    case_id=case_id,
                    relative_path=relative_path,
                    storage_key=stored.storage_key,
                    size_bytes=stored.size_bytes,
                    sha256=stored.sha256,
                    created_at=created_at,
                )
            )
        return tuple(records)

    @staticmethod
    def _persist_failure(
        database: Database,
        principal: Principal,
        run_id: str,
        inspection_id: str,
        case_id: str,
        source_id: str,
        working_copy: EvidenceWorkingCopyRecord,
        release_label: str,
        program_sha256: str,
        exit_code: int,
        started_at: datetime,
        completed_at: datetime,
    ) -> AleappExecutionRecord:
        payload = {
            "completed_at": completed_at.isoformat(),
            "exit_code": exit_code,
            "program_sha256": program_sha256,
            "release_label": release_label,
            "source_sha256": working_copy.expected_source_sha256,
            "started_at": started_at.isoformat(),
            "status": "failed",
            "working_copy_id": working_copy.id,
        }
        run = EvidenceParserRunRecord(
            id=run_id,
            evidence_source_id=source_id,
            working_copy_id=working_copy.id,
            inspection_id=inspection_id,
            case_id=case_id,
            executed_by=principal.user_id,
            parser_id=AleappEvidenceService.parser_id,
            parser_version=release_label,
            status="failed",
            artifact_count=0,
            source_sha256=working_copy.expected_source_sha256,
            input_locator="working_copy",
            input_sha256=working_copy.expected_source_sha256,
            run_hash=sha256(_canonical_json(payload).encode()).hexdigest(),
            error_code="ALEAPP_NONZERO_EXIT",
            error_message=f"ALEAPP exited with code {exit_code}.",
            started_at=started_at,
            completed_at=completed_at,
        )
        with database.session() as session:
            session.add(run)
            session.flush()
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="aleapp_failed",
                object_type="evidence_parser_run",
                object_id=run.id,
                detail={"exit_code": exit_code, "release_label": release_label},
                created_at=completed_at,
            )
            CustodyService().append_evidence_source(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="parser_failed",
                evidence_source_id=source_id,
                parser_run_id=run.id,
                purpose=(
                    f"Pinned ALEAPP {release_label} failed with exit code {exit_code}; "
                    "no derived output was accepted."
                ),
            )
            session.flush()
        return AleappExecutionRecord(run=run, outputs=())


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
