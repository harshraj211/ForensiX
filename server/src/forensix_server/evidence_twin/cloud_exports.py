"""Cloud export intake through the sealed source and versioned examination pipeline."""

import json
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO

from sqlalchemy import select

from forensix_forensic.extractors.cloud.exports import CloudExportError, CloudExportParser
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.db import (
    Database,
    EvidenceParserRunRecord,
    EvidenceSourceArtifactRecord,
    EvidenceSourceRecord,
)

from .examination import EvidenceExaminationService
from .service import EvidenceTwinError, EvidenceTwinIntegrityError, EvidenceTwinService

MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
EXTENSIONS = {
    ".zip",
    ".json",
    ".txt",
    ".csv",
    ".vcf",
    ".ics",
    ".eml",
    ".mbox",
    ".db",
    ".sqlite",
    ".sqlite3",
}


class CloudExportService:
    def import_stream(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        stream: BinaryIO,
        *,
        source_name: str,
        provider: str,
        source_timezone: str = "UTC",
        date_order: str = "DMY",
    ) -> tuple[EvidenceSourceRecord, EvidenceParserRunRecord, dict[str, Any]]:
        # Authorize before reading, decompressing, or processing attacker-supplied data.
        with database.session() as session:
            case = CaseService().get(session, principal, case_id)
            if not principal.can(Permission.ACQUISITIONS_OPERATE) or not principal.can(
                Permission.EVIDENCE_ANALYZE
            ):
                raise CaseAccessDeniedError(
                    "Cloud imports require acquisition and analysis permissions."
                )
            if case.status in {"closed", "archived"}:
                raise EvidenceTwinError(
                    "Cloud exports cannot be imported into a closed or archived case."
                )
        CloudExportParser(provider, source_timezone=source_timezone, date_order=date_order)
        if Path(source_name).suffix.lower() not in EXTENSIONS:
            raise CloudExportError(
                "Expected ZIP, JSON, TXT, CSV, VCF, ICS, EML, MBOX, or plaintext SQLite"
            )
        parent = database.data_dir / "work"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cloud-intake-", dir=parent) as temp:
            path = Path(temp) / "upload.evidence"  # Never use a multipart filename as a disk path.
            size = 0
            with path.open("wb") as destination:
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise CloudExportError("Cloud export exceeds 2 GiB")
                    destination.write(chunk)
            if not size:
                raise CloudExportError("Empty cloud export")
            twin = EvidenceTwinService()
            with path.open("rb") as original:
                record = twin.seal_cloud_export_stream(
                    database,
                    principal,
                    case_id,
                    original,
                    source_name=source_name,
                    declared_size_bytes=size,
                    provider=provider,
                    source_timezone=source_timezone,
                    date_order=date_order,
                )
            copy = twin.create_working_copy(database, principal, case_id, record.id)
            results = EvidenceExaminationService().run_native_parsers(
                database, principal, case_id, record.id, copy.id
            )
        result = results[0]
        summary: dict[str, Any] = next(
            (
                json.loads(a.metadata_json)
                for a in result.artifacts
                if a.subtype == "cloud_export_summary"
            ),
            {},
        )
        return record, result.run, summary

    def summary(
        self, database: Database, principal: Principal, case_id: str, source_id: str
    ) -> tuple[EvidenceSourceRecord, EvidenceParserRunRecord | None, dict[str, Any]]:
        source = EvidenceTwinService().get_source(database, principal, case_id, source_id)
        if not source.manifest_storage_key:
            raise EvidenceTwinError("Source is not sealed")
        raw = (
            EvidenceStore(database.data_dir / "evidence")
            .resolve(source.manifest_storage_key, require_file=True)
            .read_bytes()
        )
        if sha256(raw).hexdigest() != source.manifest_sha256:
            raise EvidenceTwinIntegrityError("The evidence manifest hash does not match.")
        metadata = json.loads(raw).get("acquisition_metadata", {})
        if metadata.get("operation") != "cloud_export_import":
            raise EvidenceTwinError("This source is not a cloud export")
        with database.session() as session:
            run = session.scalar(
                select(EvidenceParserRunRecord)
                .where(EvidenceParserRunRecord.evidence_source_id == source_id)
                .order_by(EvidenceParserRunRecord.completed_at.desc())
            )
            summary = (
                session.scalar(
                    select(EvidenceSourceArtifactRecord).where(
                        EvidenceSourceArtifactRecord.parser_run_id == run.id,
                        EvidenceSourceArtifactRecord.subtype == "cloud_export_summary",
                    )
                )
                if run
                else None
            )
        return source, run, {**metadata, **(json.loads(summary.metadata_json) if summary else {})}
