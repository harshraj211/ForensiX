"""Streaming Evidence Twin import, sealing, verification, and working-copy services."""

import json
import shutil
import stat
from collections.abc import Iterator
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO
from uuid import uuid4

from sqlalchemy import select

from forensix_forensic.storage import EvidenceStore
from forensix_server import __version__
from forensix_server.auth import Permission, Principal
from forensix_server.cases import (
    CaseAccessDeniedError,
    CaseError,
    CaseInvalidStateError,
    CaseService,
    CaseStatus,
)
from forensix_server.custody import AuditService
from forensix_server.db import (
    CaseEventRecord,
    Database,
    EvidenceSourceChunkRecord,
    EvidenceSourceRecord,
    EvidenceSourceVerificationRecord,
    EvidenceWorkingCopyRecord,
)

from .domain import (
    DEFAULT_EVIDENCE_CHUNK_SIZE,
    FORMAT_BY_SUFFIX,
    MAX_EVIDENCE_CHUNK_SIZE,
    MIN_EVIDENCE_CHUNK_SIZE,
    MINIMUM_FREE_BYTES,
    AcquisitionLevel,
    EvidenceContainerFormat,
    EvidenceSourceType,
)


class EvidenceTwinError(CaseInvalidStateError):
    code = "EVIDENCE_TWIN_INVALID"


class EvidenceTwinNotFoundError(CaseError):
    code = "EVIDENCE_TWIN_NOT_FOUND"


class EvidenceTwinIntegrityError(EvidenceTwinError):
    code = "EVIDENCE_TWIN_INTEGRITY_FAILED"


class EvidenceTwinStorageError(EvidenceTwinError):
    code = "EVIDENCE_TWIN_STORAGE_LOW"


class EvidenceTwinService:
    """Creates sealed masters and separate hash-verified examination copies."""

    def import_stream(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        stream: BinaryIO,
        *,
        source_name: str,
        display_name: str | None = None,
        declared_size_bytes: int | None = None,
        chunk_size_bytes: int = DEFAULT_EVIDENCE_CHUNK_SIZE,
    ) -> EvidenceSourceRecord:
        self._validate_chunk_size(chunk_size_bytes)
        safe_source_name = _safe_source_name(source_name)
        safe_display_name = _display_name(display_name or safe_source_name)
        container_format = FORMAT_BY_SUFFIX.get(
            Path(safe_source_name).suffix.casefold(), EvidenceContainerFormat.UNKNOWN
        )
        if declared_size_bytes is not None and declared_size_bytes < 1:
            raise EvidenceTwinError("Declared evidence size must be greater than zero.")
        self._require_disk_space(database, declared_size_bytes)
        source = self._create_pending_source(
            database,
            principal,
            case_id,
            source_name=safe_source_name,
            display_name=safe_display_name,
            container_format=container_format,
            chunk_size_bytes=chunk_size_bytes,
        )
        extension = _storage_extension(container_format)
        base_key = f"c/{case_id[:8]}/tw/{source.id}"
        master_key = f"{base_key}/master/source.{extension}"
        chunks_key = f"{base_key}/master/chunks.jsonl"
        manifest_key = f"{base_key}/master/manifest.json"
        store = EvidenceStore(database.data_dir / "evidence")
        master_writer = store.open_writer(master_key)
        chunks_writer = store.open_writer(chunks_key)
        chunk_batch: list[EvidenceSourceChunkRecord] = []
        chunk_count = 0
        try:
            for ordinal, offset, data in _fixed_chunks(stream, chunk_size_bytes):
                master_writer.write(data)
                digest = sha256(data).hexdigest()
                chunks_writer.write(
                    _canonical_json(
                        {
                            "offset_bytes": offset,
                            "ordinal": ordinal,
                            "sha256": digest,
                            "size_bytes": len(data),
                        }
                    ).encode("utf-8")
                    + b"\n"
                )
                chunk_batch.append(
                    EvidenceSourceChunkRecord(
                        evidence_source_id=source.id,
                        ordinal=ordinal,
                        offset_bytes=offset,
                        size_bytes=len(data),
                        sha256=digest,
                        created_at=datetime.now(UTC),
                    )
                )
                chunk_count += 1
                if len(chunk_batch) >= 500:
                    self._persist_chunk_batch(database, chunk_batch)
                    chunk_batch = []
            if chunk_count == 0:
                raise EvidenceTwinError("An empty file cannot be registered as evidence.")
            if chunk_batch:
                self._persist_chunk_batch(database, chunk_batch)
            master = master_writer.seal()
            chunks = chunks_writer.seal()
            manifest_payload = {
                "acquisition_level": AcquisitionLevel.FILESYSTEM.value,
                "case_id": case_id,
                "chunk_count": chunk_count,
                "chunk_size_bytes": chunk_size_bytes,
                "chunks_sha256": chunks.sha256,
                "chunks_storage_key": chunks.storage_key,
                "container_format": container_format.value,
                "created_at": source.created_at.astimezone(UTC).isoformat(),
                "created_by": principal.user_id,
                "evidence_source_id": source.id,
                "limitations": [
                    "Imported evidence is not claimed to have been acquired by ForensiX.",
                    "Source acquisition method and device-side effects require examiner review.",
                ],
                "master_sha256": master.sha256,
                "master_storage_key": master.storage_key,
                "schema_version": "1.0.0",
                "size_bytes": master.size_bytes,
                "source_name": safe_source_name,
                "source_type": EvidenceSourceType.IMPORTED_FILE.value,
                "tool_version": __version__,
            }
            with store.open_writer(manifest_key) as manifest_writer:
                manifest_writer.write(_canonical_json(manifest_payload).encode("utf-8"))
                manifest = manifest_writer.seal()
            read_only = all(
                _apply_read_only(store.resolve(key, require_file=True))
                for key in (master_key, chunks_key, manifest_key)
            )
            return self._complete_source(
                database,
                principal,
                source.id,
                master_key=master_key,
                chunks_key=chunks_key,
                manifest_key=manifest_key,
                size_bytes=master.size_bytes,
                master_sha256=master.sha256,
                chunks_sha256=chunks.sha256,
                manifest_sha256=manifest.sha256,
                chunk_count=chunk_count,
                read_only=read_only,
            )
        except Exception as error:
            master_writer.close(preserve_partial=False)
            chunks_writer.close(preserve_partial=False)
            self._fail_source(database, source.id, error)
            raise

    def list_sources(
        self, database: Database, principal: Principal, case_id: str
    ) -> list[EvidenceSourceRecord]:
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            return list(
                session.scalars(
                    select(EvidenceSourceRecord)
                    .where(EvidenceSourceRecord.case_id == case_id)
                    .order_by(EvidenceSourceRecord.created_at.desc())
                )
            )

    def get_source(
        self, database: Database, principal: Principal, case_id: str, source_id: str
    ) -> EvidenceSourceRecord:
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            source = session.get(EvidenceSourceRecord, source_id)
            if source is None or source.case_id != case_id:
                raise EvidenceTwinNotFoundError("The requested evidence source does not exist.")
            return source

    def verify_master(
        self, database: Database, principal: Principal, case_id: str, source_id: str
    ) -> EvidenceSourceVerificationRecord:
        source = self.get_source(database, principal, case_id, source_id)
        if source.status != "sealed" or not source.sealed_storage_key or not source.sha256:
            raise EvidenceTwinError("Only a sealed evidence source can be verified.")
        return self._verify_object(
            database,
            principal,
            source,
            working_copy=None,
            storage_key=source.sealed_storage_key,
            expected_sha256=source.sha256,
        )

    def create_working_copy(
        self, database: Database, principal: Principal, case_id: str, source_id: str
    ) -> EvidenceWorkingCopyRecord:
        source = self.get_source(database, principal, case_id, source_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot create working copies.")
        if source.status != "sealed" or not source.sealed_storage_key or not source.sha256:
            raise EvidenceTwinError("Only a sealed evidence source can create a working copy.")
        copy_id = str(uuid4())
        storage_key = f"c/{case_id[:8]}/tw/{source.id}/working/{copy_id}.evidence"
        now = datetime.now(UTC)
        with database.session() as session:
            copy = EvidenceWorkingCopyRecord(
                id=copy_id,
                evidence_source_id=source.id,
                case_id=case_id,
                created_by=principal.user_id,
                status="creating",
                storage_key=storage_key,
                size_bytes=None,
                expected_source_sha256=source.sha256,
                observed_sha256=None,
                copy_method="stream_copy",
                verified_at=None,
                created_at=now,
            )
            session.add(copy)
            session.flush()
        store = EvidenceStore(database.data_dir / "evidence")
        source_path = store.resolve(source.sealed_storage_key, require_file=True)
        with source_path.open("rb") as input_stream, store.open_writer(storage_key) as writer:
            for _, _, data in _fixed_chunks(input_stream, source.chunk_size_bytes):
                writer.write(data)
            stored = writer.seal()
        matches = stored.sha256 == source.sha256 and stored.size_bytes == source.size_bytes
        _apply_read_only(store.resolve(storage_key, require_file=True))
        with database.session() as session:
            stored_copy = session.get(EvidenceWorkingCopyRecord, copy_id)
            assert stored_copy is not None
            stored_copy.status = "ready" if matches else "verification_failed"
            stored_copy.size_bytes = stored.size_bytes
            stored_copy.observed_sha256 = stored.sha256
            stored_copy.verified_at = datetime.now(UTC)
            session.flush()
        verification = self._verify_object(
            database,
            principal,
            source,
            working_copy=stored_copy,
            storage_key=storage_key,
            expected_sha256=source.sha256,
        )
        if verification.status != "verified":
            raise EvidenceTwinIntegrityError(
                "The working copy does not match the sealed master evidence source."
            )
        return stored_copy

    @staticmethod
    def _validate_chunk_size(chunk_size_bytes: int) -> None:
        if not MIN_EVIDENCE_CHUNK_SIZE <= chunk_size_bytes <= MAX_EVIDENCE_CHUNK_SIZE:
            raise EvidenceTwinError("Evidence chunk size must be between 1 MiB and 64 MiB.")

    @staticmethod
    def _require_disk_space(database: Database, declared_size_bytes: int | None) -> None:
        free = shutil.disk_usage(database.data_dir).free
        required = MINIMUM_FREE_BYTES + (declared_size_bytes or 0)
        if free < required:
            raise EvidenceTwinStorageError(
                "The workstation does not have enough free storage for this evidence import."
            )

    @staticmethod
    def _persist_chunk_batch(database: Database, chunks: list[EvidenceSourceChunkRecord]) -> None:
        with database.session() as session:
            session.add_all(chunks)
            session.flush()

    def _create_pending_source(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        *,
        source_name: str,
        display_name: str,
        container_format: EvidenceContainerFormat,
        chunk_size_bytes: int,
    ) -> EvidenceSourceRecord:
        with database.session() as session:
            case = CaseService().get(session, principal, case_id)
            if not principal.can(Permission.ACQUISITIONS_OPERATE):
                raise CaseAccessDeniedError("The current user cannot import evidence sources.")
            if case.status in {CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value}:
                raise EvidenceTwinError(
                    "Evidence sources cannot be imported into a closed or archived case."
                )
            now = datetime.now(UTC)
            source = EvidenceSourceRecord(
                case_id=case_id,
                device_id=None,
                created_by=principal.user_id,
                source_type=EvidenceSourceType.IMPORTED_FILE.value,
                acquisition_level=AcquisitionLevel.FILESYSTEM.value,
                status="pending",
                display_name=display_name,
                source_name=source_name,
                container_format=container_format.value,
                sealed_storage_key=None,
                chunks_storage_key=None,
                manifest_storage_key=None,
                size_bytes=None,
                sha256=None,
                chunks_sha256=None,
                manifest_sha256=None,
                chunk_size_bytes=chunk_size_bytes,
                chunk_count=0,
                read_only_applied=False,
                validation_state="import_origin_unverified",
                limitations_json=_canonical_json(
                    [
                        "Imported evidence is not claimed to have been acquired by ForensiX.",
                        "Source acquisition method and device-side effects require "
                        "examiner review.",
                    ]
                ),
                tool_version=__version__,
                error_code=None,
                error_message=None,
                sealed_at=None,
                created_at=now,
            )
            session.add(source)
            session.flush()
            session.add(
                CaseEventRecord(
                    case_id=case_id,
                    actor_id=principal.user_id,
                    event_type="evidence_source_import_started",
                    safe_detail=f"evidence_source_id={source.id};format={container_format.value}",
                    created_at=now,
                )
            )
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="evidence_source_import_started",
                object_type="evidence_source",
                object_id=source.id,
                detail={"container_format": container_format.value},
                created_at=now,
            )
            session.flush()
            return source

    @staticmethod
    def _complete_source(
        database: Database,
        principal: Principal,
        source_id: str,
        *,
        master_key: str,
        chunks_key: str,
        manifest_key: str,
        size_bytes: int,
        master_sha256: str,
        chunks_sha256: str,
        manifest_sha256: str,
        chunk_count: int,
        read_only: bool,
    ) -> EvidenceSourceRecord:
        with database.session() as session:
            source = session.get(EvidenceSourceRecord, source_id)
            if source is None or source.status != "pending":
                raise EvidenceTwinError("The pending evidence-source record changed during import.")
            now = datetime.now(UTC)
            source.status = "sealed"
            source.sealed_storage_key = master_key
            source.chunks_storage_key = chunks_key
            source.manifest_storage_key = manifest_key
            source.size_bytes = size_bytes
            source.sha256 = master_sha256
            source.chunks_sha256 = chunks_sha256
            source.manifest_sha256 = manifest_sha256
            source.chunk_count = chunk_count
            source.read_only_applied = read_only
            source.validation_state = "sealed_unverified_import"
            source.sealed_at = now
            session.add(
                CaseEventRecord(
                    case_id=source.case_id,
                    actor_id=principal.user_id,
                    event_type="evidence_source_sealed",
                    safe_detail=(
                        f"evidence_source_id={source.id};size_bytes={size_bytes};"
                        f"sha256={master_sha256}"
                    ),
                    created_at=now,
                )
            )
            AuditService().append(
                session,
                case_id=source.case_id,
                actor_id=principal.user_id,
                event_type="evidence_source_sealed",
                object_type="evidence_source",
                object_id=source.id,
                detail={
                    "chunk_count": chunk_count,
                    "manifest_sha256": manifest_sha256,
                    "sha256": master_sha256,
                    "size_bytes": size_bytes,
                },
                created_at=now,
            )
            session.flush()
            return source

    @staticmethod
    def _fail_source(database: Database, source_id: str, error: Exception) -> None:
        with database.session() as session:
            source = session.get(EvidenceSourceRecord, source_id)
            if source is None or source.status != "pending":
                return
            source.status = "failed"
            source.error_code = getattr(error, "code", "EVIDENCE_TWIN_IMPORT_FAILED")
            source.error_message = str(error)[:1000]
            session.flush()

    @staticmethod
    def _verify_object(
        database: Database,
        principal: Principal,
        source: EvidenceSourceRecord,
        *,
        working_copy: EvidenceWorkingCopyRecord | None,
        storage_key: str,
        expected_sha256: str,
    ) -> EvidenceSourceVerificationRecord:
        store = EvidenceStore(database.data_dir / "evidence")
        now = datetime.now(UTC)
        observed_sha256: str | None = None
        size_bytes: int | None = None
        error_code: str | None = None
        try:
            observed = store.hash(storage_key)
            observed_sha256 = observed.hexdigest
            size_bytes = observed.size_bytes
            status = "verified" if observed_sha256 == expected_sha256 else "mismatch"
        except Exception as error:
            status = "error"
            error_code = getattr(error, "code", "EVIDENCE_TWIN_VERIFY_FAILED")
        payload = {
            "case_id": source.case_id,
            "evidence_source_id": source.id,
            "expected_sha256": expected_sha256,
            "observed_sha256": observed_sha256,
            "size_bytes": size_bytes,
            "status": status,
            "target_type": "working_copy" if working_copy else "master",
            "tool_version": __version__,
            "verified_at": now.isoformat(),
            "verified_by": principal.user_id,
            "working_copy_id": working_copy.id if working_copy else None,
        }
        record = EvidenceSourceVerificationRecord(
            evidence_source_id=source.id,
            working_copy_id=working_copy.id if working_copy else None,
            case_id=source.case_id,
            verified_by=principal.user_id,
            target_type="working_copy" if working_copy else "master",
            status=status,
            expected_sha256=expected_sha256,
            observed_sha256=observed_sha256,
            size_bytes=size_bytes,
            error_code=error_code,
            verification_hash=sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
            tool_version=__version__,
            verified_at=now,
        )
        with database.session() as session:
            session.add(record)
            AuditService().append(
                session,
                case_id=source.case_id,
                actor_id=principal.user_id,
                event_type="evidence_source_integrity_verified",
                object_type=record.target_type,
                object_id=working_copy.id if working_copy else source.id,
                detail={"status": status, "verification_hash": record.verification_hash},
                created_at=now,
            )
            session.flush()
            return record


def _fixed_chunks(stream: BinaryIO, chunk_size: int) -> Iterator[tuple[int, int, bytes]]:
    ordinal = 0
    offset = 0
    while True:
        buffer = bytearray()
        while len(buffer) < chunk_size:
            piece = stream.read(chunk_size - len(buffer))
            if not piece:
                break
            buffer.extend(piece)
        if not buffer:
            return
        data = bytes(buffer)
        yield ordinal, offset, data
        ordinal += 1
        offset += len(data)


def _safe_source_name(value: str) -> str:
    name = Path(value.replace("\\", "/")).name.strip()
    if not name or len(name) > 255 or any(ord(character) < 32 for character in name):
        raise EvidenceTwinError("Evidence source name is invalid.")
    return name


def _display_name(value: str) -> str:
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 255:
        raise EvidenceTwinError("Evidence display name is invalid.")
    return normalized


def _storage_extension(container_format: EvidenceContainerFormat) -> str:
    if container_format is EvidenceContainerFormat.UNKNOWN:
        return "evidence"
    return container_format.value


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _apply_read_only(path: Path) -> bool:
    try:
        path.chmod(stat.S_IRUSR)
    except OSError:
        return False
    return True
