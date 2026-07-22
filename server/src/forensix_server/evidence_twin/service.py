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
from forensix_server.custody import AuditService, CustodyService
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
        return self._seal_stream(
            database,
            principal,
            case_id,
            stream,
            source_name=source_name,
            display_name=display_name,
            declared_size_bytes=declared_size_bytes,
            chunk_size_bytes=chunk_size_bytes,
            source_type=EvidenceSourceType.IMPORTED_FILE,
            acquisition_level=AcquisitionLevel.FILESYSTEM,
            device_id=None,
            limitations=(
                "Imported evidence is not claimed to have been acquired by ForensiX.",
                "Source acquisition method and device-side effects require examiner review.",
            ),
            manifest_metadata=None,
        )

    def seal_rooted_stream(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        device_id: str,
        stream: BinaryIO,
        *,
        source_name: str,
        display_name: str,
        declared_size_bytes: int,
        profile: str,
        chunk_size_bytes: int = DEFAULT_EVIDENCE_CHUNK_SIZE,
    ) -> EvidenceSourceRecord:
        """Seal a bundle produced only by the controlled rooted acquisition service."""
        return self._seal_stream(
            database,
            principal,
            case_id,
            stream,
            source_name=source_name,
            display_name=display_name,
            declared_size_bytes=declared_size_bytes,
            chunk_size_bytes=chunk_size_bytes,
            source_type=EvidenceSourceType.ROOTED_FILESYSTEM,
            acquisition_level=AcquisitionLevel.FILESYSTEM,
            device_id=device_id,
            limitations=(
                "Rooted filesystem collection can create device logs and root-manager activity.",
                "This bounded rooted bundle is not a physical or bit-for-bit device image.",
                "Encrypted application data may remain unavailable or require separate keys.",
            ),
            manifest_metadata={"profile": profile},
        )

    def seal_logical_stream(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        device_id: str,
        stream: BinaryIO,
        *,
        source_name: str,
        display_name: str,
        declared_size_bytes: int,
        operation: str,
        limitations: tuple[str, ...],
        chunk_size_bytes: int = DEFAULT_EVIDENCE_CHUNK_SIZE,
    ) -> EvidenceSourceRecord:
        """Seal a workstation-streamed, case-authorized logical ADB artifact."""
        return self._seal_stream(
            database,
            principal,
            case_id,
            stream,
            source_name=source_name,
            display_name=display_name,
            declared_size_bytes=declared_size_bytes,
            chunk_size_bytes=chunk_size_bytes,
            source_type=EvidenceSourceType.LOGICAL_ADB,
            acquisition_level=AcquisitionLevel.SELECTIVE,
            device_id=device_id,
            limitations=limitations,
            manifest_metadata={"operation": operation},
        )

    def seal_physical_stream(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        device_id: str,
        stream: BinaryIO,
        *,
        source_name: str,
        display_name: str,
        declared_size_bytes: int,
        root_probe_id: str,
        physical_probe_id: str,
        profile: str,
        device_path: str,
        encryption_state: str,
        chunk_size_bytes: int = DEFAULT_EVIDENCE_CHUNK_SIZE,
    ) -> EvidenceSourceRecord:
        """Seal one explicitly enabled experimental block stream without interpreting it."""
        return self._seal_stream(
            database,
            principal,
            case_id,
            stream,
            source_name=source_name,
            display_name=display_name,
            declared_size_bytes=declared_size_bytes,
            chunk_size_bytes=chunk_size_bytes,
            source_type=EvidenceSourceType.PHYSICAL_BLOCK,
            acquisition_level=AcquisitionLevel.PHYSICAL,
            device_id=device_id,
            limitations=(
                "Experimental raw block acquisition is not production validated.",
                "A userdata block image is commonly encrypted and does not bypass Android locks.",
                "This transport is not hardware write blocking and may create device logs.",
                "The current experimental transfer is not resumable after interruption.",
            ),
            manifest_metadata={
                "device_path": device_path,
                "encryption_state": encryption_state,
                "physical_probe_id": physical_probe_id,
                "profile": profile,
                "root_probe_id": root_probe_id,
            },
        )

    def _seal_stream(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        stream: BinaryIO,
        *,
        source_name: str,
        display_name: str | None,
        declared_size_bytes: int | None,
        chunk_size_bytes: int,
        source_type: EvidenceSourceType,
        acquisition_level: AcquisitionLevel,
        device_id: str | None,
        limitations: tuple[str, ...],
        manifest_metadata: dict[str, Any] | None,
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
            source_type=source_type,
            acquisition_level=acquisition_level,
            device_id=device_id,
            limitations=limitations,
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
                "acquisition_level": acquisition_level.value,
                "acquisition_metadata": manifest_metadata or {},
                "case_id": case_id,
                "chunk_count": chunk_count,
                "chunk_size_bytes": chunk_size_bytes,
                "chunks_sha256": chunks.sha256,
                "chunks_storage_key": chunks.storage_key,
                "container_format": container_format.value,
                "created_at": source.created_at.astimezone(UTC).isoformat(),
                "created_by": principal.user_id,
                "device_id": device_id,
                "evidence_source_id": source.id,
                "limitations": list(limitations),
                "master_sha256": master.sha256,
                "master_storage_key": master.storage_key,
                "schema_version": "1.0.0",
                "size_bytes": master.size_bytes,
                "source_name": safe_source_name,
                "source_type": source_type.value,
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

    def list_working_copies(
        self, database: Database, principal: Principal, case_id: str, source_id: str
    ) -> list[EvidenceWorkingCopyRecord]:
        self.get_source(database, principal, case_id, source_id)
        with database.session() as session:
            return list(
                session.scalars(
                    select(EvidenceWorkingCopyRecord)
                    .where(EvidenceWorkingCopyRecord.evidence_source_id == source_id)
                    .order_by(EvidenceWorkingCopyRecord.created_at.desc())
                )
            )

    def list_verifications(
        self, database: Database, principal: Principal, case_id: str, source_id: str
    ) -> list[EvidenceSourceVerificationRecord]:
        self.get_source(database, principal, case_id, source_id)
        with database.session() as session:
            return list(
                session.scalars(
                    select(EvidenceSourceVerificationRecord)
                    .where(EvidenceSourceVerificationRecord.evidence_source_id == source_id)
                    .order_by(EvidenceSourceVerificationRecord.verified_at.desc())
                )
            )

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

    def verify_working_copy(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
    ) -> EvidenceSourceVerificationRecord:
        source = self.get_source(database, principal, case_id, source_id)
        with database.session() as session:
            working_copy = session.get(EvidenceWorkingCopyRecord, working_copy_id)
            if (
                working_copy is None
                or working_copy.case_id != case_id
                or working_copy.evidence_source_id != source_id
            ):
                raise EvidenceTwinNotFoundError(
                    "The requested Evidence Twin working copy does not exist."
                )
            if working_copy.status != "ready":
                raise EvidenceTwinError("Only a ready working copy can be verified.")
        return self._verify_object(
            database,
            principal,
            source,
            working_copy=working_copy,
            storage_key=working_copy.storage_key,
            expected_sha256=working_copy.expected_source_sha256,
        )

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
        source_type: EvidenceSourceType,
        acquisition_level: AcquisitionLevel,
        device_id: str | None,
        limitations: tuple[str, ...],
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
                device_id=device_id,
                created_by=principal.user_id,
                source_type=source_type.value,
                acquisition_level=acquisition_level.value,
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
                validation_state=(
                    "import_origin_unverified"
                    if source_type is EvidenceSourceType.IMPORTED_FILE
                    else "acquisition_pending_verification"
                ),
                limitations_json=_canonical_json(list(limitations)),
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
                    event_type="evidence_source_registration_started",
                    safe_detail=(
                        f"evidence_source_id={source.id};format={container_format.value};"
                        f"source_type={source_type.value}"
                    ),
                    created_at=now,
                )
            )
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="evidence_source_registration_started",
                object_type="evidence_source",
                object_id=source.id,
                detail={
                    "acquisition_level": acquisition_level.value,
                    "container_format": container_format.value,
                    "device_id": device_id,
                    "source_type": source_type.value,
                },
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
            source.validation_state = (
                "sealed_unverified_import"
                if source.source_type == EvidenceSourceType.IMPORTED_FILE.value
                else "sealed_unverified_acquisition"
            )
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
            CustodyService().append_evidence_source(
                session,
                case_id=source.case_id,
                actor_id=principal.user_id,
                event_type="evidence_source_registered",
                evidence_source_id=source.id,
                purpose=(
                    "Imported source sealed with chunk, master, and manifest SHA-256; "
                    "origin remains examiner-declared."
                    if source.source_type == EvidenceSourceType.IMPORTED_FILE.value
                    else (
                        "Experimental raw block stream sealed with chunk, master, and manifest "
                        "SHA-256; encryption state remains examiner-verifiable."
                        if source.source_type == EvidenceSourceType.PHYSICAL_BLOCK.value
                        else "Controlled rooted provider bundle sealed with chunk, master, and "
                        "manifest SHA-256; this is not a physical device image."
                    )
                ),
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
            CustodyService().append_evidence_source(
                session,
                case_id=source.case_id,
                actor_id=principal.user_id,
                event_type=(
                    "source_integrity_verified"
                    if status == "verified" and working_copy is None
                    else "working_copy_verified"
                    if status == "verified"
                    else "integrity_exception"
                ),
                evidence_source_id=source.id,
                purpose=(
                    f"{record.target_type} SHA-256 verification status: {status}; "
                    f"verification record {record.id}."
                ),
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
