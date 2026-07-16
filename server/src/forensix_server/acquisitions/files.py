"""Selected, inventory-bound evidence-file acquisition with durable provenance."""

import json
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_forensic.adb import (
    MAX_ACQUIRED_FILE_BYTES,
    AdbClient,
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    AdbError,
    AdbTransferLimitError,
    DeviceState,
    SharedStorageRoot,
)
from forensix_forensic.storage import EvidenceStore, StoredEvidence
from forensix_server import __version__
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService, CaseStatus
from forensix_server.custody import CustodyService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionInventoryItemRecord,
    AcquisitionInventoryRecord,
    CaseDeviceRecord,
    CaseEventRecord,
    Database,
)
from forensix_server.evidence import ArtifactService
from forensix_server.jobs import JobState

from .execution import AcquisitionExecutionService
from .inventory import AcquisitionInventoryError, DeviceIdentityChangedError
from .recovery import AcquisitionRecoveryService

MINIMUM_POST_TRANSFER_FREE_BYTES = 100 * 1024 * 1024


class AcquisitionFileError(AcquisitionInventoryError):
    code = "ACQUISITION_FILE_INVALID"


class EvidenceDiskSpaceError(AcquisitionFileError):
    code = "EVIDENCE_DISK_SPACE_LOW"


@dataclass(frozen=True, slots=True)
class _FileContext:
    record_id: str
    case_id: str
    job_id: str
    plan_id: str
    inventory_id: str
    inventory_item_id: str
    device_id: str
    operator_id: str
    serial_hash: str
    build_fingerprint: str | None
    root: SharedStorageRoot
    relative_path: str
    source_path_hash: str
    storage_key: str
    manifest_storage_key: str
    started_at: datetime


class AcquisitionFileService:
    """Pulls exactly one persisted inventory item into contained evidence storage."""

    async def acquire(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
        item_id: str,
        adb_client: AdbClient,
    ) -> AcquiredEvidenceFileRecord:
        context, completed = self._begin(database, principal, case_id, job_id, item_id)
        if completed is not None:
            return completed
        assert context is not None
        store = EvidenceStore(database.data_dir / "evidence")
        partial_preserved = False
        partial_id: str | None = None
        try:
            serial = await self._revalidate_live_device(adb_client, context)
            stored = self._recover_sealed_file(store, context.storage_key)
            if stored is None:
                partial_id = str(uuid4())
                partial_storage_key = f"c/{context.case_id[:8]}/p/{partial_id}.partial"
                reservation = store.reserve_external(
                    context.storage_key,
                    partial_storage_key=partial_storage_key,
                )
                AcquisitionRecoveryService().begin_attempt(
                    database,
                    partial_id=partial_id,
                    evidence_file_id=context.record_id,
                    case_id=context.case_id,
                    job_id=context.job_id,
                    created_by=context.operator_id,
                    storage_key=partial_storage_key,
                )
                try:
                    transfer = await adb_client.pull_inventory_file(
                        serial,
                        context.root,
                        context.relative_path,
                        reservation.partial_path,
                    )
                    if (
                        transfer.root_id != context.root.value
                        or transfer.relative_path != context.relative_path
                    ):
                        raise AcquisitionFileError(
                            "The ADB transfer result did not match the selected inventory item."
                        )
                    if reservation.partial_path.stat().st_size != transfer.size_bytes:
                        raise AcquisitionFileError(
                            "The evidence partial size differs from the ADB transfer result."
                        )
                    stored = reservation.seal()
                    AcquisitionRecoveryService().mark_sealed(
                        database,
                        partial_id,
                        size_bytes=stored.size_bytes,
                        sha256=stored.sha256,
                    )
                except Exception as error:
                    preserve_partial = not isinstance(error, AdbTransferLimitError)
                    reservation.close(preserve_partial=preserve_partial)
                    reconciled = AcquisitionRecoveryService().reconcile_attempt(
                        database,
                        partial_id,
                        reason_code=getattr(error, "code", "TRANSFER_FAILED"),
                        preserve=preserve_partial,
                    )
                    partial_preserved = reconciled.status == "retained"
                    raise
            return self._complete(database, store, context, stored)
        except AdbError as error:
            self._fail(database, context, error.code, str(error), partial_preserved)
            raise
        except AcquisitionFileError as error:
            self._fail(database, context, error.code, str(error), partial_preserved)
            raise
        except Exception as error:
            safe_error = AcquisitionFileError(
                "The selected evidence file could not be sealed and recorded safely."
            )
            self._fail(database, context, safe_error.code, str(safe_error), partial_preserved)
            raise safe_error from error

    def list_for_job(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> list[AcquiredEvidenceFileRecord]:
        AcquisitionExecutionService().get(session, principal, case_id, job_id)
        return list(
            session.scalars(
                select(AcquiredEvidenceFileRecord)
                .where(
                    AcquiredEvidenceFileRecord.case_id == case_id,
                    AcquiredEvidenceFileRecord.job_id == job_id,
                )
                .order_by(AcquiredEvidenceFileRecord.started_at)
            )
        )

    def _begin(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
        item_id: str,
    ) -> tuple[_FileContext | None, AcquiredEvidenceFileRecord | None]:
        if not principal.can(Permission.ACQUISITIONS_OPERATE):
            raise CaseAccessDeniedError("The current user cannot acquire evidence files.")
        with database.session() as session:
            case = CaseService().get(session, principal, case_id)
            job = AcquisitionExecutionService().get(session, principal, case_id, job_id)
            if case.status in {CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value}:
                raise AcquisitionFileError(
                    "Evidence files cannot be acquired for a closed or archived case."
                )
            if job.state != JobState.COMPLETED.value or job.plan_id is None:
                raise AcquisitionFileError(
                    "A completed bounded inventory job is required before file acquisition."
                )
            inventory = session.scalar(
                select(AcquisitionInventoryRecord).where(
                    AcquisitionInventoryRecord.job_id == job.id
                )
            )
            item = session.get(AcquisitionInventoryItemRecord, item_id)
            if inventory is None or item is None or item.inventory_id != inventory.id:
                raise AcquisitionFileError(
                    "The selected path was not issued by this acquisition inventory."
                )
            existing = session.scalar(
                select(AcquiredEvidenceFileRecord).where(
                    AcquiredEvidenceFileRecord.inventory_item_id == item.id
                )
            )
            if existing is not None and existing.status == "completed":
                return None, existing
            if existing is not None and existing.status == "acquiring":
                raise AcquisitionFileError("This inventory item is already being acquired.")
            if existing is not None and AcquisitionRecoveryService().has_unreviewed_partial(
                session, existing.id
            ):
                raise AcquisitionFileError(
                    "Review whether to retain or discard the preserved partial before restart."
                )
            required_free = MAX_ACQUIRED_FILE_BYTES + MINIMUM_POST_TRANSFER_FREE_BYTES
            if shutil.disk_usage(database.data_dir).free < required_free:
                raise EvidenceDiskSpaceError(
                    "At least 200 MiB of free workstation storage is required."
                )
            device = session.get(CaseDeviceRecord, inventory.device_id)
            if device is None:
                raise AcquisitionFileError("The case-linked device provenance is unavailable.")
            try:
                root = SharedStorageRoot(inventory.root_id)
            except ValueError as error:
                raise AcquisitionFileError("The inventory storage root is unsupported.") from error
            started_at = datetime.now(UTC)
            record_id = existing.id if existing is not None else str(uuid4())
            extension = (
                item.extension
                if item.extension and re.fullmatch(r"[a-z0-9]{1,16}", item.extension)
                else "bin"
            )
            base_key = f"c/{case_id[:8]}"
            storage_key = f"{base_key}/r/{record_id}.{extension}"
            manifest_storage_key = f"{base_key}/m/{record_id}.json"
            if existing is None:
                existing = AcquiredEvidenceFileRecord(
                    id=record_id,
                    inventory_id=inventory.id,
                    inventory_item_id=item.id,
                    job_id=job.id,
                    case_id=case_id,
                    plan_id=job.plan_id,
                    device_id=device.id,
                    acquired_by=principal.user_id,
                    status="acquiring",
                    source_root_id=root.value,
                    source_path_hash=item.path_hash,
                    storage_key=storage_key,
                    manifest_storage_key=manifest_storage_key,
                    transfer_limit_bytes=MAX_ACQUIRED_FILE_BYTES,
                    tool_version=__version__,
                    validation_state="not_physically_validated",
                    partial_preserved=False,
                    started_at=started_at,
                )
                session.add(existing)
            else:
                existing.status = "acquiring"
                existing.acquired_by = principal.user_id
                existing.error_code = None
                existing.error_message = None
                existing.partial_preserved = False
                existing.started_at = started_at
                existing.completed_at = None
            session.add(
                CaseEventRecord(
                    case_id=case_id,
                    actor_id=principal.user_id,
                    event_type="evidence_file_acquisition_started",
                    safe_detail=f"record_id={record_id};inventory_item_id={item.id}",
                )
            )
            session.flush()
            return (
                _FileContext(
                    record_id=record_id,
                    case_id=case_id,
                    job_id=job.id,
                    plan_id=job.plan_id,
                    inventory_id=inventory.id,
                    inventory_item_id=item.id,
                    device_id=device.id,
                    operator_id=principal.user_id,
                    serial_hash=device.serial_hash,
                    build_fingerprint=device.build_fingerprint,
                    root=root,
                    relative_path=item.relative_path,
                    source_path_hash=item.path_hash,
                    storage_key=storage_key,
                    manifest_storage_key=manifest_storage_key,
                    started_at=started_at,
                ),
                None,
            )

    async def _revalidate_live_device(self, adb_client: AdbClient, context: _FileContext) -> str:
        transports = await adb_client.list_transports()
        transport = next(
            (
                item
                for item in transports
                if sha256(item.serial.encode("utf-8")).hexdigest() == context.serial_hash
            ),
            None,
        )
        if transport is None:
            raise AdbDeviceNotFoundError
        if transport.state is not DeviceState.AUTHORIZED:
            raise AdbDeviceNotAuthorizedError(transport.state.value)
        properties = await adb_client.get_properties(transport.serial)
        if (
            context.build_fingerprint
            and properties.get("ro.build.fingerprint") != context.build_fingerprint
        ):
            raise DeviceIdentityChangedError(
                "The live build fingerprint differs from the case-linked readiness record."
            )
        probes = await adb_client.probe_shared_storage(transport.serial)
        root = next((item for item in probes if item.root_id == context.root.value), None)
        if root is None or not root.readable:
            raise AcquisitionFileError("The approved source root is no longer readable.")
        return transport.serial

    @staticmethod
    def _recover_sealed_file(store: EvidenceStore, storage_key: str) -> StoredEvidence | None:
        path = store.resolve(storage_key)
        if not path.exists():
            return None
        result = store.hash(storage_key)
        return StoredEvidence(
            storage_key=storage_key,
            size_bytes=result.size_bytes,
            sha256=result.hexdigest,
        )

    @staticmethod
    def _complete(
        database: Database,
        store: EvidenceStore,
        context: _FileContext,
        stored: StoredEvidence,
    ) -> AcquiredEvidenceFileRecord:
        completed_at = datetime.now(UTC)
        manifest_payload = {
            "acquired_by": context.operator_id,
            "case_id": context.case_id,
            "completed_at": completed_at.isoformat(),
            "device_id": context.device_id,
            "file_sha256": stored.sha256,
            "inventory_id": context.inventory_id,
            "inventory_item_id": context.inventory_item_id,
            "job_id": context.job_id,
            "plan_id": context.plan_id,
            "record_id": context.record_id,
            "schema_version": "1.0.0",
            "size_bytes": stored.size_bytes,
            "source_path_hash": context.source_path_hash,
            "source_relative_path": context.relative_path,
            "source_root_id": context.root.value,
            "started_at": context.started_at.isoformat(),
            "storage_key": stored.storage_key,
            "tool_version": __version__,
            "validation_state": "not_physically_validated",
        }
        manifest_bytes = json.dumps(
            manifest_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        manifest_path = store.resolve(context.manifest_storage_key)
        if manifest_path.exists():
            existing_manifest = store.hash(context.manifest_storage_key)
            manifest_sha256 = existing_manifest.hexdigest
            if manifest_sha256 != sha256(manifest_bytes).hexdigest():
                raise AcquisitionFileError(
                    "An existing manifest does not match the sealed evidence record."
                )
        else:
            with store.open_writer(context.manifest_storage_key) as writer:
                writer.write(manifest_bytes)
                manifest_sha256 = writer.seal().sha256
        with database.session() as session:
            record = session.get(AcquiredEvidenceFileRecord, context.record_id)
            if record is None or record.status != "acquiring":
                raise AcquisitionFileError(
                    "The durable evidence-file record changed during acquisition."
                )
            record.status = "completed"
            record.size_bytes = stored.size_bytes
            record.sha256 = stored.sha256
            record.manifest_hash = manifest_sha256
            record.partial_preserved = False
            record.completed_at = completed_at
            artifact = ArtifactService().normalize_completed(session, record, context.relative_path)
            CustodyService().append_automatic(
                session,
                case_id=context.case_id,
                actor_id=context.operator_id,
                event_type="evidence_registered",
                evidence_file_id=record.id,
                purpose="Evidence file acquired and sealed by ForensiX.",
            )
            session.add(
                CaseEventRecord(
                    case_id=context.case_id,
                    actor_id=context.operator_id,
                    event_type="evidence_file_acquisition_completed",
                    safe_detail=(
                        f"record_id={record.id};size_bytes={stored.size_bytes};"
                        f"sha256={stored.sha256}"
                    ),
                )
            )
            session.add(
                CaseEventRecord(
                    case_id=context.case_id,
                    actor_id=context.operator_id,
                    event_type="artifact_normalized",
                    safe_detail=f"artifact_id={artifact.id};evidence_file_id={record.id}",
                )
            )
            session.flush()
            return record

    @staticmethod
    def _fail(
        database: Database,
        context: _FileContext,
        error_code: str,
        message: str,
        partial_preserved: bool,
    ) -> None:
        with database.session() as session:
            record = session.get(AcquiredEvidenceFileRecord, context.record_id)
            if record is None or record.status != "acquiring":
                return
            record.status = "failed"
            record.error_code = error_code[:64]
            record.error_message = message[:1000]
            record.partial_preserved = partial_preserved
            record.completed_at = datetime.now(UTC)
            session.add(
                CaseEventRecord(
                    case_id=context.case_id,
                    actor_id=context.operator_id,
                    event_type="evidence_file_acquisition_failed",
                    safe_detail=f"record_id={record.id};error_code={error_code[:64]}",
                )
            )
            session.flush()
