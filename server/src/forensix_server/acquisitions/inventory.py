"""Bounded, content-free shared-storage inventory orchestration."""

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_forensic.adb import (
    AdbClient,
    AdbCommandPolicy,
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    AdbError,
    DeviceState,
    SharedStorageRoot,
    StorageInventoryResult,
)
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService, CaseStatus
from forensix_server.db import (
    AcquisitionInventoryItemRecord,
    AcquisitionInventoryRecord,
    AcquisitionPlanRecord,
    CaseDeviceAssessmentRecord,
    CaseDeviceRecord,
    CaseEventRecord,
    Database,
)
from forensix_server.jobs import JobService, JobState

from .domain import AcquisitionModule
from .execution import AcquisitionExecutionService, AcquisitionJobInvalidStateError
from .service import plan_modules

MINIMUM_INVENTORY_FREE_BYTES = 100 * 1024 * 1024


class AcquisitionInventoryError(AcquisitionJobInvalidStateError):
    code = "ACQUISITION_INVENTORY_INVALID"


class DeviceIdentityChangedError(AcquisitionInventoryError):
    code = "DEVICE_IDENTITY_CHANGED"


class InventoryDiskSpaceError(AcquisitionInventoryError):
    code = "INVENTORY_DISK_SPACE_LOW"


class InventoryCancelledError(AcquisitionInventoryError):
    code = "ACQUISITION_CANCELLED"


@dataclass(frozen=True, slots=True)
class _InventoryContext:
    case_id: str
    job_id: str
    plan_id: str
    device_id: str
    operator_id: str
    serial_hash: str
    build_fingerprint: str | None
    root: SharedStorageRoot
    started_at: datetime


class AcquisitionInventoryService:
    """Runs one fixed ADB find operation after live identity/capability checks."""

    async def run(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
        adb_client: AdbClient,
    ) -> AcquisitionInventoryRecord:
        context, existing = self._begin(database, principal, case_id, job_id)
        if existing is not None:
            return existing
        assert context is not None
        try:
            serial = await self._revalidate_live_device(adb_client, context)
            if self._finish_revalidation(database, context.job_id):
                raise InventoryCancelledError(
                    "The acquisition was cancelled before inventory execution."
                )
            result = await adb_client.inventory_shared_storage(serial, context.root)
            if (
                result.root_id != context.root.value
                or result.display_path != AdbCommandPolicy.display_path(context.root)
            ):
                raise AcquisitionInventoryError(
                    "The inventory result did not match the approved storage root."
                )
            return self._persist_result(database, context, result)
        except AdbError as error:
            self._fail_job(database, context, error.code, str(error))
            raise
        except AcquisitionInventoryError as error:
            self._fail_job(database, context, error.code, str(error))
            raise

    def get_for_job(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> AcquisitionInventoryRecord:
        AcquisitionExecutionService().get(session, principal, case_id, job_id)
        inventory = session.scalar(
            select(AcquisitionInventoryRecord).where(AcquisitionInventoryRecord.job_id == job_id)
        )
        if inventory is None:
            raise AcquisitionInventoryError(
                "No bounded inventory result exists for this acquisition job."
            )
        return inventory

    def list_items(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        job_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[AcquisitionInventoryRecord, list[AcquisitionInventoryItemRecord], int]:
        inventory = self.get_for_job(session, principal, case_id, job_id)
        total = inventory.persisted_count
        items = list(
            session.scalars(
                select(AcquisitionInventoryItemRecord)
                .where(AcquisitionInventoryItemRecord.inventory_id == inventory.id)
                .order_by(AcquisitionInventoryItemRecord.ordinal)
                .offset(offset)
                .limit(limit)
            )
        )
        return inventory, items, total

    def _begin(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> tuple[_InventoryContext | None, AcquisitionInventoryRecord | None]:
        if not principal.can(Permission.ACQUISITIONS_OPERATE):
            raise CaseAccessDeniedError("The current user cannot run acquisition inventories.")
        with database.session() as session:
            case = CaseService().get(session, principal, case_id)
            job = AcquisitionExecutionService().get(session, principal, case_id, job_id)
            existing = session.scalar(
                select(AcquisitionInventoryRecord).where(
                    AcquisitionInventoryRecord.job_id == job.id
                )
            )
            if existing is not None:
                return None, existing
            if case.status in {CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value}:
                raise AcquisitionInventoryError(
                    "A bounded inventory cannot run for a closed or archived case."
                )
            if job.state != JobState.READY.value or job.plan_id is None:
                raise AcquisitionInventoryError(
                    "The acquisition job must be ready before inventory execution."
                )
            if shutil.disk_usage(database.data_dir).free < MINIMUM_INVENTORY_FREE_BYTES:
                raise InventoryDiskSpaceError(
                    "At least 100 MiB of free workstation storage is required."
                )
            plan = session.get(AcquisitionPlanRecord, job.plan_id)
            if plan is None or plan.case_id != case_id:
                raise AcquisitionInventoryError("The acquisition plan is unavailable.")
            if AcquisitionModule.SHARED_STORAGE_INVENTORY.value not in plan_modules(plan):
                raise AcquisitionInventoryError(
                    "This plan does not authorize shared-storage inventory."
                )
            device = session.get(CaseDeviceRecord, plan.device_id)
            assessment = session.get(CaseDeviceAssessmentRecord, plan.assessment_id)
            if device is None or assessment is None:
                raise AcquisitionInventoryError("The plan readiness provenance is unavailable.")
            root = _select_approved_root(assessment.snapshot_json)
            started_at = datetime.now(UTC)
            jobs = JobService()
            jobs.transition(session, job.id, JobState.VALIDATING)
            jobs.update_progress(
                session,
                job.id,
                10,
                current_step="Revalidating live device identity and storage access",
                current_module=AcquisitionModule.SHARED_STORAGE_INVENTORY.value,
                checkpoint={
                    "phase": "live_revalidation",
                    "root_id": root.value,
                },
            )
            return (
                _InventoryContext(
                    case_id=case_id,
                    job_id=job.id,
                    plan_id=plan.id,
                    device_id=device.id,
                    operator_id=principal.user_id,
                    serial_hash=device.serial_hash,
                    build_fingerprint=device.build_fingerprint,
                    root=root,
                    started_at=started_at,
                ),
                None,
            )

    async def _revalidate_live_device(
        self, adb_client: AdbClient, context: _InventoryContext
    ) -> str:
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
        live_fingerprint = properties.get("ro.build.fingerprint")
        if context.build_fingerprint and live_fingerprint != context.build_fingerprint:
            raise DeviceIdentityChangedError(
                "The live build fingerprint differs from the case-linked readiness record."
            )
        probes = await adb_client.probe_shared_storage(transport.serial)
        live_root = next((item for item in probes if item.root_id == context.root.value), None)
        if live_root is None or not live_root.readable:
            raise AcquisitionInventoryError(
                "The approved shared-storage root is no longer readable."
            )
        return transport.serial

    @staticmethod
    def _finish_revalidation(database: Database, job_id: str) -> bool:
        with database.session() as session:
            job = JobService().get(session, job_id)
            jobs = JobService()
            if job.state == JobState.CANCELLING.value:
                jobs.transition(session, job.id, JobState.CANCELLED)
                return True
            if job.state != JobState.VALIDATING.value:
                raise AcquisitionInventoryError(
                    "The acquisition job changed state during live revalidation."
                )
            jobs.transition(session, job.id, JobState.READY)
            jobs.transition(session, job.id, JobState.RUNNING)
            jobs.update_progress(
                session,
                job.id,
                25,
                current_step="Enumerating bounded path metadata from the approved root",
                current_module=AcquisitionModule.SHARED_STORAGE_INVENTORY.value,
                checkpoint={"phase": "path_inventory"},
            )
            return False

    @staticmethod
    def _persist_result(
        database: Database,
        context: _InventoryContext,
        result: StorageInventoryResult,
    ) -> AcquisitionInventoryRecord:
        completed_at = datetime.now(UTC)
        inventory_id = str(uuid4())
        item_payload: list[dict[str, Any]] = []
        ordered_entries = sorted(result.entries, key=lambda item: item.relative_path)
        for ordinal, entry in enumerate(ordered_entries, 1):
            path_hash = sha256(entry.relative_path.encode("utf-8")).hexdigest()
            item_payload.append(
                {
                    "extension": _extension(entry.relative_path),
                    "ordinal": ordinal,
                    "path_hash": path_hash,
                    "relative_path": entry.relative_path,
                    "size_bytes": entry.size_bytes,
                    "modified_time_raw": entry.modified_time_raw,
                    "modified_at": (
                        entry.modified_at.astimezone(UTC).isoformat()
                        if entry.modified_at is not None
                        else None
                    ),
                    "timestamp_source": entry.timestamp_source,
                    "timestamp_confidence": entry.timestamp_confidence,
                }
            )
        manifest_payload = {
            "case_id": context.case_id,
            "completed_at": completed_at.isoformat(),
            "device_id": context.device_id,
            "discovered_count": result.discovered_count,
            "inventory_id": inventory_id,
            "items": item_payload,
            "job_id": context.job_id,
            "max_depth": result.max_depth,
            "max_items": result.max_items,
            "operator_id": context.operator_id,
            "plan_id": context.plan_id,
            "root_id": result.root_id,
            "skipped_count": result.skipped_count,
            "started_at": context.started_at.isoformat(),
            "status": "truncated" if result.truncated else "completed",
        }
        manifest_hash = sha256(_canonical_json(manifest_payload).encode("utf-8")).hexdigest()
        with database.session() as session:
            job = JobService().get(session, context.job_id)
            if job.state not in {JobState.RUNNING.value, JobState.CANCELLING.value}:
                raise AcquisitionInventoryError(
                    "The acquisition job changed state before inventory persistence."
                )
            inventory = AcquisitionInventoryRecord(
                id=inventory_id,
                job_id=context.job_id,
                case_id=context.case_id,
                plan_id=context.plan_id,
                device_id=context.device_id,
                created_by=context.operator_id,
                root_id=result.root_id,
                display_path=result.display_path,
                status="truncated" if result.truncated else "completed",
                discovered_count=result.discovered_count,
                persisted_count=len(item_payload),
                skipped_count=result.skipped_count,
                max_items=result.max_items,
                max_depth=result.max_depth,
                manifest_hash=manifest_hash,
                started_at=context.started_at,
                completed_at=completed_at,
            )
            session.add(inventory)
            session.flush()
            session.add_all(
                AcquisitionInventoryItemRecord(
                    inventory_id=inventory.id,
                    ordinal=item["ordinal"],
                    relative_path=item["relative_path"],
                    path_hash=item["path_hash"],
                    extension=item["extension"],
                    size_bytes=item["size_bytes"],
                    modified_time_raw=item["modified_time_raw"],
                    modified_at=(
                        datetime.fromisoformat(item["modified_at"])
                        if item["modified_at"] is not None
                        else None
                    ),
                    timestamp_source=item["timestamp_source"],
                    timestamp_confidence=item["timestamp_confidence"],
                )
                for item in item_payload
            )
            session.flush()
            jobs = JobService()
            jobs.update_progress(
                session,
                job.id,
                95,
                current_step="Bounded path inventory persisted with manifest hash",
                current_module=AcquisitionModule.SHARED_STORAGE_INVENTORY.value,
                checkpoint={
                    "inventory_id": inventory.id,
                    "manifest_hash": inventory.manifest_hash,
                    "persisted_count": inventory.persisted_count,
                    "phase": "inventory_persisted",
                    "truncated": result.truncated,
                },
            )
            if job.state == JobState.CANCELLING.value:
                jobs.transition(
                    session,
                    job.id,
                    JobState.CANCELLED,
                    result_reference=inventory.id,
                )
                event_type = "acquisition_inventory_preserved_after_cancel"
            else:
                jobs.transition(
                    session,
                    job.id,
                    JobState.COMPLETED,
                    result_reference=inventory.id,
                )
                event_type = "acquisition_inventory_completed"
            session.add(
                CaseEventRecord(
                    case_id=context.case_id,
                    actor_id=context.operator_id,
                    event_type=event_type,
                    safe_detail=(
                        f"inventory_id={inventory.id};count={inventory.persisted_count};"
                        f"status={inventory.status}"
                    ),
                )
            )
            session.flush()
            return inventory

    @staticmethod
    def _fail_job(
        database: Database,
        context: _InventoryContext,
        error_code: str,
        message: str,
    ) -> None:
        with database.session() as session:
            job = JobService().get(session, context.job_id)
            state = JobState(job.state)
            if state in {
                JobState.VALIDATING,
                JobState.RUNNING,
                JobState.CANCELLING,
            }:
                JobService().transition(
                    session,
                    job.id,
                    JobState.FAILED,
                    error_code=error_code[:64],
                    error_message=message[:1000],
                )
                session.add(
                    CaseEventRecord(
                        case_id=context.case_id,
                        actor_id=context.operator_id,
                        event_type="acquisition_inventory_failed",
                        safe_detail=f"job_id={job.id};error_code={error_code[:64]}",
                    )
                )
                session.flush()


def _select_approved_root(snapshot_json: str) -> SharedStorageRoot:
    try:
        snapshot = json.loads(snapshot_json)
    except json.JSONDecodeError as error:
        raise AcquisitionInventoryError("The readiness snapshot is malformed.") from error
    roots = snapshot.get("storage_roots") if isinstance(snapshot, dict) else None
    if not isinstance(roots, list):
        raise AcquisitionInventoryError("The readiness snapshot has no storage-root decisions.")
    readable = {
        item.get("root_id")
        for item in roots
        if isinstance(item, dict) and item.get("readable") is True
    }
    for candidate in (
        SharedStorageRoot.EMULATED_PRIMARY,
        SharedStorageRoot.PRIMARY_ALIAS,
    ):
        if candidate.value in readable:
            return candidate
    raise AcquisitionInventoryError("The plan snapshot has no approved readable storage root.")


def _extension(relative_path: str) -> str | None:
    suffix = PurePosixPath(relative_path).suffix.lower().removeprefix(".")
    if not suffix:
        return None
    return suffix[:32]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
