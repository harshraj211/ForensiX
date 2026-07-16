from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from forensix_forensic.adb import (
    AdbDeviceNotFoundError,
    MockAdbClient,
    MockAdbScenario,
    SharedStorageRootProbe,
    StorageProbeStatus,
)
from forensix_forensic.capabilities import (
    CapabilityDecision,
    CapabilityStatus,
    DeviceCapabilitySnapshot,
)
from forensix_server.acquisitions import (
    AcquisitionExecutionService,
    AcquisitionInventoryError,
    AcquisitionInventoryService,
    AcquisitionPlanService,
    AcquisitionScope,
    DeviceIdentityChangedError,
)
from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseService
from forensix_server.db import (
    AcquisitionInventoryItemRecord,
    AcquisitionInventoryRecord,
    Database,
    JobRecord,
    UserRecord,
)
from forensix_server.jobs import JobService, JobState


@pytest.fixture
def database(tmp_path: Path) -> Database:
    active = Database(f"sqlite:///{(tmp_path / 'inventory.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal(database: Database) -> Principal:
    with database.session() as session:
        user = UserRecord(
            username="inventory.owner",
            display_name="Inventory Owner",
            password_hash="$argon2id$test-placeholder",
        )
        session.add(user)
        session.flush()
        return Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({RoleName.INVESTIGATOR}),
            permissions=ROLE_PERMISSIONS[RoleName.INVESTIGATOR],
        )


def _decision(status: CapabilityStatus) -> CapabilityDecision:
    return CapabilityDecision(
        status=status,
        reason_code=f"TEST_{status.value.upper()}",
        explanation="Controlled inventory test decision.",
    )


def _snapshot() -> DeviceCapabilitySnapshot:
    return DeviceCapabilitySnapshot(
        assessed_at=datetime.now(UTC),
        serial="FX-DEMO-001",
        manufacturer="ForensiX Labs",
        model="Controlled Test Device",
        android_version="14",
        sdk_level=34,
        build_fingerprint="forensix/demo/fx_virtual:14/TEST/001:user/test-keys",
        security_patch="2026-07-01",
        package_count=3,
        storage_roots=tuple(
            SharedStorageRootProbe(
                root_id=root_id,
                display_path=display_path,
                status=StorageProbeStatus.ACCESSIBLE,
                exists=True,
                readable=True,
                reason_code="ROOT_READABLE",
            )
            for root_id, display_path in (
                ("primary_alias", "/sdcard"),
                ("emulated_primary", "/storage/emulated/0"),
            )
        ),
        capabilities={
            "device_metadata": _decision(CapabilityStatus.SUPPORTED),
            "package_inventory": _decision(CapabilityStatus.SUPPORTED),
            "shared_storage": _decision(CapabilityStatus.SUPPORTED),
        },
        warnings=("Controlled inventory fixture.",),
    )


def _ready_job(
    database: Database,
    principal: Principal,
    *,
    scope: AcquisitionScope = AcquisitionScope.QUICK_TRIAGE,
) -> tuple[str, str, str]:
    with database.session() as session:
        case = CaseService().create(session, principal, title="Bounded inventory case")
        device, assessment = CaseDeviceService().register_assessment(
            session, principal, case.id, _snapshot()
        )
        plan = AcquisitionPlanService().create(
            session,
            principal,
            case.id,
            device_id=device.id,
            assessment_id=assessment.id,
            scope=scope,
            limitations_acknowledged=True,
        )
        job, _ = AcquisitionExecutionService().prepare(session, principal, case.id, plan.id)
        return case.id, plan.id, job.id


@pytest.mark.asyncio
async def test_bounded_inventory_revalidates_persists_and_hashes_paths(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, plan_id, job_id = _ready_job(database, principal)
    service = AcquisitionInventoryService()

    inventory = await service.run(database, principal, case_id, job_id, MockAdbClient())
    repeated = await service.run(database, principal, case_id, job_id, MockAdbClient())

    assert repeated.id == inventory.id
    assert inventory.plan_id == plan_id
    assert inventory.root_id == "emulated_primary"
    assert inventory.status == "completed"
    assert inventory.discovered_count == inventory.persisted_count == 3
    assert len(inventory.manifest_hash) == 64
    with database.session() as session:
        job = session.get(JobRecord, job_id)
        items = list(
            session.scalars(
                select(AcquisitionInventoryItemRecord).order_by(
                    AcquisitionInventoryItemRecord.ordinal
                )
            )
        )
        events = JobService().list_events(session, job_id)
        inventories = list(session.scalars(select(AcquisitionInventoryRecord)))
    assert job is not None
    assert job.state == JobState.COMPLETED.value
    assert job.progress_percent == 100
    assert job.result_reference == inventory.id
    assert len(inventories) == 1
    assert [item.relative_path for item in items] == [
        "DCIM/Camera/IMG_0001.jpg",
        "Documents/timeline.csv",
        "Download/incident-notes.pdf",
    ]
    assert all(len(item.path_hash) == 64 for item in items)
    assert [item.extension for item in items] == ["jpg", "csv", "pdf"]
    assert events[-1].state == JobState.COMPLETED.value
    assert events[-1].checkpoint_json is not None


@pytest.mark.asyncio
async def test_plan_without_storage_module_cannot_run_inventory(database: Database) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal, scope=AcquisitionScope.METADATA_ONLY)

    with pytest.raises(AcquisitionInventoryError, match="does not authorize"):
        await AcquisitionInventoryService().run(
            database, principal, case_id, job_id, MockAdbClient()
        )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
    assert job is not None
    assert job.state == JobState.READY.value


@pytest.mark.asyncio
async def test_missing_live_device_fails_job_without_inventory(database: Database) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)

    with pytest.raises(AdbDeviceNotFoundError):
        await AcquisitionInventoryService().run(
            database,
            principal,
            case_id,
            job_id,
            MockAdbClient(MockAdbScenario.NO_DEVICES),
        )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
        inventories = list(session.scalars(select(AcquisitionInventoryRecord)))
    assert job is not None
    assert job.state == JobState.FAILED.value
    assert job.error_code == "DEVICE_NOT_FOUND"
    assert inventories == []


@pytest.mark.asyncio
async def test_live_storage_block_is_recorded_as_failed_revalidation(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)

    with pytest.raises(AcquisitionInventoryError, match="no longer readable"):
        await AcquisitionInventoryService().run(
            database,
            principal,
            case_id,
            job_id,
            MockAdbClient(MockAdbScenario.STORAGE_BLOCKED),
        )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
    assert job is not None
    assert job.state == JobState.FAILED.value
    assert job.error_code == "ACQUISITION_INVENTORY_INVALID"


class ChangedFingerprintClient(MockAdbClient):
    async def get_properties(self, serial: str) -> dict[str, str]:
        properties = await super().get_properties(serial)
        properties["ro.build.fingerprint"] = "changed/build/fingerprint"
        return properties


@pytest.mark.asyncio
async def test_build_fingerprint_change_blocks_inventory(database: Database) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)

    with pytest.raises(DeviceIdentityChangedError):
        await AcquisitionInventoryService().run(
            database, principal, case_id, job_id, ChangedFingerprintClient()
        )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
    assert job is not None
    assert job.error_code == "DEVICE_IDENTITY_CHANGED"


class CancellingInventoryClient(MockAdbClient):
    def __init__(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> None:
        super().__init__()
        self.database = database
        self.principal = principal
        self.case_id = case_id
        self.job_id = job_id

    async def inventory_shared_storage(self, serial, root):  # type: ignore[no-untyped-def]
        with self.database.session() as session:
            AcquisitionExecutionService().cancel(session, self.principal, self.case_id, self.job_id)
        return await super().inventory_shared_storage(serial, root)


@pytest.mark.asyncio
async def test_cancellation_preserves_completed_inventory_metadata(database: Database) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)
    client = CancellingInventoryClient(database, principal, case_id, job_id)

    inventory = await AcquisitionInventoryService().run(
        database, principal, case_id, job_id, client
    )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
    assert job is not None
    assert job.state == JobState.CANCELLED.value
    assert job.result_reference == inventory.id
    assert inventory.persisted_count == 3
