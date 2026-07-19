import tarfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select

from forensix_forensic.adb import (
    MockAdbClient,
    MockAdbScenario,
    PhysicalBlockProfile,
    RootedCollectionProfile,
)
from forensix_forensic.capabilities import DeviceCapabilityAssessor
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseService
from forensix_server.config import Settings
from forensix_server.db import (
    AuditLogRecord,
    CustodyEventRecord,
    Database,
    PhysicalBlockProbeRecord,
    RootAccessProbeRecord,
    UserRecord,
)
from forensix_server.rooted import RootedDeviceError, RootedDeviceService


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'rooted.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


async def _case_device(database: Database) -> tuple[Principal, str, str]:
    with database.session() as session:
        user = UserRecord(
            username="root.examiner",
            display_name="Root Examiner",
            password_hash="$argon2id$test-placeholder",
        )
        session.add(user)
        session.flush()
        principal = Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({RoleName.INVESTIGATOR}),
            permissions=ROLE_PERMISSIONS[RoleName.INVESTIGATOR],
        )
        case_id = CaseService().create(session, principal, title="Rooted case").id
    snapshot = await DeviceCapabilityAssessor(MockAdbClient(MockAdbScenario.ROOTED)).assess(
        "FX-DEMO-001"
    )
    with database.session() as session:
        device, _ = CaseDeviceService().register_assessment(session, principal, case_id, snapshot)
        return principal, case_id, device.id


@pytest.mark.asyncio
async def test_explicit_root_probe_is_case_bound_expiring_and_audited(database: Database) -> None:
    principal, case_id, device_id = await _case_device(database)

    probe = await RootedDeviceService().probe_access(
        database,
        MockAdbClient(MockAdbScenario.ROOTED),
        principal,
        case_id,
        device_id,
        serial="FX-DEMO-001",
    )

    assert probe.status == "available"
    assert probe.uid == 0
    assert probe.expires_at > probe.probed_at
    assert len(probe.probe_hash) == 64
    assert "Invoking su" not in probe.potential_side_effect
    with database.session() as session:
        assert session.scalar(select(RootAccessProbeRecord.id)) == probe.id
        audit = session.scalar(
            select(AuditLogRecord).where(AuditLogRecord.event_type == "root_access_probed")
        )
    assert audit is not None
    assert "FX-DEMO-001" not in audit.detail_json


@pytest.mark.asyncio
async def test_root_probe_rejects_transport_not_bound_to_case_device(database: Database) -> None:
    principal, case_id, device_id = await _case_device(database)

    with pytest.raises(RootedDeviceError, match="does not match"):
        await RootedDeviceService().probe_access(
            database,
            MockAdbClient(MockAdbScenario.ROOTED),
            principal,
            case_id,
            device_id,
            serial="DIFFERENT-DEVICE",
        )


@pytest.mark.asyncio
async def test_rooted_provider_capture_is_sealed_case_evidence(database: Database) -> None:
    principal, case_id, device_id = await _case_device(database)
    adb_client = MockAdbClient(MockAdbScenario.ROOTED)
    service = RootedDeviceService()
    probe = await service.probe_access(
        database,
        adb_client,
        principal,
        case_id,
        device_id,
        serial="FX-DEMO-001",
    )

    source = await service.capture_provider_bundle(
        database,
        adb_client,
        principal,
        case_id,
        device_id,
        serial="FX-DEMO-001",
        probe_id=probe.id,
        profile=RootedCollectionProfile.ANDROID_PROVIDERS,
        side_effects_acknowledged=True,
    )

    assert source.source_type == "rooted_filesystem"
    assert source.acquisition_level == "filesystem"
    assert source.device_id == device_id
    assert source.status == "sealed"
    assert source.container_format == "tar"
    assert source.sha256 is not None
    assert source.sealed_storage_key is not None
    master = EvidenceStore(database.data_dir / "evidence").resolve(
        source.sealed_storage_key, require_file=True
    )
    with tarfile.open(master, "r:") as archive:
        assert any(name.endswith("contacts2.db") for name in archive.getnames())
    with database.session() as session:
        audits = list(
            session.scalars(
                select(AuditLogRecord).where(
                    AuditLogRecord.event_type == "rooted_provider_bundle_captured"
                )
            )
        )
        custody = list(
            session.scalars(
                select(CustodyEventRecord).where(
                    CustodyEventRecord.evidence_source_id == source.id
                )
            )
        )
    assert len(audits) == 1
    assert "FX-DEMO-001" not in audits[0].detail_json
    assert custody


@pytest.mark.asyncio
async def test_rooted_capture_requires_acknowledgement(database: Database) -> None:
    principal, case_id, device_id = await _case_device(database)

    with pytest.raises(RootedDeviceError, match="acknowledged"):
        await RootedDeviceService().capture_provider_bundle(
            database,
            MockAdbClient(MockAdbScenario.ROOTED),
            principal,
            case_id,
            device_id,
            serial="FX-DEMO-001",
            probe_id="00000000-0000-0000-0000-000000000000",
            profile=RootedCollectionProfile.ANDROID_PROVIDERS,
            side_effects_acknowledged=False,
        )


@pytest.mark.asyncio
async def test_experimental_physical_capture_is_probed_gated_and_sealed(
    database: Database,
) -> None:
    principal, case_id, device_id = await _case_device(database)
    adb_client = MockAdbClient(MockAdbScenario.ROOTED)
    service = RootedDeviceService()
    settings = Settings(
        environment="test",
        data_dir=database.data_dir,
        enable_experimental_physical_acquisition=True,
        max_physical_acquisition_bytes=1024 * 1024,
    )
    root_probe = await service.probe_access(
        database,
        adb_client,
        principal,
        case_id,
        device_id,
        serial="FX-DEMO-001",
    )
    block_probe = await service.probe_physical_block(
        database,
        adb_client,
        settings,
        principal,
        case_id,
        device_id,
        serial="FX-DEMO-001",
        root_probe_id=root_probe.id,
        profile=PhysicalBlockProfile.USERDATA_BY_NAME,
        risk_acknowledged=True,
    )

    source = await service.capture_physical_block(
        database,
        adb_client,
        settings,
        principal,
        case_id,
        device_id,
        serial="FX-DEMO-001",
        physical_probe_id=block_probe.id,
        acquisition_acknowledged=True,
        encryption_acknowledged=True,
        non_resumable_acknowledged=True,
    )

    assert block_probe.size_bytes == 8192
    assert block_probe.device_path == "/dev/block/by-name/userdata"
    assert source.source_type == "physical_block"
    assert source.acquisition_level == "physical"
    assert source.container_format == "dd"
    assert source.size_bytes == 8192
    assert source.device_id == device_id
    with database.session() as session:
        assert session.scalar(select(PhysicalBlockProbeRecord.id)) == block_probe.id
        audit_types = set(session.scalars(select(AuditLogRecord.event_type)))
    assert "experimental_physical_block_probed" in audit_types
    assert "experimental_physical_block_captured" in audit_types


@pytest.mark.asyncio
async def test_physical_probe_is_disabled_by_default(database: Database) -> None:
    principal, case_id, device_id = await _case_device(database)

    with pytest.raises(RootedDeviceError, match="disabled"):
        await RootedDeviceService().probe_physical_block(
            database,
            MockAdbClient(MockAdbScenario.ROOTED),
            Settings(environment="test", data_dir=database.data_dir),
            principal,
            case_id,
            device_id,
            serial="FX-DEMO-001",
            root_probe_id="00000000-0000-0000-0000-000000000000",
            profile=PhysicalBlockProfile.USERDATA_BY_NAME,
            risk_acknowledged=True,
        )
