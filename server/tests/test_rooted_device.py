from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select

from forensix_forensic.adb import MockAdbClient, MockAdbScenario
from forensix_forensic.capabilities import DeviceCapabilityAssessor
from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseService
from forensix_server.db import AuditLogRecord, Database, RootAccessProbeRecord, UserRecord
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
