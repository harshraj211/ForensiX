from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_forensic.capabilities import (
    CapabilityDecision,
    CapabilityStatus,
    DeviceCapabilitySnapshot,
)
from forensix_server.auth.domain import ROLE_PERMISSIONS, Principal, RoleName
from forensix_server.case_devices import CaseDeviceNotFoundError, CaseDeviceService
from forensix_server.cases import (
    CaseAccessDeniedError,
    CaseInvalidStateError,
    CaseService,
    CaseStatus,
)
from forensix_server.db import CaseDeviceAssessmentRecord, CaseEventRecord, Database, UserRecord


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    database = Database(f"sqlite:///{(tmp_path / 'case-devices.db').as_posix()}", tmp_path)
    database.initialize()
    with database.session() as active_session:
        yield active_session
    database.dispose()


def _identity(session: Session, username: str, role: RoleName) -> Principal:
    user = UserRecord(
        username=username,
        display_name=username,
        password_hash="$argon2id$test-placeholder",
    )
    session.add(user)
    session.flush()
    return Principal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        roles=frozenset({role}),
        permissions=ROLE_PERMISSIONS[role],
    )


def _snapshot(serial: str = "FX-DEMO-001") -> DeviceCapabilitySnapshot:
    return DeviceCapabilitySnapshot(
        assessed_at=datetime(2026, 7, 15, 8, 30, tzinfo=UTC),
        serial=serial,
        manufacturer="ForensiX Labs",
        model="Controlled Test Device",
        android_version="14",
        sdk_level=34,
        build_fingerprint="forensix/test/device:14/TEST:userdebug/test-keys",
        security_patch="2026-06-01",
        package_count=12,
        capabilities={
            "shared_storage": CapabilityDecision(
                status=CapabilityStatus.SUPPORTED,
                reason_code="ACCESSIBLE",
                explanation="Shared storage can be enumerated.",
            )
        },
        warnings=("Private application data is not accessible.",),
    )


def test_assessment_registers_stable_device_without_raw_serial(session: Session) -> None:
    principal = _identity(session, "device.owner", RoleName.INVESTIGATOR)
    case = CaseService().create(session, principal, title="Device case")
    service = CaseDeviceService()

    first_device, first = service.register_assessment(session, principal, case.id, _snapshot())
    second_device, second = service.register_assessment(session, principal, case.id, _snapshot())

    assert first_device.id == second_device.id
    assert first.id != second.id
    assert first_device.serial_hash != "FX-DEMO-001"
    assert first_device.serial_suffix == "O-001"
    assert "FX-DEMO-001" not in first.snapshot_json
    assert len(service.list_assessments(session, principal, case.id, first_device.id)) == 2
    persisted = list(session.scalars(select(CaseDeviceAssessmentRecord)))
    assert len(persisted) == 2
    event_types = set(session.scalars(select(CaseEventRecord.event_type)))
    assert "device_assessed" in event_types


def test_detection_is_case_scoped_and_append_only(session: Session) -> None:
    principal = _identity(session, "device.owner", RoleName.INVESTIGATOR)
    case = CaseService().create(session, principal, title="Detection case")

    detection = CaseDeviceService().record_detection(
        session,
        principal,
        case.id,
        observed_at=datetime.now(UTC),
        adb_version="1.0.41",
        device_count=1,
        result="single_device",
    )

    assert detection.case_id == case.id
    assert detection.operator_id == principal.user_id


def test_nonmember_and_nonoperator_cannot_register_assessment(session: Session) -> None:
    owner = _identity(session, "device.owner", RoleName.INVESTIGATOR)
    outsider = _identity(session, "device.outsider", RoleName.INVESTIGATOR)
    reviewer = _identity(session, "device.reviewer", RoleName.REVIEWER)
    case = CaseService().create(session, owner, title="Restricted device case")

    with pytest.raises(CaseAccessDeniedError):
        CaseDeviceService().register_assessment(session, outsider, case.id, _snapshot())
    with pytest.raises(CaseAccessDeniedError):
        CaseDeviceService().register_assessment(session, reviewer, case.id, _snapshot())


def test_closed_case_rejects_new_device_operations(session: Session) -> None:
    principal = _identity(session, "device.owner", RoleName.INVESTIGATOR)
    case = CaseService().create(session, principal, title="Closed device case")
    CaseService().transition(
        session,
        principal,
        case.id,
        requested=CaseStatus.CLOSED,
        expected_version=case.version,
    )

    with pytest.raises(CaseInvalidStateError):
        CaseDeviceService().register_assessment(session, principal, case.id, _snapshot())


def test_device_lookup_cannot_cross_case_boundary(session: Session) -> None:
    principal = _identity(session, "device.owner", RoleName.INVESTIGATOR)
    first_case = CaseService().create(session, principal, title="First case")
    second_case = CaseService().create(session, principal, title="Second case")
    device, _ = CaseDeviceService().register_assessment(
        session, principal, first_case.id, _snapshot()
    )

    with pytest.raises(CaseDeviceNotFoundError):
        CaseDeviceService().get_device(session, principal, second_case.id, device.id)
