from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_forensic.adb import SharedStorageRootProbe, StorageProbeStatus
from forensix_forensic.capabilities import (
    CapabilityDecision,
    CapabilityStatus,
    DeviceCapabilitySnapshot,
)
from forensix_server.acquisitions import (
    AcquisitionModule,
    AcquisitionPlanService,
    AcquisitionPlanValidationError,
    AcquisitionScope,
    plan_limitations,
    plan_modules,
)
from forensix_server.auth.domain import ROLE_PERMISSIONS, Principal, RoleName
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseAccessDeniedError, CaseAccessLevel, CaseService
from forensix_server.db import CaseEventRecord, Database, UserRecord


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    database = Database(f"sqlite:///{(tmp_path / 'plans.db').as_posix()}", tmp_path)
    database.initialize()
    with database.session() as active_session:
        yield active_session
    database.dispose()


def _identity(session: Session, username: str, role: RoleName) -> tuple[Principal, UserRecord]:
    user = UserRecord(
        username=username,
        display_name=username,
        password_hash="$argon2id$test-placeholder",
    )
    session.add(user)
    session.flush()
    return (
        Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({role}),
            permissions=ROLE_PERMISSIONS[role],
        ),
        user,
    )


def _snapshot(assessed_at: datetime, *, storage_supported: bool = True) -> DeviceCapabilitySnapshot:
    storage_status = CapabilityStatus.SUPPORTED if storage_supported else CapabilityStatus.BLOCKED
    return DeviceCapabilitySnapshot(
        assessed_at=assessed_at,
        serial="FX-DEMO-001",
        manufacturer="ForensiX Labs",
        model="Controlled Test Device",
        android_version="14",
        sdk_level=34,
        build_fingerprint="forensix/test",
        security_patch="2026-07-01",
        package_count=3,
        storage_roots=(
            SharedStorageRootProbe(
                root_id="primary_alias",
                display_path="/sdcard",
                status=(
                    StorageProbeStatus.ACCESSIBLE
                    if storage_supported
                    else StorageProbeStatus.BLOCKED
                ),
                exists=True,
                readable=storage_supported,
                reason_code="ROOT_READABLE" if storage_supported else "ROOT_NOT_READABLE",
            ),
        ),
        capabilities={
            "device_metadata": _decision(CapabilityStatus.SUPPORTED),
            "package_inventory": _decision(CapabilityStatus.SUPPORTED),
            "shared_storage": _decision(storage_status),
        },
        warnings=("Controlled validation snapshot.",),
    )


def _decision(status: CapabilityStatus) -> CapabilityDecision:
    return CapabilityDecision(
        status=status,
        reason_code=f"TEST_{status.value.upper()}",
        explanation="Controlled test decision.",
    )


def _case_device(
    session: Session,
    principal: Principal,
    assessed_at: datetime,
    *,
    storage_supported: bool = True,
):
    case = CaseService().create(session, principal, title="Acquisition planning case")
    device, assessment = CaseDeviceService().register_assessment(
        session,
        principal,
        case.id,
        _snapshot(assessed_at, storage_supported=storage_supported),
    )
    return case, device, assessment


def test_quick_triage_plan_is_frozen_to_exact_readiness_snapshot(session: Session) -> None:
    now = datetime(2026, 7, 15, 10, 0, tzinfo=UTC)
    principal, _ = _identity(session, "plan.owner", RoleName.INVESTIGATOR)
    case, device, assessment = _case_device(session, principal, now)

    plan = AcquisitionPlanService().create(
        session,
        principal,
        case.id,
        device_id=device.id,
        assessment_id=assessment.id,
        scope=AcquisitionScope.QUICK_TRIAGE,
        limitations_acknowledged=True,
        now=now + timedelta(minutes=1),
    )

    assert plan.status == "ready"
    assert plan_modules(plan) == [
        "device_metadata",
        "package_inventory",
        "shared_storage_inventory",
    ]
    assert len(plan.plan_hash) == 64
    assert plan.snapshot_hash == sha256(assessment.snapshot_json.encode()).hexdigest()
    assert any("does not start acquisition" in item for item in plan_limitations(plan))
    event = session.scalar(
        select(CaseEventRecord).where(CaseEventRecord.event_type == "acquisition_plan_created")
    )
    assert event is not None
    assert plan.id in (event.safe_detail or "")


def test_blocked_storage_rejects_quick_triage_but_allows_metadata(session: Session) -> None:
    now = datetime.now(UTC)
    principal, _ = _identity(session, "plan.owner", RoleName.INVESTIGATOR)
    case, device, assessment = _case_device(session, principal, now, storage_supported=False)
    service = AcquisitionPlanService()

    with pytest.raises(AcquisitionPlanValidationError):
        service.create(
            session,
            principal,
            case.id,
            device_id=device.id,
            assessment_id=assessment.id,
            scope=AcquisitionScope.QUICK_TRIAGE,
            limitations_acknowledged=True,
            now=now,
        )
    metadata = service.create(
        session,
        principal,
        case.id,
        device_id=device.id,
        assessment_id=assessment.id,
        scope=AcquisitionScope.METADATA_ONLY,
        limitations_acknowledged=True,
        now=now,
    )
    assert plan_modules(metadata) == ["device_metadata", "package_inventory"]


def test_stale_readiness_snapshot_is_rejected(session: Session) -> None:
    assessed_at = datetime.now(UTC) - timedelta(minutes=31)
    principal, _ = _identity(session, "plan.owner", RoleName.INVESTIGATOR)
    case, device, assessment = _case_device(session, principal, assessed_at)

    with pytest.raises(AcquisitionPlanValidationError, match="stale"):
        AcquisitionPlanService().create(
            session,
            principal,
            case.id,
            device_id=device.id,
            assessment_id=assessment.id,
            scope=AcquisitionScope.METADATA_ONLY,
            limitations_acknowledged=True,
        )


def test_custom_plan_requires_registered_supported_modules(session: Session) -> None:
    now = datetime.now(UTC)
    principal, _ = _identity(session, "plan.owner", RoleName.INVESTIGATOR)
    case, device, assessment = _case_device(session, principal, now)
    service = AcquisitionPlanService()

    with pytest.raises(AcquisitionPlanValidationError, match="at least one"):
        service.create(
            session,
            principal,
            case.id,
            device_id=device.id,
            assessment_id=assessment.id,
            scope=AcquisitionScope.CUSTOM,
            limitations_acknowledged=True,
            now=now,
        )
    custom = service.create(
        session,
        principal,
        case.id,
        device_id=device.id,
        assessment_id=assessment.id,
        scope=AcquisitionScope.CUSTOM,
        requested_modules=(AcquisitionModule.DEVICE_METADATA,),
        limitations_acknowledged=True,
        now=now,
    )
    assert plan_modules(custom) == ["device_metadata"]


def test_case_member_without_acquisition_permission_cannot_plan(session: Session) -> None:
    now = datetime.now(UTC)
    owner, _ = _identity(session, "plan.owner", RoleName.INVESTIGATOR)
    analyst, analyst_user = _identity(session, "plan.analyst", RoleName.ANALYST)
    case, device, assessment = _case_device(session, owner, now)
    CaseService().add_member(
        session,
        owner,
        case.id,
        user_id=analyst_user.id,
        access_level=CaseAccessLevel.ANALYST,
    )

    with pytest.raises(CaseAccessDeniedError):
        AcquisitionPlanService().create(
            session,
            analyst,
            case.id,
            device_id=device.id,
            assessment_id=assessment.id,
            scope=AcquisitionScope.METADATA_ONLY,
            limitations_acknowledged=True,
            now=now,
        )
