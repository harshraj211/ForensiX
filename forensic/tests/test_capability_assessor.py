import pytest

from forensix_forensic.adb import (
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    MockAdbClient,
    MockAdbScenario,
)
from forensix_forensic.capabilities import CapabilityStatus, DeviceCapabilityAssessor


@pytest.mark.asyncio
async def test_authorized_capability_snapshot_is_explicit() -> None:
    snapshot = await DeviceCapabilityAssessor(MockAdbClient()).assess("FX-DEMO-001")

    assert snapshot.android_version == "14"
    assert snapshot.sdk_level == 34
    assert snapshot.package_count == 3
    assert snapshot.capabilities["device_metadata"].status is CapabilityStatus.SUPPORTED
    assert snapshot.capabilities["shared_storage"].status is CapabilityStatus.UNKNOWN
    assert snapshot.capabilities["private_app_data"].status is CapabilityStatus.UNSUPPORTED
    assert snapshot.warnings


@pytest.mark.asyncio
async def test_assessor_revalidates_authorization() -> None:
    assessor = DeviceCapabilityAssessor(MockAdbClient(MockAdbScenario.UNAUTHORIZED))

    with pytest.raises(AdbDeviceNotAuthorizedError):
        await assessor.assess("FX-DEMO-001")


@pytest.mark.asyncio
async def test_assessor_rejects_stale_serial() -> None:
    with pytest.raises(AdbDeviceNotFoundError):
        await DeviceCapabilityAssessor(MockAdbClient()).assess("STALE-SERIAL")
