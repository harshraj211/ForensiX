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
    assert snapshot.capabilities["shared_storage"].status is CapabilityStatus.SUPPORTED
    assert len(snapshot.storage_roots) == 2
    assert all(root.readable for root in snapshot.storage_roots)
    assert snapshot.capabilities["private_app_data"].status is CapabilityStatus.UNSUPPORTED
    assert snapshot.capabilities["media_files"].status is CapabilityStatus.SUPPORTED
    assert snapshot.capabilities["download_files"].status is CapabilityStatus.SUPPORTED
    for capability in (
        "contacts",
        "sms_mms",
        "call_logs",
        "calendar",
        "notifications",
        "wifi_records",
        "bluetooth_records",
        "location_artifacts",
        "browser_history",
        "whatsapp_private_data",
        "telegram_private_data",
        "signal_private_data",
        "messenger_private_data",
        "instagram_private_data",
        "facebook_private_data",
        "snapchat_private_data",
    ):
        assert snapshot.capabilities[capability].status is CapabilityStatus.UNSUPPORTED
        assert snapshot.capabilities[capability].reason_code
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


@pytest.mark.asyncio
async def test_storage_probe_can_explicitly_block_shared_storage() -> None:
    snapshot = await DeviceCapabilityAssessor(
        MockAdbClient(MockAdbScenario.STORAGE_BLOCKED)
    ).assess("FX-DEMO-001")

    assert snapshot.capabilities["shared_storage"].status is CapabilityStatus.BLOCKED
    assert snapshot.capabilities["media_files"].status is CapabilityStatus.BLOCKED
    assert snapshot.capabilities["document_files"].status is CapabilityStatus.BLOCKED
    assert not any(root.readable for root in snapshot.storage_roots)
