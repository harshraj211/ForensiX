from __future__ import annotations

from typing import Any

import pytest

from forensix_forensic.adb import (
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    DeviceState,
    DeviceTransport,
    SharedStorageRootProbe,
    StorageProbeStatus,
)
from forensix_forensic.capabilities import (
    CapabilityStatus,
    DeviceCapabilityAssessor,
)


class MockAdbClient:
    def __init__(
        self,
        serial: str = "FX-TEST-001",
        state: DeviceState = DeviceState.AUTHORIZED,
        properties: dict[str, str] | None = None,
        storage_readable: bool = True,
        shell_responses: dict[str, str] | None = None,
    ) -> None:
        self.serial = serial
        self.state = state
        self.properties = properties or {}
        self.storage_readable = storage_readable
        self.shell_responses = shell_responses or {}

    async def list_transports(self) -> tuple[DeviceTransport, ...]:
        return (
            DeviceTransport(
                serial=self.serial,
                transport_id="1",
                connection_type="usb",
                state=self.state,
                raw_state=self.state.value,
            ),
        )

    async def get_properties(self, serial: str) -> dict[str, str]:
        return self.properties

    async def get_battery(self, serial: str) -> dict[str, str]:
        return {"level": "85", "status": "2"}

    async def list_packages(self, serial: str) -> tuple[str, ...]:
        return ("com.whatsapp", "org.telegram.messenger")

    async def probe_shared_storage(self, serial: str) -> tuple[SharedStorageRootProbe, ...]:
        return (
            SharedStorageRootProbe(
                root_id="primary",
                display_path="/sdcard",
                status=(
                    StorageProbeStatus.ACCESSIBLE
                    if self.storage_readable
                    else StorageProbeStatus.BLOCKED
                ),
                exists=True,
                readable=self.storage_readable,
                reason_code="ROOT_READABLE" if self.storage_readable else "ROOT_BLOCKED",
            ),
        )

    async def probe_content_provider(self, serial: str, profile: Any) -> Any:
        from forensix_forensic.adb import ContentProviderAccessProbe, ContentProviderAccessStatus

        return ContentProviderAccessProbe(
            profile=profile.value if hasattr(profile, "value") else str(profile),
            status=ContentProviderAccessStatus.AVAILABLE,
            reason_code="PROVIDER_AVAILABLE",
            explanation="Test provider available.",
            exit_code=0,
        )

    async def shell(self, serial: str, command: str) -> str:
        for cmd_pattern, response in self.shell_responses.items():
            if cmd_pattern in command:
                return response
        return ""


@pytest.mark.asyncio
async def test_case_a_unlocked_authorized_non_rooted_modern_android_fbe() -> None:
    adb = MockAdbClient(
        serial="FX-CASE-A",
        state=DeviceState.AUTHORIZED,
        properties={
            "ro.product.manufacturer": "Google",
            "ro.product.model": "Pixel 7",
            "ro.build.version.release": "13",
            "ro.build.version.sdk": "33",
            "ro.build.version.security_patch": "2023-08-01",
            "ro.build.fingerprint": (
                "google/panther/panther:13/TQ3A.230805.001/10316531:user/release-keys"
            ),
            "ro.crypto.type": "file",
            "ro.crypto.state": "encrypted",
            "sys.user.0.ce_available": "true",
            "ro.board.platform": "gs201",
            "ro.soc.manufacturer": "Google",
        },
        storage_readable=True,
        shell_responses={"id": "uid=2000(shell) gid=2000(shell)"},
    )

    snapshot = await DeviceCapabilityAssessor(adb).assess("FX-CASE-A")

    assert snapshot.device_state.adb_state == "authorized"
    assert snapshot.device_state.authorization_state == "authorized"
    assert snapshot.device_state.lock_state == "unlocked"
    assert snapshot.device_state.root_state == "non_rooted"
    assert snapshot.device_state.encryption_state == "file_based"

    # Capability decisions
    assert snapshot.capabilities["LOGICAL_AGENT"].status == CapabilityStatus.SUPPORTED
    assert snapshot.capabilities["SHARED_STORAGE"].status == CapabilityStatus.SUPPORTED
    assert snapshot.capabilities["ADB_LOGICAL"].status == CapabilityStatus.SUPPORTED

    # Modern Android blocks APK downgrade
    assert snapshot.capabilities["APK_DOWNGRADE"].status == CapabilityStatus.UNSUPPORTED
    assert "Android 12+" in snapshot.capabilities["APK_DOWNGRADE"].explanation

    # Non-rooted blocks rooted collection
    assert snapshot.capabilities["ROOTED_COLLECTION"].status == CapabilityStatus.UNSUPPORTED

    # Explainability fields
    decision = snapshot.capabilities["LOGICAL_AGENT"]
    assert decision.capability == "LOGICAL_AGENT"
    assert decision.reason == decision.explanation
    assert decision.evidence is not None
    assert decision.limitations is not None


@pytest.mark.asyncio
async def test_case_b_locked_unauthorized_non_rooted_fbe() -> None:
    adb = MockAdbClient(
        serial="FX-CASE-B",
        state=DeviceState.UNAUTHORIZED,
        properties={},
    )

    # Standard call raises AdbDeviceNotAuthorizedError
    with pytest.raises(AdbDeviceNotAuthorizedError):
        await DeviceCapabilityAssessor(adb).assess("FX-CASE-B")

    # Assessment with allow_unauthorized produces snapshot without raising
    snapshot = await DeviceCapabilityAssessor(adb).assess("FX-CASE-B", allow_unauthorized=True)

    assert snapshot.device_state.adb_state == "unauthorized"
    assert snapshot.device_state.authorization_state == "unauthorized"
    assert snapshot.device_state.lock_state == "unknown"
    assert snapshot.device_state.storage_access_state == "inaccessible"

    assert snapshot.capabilities["LOGICAL_AGENT"].status == CapabilityStatus.BLOCKED
    assert snapshot.capabilities["SHARED_STORAGE"].status in (
        CapabilityStatus.BLOCKED,
        CapabilityStatus.UNKNOWN,
    )
    assert snapshot.capabilities["ADB_LOGICAL"].status == CapabilityStatus.BLOCKED
    assert snapshot.capabilities["APK_DOWNGRADE"].status == CapabilityStatus.BLOCKED


@pytest.mark.asyncio
async def test_case_c_unlocked_authorized_rooted() -> None:
    adb = MockAdbClient(
        serial="FX-CASE-C",
        state=DeviceState.AUTHORIZED,
        properties={
            "ro.product.manufacturer": "Google",
            "ro.product.model": "Pixel 4",
            "ro.build.version.release": "11",
            "ro.build.version.sdk": "30",
            "ro.build.version.security_patch": "2021-05-05",
            "ro.crypto.type": "file",
            "sys.user.0.ce_available": "true",
        },
        storage_readable=True,
        shell_responses={"id": "uid=0(root) gid=0(root) groups=0(root)"},
    )

    snapshot = await DeviceCapabilityAssessor(adb).assess("FX-CASE-C")

    assert snapshot.device_state.root_state == "rooted"
    assert snapshot.capabilities["ROOTED_COLLECTION"].status == CapabilityStatus.SUPPORTED
    assert "uid 0" in snapshot.capabilities["ROOTED_COLLECTION"].evidence

    # Legacy Android API 30 allows APK downgrade
    assert snapshot.capabilities["APK_DOWNGRADE"].status == CapabilityStatus.LEGACY_SUPPORTED


@pytest.mark.asyncio
async def test_case_d_missing_or_malformed_getprop() -> None:
    adb = MockAdbClient(
        serial="FX-CASE-D",
        state=DeviceState.AUTHORIZED,
        properties={
            "ro.build.version.sdk": "invalid_sdk",
        },
    )

    snapshot = await DeviceCapabilityAssessor(adb).assess("FX-CASE-D")

    assert snapshot.sdk_level is None
    assert snapshot.device_state.encryption_state == "unknown"
    assert snapshot.capabilities["APK_DOWNGRADE"].status == CapabilityStatus.UNKNOWN
    assert snapshot.capabilities["PHYSICAL_ACQUISITION"].status == CapabilityStatus.UNKNOWN


@pytest.mark.asyncio
async def test_case_e_accessibility_authorization_unavailable() -> None:
    adb = MockAdbClient(
        serial="FX-CASE-E",
        state=DeviceState.AUTHORIZED,
        properties={
            "ro.build.version.sdk": "31",
            "ro.build.version.release": "12",
        },
        shell_responses={
            "settings get secure enabled_accessibility_services": "com.example.other/Service"
        },
    )

    snapshot = await DeviceCapabilityAssessor(adb).assess("FX-CASE-E")

    assert snapshot.device_state.accessibility_state == "installed_unauthorized"
    assert snapshot.capabilities["ACCESSIBILITY_COLLECTION"].status == CapabilityStatus.UNSUPPORTED
    assert "not been granted" in snapshot.capabilities["ACCESSIBILITY_COLLECTION"].explanation


@pytest.mark.asyncio
async def test_device_not_found_raises() -> None:
    adb = MockAdbClient(serial="FX-OTHER")
    with pytest.raises(AdbDeviceNotFoundError):
        await DeviceCapabilityAssessor(adb).assess("FX-MISSING")
