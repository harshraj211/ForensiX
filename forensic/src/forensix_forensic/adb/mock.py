"""Deterministic ADB scenarios for development and acceptance tests."""

from enum import StrEnum

from .errors import AdbTimeoutError
from .models import (
    AdbServerInfo,
    DeviceState,
    DeviceTransport,
    SharedStorageRootProbe,
    StorageInventoryEntry,
    StorageInventoryResult,
    StorageProbeStatus,
)
from .policy import INVENTORY_MAX_DEPTH, INVENTORY_MAX_ITEMS, AdbCommandPolicy, SharedStorageRoot


class MockAdbScenario(StrEnum):
    NO_DEVICES = "no_devices"
    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    OFFLINE = "offline"
    MULTIPLE = "multiple"
    TIMEOUT = "timeout"
    STORAGE_BLOCKED = "storage_blocked"


class MockAdbClient:
    def __init__(self, scenario: MockAdbScenario = MockAdbScenario.AUTHORIZED) -> None:
        self.scenario = scenario

    async def server_info(self) -> AdbServerInfo:
        if self.scenario is MockAdbScenario.TIMEOUT:
            raise AdbTimeoutError(5.0)
        return AdbServerInfo(
            version="1.0.41",
            executable_path="mock://adb",
            raw_output="Android Debug Bridge version 1.0.41",
        )

    async def list_transports(self) -> tuple[DeviceTransport, ...]:
        if self.scenario is MockAdbScenario.TIMEOUT:
            raise AdbTimeoutError(5.0)
        if self.scenario is MockAdbScenario.NO_DEVICES:
            return ()
        if self.scenario is MockAdbScenario.MULTIPLE:
            return (
                self._transport("FX-DEMO-001", DeviceState.AUTHORIZED),
                self._transport("FX-DEMO-002", DeviceState.UNAUTHORIZED),
            )
        state = {
            MockAdbScenario.AUTHORIZED: DeviceState.AUTHORIZED,
            MockAdbScenario.UNAUTHORIZED: DeviceState.UNAUTHORIZED,
            MockAdbScenario.OFFLINE: DeviceState.OFFLINE,
            MockAdbScenario.STORAGE_BLOCKED: DeviceState.AUTHORIZED,
        }[self.scenario]
        return (self._transport("FX-DEMO-001", state),)

    async def get_properties(self, serial: str) -> dict[str, str]:
        await self._require_authorized(serial)
        return {
            "ro.product.manufacturer": "ForensiX Labs",
            "ro.product.model": "Controlled Test Device",
            "ro.build.version.release": "14",
            "ro.build.version.sdk": "34",
            "ro.build.fingerprint": "forensix/demo/fx_virtual:14/TEST/001:user/test-keys",
            "ro.build.version.security_patch": "2026-07-01",
        }

    async def list_packages(self, serial: str) -> tuple[str, ...]:
        await self._require_authorized(serial)
        return (
            "android",
            "com.android.settings",
            "org.forensix.synthetic.fixture",
        )

    async def probe_shared_storage(self, serial: str) -> tuple[SharedStorageRootProbe, ...]:
        await self._require_authorized(serial)
        accessible = self.scenario is not MockAdbScenario.STORAGE_BLOCKED
        return tuple(
            SharedStorageRootProbe(
                root_id=root_id,
                display_path=display_path,
                status=(
                    StorageProbeStatus.ACCESSIBLE if accessible else StorageProbeStatus.BLOCKED
                ),
                exists=True,
                readable=accessible,
                reason_code="ROOT_READABLE" if accessible else "ROOT_NOT_READABLE",
            )
            for root_id, display_path in (
                ("primary_alias", "/sdcard"),
                ("emulated_primary", "/storage/emulated/0"),
            )
        )

    async def inventory_shared_storage(
        self, serial: str, root: SharedStorageRoot
    ) -> StorageInventoryResult:
        await self._require_authorized(serial)
        return StorageInventoryResult(
            root_id=root.value,
            display_path=AdbCommandPolicy.display_path(root),
            entries=tuple(
                StorageInventoryEntry(relative_path=path)
                for path in (
                    "DCIM/Camera/IMG_0001.jpg",
                    "Documents/timeline.csv",
                    "Download/incident-notes.pdf",
                )
            ),
            discovered_count=3,
            skipped_count=0,
            truncated=False,
            max_items=INVENTORY_MAX_ITEMS,
            max_depth=INVENTORY_MAX_DEPTH,
        )

    async def _require_authorized(self, serial: str) -> DeviceTransport:
        from .errors import AdbDeviceNotAuthorizedError, AdbDeviceNotFoundError

        transports = await self.list_transports()
        transport = next((item for item in transports if item.serial == serial), None)
        if transport is None:
            raise AdbDeviceNotFoundError
        if transport.state is not DeviceState.AUTHORIZED:
            raise AdbDeviceNotAuthorizedError(transport.state.value)
        return transport

    @staticmethod
    def _transport(serial: str, state: DeviceState) -> DeviceTransport:
        raw_state = "device" if state is DeviceState.AUTHORIZED else state.value
        return DeviceTransport(
            serial=serial,
            state=state,
            raw_state=raw_state,
            product="forensix_demo",
            model="Controlled_Test_Device",
            device="fx_virtual",
            transport_id="1",
            usb="1-1",
        )
