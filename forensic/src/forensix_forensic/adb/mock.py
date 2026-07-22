"""Deterministic ADB scenarios for development and acceptance tests."""

import asyncio
import io
import tarfile
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .errors import AdbCommandError, AdbTimeoutError
from .models import (
    AdbServerInfo,
    ContentProviderAccessProbe,
    ContentProviderAccessStatus,
    ContentProviderQueryResult,
    ContentProviderRecord,
    DeviceState,
    DeviceTransport,
    PhysicalBlockCaptureResult,
    PhysicalBlockProbe,
    PulledFileResult,
    RootAccessProbe,
    RootAccessStatus,
    RootedBundleResult,
    SharedStorageRootProbe,
    StorageInventoryEntry,
    StorageInventoryResult,
    StorageProbeStatus,
)
from .policy import (
    CONTENT_PROVIDER_MAX_RECORDS,
    INVENTORY_MAX_DEPTH,
    INVENTORY_MAX_ITEMS,
    AdbCommandPolicy,
    ContentProviderProfile,
    PhysicalBlockProfile,
    RootedCollectionProfile,
    SharedStorageRoot,
)
from .validation_fixture import (
    KNOWN_FILE_RELATIVE_PATH,
    KNOWN_FILE_SIZE_BYTES,
    known_file_payload,
)


class MockAdbScenario(StrEnum):
    NO_DEVICES = "no_devices"
    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    OFFLINE = "offline"
    MULTIPLE = "multiple"
    TIMEOUT = "timeout"
    STORAGE_BLOCKED = "storage_blocked"
    ROOTED = "rooted"
    PROVIDERS_ACCESSIBLE = "providers_accessible"


class MockAdbClient:
    def __init__(
        self,
        scenario: MockAdbScenario = MockAdbScenario.AUTHORIZED,
        *,
        include_validation_fixture: bool = False,
    ) -> None:
        self.scenario = scenario
        self.include_validation_fixture = include_validation_fixture

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
            MockAdbScenario.ROOTED: DeviceState.AUTHORIZED,
            MockAdbScenario.PROVIDERS_ACCESSIBLE: DeviceState.AUTHORIZED,
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

    async def probe_content_provider(
        self, serial: str, profile: ContentProviderProfile
    ) -> ContentProviderAccessProbe:
        await self._require_authorized(serial)
        available = self.scenario is MockAdbScenario.PROVIDERS_ACCESSIBLE
        return ContentProviderAccessProbe(
            profile=profile.value,
            status=(
                ContentProviderAccessStatus.AVAILABLE
                if available
                else ContentProviderAccessStatus.DENIED
            ),
            reason_code=(
                "CONTENT_PROVIDER_QUERY_ALLOWED"
                if available
                else "CONTENT_PROVIDER_PERMISSION_DENIED"
            ),
            explanation=(
                "Synthetic provider access is available."
                if available
                else "Synthetic Android permission denial."
            ),
            exit_code=0 if available else 1,
        )

    async def query_content_provider(
        self, serial: str, profile: ContentProviderProfile
    ) -> ContentProviderQueryResult:
        probe = await self.probe_content_provider(serial, profile)
        if probe.status is not ContentProviderAccessStatus.AVAILABLE:
            raise AdbCommandError(1, "Synthetic provider access was denied.")
        fixtures: dict[ContentProviderProfile, tuple[dict[str, str | None], ...]] = {
            ContentProviderProfile.CONTACTS: (
                {
                    "_id": "1",
                    "has_phone_number": "1",
                    "last_time_contacted": "1784160000000",
                    "display_name": "Controlled Contact",
                },
            ),
            ContentProviderProfile.SMS: (
                {
                    "_id": "1",
                    "thread_id": "1",
                    "address": "+15550100",
                    "date": "1784160000000",
                    "date_sent": "1784160000000",
                    "type": "1",
                    "read": "1",
                    "body": "Controlled SMS fixture",
                },
            ),
            ContentProviderProfile.CALL_LOG: (
                {
                    "_id": "1",
                    "number": "+15550100",
                    "date": "1784160000000",
                    "duration": "42",
                    "type": "1",
                    "name": "Controlled Contact",
                },
            ),
        }
        records = tuple(ContentProviderRecord(values=item) for item in fixtures[profile])
        return ContentProviderQueryResult(
            profile=profile.value,
            records=records,
            discovered_count=len(records),
            truncated=False,
            max_records=CONTENT_PROVIDER_MAX_RECORDS,
        )

    async def probe_root_access(self, serial: str) -> RootAccessProbe:
        await self._require_authorized(serial)
        available = self.scenario is MockAdbScenario.ROOTED
        return RootAccessProbe(
            status=(RootAccessStatus.AVAILABLE if available else RootAccessStatus.UNAVAILABLE),
            uid=0 if available else None,
            identity="uid=0(root) gid=0(root)" if available else None,
            reason_code="ROOT_UID_CONFIRMED" if available else "ROOT_UID_NOT_AVAILABLE",
            potential_side_effect="Synthetic mock root probe; no device operation occurred.",
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
        entries = [
            ("DCIM/Camera/IMG_0001.jpg", 33, "1784160000"),
            ("Documents/timeline.csv", 42, "1784246400"),
            ("Download/incident-notes.pdf", 38, "1784332800"),
        ]
        if self.include_validation_fixture:
            entries.append((KNOWN_FILE_RELATIVE_PATH, KNOWN_FILE_SIZE_BYTES, "1784419200"))
        return StorageInventoryResult(
            root_id=root.value,
            display_path=AdbCommandPolicy.display_path(root),
            entries=tuple(
                StorageInventoryEntry(
                    relative_path=path,
                    size_bytes=size_bytes,
                    modified_time_raw=epoch,
                    modified_at=datetime.fromtimestamp(int(epoch), tz=UTC),
                    timestamp_source="android_stat_mtime_epoch",
                    timestamp_confidence="medium",
                )
                for path, size_bytes, epoch in entries
            ),
            discovered_count=len(entries),
            skipped_count=0,
            truncated=False,
            max_items=INVENTORY_MAX_ITEMS,
            max_depth=INVENTORY_MAX_DEPTH,
        )

    async def pull_inventory_file(
        self,
        serial: str,
        root: SharedStorageRoot,
        relative_path: str,
        destination: Path,
    ) -> PulledFileResult:
        await self._require_authorized(serial)
        AdbCommandPolicy.pull_inventory_file(serial, root, relative_path, destination)
        fixtures = {
            "DCIM/Camera/IMG_0001.jpg": b"ForensiX synthetic JPEG fixture\x00\x01",
            "Documents/timeline.csv": b"timestamp,event\n2026-07-16T00:00:00Z,test\n",
            "Download/incident-notes.pdf": b"%PDF-1.4\n% ForensiX synthetic fixture\n",
            KNOWN_FILE_RELATIVE_PATH: known_file_payload(),
        }
        payload = fixtures.get(relative_path)
        if payload is None:
            raise AdbCommandError(1, "The selected mock inventory file is unavailable.")
        await asyncio.to_thread(destination.write_bytes, payload)
        return PulledFileResult(
            root_id=root.value,
            relative_path=relative_path,
            size_bytes=len(payload),
        )

    async def capture_rooted_bundle(
        self,
        serial: str,
        profile: RootedCollectionProfile,
        destination: Path,
    ) -> RootedBundleResult:
        await self._require_authorized(serial)
        if self.scenario is not MockAdbScenario.ROOTED:
            raise AdbCommandError(1, "Root UID is unavailable in this mock scenario.")
        AdbCommandPolicy.capture_rooted_bundle(serial, profile)
        await asyncio.to_thread(_write_rooted_fixture_bundle, destination, profile)
        size_bytes = await asyncio.to_thread(lambda: destination.stat().st_size)
        return RootedBundleResult(profile=profile.value, size_bytes=size_bytes)

    async def probe_physical_block(
        self, serial: str, profile: PhysicalBlockProfile
    ) -> PhysicalBlockProbe:
        await self._require_authorized(serial)
        if self.scenario is not MockAdbScenario.ROOTED:
            raise AdbCommandError(1, "Root UID is unavailable in this mock scenario.")
        return PhysicalBlockProbe(
            profile=profile.value,
            device_path=AdbCommandPolicy.physical_block_path(profile),
            size_bytes=8192,
            encryption_state="unknown",
        )

    async def capture_physical_block(
        self,
        serial: str,
        profile: PhysicalBlockProfile,
        destination: Path,
        *,
        expected_size_bytes: int,
    ) -> PhysicalBlockCaptureResult:
        await self._require_authorized(serial)
        if self.scenario is not MockAdbScenario.ROOTED:
            raise AdbCommandError(1, "Root UID is unavailable in this mock scenario.")
        if expected_size_bytes != 8192:
            raise AdbCommandError(1, "The synthetic block size does not match its probe.")
        AdbCommandPolicy.capture_physical_block(serial, profile)
        payload = bytes(range(256)) * 32
        await asyncio.to_thread(destination.write_bytes, payload)
        return PhysicalBlockCaptureResult(profile=profile.value, size_bytes=len(payload))

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


def _write_rooted_fixture_bundle(destination: Path, profile: RootedCollectionProfile) -> None:
    if profile is RootedCollectionProfile.ANDROID_PROVIDERS:
        fixtures = {
            "data/user_de/0/com.android.providers.contacts/databases/contacts2.db": (
                b"SQLite format 3\x00ForensiX synthetic contacts provider fixture"
            ),
            "data/user_de/0/com.android.providers.telephony/databases/mmssms.db": (
                b"SQLite format 3\x00ForensiX synthetic telephony provider fixture"
            ),
        }
    else:
        fixtures = {
            "data/user_de/0/com.android.providers.downloads/databases/downloads.db": (
                b"SQLite format 3\x00ForensiX synthetic downloads provider fixture"
            ),
            "data/system/users/0/settings_secure.xml": (
                b"<?xml version='1.0'?><settings version='1'/>"
            ),
            "data/misc/apexdata/com.android.wifi/WifiConfigStore.xml": (
                b"<?xml version='1.0'?><WifiConfigStoreData/>"
            ),
        }
    with destination.open("xb") as output, tarfile.open(fileobj=output, mode="w|") as archive:
        for member_name, payload in fixtures.items():
            metadata = tarfile.TarInfo(member_name)
            metadata.size = len(payload)
            metadata.mode = 0o400
            metadata.mtime = 0
            archive.addfile(metadata, io.BytesIO(payload))
