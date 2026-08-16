"""High-level ADB client limited to registered forensic operations."""

import asyncio
import re
from pathlib import Path
from typing import Protocol

from .errors import AdbCommandError
from .models import (
    AdbServerInfo,
    BackupResult,
    ContentProviderAccessProbe,
    ContentProviderAccessStatus,
    ContentProviderQueryResult,
    DeviceTransport,
    PhysicalBlockCaptureResult,
    PhysicalBlockProbe,
    PulledFileResult,
    RootAccessProbe,
    RootAccessStatus,
    RootedBundleResult,
    ScreenshotCaptureResult,
    SharedStorageRootProbe,
    StorageInventoryResult,
    StorageProbeStatus,
)
from .parser import (
    parse_adb_version,
    parse_content_provider_rows,
    parse_devices_output,
    parse_getprop_output,
    parse_package_list,
    parse_storage_inventory,
)
from .policy import (
    CONTENT_PROVIDER_MAX_RECORDS,
    INVENTORY_MAX_DEPTH,
    INVENTORY_MAX_ITEMS,
    MAX_ACQUIRED_FILE_BYTES,
    MAX_BACKUP_FILE_BYTES,
    MAX_PACKAGE_APK_BYTES,
    MAX_PHYSICAL_BLOCK_BYTES,
    MAX_ROOTED_BUNDLE_BYTES,
    MAX_SCREENSHOT_BYTES,
    AdbCommandPolicy,
    ApprovedAdbCommand,
    ContentProviderProfile,
    PhysicalBlockProfile,
    RootedCollectionProfile,
    SharedStorageRoot,
)
from .runner import AdbCommandResult, SubprocessAdbRunner


class AdbClient(Protocol):
    async def server_info(self) -> AdbServerInfo: ...

    async def list_transports(self) -> tuple[DeviceTransport, ...]: ...

    async def get_properties(self, serial: str) -> dict[str, str]: ...

    async def get_kernel_version(self, serial: str) -> str: ...

    async def get_battery(self, serial: str) -> dict[str, str]: ...

    async def list_packages(self, serial: str) -> tuple[str, ...]: ...

    async def probe_content_provider(
        self, serial: str, profile: ContentProviderProfile
    ) -> ContentProviderAccessProbe: ...

    async def query_content_provider(
        self, serial: str, profile: ContentProviderProfile
    ) -> ContentProviderQueryResult: ...

    async def capture_screenshot(
        self, serial: str, destination: Path
    ) -> ScreenshotCaptureResult: ...

    async def probe_root_access(self, serial: str) -> RootAccessProbe: ...

    async def probe_shared_storage(self, serial: str) -> tuple[SharedStorageRootProbe, ...]: ...

    async def inventory_shared_storage(
        self, serial: str, root: SharedStorageRoot
    ) -> StorageInventoryResult: ...

    async def pull_inventory_file(
        self,
        serial: str,
        root: SharedStorageRoot,
        relative_path: str,
        destination: Path,
    ) -> PulledFileResult: ...

    async def capture_rooted_bundle(
        self,
        serial: str,
        profile: RootedCollectionProfile,
        destination: Path,
    ) -> RootedBundleResult: ...

    async def probe_physical_block(
        self, serial: str, profile: PhysicalBlockProfile
    ) -> PhysicalBlockProbe: ...

    async def capture_physical_block(
        self,
        serial: str,
        profile: PhysicalBlockProfile,
        destination: Path,
        *,
        expected_size_bytes: int,
    ) -> PhysicalBlockCaptureResult: ...

    async def dump_package(self, serial: str, package_name: str) -> str: ...

    async def backup_package(
        self, serial: str, package_name: str, destination: Path
    ) -> BackupResult: ...

    async def install_package(self, serial: str, apk_path: str) -> bool: ...

    async def install_packages(self, serial: str, apk_paths: tuple[str, ...]) -> bool: ...

    async def list_package_apks(self, serial: str, package_name: str) -> tuple[str, ...]: ...

    async def pull_package_apk(
        self, serial: str, remote_path: str, destination: Path
    ) -> PulledFileResult: ...

    async def uninstall_package(self, serial: str, package_name: str) -> bool: ...

    async def push_file(self, serial: str, local_path: Path, remote_path: str) -> bool: ...

    async def root_exec(self, serial: str, command: str) -> str: ...


class SystemAdbClient:
    def __init__(self, runner: SubprocessAdbRunner) -> None:
        self._runner = runner

    async def server_info(self) -> AdbServerInfo:
        result = await self._run(AdbCommandPolicy.server_info())
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return AdbServerInfo(
            version=parse_adb_version(result.stdout),
            executable_path=str(self._runner.adb_path),
            raw_output=result.stdout[:4096],
        )

    async def list_transports(self) -> tuple[DeviceTransport, ...]:
        result = await self._run(AdbCommandPolicy.list_transports())
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_devices_output(result.stdout)

    async def get_properties(self, serial: str) -> dict[str, str]:
        result = await self._run(AdbCommandPolicy.get_properties(serial))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_getprop_output(result.stdout)

    async def get_kernel_version(self, serial: str) -> str:
        """Return the live ``uname -r`` kernel version for provider revalidation."""
        result = await self._run(AdbCommandPolicy.get_kernel_version(serial))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        version = result.stdout.strip()
        if (
            not version
            or len(version) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in version)
        ):
            raise AdbCommandError(result.exit_code, "ADB returned an invalid kernel version.")
        return version

    async def get_battery(self, serial: str) -> dict[str, str]:
        from .parser import parse_dumpsys_battery

        result = await self._run(AdbCommandPolicy.get_battery(serial))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_dumpsys_battery(result.stdout)

    async def list_packages(self, serial: str) -> tuple[str, ...]:
        result = await self._run(AdbCommandPolicy.list_packages(serial))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_package_list(result.stdout)

    async def probe_content_provider(
        self, serial: str, profile: ContentProviderProfile
    ) -> ContentProviderAccessProbe:
        result = await self._run(AdbCommandPolicy.probe_content_provider(serial, profile))
        combined = " ".join((result.stdout, result.stderr)).lower()
        if result.exit_code == 0 and not _provider_denied(combined):
            status = ContentProviderAccessStatus.AVAILABLE
            reason_code = "CONTENT_PROVIDER_QUERY_ALLOWED"
            explanation = (
                "The provider accepted a content-free query from this ADB shell transport."
            )
        elif _provider_denied(combined):
            status = ContentProviderAccessStatus.DENIED
            reason_code = "CONTENT_PROVIDER_PERMISSION_DENIED"
            explanation = "Android denied this ADB shell transport access to the provider."
        elif any(
            marker in combined for marker in ("unknown uri", "no content provider", "not found")
        ):
            status = ContentProviderAccessStatus.MISSING
            reason_code = "CONTENT_PROVIDER_NOT_FOUND"
            explanation = "The provider URI is not available on this Android build."
        else:
            status = ContentProviderAccessStatus.INDETERMINATE
            reason_code = "CONTENT_PROVIDER_PROBE_FAILED"
            explanation = "The provider probe failed without a recognized permission decision."
        return ContentProviderAccessProbe(
            profile=profile.value,
            status=status,
            reason_code=reason_code,
            explanation=explanation,
            exit_code=result.exit_code,
        )

    async def query_content_provider(
        self, serial: str, profile: ContentProviderProfile
    ) -> ContentProviderQueryResult:
        result = await self._run(AdbCommandPolicy.query_content_provider(serial, profile))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_content_provider_rows(
            result.stdout,
            profile=profile,
            projection=AdbCommandPolicy.content_provider_projection(profile),
            max_records=CONTENT_PROVIDER_MAX_RECORDS,
        )

    async def capture_screenshot(self, serial: str, destination: Path) -> ScreenshotCaptureResult:
        command = AdbCommandPolicy.capture_screenshot(serial)
        result = await self._runner.run_stdout_to_file(
            command.arguments,
            destination,
            timeout_seconds=command.timeout_seconds,
            max_file_bytes=MAX_SCREENSHOT_BYTES,
        )
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        size_bytes = await asyncio.to_thread(_regular_file_size, destination)
        if size_bytes is None or size_bytes < 8:
            raise AdbCommandError(result.exit_code, "ADB did not create a valid screenshot stream.")
        signature = await asyncio.to_thread(_read_prefix, destination, 8)
        if signature != b"\x89PNG\r\n\x1a\n":
            raise AdbCommandError(result.exit_code, "ADB screenshot output was not a PNG image.")
        return ScreenshotCaptureResult(size_bytes=size_bytes)

    async def probe_root_access(self, serial: str) -> RootAccessProbe:
        result = await self._run(AdbCommandPolicy.probe_root_access(serial))
        if "invalid uid/gid" in result.stderr.lower():
            # Some Android Studio userdebug images expose su with UID-first syntax.
            result = await self._run(AdbCommandPolicy.probe_root_access_android_su(serial))
        identity = " ".join(result.stdout.split())[:240] or None
        uid_match = re.search(r"(?:^|\s)uid=(\d+)(?:\(|\s|$)", identity or "")
        uid = int(uid_match.group(1)) if uid_match else None
        if result.exit_code == 0 and uid == 0:
            status = RootAccessStatus.AVAILABLE
            reason_code = "ROOT_UID_CONFIRMED"
        elif result.exit_code in {0, 1, 126, 127, 255}:
            status = RootAccessStatus.UNAVAILABLE
            reason_code = "ROOT_UID_NOT_AVAILABLE"
        else:
            status = RootAccessStatus.INDETERMINATE
            reason_code = "ROOT_PROBE_INDETERMINATE"
        return RootAccessProbe(
            status=status,
            uid=uid,
            identity=identity,
            reason_code=reason_code,
            potential_side_effect=(
                "Invoking su can create device logs or an on-device root-manager authorization "
                "prompt; the operation must be explicitly acknowledged."
            ),
        )

    async def probe_shared_storage(self, serial: str) -> tuple[SharedStorageRootProbe, ...]:
        probes: list[SharedStorageRootProbe] = []
        for root in SharedStorageRoot:
            exists = await self._run_boolean(AdbCommandPolicy.storage_root_exists(serial, root))
            readable = (
                await self._run_boolean(AdbCommandPolicy.storage_root_readable(serial, root))
                if exists
                else False
            )
            status = (
                StorageProbeStatus.ACCESSIBLE
                if readable
                else StorageProbeStatus.BLOCKED
                if exists
                else StorageProbeStatus.MISSING
            )
            reason_code = (
                "ROOT_READABLE"
                if readable
                else "ROOT_NOT_READABLE"
                if exists
                else "ROOT_NOT_PRESENT"
            )
            probes.append(
                SharedStorageRootProbe(
                    root_id=root.value,
                    display_path=AdbCommandPolicy.display_path(root),
                    status=status,
                    exists=exists,
                    readable=readable,
                    reason_code=reason_code,
                )
            )
        return tuple(probes)

    async def inventory_shared_storage(
        self, serial: str, root: SharedStorageRoot
    ) -> StorageInventoryResult:
        result = await self._run(AdbCommandPolicy.inventory_storage_paths(serial, root))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_storage_inventory(
            result.stdout,
            root_id=root.value,
            display_path=AdbCommandPolicy.display_path(root),
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
        command = AdbCommandPolicy.pull_inventory_file(serial, root, relative_path, destination)
        result = await self._runner.run_to_file(
            command.arguments,
            destination,
            timeout_seconds=command.timeout_seconds,
            max_file_bytes=MAX_ACQUIRED_FILE_BYTES,
        )
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        size_bytes = await asyncio.to_thread(_regular_file_size, destination)
        if size_bytes is None:
            raise AdbCommandError(result.exit_code, "ADB did not create a regular local file.")
        return PulledFileResult(
            root_id=root.value,
            relative_path=relative_path,
            size_bytes=size_bytes,
        )

    async def capture_rooted_bundle(
        self,
        serial: str,
        profile: RootedCollectionProfile,
        destination: Path,
    ) -> RootedBundleResult:
        command = AdbCommandPolicy.capture_rooted_bundle(serial, profile)
        result = await self._runner.run_stdout_to_file(
            command.arguments,
            destination,
            timeout_seconds=command.timeout_seconds,
            max_file_bytes=MAX_ROOTED_BUNDLE_BYTES,
        )
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        size_bytes = await asyncio.to_thread(_regular_file_size, destination)
        if size_bytes is None or size_bytes == 0:
            raise AdbCommandError(result.exit_code, "ADB did not create a non-empty rooted bundle.")
        return RootedBundleResult(profile=profile.value, size_bytes=size_bytes)

    async def probe_physical_block(
        self, serial: str, profile: PhysicalBlockProfile
    ) -> PhysicalBlockProbe:
        result = await self._run(AdbCommandPolicy.probe_physical_block(serial, profile))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        value = result.stdout.strip()
        if not value.isdecimal():
            raise AdbCommandError(result.exit_code, "The block-device size was not numeric.")
        size_bytes = int(value)
        if size_bytes < 1 or size_bytes > MAX_PHYSICAL_BLOCK_BYTES:
            raise AdbCommandError(result.exit_code, "The block-device size violates policy.")
        return PhysicalBlockProbe(
            profile=profile.value,
            device_path=AdbCommandPolicy.physical_block_path(profile),
            size_bytes=size_bytes,
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
        if expected_size_bytes < 1 or expected_size_bytes > MAX_PHYSICAL_BLOCK_BYTES:
            raise ValueError("Expected physical block size violates policy.")
        command = AdbCommandPolicy.capture_physical_block(serial, profile)
        result = await self._runner.run_stdout_to_file(
            command.arguments,
            destination,
            timeout_seconds=command.timeout_seconds,
            max_file_bytes=expected_size_bytes,
        )
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        size_bytes = await asyncio.to_thread(_regular_file_size, destination)
        if size_bytes != expected_size_bytes:
            raise AdbCommandError(
                result.exit_code,
                "The physical capture size did not match the pre-acquisition probe.",
            )
        return PhysicalBlockCaptureResult(profile=profile.value, size_bytes=size_bytes)

    # ------------------------------------------------------------------
    # Extraction-attack client methods
    # ------------------------------------------------------------------

    async def dump_package(self, serial: str, package_name: str) -> str:
        """Return raw dumpsys package output for the given package."""
        result = await self._run(AdbCommandPolicy.dump_package(serial, package_name))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return result.stdout

    async def backup_package(
        self, serial: str, package_name: str, destination: Path
    ) -> "BackupResult":
        """Issue ``adb backup -noapk`` and capture the ``.ab`` file."""
        from .models import BackupResult

        command = AdbCommandPolicy.backup_package(serial, package_name, destination)
        result = await self._runner.run_to_file(
            command.arguments,
            destination,
            timeout_seconds=command.timeout_seconds,
            max_file_bytes=MAX_BACKUP_FILE_BYTES,
        )
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        size_bytes = await asyncio.to_thread(_regular_file_size, destination)
        if size_bytes is None or size_bytes == 0:
            raise AdbCommandError(result.exit_code, "ADB backup produced an empty file.")
        return BackupResult(
            backup_file_size_bytes=size_bytes,
            destination_path=str(destination),
            package_name=package_name,
            backup_format="ab",
            success=True,
        )

    async def install_package(self, serial: str, apk_path: str) -> bool:
        """Install an APK on the device (returns True on success)."""
        result = await self._run(AdbCommandPolicy.install_package(serial, apk_path))
        combined = " ".join((result.stdout, result.stderr)).lower()
        return result.exit_code == 0 or "success" in combined

    async def install_packages(self, serial: str, apk_paths: tuple[str, ...]) -> bool:
        """Install a base APK and all split APKs atomically."""
        result = await self._run(AdbCommandPolicy.install_packages(serial, apk_paths))
        combined = " ".join((result.stdout, result.stderr)).lower()
        return result.exit_code == 0 or "success" in combined

    async def list_package_apks(self, serial: str, package_name: str) -> tuple[str, ...]:
        """Return validated installed APK paths reported by ``pm path``."""
        result = await self._run(AdbCommandPolicy.list_package_apks(serial, package_name))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        paths = tuple(
            line.removeprefix("package:").strip()
            for line in result.stdout.splitlines()
            if line.startswith("package:") and line.removeprefix("package:").strip()
        )
        if not paths:
            raise AdbCommandError(result.exit_code, "Package manager returned no APK paths.")
        for path in paths:
            AdbCommandPolicy.pull_package_apk(serial, path, Path("package.apk"))
        return paths

    async def pull_package_apk(
        self, serial: str, remote_path: str, destination: Path
    ) -> PulledFileResult:
        """Copy one installed APK with a bounded local file size."""
        command = AdbCommandPolicy.pull_package_apk(serial, remote_path, destination)
        result = await self._runner.run_to_file(
            command.arguments,
            destination,
            timeout_seconds=command.timeout_seconds,
            max_file_bytes=MAX_PACKAGE_APK_BYTES,
        )
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        size_bytes = await asyncio.to_thread(_regular_file_size, destination)
        if size_bytes is None or size_bytes == 0:
            raise AdbCommandError(result.exit_code, "ADB pull produced an empty APK file.")
        return PulledFileResult(
            root_id="installed_package",
            relative_path=remote_path,
            size_bytes=size_bytes,
        )

    async def uninstall_package(self, serial: str, package_name: str) -> bool:
        """Uninstall a package while keeping its data."""
        result = await self._run(AdbCommandPolicy.uninstall_package(serial, package_name))
        combined = " ".join((result.stdout, result.stderr)).lower()
        return result.exit_code == 0 or "success" in combined

    async def push_file(self, serial: str, local_path: Path, remote_path: str) -> bool:
        """Push a local file to the device filesystem."""
        result = await self._run(AdbCommandPolicy.push_file(serial, local_path, remote_path))
        combined = " ".join((result.stdout, result.stderr)).lower()
        return result.exit_code == 0 or "pushed" in combined or "1 file pushed" in combined

    async def root_exec(self, serial: str, command: str) -> str:
        """Execute an approved command via ``su -c`` and return stdout."""
        result = await self._run(AdbCommandPolicy.root_exec(serial, command))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return result.stdout

    async def _run(self, command: ApprovedAdbCommand) -> AdbCommandResult:
        return await self._runner.run(command.arguments, timeout_seconds=command.timeout_seconds)

    async def _run_boolean(self, command: ApprovedAdbCommand) -> bool:
        result = await self._run(command)
        if result.exit_code not in {0, 1}:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return result.exit_code == 0


def _safe_summary(stderr: str) -> str:
    compact = " ".join(stderr.split())
    return compact[:240] or "No error details were provided."


def _provider_denied(output: str) -> bool:
    return any(
        marker in output
        for marker in (
            "securityexception",
            "permission denial",
            "permission denied",
            "requires android.permission",
            "not allowed to read",
        )
    )


def _regular_file_size(path: Path) -> int | None:
    if path.is_symlink() or not path.is_file():
        return None
    return path.stat().st_size


def _read_prefix(path: Path, size: int) -> bytes:
    with path.open("rb") as stream:
        return stream.read(size)
