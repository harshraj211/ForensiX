"""High-level ADB client limited to registered forensic operations."""

import asyncio
import re
from pathlib import Path
from typing import Protocol

from .errors import AdbCommandError
from .models import (
    AdbServerInfo,
    DeviceTransport,
    PulledFileResult,
    RootAccessProbe,
    RootAccessStatus,
    RootedBundleResult,
    SharedStorageRootProbe,
    StorageInventoryResult,
    StorageProbeStatus,
)
from .parser import (
    parse_adb_version,
    parse_devices_output,
    parse_getprop_output,
    parse_package_list,
    parse_storage_inventory,
)
from .policy import (
    INVENTORY_MAX_DEPTH,
    INVENTORY_MAX_ITEMS,
    MAX_ACQUIRED_FILE_BYTES,
    MAX_ROOTED_BUNDLE_BYTES,
    AdbCommandPolicy,
    ApprovedAdbCommand,
    RootedCollectionProfile,
    SharedStorageRoot,
)
from .runner import AdbCommandResult, SubprocessAdbRunner


class AdbClient(Protocol):
    async def server_info(self) -> AdbServerInfo: ...

    async def list_transports(self) -> tuple[DeviceTransport, ...]: ...

    async def get_properties(self, serial: str) -> dict[str, str]: ...

    async def list_packages(self, serial: str) -> tuple[str, ...]: ...

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

    async def list_packages(self, serial: str) -> tuple[str, ...]:
        result = await self._run(AdbCommandPolicy.list_packages(serial))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_package_list(result.stdout)

    async def probe_root_access(self, serial: str) -> RootAccessProbe:
        result = await self._run(AdbCommandPolicy.probe_root_access(serial))
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


def _regular_file_size(path: Path) -> int | None:
    if path.is_symlink() or not path.is_file():
        return None
    return path.stat().st_size
