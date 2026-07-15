"""High-level ADB client limited to registered forensic operations."""

from typing import Protocol

from .errors import AdbCommandError
from .models import (
    AdbServerInfo,
    DeviceTransport,
    SharedStorageRootProbe,
    StorageProbeStatus,
)
from .parser import (
    parse_adb_version,
    parse_devices_output,
    parse_getprop_output,
    parse_package_list,
)
from .policy import AdbCommandPolicy, ApprovedAdbCommand, SharedStorageRoot
from .runner import AdbCommandResult, SubprocessAdbRunner


class AdbClient(Protocol):
    async def server_info(self) -> AdbServerInfo: ...

    async def list_transports(self) -> tuple[DeviceTransport, ...]: ...

    async def get_properties(self, serial: str) -> dict[str, str]: ...

    async def list_packages(self, serial: str) -> tuple[str, ...]: ...

    async def probe_shared_storage(self, serial: str) -> tuple[SharedStorageRootProbe, ...]: ...


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
