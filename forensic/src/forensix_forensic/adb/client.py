"""High-level ADB client limited to registered forensic operations."""

from typing import Protocol

from .errors import AdbCommandError
from .models import AdbServerInfo, DeviceTransport
from .parser import parse_adb_version, parse_devices_output
from .runner import SubprocessAdbRunner


class AdbClient(Protocol):
    async def server_info(self) -> AdbServerInfo: ...

    async def list_transports(self) -> tuple[DeviceTransport, ...]: ...


class SystemAdbClient:
    def __init__(self, runner: SubprocessAdbRunner) -> None:
        self._runner = runner

    async def server_info(self) -> AdbServerInfo:
        result = await self._runner.run(("version",))
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return AdbServerInfo(
            version=parse_adb_version(result.stdout),
            executable_path=str(self._runner.adb_path),
            raw_output=result.stdout[:4096],
        )

    async def list_transports(self) -> tuple[DeviceTransport, ...]:
        result = await self._runner.run(("devices", "-l"), timeout_seconds=5.0)
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_devices_output(result.stdout)


def _safe_summary(stderr: str) -> str:
    compact = " ".join(stderr.split())
    return compact[:240] or "No error details were provided."
