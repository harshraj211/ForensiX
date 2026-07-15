"""High-level ADB client limited to registered forensic operations."""

from typing import Protocol

from .errors import AdbCommandError
from .models import AdbServerInfo, DeviceTransport
from .parser import (
    parse_adb_version,
    parse_devices_output,
    parse_getprop_output,
    parse_package_list,
)
from .runner import SubprocessAdbRunner


class AdbClient(Protocol):
    async def server_info(self) -> AdbServerInfo: ...

    async def list_transports(self) -> tuple[DeviceTransport, ...]: ...

    async def get_properties(self, serial: str) -> dict[str, str]: ...

    async def list_packages(self, serial: str) -> tuple[str, ...]: ...


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

    async def get_properties(self, serial: str) -> dict[str, str]:
        _validate_serial(serial)
        result = await self._runner.run(("-s", serial, "shell", "getprop"), timeout_seconds=8.0)
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_getprop_output(result.stdout)

    async def list_packages(self, serial: str) -> tuple[str, ...]:
        _validate_serial(serial)
        result = await self._runner.run(
            ("-s", serial, "shell", "cmd", "package", "list", "packages"),
            timeout_seconds=12.0,
        )
        if result.exit_code != 0:
            raise AdbCommandError(result.exit_code, _safe_summary(result.stderr))
        return parse_package_list(result.stdout)


def _safe_summary(stderr: str) -> str:
    compact = " ".join(stderr.split())
    return compact[:240] or "No error details were provided."


def _validate_serial(serial: str) -> None:
    if not serial or len(serial) > 255:
        raise ValueError("ADB serial must contain between 1 and 255 characters")
    if any(character.isspace() or ord(character) < 32 for character in serial):
        raise ValueError("ADB serial contains a prohibited control character")
