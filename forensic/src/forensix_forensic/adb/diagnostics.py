"""Bounded, identifier-free workstation ADB readiness diagnostics."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path

from .client import SystemAdbClient
from .discovery import AdbBinaryResolver
from .errors import AdbError
from .models import DeviceState
from .runner import SubprocessAdbRunner


@dataclass(frozen=True, slots=True)
class AdbDiagnostic:
    mode: str
    status: str
    available: bool
    platform: str
    executable_path: str | None
    version: str | None
    transport_counts: dict[str, int]
    checked_locations: tuple[str, ...]
    guidance: tuple[str, ...]


async def diagnose_adb(mode: str, configured_path: Path | None) -> AdbDiagnostic:
    host = platform.system().lower() or "unknown"
    checked = tuple([str(configured_path)] if configured_path else []) + tuple(
        str(item) for item in AdbBinaryResolver.sdk_candidates()
    )
    try:
        adb_path = AdbBinaryResolver(configured_path).resolve()
    except AdbError:
        return AdbDiagnostic(
            mode="system",
            status="missing",
            available=False,
            platform=host,
            executable_path=None,
            version=None,
            transport_counts={},
            checked_locations=checked,
            guidance=_missing_guidance(host),
        )
    try:
        client = SystemAdbClient(
            SubprocessAdbRunner(adb_path, default_timeout_seconds=8, output_limit_bytes=64 * 1024)
        )
        info = await client.server_info()
        transports = await client.list_transports()
    except (AdbError, OSError):
        return AdbDiagnostic(
            mode="system",
            status="execution_failed",
            available=False,
            platform=host,
            executable_path=str(adb_path),
            version=None,
            transport_counts={},
            checked_locations=checked,
            guidance=(
                "The ADB executable was found but did not complete a bounded version/device check.",
                "Close other Android tools, run 'adb kill-server', reconnect the cable, and retry.",
            ),
        )
    counts: dict[str, int] = {}
    for transport in transports:
        key = transport.state.value
        counts[key] = counts.get(key, 0) + 1
    status = _transport_status(counts)
    return AdbDiagnostic(
        mode="system",
        status=status,
        available=True,
        platform=host,
        executable_path=info.executable_path,
        version=info.version,
        transport_counts=counts,
        checked_locations=checked,
        guidance=_transport_guidance(status, host),
    )


def _transport_status(counts: dict[str, int]) -> str:
    if counts.get(DeviceState.AUTHORIZED.value, 0):
        return "healthy"
    if counts.get(DeviceState.UNAUTHORIZED.value, 0):
        return "authorization_required"
    if counts.get(DeviceState.OFFLINE.value, 0):
        return "offline"
    return "no_transports" if not counts else "unsupported_transport"


def _missing_guidance(host: str) -> tuple[str, ...]:
    base = (
        "Install Android SDK Platform-Tools or configure FORENSIX_ADB_PATH with the full "
        "ADB executable path.",
        "Restart ForensiX after changing the ADB path.",
    )
    if host == "windows":
        return base + ("If ADB is installed but the phone is absent, install the OEM USB driver.",)
    if host == "linux":
        return base + ("Confirm udev rules and membership of the required USB-access group.",)
    return base + ("Confirm macOS Gatekeeper/quarantine allows the downloaded ADB binary.",)


def _transport_guidance(status: str, host: str) -> tuple[str, ...]:
    if status == "healthy":
        return ("At least one authorized ADB transport is ready for capability assessment.",)
    if status == "authorization_required":
        return ("Unlock the phone and approve this workstation's USB debugging fingerprint.",)
    if status == "offline":
        return ("Reconnect the data cable, then restart the ADB server and detect again.",)
    if status == "no_transports":
        suffix = (
            "On Windows, verify the OEM USB driver in Device Manager."
            if host == "windows"
            else "Verify host USB permissions and reconnect using a data-capable cable."
        )
        return (
            "ADB is healthy but no Android transport is visible; this does not prove "
            "debugging is disabled.",
            suffix,
        )
    return ("ADB sees a transport state that ForensiX will not acquire from.",)
