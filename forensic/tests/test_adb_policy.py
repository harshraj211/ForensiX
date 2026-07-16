from collections import deque
from pathlib import Path
from typing import cast

import pytest

from forensix_forensic.adb import (
    AdbCommandError,
    AdbCommandPolicy,
    AdbCommandResult,
    SharedStorageRoot,
    StorageProbeStatus,
    SubprocessAdbRunner,
    SystemAdbClient,
)


class RecordingRunner:
    def __init__(self, results: list[AdbCommandResult]) -> None:
        self.adb_path = Path("mock-adb")
        self.results = deque(results)
        self.calls: list[tuple[tuple[str, ...], float | None]] = []

    async def run(
        self, arguments: tuple[str, ...], *, timeout_seconds: float | None = None
    ) -> AdbCommandResult:
        self.calls.append((arguments, timeout_seconds))
        return self.results.popleft()


def _result(exit_code: int, stderr: str = "", stdout: str = "") -> AdbCommandResult:
    return AdbCommandResult(
        argv=(),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.01,
    )


def test_storage_policy_builds_only_fixed_content_free_commands() -> None:
    exists = AdbCommandPolicy.storage_root_exists("FX-DEMO-001", SharedStorageRoot.PRIMARY_ALIAS)
    readable = AdbCommandPolicy.storage_root_readable(
        "FX-DEMO-001", SharedStorageRoot.EMULATED_PRIMARY
    )

    assert exists.arguments == (
        "-s",
        "FX-DEMO-001",
        "shell",
        "test",
        "-d",
        "/sdcard",
    )
    assert readable.arguments == (
        "-s",
        "FX-DEMO-001",
        "shell",
        "test",
        "-r",
        "/storage/emulated/0",
    )
    assert all(token not in exists.arguments for token in {"ls", "find", "pull", "sh", "-c"})


def test_inventory_policy_is_fixed_bounded_and_has_no_shell_composition() -> None:
    command = AdbCommandPolicy.inventory_storage_paths(
        "FX-DEMO-001", SharedStorageRoot.EMULATED_PRIMARY
    )

    assert command.arguments == (
        "-s",
        "FX-DEMO-001",
        "shell",
        "find",
        "/storage/emulated/0",
        "-xdev",
        "-maxdepth",
        "6",
        "-type",
        "f",
        "-print0",
    )
    assert command.timeout_seconds == 30.0
    assert all(token not in command.arguments for token in {"pull", "sh", "-c", "|", ";"})


@pytest.mark.parametrize("serial", ["", "bad serial", "bad\nserial", "x" * 256])
def test_policy_rejects_invalid_serials(serial: str) -> None:
    with pytest.raises(ValueError):
        AdbCommandPolicy.storage_root_exists(serial, SharedStorageRoot.PRIMARY_ALIAS)


@pytest.mark.asyncio
async def test_system_probe_classifies_accessible_and_missing_roots() -> None:
    runner = RecordingRunner([_result(0), _result(0), _result(1)])
    client = SystemAdbClient(cast(SubprocessAdbRunner, runner))

    probes = await client.probe_shared_storage("FX-DEMO-001")

    assert probes[0].status is StorageProbeStatus.ACCESSIBLE
    assert probes[0].readable is True
    assert probes[1].status is StorageProbeStatus.MISSING
    assert probes[1].readable is False
    assert len(runner.calls) == 3
    assert all(call[1] == 5.0 for call in runner.calls)


@pytest.mark.asyncio
async def test_system_probe_does_not_treat_command_failure_as_missing_storage() -> None:
    runner = RecordingRunner([_result(127, "test: inaccessible")])
    client = SystemAdbClient(cast(SubprocessAdbRunner, runner))

    with pytest.raises(AdbCommandError):
        await client.probe_shared_storage("FX-DEMO-001")


@pytest.mark.asyncio
async def test_system_inventory_parses_paths_without_running_path_derived_commands() -> None:
    output = "/sdcard/DCIM/IMG_1.jpg\x00/sdcard/Download/report.pdf\x00"
    runner = RecordingRunner([_result(0, stdout=output)])
    client = SystemAdbClient(cast(SubprocessAdbRunner, runner))

    inventory = await client.inventory_shared_storage(
        "FX-DEMO-001", SharedStorageRoot.PRIMARY_ALIAS
    )

    assert [entry.relative_path for entry in inventory.entries] == [
        "DCIM/IMG_1.jpg",
        "Download/report.pdf",
    ]
    assert len(runner.calls) == 1
    assert runner.calls[0][0][3] == "find"
