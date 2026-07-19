import asyncio
from collections import deque
from pathlib import Path
from typing import cast

import pytest

from forensix_forensic.adb import (
    AdbCommandError,
    AdbCommandPolicy,
    AdbCommandResult,
    PhysicalBlockProfile,
    RootAccessStatus,
    RootedCollectionProfile,
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

    async def run_to_file(
        self,
        arguments: tuple[str, ...],
        destination: Path,
        *,
        timeout_seconds: float,
        max_file_bytes: int,
    ) -> AdbCommandResult:
        self.calls.append((arguments, timeout_seconds))
        await asyncio.to_thread(destination.write_bytes, b"known-answer")
        return self.results.popleft()

    async def run_stdout_to_file(
        self,
        arguments: tuple[str, ...],
        destination: Path,
        *,
        timeout_seconds: float,
        max_file_bytes: int,
    ) -> AdbCommandResult:
        self.calls.append((arguments, timeout_seconds))
        await asyncio.to_thread(destination.write_bytes, b"rooted-tar-fixture")
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


def test_root_probe_policy_is_fixed_and_serial_scoped() -> None:
    command = AdbCommandPolicy.probe_root_access("FX-DEMO-001")

    assert command.arguments == (
        "-s",
        "FX-DEMO-001",
        "shell",
        "su",
        "-c",
        "id",
    )
    assert command.timeout_seconds == 8.0


def test_rooted_bundle_policy_uses_only_fixed_provider_paths() -> None:
    command = AdbCommandPolicy.capture_rooted_bundle(
        "FX-DEMO-001", RootedCollectionProfile.ANDROID_PROVIDERS
    )

    assert command.arguments[:5] == ("-s", "FX-DEMO-001", "exec-out", "su", "-c")
    assert command.timeout_seconds == 600.0
    shell_text = command.arguments[5]
    assert "FX-DEMO-001" not in shell_text
    assert "com.android.providers.contacts/databases" in shell_text
    assert "com.android.providers.telephony/databases" in shell_text
    assert "com.android.providers.calendar/databases" in shell_text
    assert "tar -cf -" in shell_text


def test_physical_block_policy_is_fixed_and_has_no_caller_path() -> None:
    probe = AdbCommandPolicy.probe_physical_block(
        "FX-DEMO-001", PhysicalBlockProfile.USERDATA_BY_NAME
    )
    capture = AdbCommandPolicy.capture_physical_block(
        "FX-DEMO-001", PhysicalBlockProfile.USERDATA_BY_NAME
    )

    assert probe.arguments[:5] == ("-s", "FX-DEMO-001", "exec-out", "su", "-c")
    assert probe.arguments[5] == "blockdev --getsize64 '/dev/block/by-name/userdata'"
    assert capture.arguments[5] == "exec dd if='/dev/block/by-name/userdata' bs=1048576"
    assert "FX-DEMO-001" not in probe.arguments[5]
    assert capture.timeout_seconds == 24 * 60 * 60


def test_inventory_policy_is_fixed_bounded_and_uses_no_caller_controlled_shell_text() -> None:
    command = AdbCommandPolicy.inventory_storage_paths(
        "FX-DEMO-001", SharedStorageRoot.EMULATED_PRIMARY
    )

    assert command.arguments == (
        "-s",
        "FX-DEMO-001",
        "shell",
        "find /storage/emulated/0 -xdev -maxdepth 6 -type f "
        "-exec stat -c '%n:%s:%Y' {} + | head -n 250",
    )
    assert command.timeout_seconds == 30.0
    assert command.arguments[3] == (
        "find /storage/emulated/0 -xdev -maxdepth 6 -type f "
        "-exec stat -c '%n:%s:%Y' {} + | head -n 250"
    )
    assert "FX-DEMO-001" not in command.arguments[3]
    assert "pull" not in command.arguments[3]


def test_pull_policy_uses_shell_free_inventory_path_and_absolute_destination(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "partial.bin"
    command = AdbCommandPolicy.pull_inventory_file(
        "FX-DEMO-001",
        SharedStorageRoot.EMULATED_PRIMARY,
        "DCIM/Camera/image name;$(safe).jpg",
        destination,
    )

    assert command.arguments[:3] == ("-s", "FX-DEMO-001", "pull")
    assert command.arguments[3] == "/storage/emulated/0/DCIM/Camera/image name;$(safe).jpg"
    assert command.arguments[4] == str(destination.absolute())
    assert "shell" not in command.arguments
    assert command.timeout_seconds == 120.0


@pytest.mark.parametrize(
    "relative_path",
    ["", "/absolute.jpg", "../escape.jpg", "DCIM//file.jpg", "a/b/c/d/e/f/g.jpg", "bad\nname"],
)
def test_pull_policy_rejects_paths_outside_inventory_policy(
    tmp_path: Path, relative_path: str
) -> None:
    with pytest.raises(ValueError):
        AdbCommandPolicy.pull_inventory_file(
            "FX-DEMO-001",
            SharedStorageRoot.PRIMARY_ALIAS,
            relative_path,
            tmp_path / "partial.bin",
        )


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
async def test_system_root_probe_requires_confirmed_uid_zero() -> None:
    rooted_runner = RecordingRunner([_result(0, stdout="uid=0(root) gid=0(root)")])
    ordinary_runner = RecordingRunner([_result(0, stdout="uid=2000(shell) gid=2000(shell)")])

    rooted = await SystemAdbClient(cast(SubprocessAdbRunner, rooted_runner)).probe_root_access(
        "FX-DEMO-001"
    )
    ordinary = await SystemAdbClient(cast(SubprocessAdbRunner, ordinary_runner)).probe_root_access(
        "FX-DEMO-001"
    )

    assert rooted.status is RootAccessStatus.AVAILABLE
    assert rooted.uid == 0
    assert ordinary.status is RootAccessStatus.UNAVAILABLE
    assert ordinary.uid == 2000


@pytest.mark.asyncio
async def test_system_inventory_parses_paths_without_running_path_derived_commands() -> None:
    output = "/sdcard/DCIM/IMG_1.jpg:128:1784160000\n/sdcard/Download/report.pdf:256:1784246400\n"
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
    assert runner.calls[0][0][3].startswith("find /sdcard ")
    assert runner.calls[0][0][3].endswith("| head -n 250")
    assert inventory.entries[0].size_bytes == 128
    assert inventory.entries[0].modified_time_raw == "1784160000"
    assert inventory.entries[0].modified_at is not None
    assert inventory.entries[0].timestamp_confidence == "medium"


@pytest.mark.asyncio
async def test_system_pull_writes_only_to_supplied_partial_path(tmp_path: Path) -> None:
    runner = RecordingRunner([_result(0, stdout="1 file pulled")])
    client = SystemAdbClient(cast(SubprocessAdbRunner, runner))
    destination = tmp_path / "partial.bin"

    result = await client.pull_inventory_file(
        "FX-DEMO-001",
        SharedStorageRoot.PRIMARY_ALIAS,
        "Download/report.pdf",
        destination,
    )

    assert destination.read_bytes() == b"known-answer"
    assert result.size_bytes == 12
    assert runner.calls[0][0][2] == "pull"
    assert "shell" not in runner.calls[0][0]


@pytest.mark.asyncio
async def test_system_rooted_bundle_streams_to_supplied_new_path(tmp_path: Path) -> None:
    runner = RecordingRunner([_result(0)])
    client = SystemAdbClient(cast(SubprocessAdbRunner, runner))
    destination = tmp_path / "providers.tar.partial"

    result = await client.capture_rooted_bundle(
        "FX-DEMO-001", RootedCollectionProfile.ANDROID_PROVIDERS, destination
    )

    assert destination.read_bytes() == b"rooted-tar-fixture"
    assert result.profile == "android_providers"
    assert result.size_bytes == len(b"rooted-tar-fixture")
    assert runner.calls[0][0][2:5] == ("exec-out", "su", "-c")


@pytest.mark.asyncio
async def test_system_physical_block_probe_and_exact_capture(tmp_path: Path) -> None:
    runner = RecordingRunner([_result(0, stdout="18\n"), _result(0)])
    client = SystemAdbClient(cast(SubprocessAdbRunner, runner))
    destination = tmp_path / "userdata.dd.partial"

    probe = await client.probe_physical_block(
        "FX-DEMO-001", PhysicalBlockProfile.USERDATA_BY_NAME
    )
    capture = await client.capture_physical_block(
        "FX-DEMO-001",
        PhysicalBlockProfile.USERDATA_BY_NAME,
        destination,
        expected_size_bytes=probe.size_bytes,
    )

    assert probe.device_path == "/dev/block/by-name/userdata"
    assert probe.size_bytes == 18
    assert capture.size_bytes == 18
    assert destination.read_bytes() == b"rooted-tar-fixture"
