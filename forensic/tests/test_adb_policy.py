import asyncio
from collections import deque
from pathlib import Path
from typing import cast

import pytest

from forensix_forensic.adb import (
    AdbCommandError,
    AdbCommandPolicy,
    AdbCommandResult,
    ContentProviderAccessStatus,
    ContentProviderProfile,
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


def test_kernel_version_policy_is_fixed_and_serial_scoped() -> None:
    command = AdbCommandPolicy.get_kernel_version("FX-DEMO-001")

    assert command.arguments == ("-s", "FX-DEMO-001", "shell", "uname", "-r")
    assert command.timeout_seconds == 8.0


def test_provider_probe_policy_is_content_free_and_profile_bounded() -> None:
    command = AdbCommandPolicy.probe_content_provider(
        "FX-DEMO-001", ContentProviderProfile.CONTACTS
    )

    assert command.arguments == (
        "-s",
        "FX-DEMO-001",
        "shell",
        "content",
        "query",
        "--uri",
        "content://com.android.contacts/data/phones",
        "--projection",
        "_id",
        "--where",
        "0=1",
    )
    assert command.timeout_seconds == 10.0


def test_provider_query_policy_uses_only_fixed_uri_and_projection() -> None:
    command = AdbCommandPolicy.query_content_provider("FX-DEMO-001", ContentProviderProfile.SMS)

    assert command.arguments == (
        "-s",
        "FX-DEMO-001",
        "shell",
        "content",
        "query",
        "--uri",
        "content://sms",
        "--projection",
        "_id:thread_id:address:date:date_sent:type:read:body",
    )
    assert command.timeout_seconds == 60.0


def test_screenshot_policy_streams_png_without_device_side_path() -> None:
    command = AdbCommandPolicy.capture_screenshot("FX-DEMO-001")

    assert command.arguments == (
        "-s",
        "FX-DEMO-001",
        "exec-out",
        "screencap",
        "-p",
    )
    assert command.timeout_seconds == 20.0
    assert all("/sdcard" not in argument for argument in command.arguments)


@pytest.mark.asyncio
async def test_system_provider_query_parses_fixed_projection_and_preserves_commas() -> None:
    output = (
        "Row: 0 _id=7, thread_id=2, address=+15550100, date=1784160000000, "
        "date_sent=1784160000000, type=1, read=1, body=hello, investigator\n"
    )
    runner = RecordingRunner([_result(0, stdout=output)])

    result = await SystemAdbClient(cast(SubprocessAdbRunner, runner)).query_content_provider(
        "FX-DEMO-001", ContentProviderProfile.SMS
    )

    assert result.discovered_count == 1
    assert result.records[0].values["_id"] == "7"
    assert result.records[0].values["body"] == "hello, investigator"


@pytest.mark.asyncio
async def test_system_provider_probe_distinguishes_access_from_permission_denial() -> None:
    available_runner = RecordingRunner([_result(0, stdout="No result found.")])
    denied_runner = RecordingRunner(
        [_result(1, stderr="java.lang.SecurityException: Permission Denial")]
    )

    available = await SystemAdbClient(
        cast(SubprocessAdbRunner, available_runner)
    ).probe_content_provider("FX-DEMO-001", ContentProviderProfile.SMS)
    denied = await SystemAdbClient(cast(SubprocessAdbRunner, denied_runner)).probe_content_provider(
        "FX-DEMO-001", ContentProviderProfile.SMS
    )

    assert available.status is ContentProviderAccessStatus.AVAILABLE
    assert denied.status is ContentProviderAccessStatus.DENIED


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


def test_rooted_app_bundle_policy_uses_only_fixed_private_app_paths() -> None:
    command = AdbCommandPolicy.capture_rooted_bundle(
        "FX-DEMO-001", RootedCollectionProfile.ANDROID_APPS
    )

    shell_text = command.arguments[5]
    assert command.arguments[:5] == ("-s", "FX-DEMO-001", "exec-out", "su", "-c")
    assert "FX-DEMO-001" not in shell_text
    assert "/data/user/0/com.whatsapp/databases" in shell_text
    assert "/data/user/0/org.telegram.messenger/files/cache4.db" in shell_text
    assert "/data/user/0/org.thoughtcrime.securesms/databases" in shell_text
    assert "/data/user/0/com.instagram.android/databases" in shell_text
    assert "/data/user/0/com.snapchat.android/databases" in shell_text
    assert "tar -cf -" in shell_text


def test_rooted_userdata_policy_uses_fixed_broad_paths_and_extended_timeout() -> None:
    command = AdbCommandPolicy.capture_rooted_bundle(
        "FX-DEMO-001", RootedCollectionProfile.ANDROID_USERDATA
    )

    shell_text = command.arguments[5]
    assert command.arguments[:5] == ("-s", "FX-DEMO-001", "exec-out", "su", "-c")
    assert command.timeout_seconds == 3600.0
    assert "/data/user/0" in shell_text
    assert "/data/user_de/0" in shell_text
    assert "/data/system" in shell_text
    assert "/data/misc" in shell_text
    assert "/data/media/0" in shell_text
    assert "tar -cf -" in shell_text


def test_bfu_credentials_policy_uses_only_fixed_locksettings_paths() -> None:
    command = AdbCommandPolicy.capture_rooted_bundle(
        "FX-DEMO-001", RootedCollectionProfile.BFU_CREDENTIALS
    )

    shell_text = command.arguments[5]
    assert command.arguments[:5] == ("-s", "FX-DEMO-001", "exec-out", "su", "-c")
    assert "/data/system/locksettings.db" in shell_text
    assert "/data/system/gatekeeper.password.key" in shell_text
    assert "/data/user/0" not in shell_text
    assert "tar -cf -" in shell_text


@pytest.mark.asyncio
async def test_system_client_reads_and_validates_kernel_version() -> None:
    runner = RecordingRunner([_result(0, stdout="4.4.177-g83bee1dc48e8\n")])

    version = await SystemAdbClient(cast(SubprocessAdbRunner, runner)).get_kernel_version(
        "FX-DEMO-001"
    )

    assert version == "4.4.177-g83bee1dc48e8"


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

    assert command.arguments[:3] == ("-s", "FX-DEMO-001", "shell")
    shell_command = command.arguments[3]
    assert shell_command.startswith("{ [ ! -d /storage/emulated/0/DCIM ]")
    assert "find /storage/emulated/0/DCIM -xdev -maxdepth 9" in shell_command
    assert "{} + | head -n 800" in shell_command
    assert "find /storage/emulated/0/Documents -xdev -maxdepth 9" in shell_command
    assert "{} + | head -n 400" in shell_command
    assert "find /storage/emulated/0/Podcasts -xdev -maxdepth 9" in shell_command
    assert "find /storage/emulated/0 -xdev -maxdepth 10" in shell_command
    assert "-path /storage/emulated/0/DCIM" in shell_command
    assert shell_command.endswith("} | head -n 5000")
    assert command.timeout_seconds == 90.0
    assert "FX-DEMO-001" not in shell_command
    assert "pull" not in shell_command


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


def test_package_apk_policy_supports_safe_split_restore(tmp_path: Path) -> None:
    paths = (str(tmp_path / "base.apk"), str(tmp_path / "split_config.en.apk"))
    install = AdbCommandPolicy.install_packages("FX-DEMO-001", paths)
    listed = AdbCommandPolicy.list_package_apks("FX-DEMO-001", "com.whatsapp")
    pulled = AdbCommandPolicy.pull_package_apk(
        "FX-DEMO-001",
        "/data/app/~~token/com.whatsapp-token/base.apk",
        tmp_path / "original.apk",
    )

    assert install.arguments[2:5] == ("install-multiple", "-r", "-d")
    assert install.arguments[-2:] == paths
    assert listed.arguments[-3:] == ("pm", "path", "com.whatsapp")
    assert pulled.arguments[2] == "pull"


@pytest.mark.parametrize(
    "remote_path",
    ["/sdcard/fake.apk", "/data/app/../data/local/tmp/fake.apk", "/data/app/not-an-apk"],
)
def test_package_apk_pull_rejects_non_package_manager_paths(
    tmp_path: Path, remote_path: str
) -> None:
    with pytest.raises(ValueError):
        AdbCommandPolicy.pull_package_apk("FX-DEMO-001", remote_path, tmp_path / "original.apk")


@pytest.mark.parametrize(
    "relative_path",
    [
        "",
        "/absolute.jpg",
        "../escape.jpg",
        "DCIM//file.jpg",
        "a/b/c/d/e/f/g/h/i/j/k.jpg",
        "bad\nname",
    ],
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
    assert runner.calls[0][0][3].startswith("{ [ ! -d /sdcard/DCIM ]")
    assert runner.calls[0][0][3].endswith("} | head -n 5000")
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

    probe = await client.probe_physical_block("FX-DEMO-001", PhysicalBlockProfile.USERDATA_BY_NAME)
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
