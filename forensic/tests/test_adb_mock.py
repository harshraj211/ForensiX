import tarfile
from pathlib import Path

import pytest

from forensix_forensic.adb.errors import AdbCommandError, AdbTimeoutError
from forensix_forensic.adb.mock import MockAdbClient, MockAdbScenario
from forensix_forensic.adb.models import DeviceState
from forensix_forensic.adb.policy import (
    PhysicalBlockProfile,
    RootedCollectionProfile,
    SharedStorageRoot,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "expected_states"),
    [
        (MockAdbScenario.NO_DEVICES, []),
        (MockAdbScenario.AUTHORIZED, [DeviceState.AUTHORIZED]),
        (MockAdbScenario.UNAUTHORIZED, [DeviceState.UNAUTHORIZED]),
        (MockAdbScenario.OFFLINE, [DeviceState.OFFLINE]),
        (MockAdbScenario.STORAGE_BLOCKED, [DeviceState.AUTHORIZED]),
        (MockAdbScenario.ROOTED, [DeviceState.AUTHORIZED]),
        (
            MockAdbScenario.MULTIPLE,
            [DeviceState.AUTHORIZED, DeviceState.UNAUTHORIZED],
        ),
    ],
)
async def test_mock_scenarios(
    scenario: MockAdbScenario, expected_states: list[DeviceState]
) -> None:
    transports = await MockAdbClient(scenario).list_transports()

    assert [transport.state for transport in transports] == expected_states


@pytest.mark.asyncio
async def test_mock_timeout() -> None:
    with pytest.raises(AdbTimeoutError):
        await MockAdbClient(MockAdbScenario.TIMEOUT).list_transports()


@pytest.mark.asyncio
async def test_rooted_mock_requires_explicit_rooted_scenario() -> None:
    ordinary = await MockAdbClient().probe_root_access("FX-DEMO-001")
    rooted = await MockAdbClient(MockAdbScenario.ROOTED).probe_root_access("FX-DEMO-001")

    assert ordinary.status.value == "unavailable"
    assert rooted.status.value == "available"
    assert rooted.uid == 0


@pytest.mark.asyncio
async def test_mock_rooted_bundle_is_a_deterministic_tar(tmp_path: Path) -> None:
    destination = tmp_path / "providers.tar"
    result = await MockAdbClient(MockAdbScenario.ROOTED).capture_rooted_bundle(
        "FX-DEMO-001", RootedCollectionProfile.ANDROID_PROVIDERS, destination
    )

    assert result.size_bytes == destination.stat().st_size
    with tarfile.open(destination, "r:") as archive:
        names = archive.getnames()
    assert names == [
        "data/user_de/0/com.android.providers.contacts/databases/contacts2.db",
        "data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
    ]


@pytest.mark.asyncio
async def test_mock_rooted_bundle_rejects_ordinary_device(tmp_path: Path) -> None:
    with pytest.raises(AdbCommandError):
        await MockAdbClient().capture_rooted_bundle(
            "FX-DEMO-001",
            RootedCollectionProfile.ANDROID_PROVIDERS,
            tmp_path / "providers.tar",
        )


@pytest.mark.asyncio
async def test_mock_physical_block_requires_root_and_exact_size(tmp_path: Path) -> None:
    rooted = MockAdbClient(MockAdbScenario.ROOTED)
    probe = await rooted.probe_physical_block("FX-DEMO-001", PhysicalBlockProfile.USERDATA_BY_NAME)
    destination = tmp_path / "userdata.dd"

    capture = await rooted.capture_physical_block(
        "FX-DEMO-001",
        PhysicalBlockProfile.USERDATA_BY_NAME,
        destination,
        expected_size_bytes=probe.size_bytes,
    )

    assert probe.size_bytes == 8192
    assert capture.size_bytes == 8192
    assert destination.stat().st_size == 8192
    with pytest.raises(AdbCommandError):
        await MockAdbClient().probe_physical_block(
            "FX-DEMO-001", PhysicalBlockProfile.USERDATA_BY_NAME
        )


@pytest.mark.asyncio
async def test_mock_inventory_is_content_free_and_deterministic() -> None:
    inventory = await MockAdbClient().inventory_shared_storage(
        "FX-DEMO-001", SharedStorageRoot.EMULATED_PRIMARY
    )

    assert inventory.root_id == "emulated_primary"
    assert inventory.discovered_count == 3
    assert [entry.relative_path for entry in inventory.entries] == [
        "DCIM/Camera/IMG_0001.jpg",
        "Documents/timeline.csv",
        "Download/incident-notes.pdf",
    ]
    assert all(entry.size_bytes is not None for entry in inventory.entries)
    assert all(entry.modified_at is not None for entry in inventory.entries)
    assert all(entry.timestamp_source == "android_stat_mtime_epoch" for entry in inventory.entries)


@pytest.mark.asyncio
async def test_mock_pull_produces_known_answer_bytes(tmp_path: Path) -> None:
    destination = tmp_path / "fixture.partial"

    result = await MockAdbClient().pull_inventory_file(
        "FX-DEMO-001",
        SharedStorageRoot.EMULATED_PRIMARY,
        "Documents/timeline.csv",
        destination,
    )

    assert destination.read_bytes().startswith(b"timestamp,event")
    assert result.size_bytes == destination.stat().st_size
