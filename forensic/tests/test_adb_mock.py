import pytest

from forensix_forensic.adb.errors import AdbTimeoutError
from forensix_forensic.adb.mock import MockAdbClient, MockAdbScenario
from forensix_forensic.adb.models import DeviceState
from forensix_forensic.adb.policy import SharedStorageRoot


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "expected_states"),
    [
        (MockAdbScenario.NO_DEVICES, []),
        (MockAdbScenario.AUTHORIZED, [DeviceState.AUTHORIZED]),
        (MockAdbScenario.UNAUTHORIZED, [DeviceState.UNAUTHORIZED]),
        (MockAdbScenario.OFFLINE, [DeviceState.OFFLINE]),
        (MockAdbScenario.STORAGE_BLOCKED, [DeviceState.AUTHORIZED]),
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
