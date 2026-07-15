import pytest

from forensix_forensic.adb.errors import AdbTimeoutError
from forensix_forensic.adb.mock import MockAdbClient, MockAdbScenario
from forensix_forensic.adb.models import DeviceState


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "expected_states"),
    [
        (MockAdbScenario.NO_DEVICES, []),
        (MockAdbScenario.AUTHORIZED, [DeviceState.AUTHORIZED]),
        (MockAdbScenario.UNAUTHORIZED, [DeviceState.UNAUTHORIZED]),
        (MockAdbScenario.OFFLINE, [DeviceState.OFFLINE]),
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
