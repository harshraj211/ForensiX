"""Deterministic ADB scenarios for development and acceptance tests."""

from enum import StrEnum

from .errors import AdbTimeoutError
from .models import AdbServerInfo, DeviceState, DeviceTransport


class MockAdbScenario(StrEnum):
    NO_DEVICES = "no_devices"
    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    OFFLINE = "offline"
    MULTIPLE = "multiple"
    TIMEOUT = "timeout"


class MockAdbClient:
    def __init__(self, scenario: MockAdbScenario = MockAdbScenario.AUTHORIZED) -> None:
        self.scenario = scenario

    async def server_info(self) -> AdbServerInfo:
        if self.scenario is MockAdbScenario.TIMEOUT:
            raise AdbTimeoutError(5.0)
        return AdbServerInfo(
            version="1.0.41",
            executable_path="mock://adb",
            raw_output="Android Debug Bridge version 1.0.41",
        )

    async def list_transports(self) -> tuple[DeviceTransport, ...]:
        if self.scenario is MockAdbScenario.TIMEOUT:
            raise AdbTimeoutError(5.0)
        if self.scenario is MockAdbScenario.NO_DEVICES:
            return ()
        if self.scenario is MockAdbScenario.MULTIPLE:
            return (
                self._transport("FX-DEMO-001", DeviceState.AUTHORIZED),
                self._transport("FX-DEMO-002", DeviceState.UNAUTHORIZED),
            )
        state = {
            MockAdbScenario.AUTHORIZED: DeviceState.AUTHORIZED,
            MockAdbScenario.UNAUTHORIZED: DeviceState.UNAUTHORIZED,
            MockAdbScenario.OFFLINE: DeviceState.OFFLINE,
        }[self.scenario]
        return (self._transport("FX-DEMO-001", state),)

    @staticmethod
    def _transport(serial: str, state: DeviceState) -> DeviceTransport:
        raw_state = "device" if state is DeviceState.AUTHORIZED else state.value
        return DeviceTransport(
            serial=serial,
            state=state,
            raw_state=raw_state,
            product="forensix_demo",
            model="Controlled_Test_Device",
            device="fx_virtual",
            transport_id="1",
            usb="1-1",
        )
