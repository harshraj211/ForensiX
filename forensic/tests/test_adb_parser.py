import pytest

from forensix_forensic.adb.models import DeviceState
from forensix_forensic.adb.parser import (
    parse_adb_version,
    parse_devices_output,
    parse_getprop_output,
    parse_package_list,
)


def test_parse_version() -> None:
    assert parse_adb_version("Android Debug Bridge version 1.0.41\nVersion 35.0.2") == "1.0.41"


def test_parse_no_devices() -> None:
    assert parse_devices_output("List of devices attached\n\n") == ()


@pytest.mark.parametrize(
    ("raw_state", "expected"),
    [
        ("device", DeviceState.AUTHORIZED),
        ("unauthorized", DeviceState.UNAUTHORIZED),
        ("offline", DeviceState.OFFLINE),
        ("mystery", DeviceState.UNKNOWN),
    ],
)
def test_parse_transport_states(raw_state: str, expected: DeviceState) -> None:
    output = (
        "* daemon started successfully *\n"
        "List of devices attached\n"
        f"ABC123\t{raw_state} product:pixel model:Pixel_9 device:komodo transport_id:4\n"
    )

    [transport] = parse_devices_output(output)

    assert transport.state is expected
    assert transport.serial == "ABC123"
    assert transport.model == "Pixel_9"
    assert transport.transport_id == "4"


def test_parse_multiple_devices_preserves_order() -> None:
    output = "List of devices attached\nA\tdevice\nB\tunauthorized\n"

    transports = parse_devices_output(output)

    assert [transport.serial for transport in transports] == ["A", "B"]


def test_parse_properties_and_packages() -> None:
    properties = parse_getprop_output(
        "[ro.product.model]: [Pixel 9]\n[ro.build.version.sdk]: [35]\n"
    )
    packages = parse_package_list("package:com.example.z\npackage:com.example.a\nnoise\n")

    assert properties["ro.product.model"] == "Pixel 9"
    assert packages == ("com.example.a", "com.example.z")
