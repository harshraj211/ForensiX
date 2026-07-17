import pytest

from forensix_forensic.adb.models import DeviceState
from forensix_forensic.adb.parser import (
    parse_adb_version,
    parse_devices_output,
    parse_getprop_output,
    parse_package_list,
    parse_storage_inventory,
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


def test_inventory_parser_rejects_unsafe_paths_and_enforces_item_limit() -> None:
    output = "\x00".join(
        (
            "/sdcard/DCIM/IMG_1.jpg",
            "/sdcard/Download/report.pdf",
            "/sdcard/Download/report.pdf",
            "/data/local/tmp/outside.txt",
            "/sdcard/bad\nname.txt",
            "/sdcard/a/b/c/d/e/f/too-deep.txt",
            "/sdcard/Pictures/third.jpg",
            "",
        )
    )

    inventory = parse_storage_inventory(
        output,
        root_id="primary_alias",
        display_path="/sdcard",
        max_items=2,
        max_depth=6,
    )

    assert [entry.relative_path for entry in inventory.entries] == [
        "DCIM/IMG_1.jpg",
        "Download/report.pdf",
    ]
    assert inventory.discovered_count == 7
    assert inventory.skipped_count == 4
    assert inventory.truncated is True


def test_inventory_parser_preserves_validated_stat_metadata() -> None:
    inventory = parse_storage_inventory(
        "/sdcard/Documents/report:final.pdf:4096:1784160000\n",
        root_id="primary_alias",
        display_path="/sdcard",
        max_items=10,
        max_depth=6,
    )

    assert len(inventory.entries) == 1
    entry = inventory.entries[0]
    assert entry.relative_path == "Documents/report:final.pdf"
    assert entry.size_bytes == 4096
    assert entry.modified_time_raw == "1784160000"
    assert entry.modified_at is not None
    assert entry.modified_at.isoformat() == "2026-07-16T00:00:00+00:00"
    assert entry.timestamp_source == "android_stat_mtime_epoch"
    assert entry.timestamp_confidence == "medium"


def test_inventory_parser_skips_malformed_or_out_of_range_stat_records() -> None:
    inventory = parse_storage_inventory(
        "/sdcard/bad.txt:not-a-size:1784160000\n/sdcard/future.txt:10:999999999999999\n",
        root_id="primary_alias",
        display_path="/sdcard",
        max_items=10,
        max_depth=6,
    )

    assert inventory.entries == ()
    assert inventory.discovered_count == 2
    assert inventory.skipped_count == 2
