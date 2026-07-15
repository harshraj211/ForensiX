"""Parsers for bounded ADB command output."""

import re
from collections.abc import Iterable

from .errors import AdbProtocolError
from .models import DeviceState, DeviceTransport

_VERSION_PATTERN = re.compile(r"Android Debug Bridge version\s+([0-9]+(?:\.[0-9]+){1,3})")
_STATE_MAP = {
    "device": DeviceState.AUTHORIZED,
    "unauthorized": DeviceState.UNAUTHORIZED,
    "offline": DeviceState.OFFLINE,
    "recovery": DeviceState.RECOVERY,
    "sideload": DeviceState.SIDELOAD,
    "bootloader": DeviceState.BOOTLOADER,
}
_GETPROP_PATTERN = re.compile(r"^\[([^]]+)]\s*:\s*\[(.*)]$")


def parse_adb_version(output: str) -> str:
    match = _VERSION_PATTERN.search(output)
    if not match:
        raise AdbProtocolError("ADB version output did not contain a supported version string.")
    return match.group(1)


def parse_devices_output(output: str) -> tuple[DeviceTransport, ...]:
    transports: list[DeviceTransport] = []
    for line in _device_lines(output.splitlines()):
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, raw_state = parts[0], parts[1]
        if not serial or any(character.isspace() or ord(character) < 32 for character in serial):
            raise AdbProtocolError("ADB returned an invalid device serial.")
        attributes: dict[str, str] = {}
        for token in parts[2:]:
            if ":" not in token:
                continue
            key, value = token.split(":", 1)
            if key and value:
                attributes[key] = value
        transports.append(
            DeviceTransport(
                serial=serial,
                state=_STATE_MAP.get(raw_state, DeviceState.UNKNOWN),
                raw_state=raw_state,
                product=attributes.get("product"),
                model=attributes.get("model"),
                device=attributes.get("device"),
                transport_id=attributes.get("transport_id"),
                usb=attributes.get("usb"),
            )
        )
    return tuple(transports)


def parse_getprop_output(output: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in output.splitlines():
        match = _GETPROP_PATTERN.match(line.strip())
        if match:
            properties[match.group(1)] = match.group(2)
    if not properties:
        raise AdbProtocolError("ADB property output did not contain any parseable properties.")
    return properties


def parse_package_list(output: str, *, maximum_packages: int = 100_000) -> tuple[str, ...]:
    packages: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("package:"):
            continue
        package_name = stripped.removeprefix("package:").split(maxsplit=1)[0]
        if not package_name or len(package_name) > 255:
            continue
        packages.append(package_name)
        if len(packages) > maximum_packages:
            raise AdbProtocolError("ADB package output exceeded the supported package count.")
    return tuple(sorted(set(packages)))


def _device_lines(lines: Iterable[str]) -> Iterable[str]:
    header_seen = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("List of devices attached"):
            header_seen = True
            continue
        if not header_seen or not stripped or stripped.startswith("*"):
            continue
        yield stripped
