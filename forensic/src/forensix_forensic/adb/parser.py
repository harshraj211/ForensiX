"""Parsers for bounded ADB command output."""

import re
from collections.abc import Iterable
from datetime import UTC, datetime

from .errors import AdbProtocolError
from .models import (
    ContentProviderQueryResult,
    ContentProviderRecord,
    DeviceState,
    DeviceTransport,
    StorageInventoryEntry,
    StorageInventoryResult,
)
from .policy import ContentProviderProfile

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


def parse_dumpsys_battery(output: str) -> dict[str, str]:
    battery_info: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if ":" in line:
            key, value = line.split(":", 1)
            battery_info[key.strip()] = value.strip()
    return battery_info


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


def parse_content_provider_rows(
    output: str,
    *,
    profile: ContentProviderProfile,
    projection: tuple[str, ...],
    max_records: int,
) -> ContentProviderQueryResult:
    """Parse fixed `content query` rows without executing row-derived text."""
    if max_records < 1:
        raise ValueError("content-provider record limit must be positive")
    records: list[ContentProviderRecord] = []
    discovered_count = 0
    for line in output.splitlines():
        match = re.match(r"^Row:\s+\d+\s+(.*)$", line.strip())
        if match is None:
            continue
        discovered_count += 1
        if len(records) >= max_records:
            continue
        values = _parse_projected_values(match.group(1), projection)
        if values is not None:
            records.append(ContentProviderRecord(values=values))
    return ContentProviderQueryResult(
        profile=profile.value,
        records=tuple(records),
        discovered_count=discovered_count,
        truncated=discovered_count > len(records),
        max_records=max_records,
    )


def _parse_projected_values(
    payload: str, projection: tuple[str, ...]
) -> dict[str, str | None] | None:
    values: dict[str, str | None] = {}
    remainder = payload
    for index, key in enumerate(projection):
        prefix = f"{key}="
        if not remainder.startswith(prefix):
            return None
        remainder = remainder[len(prefix) :]
        if index + 1 < len(projection):
            next_key = projection[index + 1]
            marker = f", {next_key}="
            value, separator, tail = remainder.partition(marker)
            if not separator:
                return None
            remainder = f"{next_key}={tail}"
        else:
            value = remainder
            remainder = ""
        values[key] = None if value == "NULL" else value
    return values


def parse_storage_inventory(
    output: str,
    *,
    root_id: str,
    display_path: str,
    max_items: int,
    max_depth: int,
) -> StorageInventoryResult:
    """Parse fixed stat records without reusing device paths as command arguments."""
    if max_items < 1 or max_depth < 1:
        raise ValueError("inventory limits must be positive")
    prefix = display_path.rstrip("/") + "/"
    legacy_nul_format = "\x00" in output
    records = (
        [item for item in output.split("\x00") if item]
        if "\x00" in output
        else [item for item in output.splitlines() if item]
    )
    accepted: list[StorageInventoryEntry] = []
    seen: set[str] = set()
    skipped = 0
    truncated = False
    for record in records:
        absolute_path, size_bytes, modified_raw, modified_at = _inventory_record(
            record, parse_metadata=not legacy_nul_format
        )
        if absolute_path is None:
            skipped += 1
            continue
        if not absolute_path.startswith(prefix):
            skipped += 1
            continue
        relative_path = absolute_path[len(prefix) :]
        parts = relative_path.split("/")
        if (
            not relative_path
            or len(relative_path) > 1024
            or len(parts) > max_depth
            or any(not part or part in {".", ".."} for part in parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in relative_path)
        ):
            skipped += 1
            continue
        if relative_path in seen:
            skipped += 1
            continue
        seen.add(relative_path)
        if len(accepted) >= max_items:
            truncated = True
            continue
        accepted.append(
            StorageInventoryEntry(
                relative_path=relative_path,
                size_bytes=size_bytes,
                modified_time_raw=modified_raw,
                modified_at=modified_at,
                timestamp_source=("android_stat_mtime_epoch" if modified_at is not None else None),
                timestamp_confidence="medium" if modified_at is not None else None,
            )
        )
    return StorageInventoryResult(
        root_id=root_id,
        display_path=display_path,
        entries=tuple(accepted),
        discovered_count=len(records),
        skipped_count=skipped,
        truncated=truncated,
        max_items=max_items,
        max_depth=max_depth,
    )


def _inventory_record(
    record: str, *, parse_metadata: bool
) -> tuple[str | None, int | None, str | None, datetime | None]:
    """Decode `path:size:mtime` while retaining legacy path-only fixtures."""
    if parse_metadata and record.count(":") >= 2:
        path, size_raw, modified_raw = record.rsplit(":", 2)
        try:
            size_bytes = int(size_raw)
            epoch_seconds = int(modified_raw)
            if size_bytes < 0 or not 0 <= epoch_seconds <= 253_402_300_799:
                raise ValueError
            modified_at = datetime.fromtimestamp(epoch_seconds, tz=UTC)
            return path, size_bytes, modified_raw, modified_at
        except (OverflowError, OSError, ValueError):
            return None, None, None, None
    if parse_metadata:
        return None, None, None, None
    return record, None, None, None


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
