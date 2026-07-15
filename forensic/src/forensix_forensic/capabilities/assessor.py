from datetime import UTC, datetime

from forensix_forensic.adb import (
    AdbClient,
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    DeviceState,
)

from .models import CapabilityDecision, CapabilityStatus, DeviceCapabilitySnapshot


class DeviceCapabilityAssessor:
    def __init__(self, adb_client: AdbClient) -> None:
        self._adb_client = adb_client

    async def assess(self, serial: str) -> DeviceCapabilitySnapshot:
        transports = await self._adb_client.list_transports()
        transport = next((item for item in transports if item.serial == serial), None)
        if transport is None:
            raise AdbDeviceNotFoundError
        if transport.state is not DeviceState.AUTHORIZED:
            raise AdbDeviceNotAuthorizedError(transport.state.value)

        properties = await self._adb_client.get_properties(serial)
        packages = await self._adb_client.list_packages(serial)
        storage_roots = await self._adb_client.probe_shared_storage(serial)
        sdk_level = _parse_sdk_level(properties.get("ro.build.version.sdk"))
        accessible_roots = tuple(root for root in storage_roots if root.readable)
        capabilities = {
            "device_metadata": _supported(
                "ADB_PROPERTY_ACCESS",
                "Core Android build properties were retrieved through an approved operation.",
            ),
            "package_inventory": _supported(
                "ADB_PACKAGE_LIST_ACCESS",
                (
                    "Package identifiers are accessible; Android visibility rules may still "
                    "limit coverage."
                ),
            ),
            "shared_storage": (
                _supported(
                    "SHARED_STORAGE_ROOT_READABLE",
                    (
                        f"{len(accessible_roots)} fixed shared-storage root(s) passed content-free "
                        "directory and readability checks."
                    ),
                )
                if accessible_roots
                else CapabilityDecision(
                    status=CapabilityStatus.BLOCKED,
                    reason_code="SHARED_STORAGE_NOT_READABLE",
                    explanation=(
                        "No approved shared-storage root passed both directory and readability "
                        "checks."
                    ),
                )
            ),
            "private_app_data": _unsupported(
                "PRIVATE_APP_DATA_INACCESSIBLE",
                "ADB authorization does not grant access to private application sandboxes.",
            ),
            "deleted_data_recovery": _unsupported(
                "BLOCK_ACCESS_UNAVAILABLE",
                (
                    "Ordinary ADB does not provide the block-level access required for reliable "
                    "recovery."
                ),
            ),
        }
        return DeviceCapabilitySnapshot(
            assessed_at=datetime.now(UTC),
            serial=serial,
            manufacturer=properties.get("ro.product.manufacturer"),
            model=properties.get("ro.product.model"),
            android_version=properties.get("ro.build.version.release"),
            sdk_level=sdk_level,
            build_fingerprint=properties.get("ro.build.fingerprint"),
            security_patch=properties.get("ro.build.version.security_patch"),
            package_count=len(packages),
            storage_roots=storage_roots,
            capabilities=capabilities,
            warnings=(
                "Private application data is not accessible on this non-rooted logical transport.",
                "Capability results apply only to this observed device state and can become stale.",
                (
                    "Storage probing checks fixed root accessibility only; it does not enumerate, "
                    "copy, or prove completeness of any evidence content."
                ),
            ),
        )


def _parse_sdk_level(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _supported(reason_code: str, explanation: str) -> CapabilityDecision:
    return CapabilityDecision(
        status=CapabilityStatus.SUPPORTED,
        reason_code=reason_code,
        explanation=explanation,
    )


def _unsupported(reason_code: str, explanation: str) -> CapabilityDecision:
    return CapabilityDecision(
        status=CapabilityStatus.UNSUPPORTED,
        reason_code=reason_code,
        explanation=explanation,
    )
