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
        sdk_level = _parse_sdk_level(properties.get("ro.build.version.sdk"))
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
            "shared_storage": CapabilityDecision(
                status=CapabilityStatus.UNKNOWN,
                reason_code="STORAGE_PROBE_PENDING",
                explanation="Shared-storage roots have not been probed in this assessment stage.",
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
            capabilities=capabilities,
            warnings=(
                "Private application data is not accessible on this non-rooted logical transport.",
                "Capability results apply only to this observed device state and can become stale.",
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
