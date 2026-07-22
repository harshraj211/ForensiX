from datetime import UTC, datetime

from forensix_forensic.adb import (
    AdbClient,
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    ContentProviderAccessStatus,
    ContentProviderProfile,
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
        provider_probes = {
            profile: await self._adb_client.probe_content_provider(serial, profile)
            for profile in ContentProviderProfile
        }
        sdk_level = _parse_sdk_level(properties.get("ro.build.version.sdk"))
        accessible_roots = tuple(root for root in storage_roots if root.readable)
        shared_file_decision = (
            _supported(
                "SHARED_STORAGE_ROOT_READABLE",
                "Accessible shared storage can be filtered for this artifact category.",
            )
            if accessible_roots
            else _blocked(
                "SHARED_STORAGE_NOT_READABLE",
                "No approved shared-storage root is currently readable.",
            )
        )
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
            "download_files": shared_file_decision,
            "media_files": shared_file_decision,
            "document_files": shared_file_decision,
            "contacts": _provider_decision(provider_probes[ContentProviderProfile.CONTACTS]),
            "sms_mms": _provider_decision(provider_probes[ContentProviderProfile.SMS]),
            "call_logs": _provider_decision(provider_probes[ContentProviderProfile.CALL_LOG]),
            "calendar": _elevated_only("READ_CALENDAR_REQUIRED"),
            "notifications": _elevated_only("NOTIFICATION_LISTENER_ACCESS_REQUIRED"),
            "wifi_records": _elevated_only("PRIVILEGED_WIFI_ACCESS_REQUIRED"),
            "bluetooth_records": _elevated_only("PRIVILEGED_BLUETOOTH_ACCESS_REQUIRED"),
            "location_artifacts": _elevated_only("PRIVATE_LOCATION_DATA_INACCESSIBLE"),
            "browser_history": _elevated_only("PRIVATE_BROWSER_DATA_INACCESSIBLE"),
            "whatsapp_private_data": _private_app_only("WhatsApp"),
            "telegram_private_data": _private_app_only("Telegram"),
            "signal_private_data": _private_app_only("Signal"),
            "messenger_private_data": _private_app_only("Messenger"),
            "instagram_private_data": _private_app_only("Instagram"),
            "facebook_private_data": _private_app_only("Facebook"),
            "snapchat_private_data": _private_app_only("Snapchat"),
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


def _blocked(reason_code: str, explanation: str) -> CapabilityDecision:
    return CapabilityDecision(
        status=CapabilityStatus.BLOCKED,
        reason_code=reason_code,
        explanation=explanation,
    )


def _elevated_only(reason_code: str) -> CapabilityDecision:
    return _unsupported(
        reason_code,
        (
            "Ordinary non-rooted ADB shell access does not hold the Android permission "
            "required for this provider."
        ),
    )


def _provider_decision(probe: object) -> CapabilityDecision:
    from forensix_forensic.adb import ContentProviderAccessProbe

    if not isinstance(probe, ContentProviderAccessProbe):
        raise TypeError("Expected a content-provider probe")
    if probe.status is ContentProviderAccessStatus.AVAILABLE:
        return _supported(probe.reason_code, probe.explanation)
    if probe.status is ContentProviderAccessStatus.DENIED:
        return _unsupported(probe.reason_code, probe.explanation)
    if probe.status is ContentProviderAccessStatus.MISSING:
        return _unsupported(probe.reason_code, probe.explanation)
    return CapabilityDecision(
        status=CapabilityStatus.UNKNOWN,
        reason_code=probe.reason_code,
        explanation=probe.explanation,
    )


def _private_app_only(application_name: str) -> CapabilityDecision:
    return _unsupported(
        "PRIVATE_APP_SANDBOX_INACCESSIBLE",
        (
            f"{application_name} private databases are sandboxed and unavailable to ordinary "
            "non-rooted ADB."
        ),
    )
