from datetime import UTC, date, datetime
from typing import Any

from forensix_forensic.adb import (
    AdbClient,
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    ContentProviderAccessStatus,
    ContentProviderProfile,
    DeviceState,
)

from .locked_device import assess_locked_device
from .models import (
    AcquisitionReadiness,
    CapabilityDecision,
    CapabilityStatus,
    DeviceCapabilitySnapshot,
    TemporaryRootReadiness,
)
from .temporary_root import (
    TEMPORARY_ROOT_PROFILES,
    find_temporary_root_profile,
    find_temporary_root_research_candidate,
)

_TEMPORARY_ROOT_MIN_ANDROID = 4
_TEMPORARY_ROOT_MAX_ANDROID = 10
_TEMPORARY_ROOT_MAX_SECURITY_PATCH = date(2019, 10, 31)


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

        try:
            battery_info = await self._adb_client.get_battery(serial)
            battery_level_str = battery_info.get("level")
            battery_level = (
                int(battery_level_str)
                if battery_level_str and battery_level_str.isdigit()
                else None
            )

            # Map the Android BatteryManager status constants when the value is available.
            status_val = battery_info.get("status")
            status_map = {
                "1": "unknown",
                "2": "charging",
                "3": "discharging",
                "4": "not charging",
                "5": "full",
            }
            battery_status = status_map.get(status_val, status_val) if status_val else None
        except Exception:
            battery_level = None
            battery_status = None

        packages = await self._adb_client.list_packages(serial)
        storage_roots = await self._adb_client.probe_shared_storage(serial)
        provider_probes = {
            profile: await self._adb_client.probe_content_provider(serial, profile)
            for profile in ContentProviderProfile
        }
        sdk_level = _parse_sdk_level(properties.get("ro.build.version.sdk"))
        acquisition_readiness = _acquisition_readiness(properties, sdk_level)
        temporary_root_readiness = _temporary_root_readiness(properties)
        locked_device_readiness = assess_locked_device(
            android_api=sdk_level,
            android_release=properties.get("ro.build.version.release"),
            manufacturer=properties.get("ro.product.manufacturer"),
            model=properties.get("ro.product.model"),
            chipset_family=acquisition_readiness.chipset_family,
            chipset_model=properties.get("ro.soc.model"),
            encryption_type=acquisition_readiness.encryption_type,
            security_patch=properties.get("ro.build.version.security_patch"),
        )
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
            battery_level=battery_level,
            battery_status=battery_status,
            acquisition_readiness=acquisition_readiness,
            temporary_root_readiness=temporary_root_readiness,
            locked_device_readiness=locked_device_readiness,
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


def _temporary_root_readiness(properties: dict[str, str]) -> TemporaryRootReadiness:
    android_version = properties.get("ro.build.version.release")
    security_patch = properties.get("ro.build.version.security_patch")
    android_major = _parse_android_major(android_version)
    patch_date = _parse_security_patch(security_patch)
    matched_profile = find_temporary_root_profile(properties)
    research_candidate = find_temporary_root_research_candidate(properties)
    provider_status = (
        "exact_profile_match"
        if matched_profile is not None
        else "no_exact_profile_match"
        if TEMPORARY_ROOT_PROFILES
        else "not_configured"
    )
    common: dict[str, Any] = {
        "provider_status": provider_status,
        "reference_android_range": "4.0-10.0",
        "reference_max_security_patch": _TEMPORARY_ROOT_MAX_SECURITY_PATCH.isoformat(),
        "research_profile_id": research_candidate.candidate_id if research_candidate else None,
    }

    if android_major is None:
        return TemporaryRootReadiness(
            eligibility_status="unknown",
            explanation=(
                "Android release could not be determined. A model, firmware, chipset, build "
                "fingerprint, and security-patch match is required before any temporary-root "
                "provider can be considered."
            ),
            **common,
        )
    if not _TEMPORARY_ROOT_MIN_ANDROID <= android_major <= _TEMPORARY_ROOT_MAX_ANDROID:
        return TemporaryRootReadiness(
            eligibility_status="outside_reference_range",
            explanation=(
                f"Android {android_version} is outside the published Android 4.0-10.0 "
                "temporary-root reference range. No validated provider is configured."
            ),
            **common,
        )
    if security_patch and patch_date is None:
        return TemporaryRootReadiness(
            eligibility_status="unknown_patch_format",
            explanation=(
                f"Android {android_version} is within the reference version range, but the "
                "reported security patch could not be interpreted. Exact firmware and exploit-"
                "profile validation is still required."
            ),
            **common,
        )
    if patch_date is None:
        return TemporaryRootReadiness(
            eligibility_status="reference_range_requires_verification",
            explanation=(
                f"Android {android_version} is within the reference version range, but no "
                "security-patch date was reported. Exact model, chipset, firmware, and a "
                "validated exploit profile are required."
            ),
            **common,
        )
    if patch_date > _TEMPORARY_ROOT_MAX_SECURITY_PATCH:
        return TemporaryRootReadiness(
            eligibility_status="patch_too_new",
            explanation=(
                f"The {patch_date.isoformat()} security patch is newer than the October 2019 "
                "temporary-root reference limit. No validated provider is configured."
            ),
            **common,
        )
    return TemporaryRootReadiness(
        eligibility_status="candidate_requires_validated_profile",
        explanation=(
            f"Android {android_version} with security patch {patch_date.isoformat()} falls within "
            "the published version-and-patch reference range. This is only an eligibility hint: "
            "the exact model, chipset, firmware, and build fingerprint must match a validated "
            "provider before temporary root can run."
        ),
        **common,
    )


def _parse_android_major(value: str | None) -> int | None:
    if value is None:
        return None
    major = value.strip().split(".", maxsplit=1)[0]
    return int(major) if major.isdigit() else None


def _parse_security_patch(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def _acquisition_readiness(
    properties: dict[str, str], sdk_level: int | None
) -> AcquisitionReadiness:
    crypto_type = properties.get("ro.crypto.type", "").strip().lower()
    crypto_state = properties.get("ro.crypto.state", "").strip().lower()
    encryption_type = (
        "file_based"
        if crypto_type == "file"
        else "full_disk"
        if crypto_type == "block"
        else "unencrypted"
        if crypto_state in {"unencrypted", "unsupported"}
        else "unknown"
    )
    credential_property = properties.get("sys.user.0.ce_available", "").strip().lower()
    credential_storage_state = (
        "unlocked"
        if credential_property in {"1", "true", "yes"}
        else "locked"
        if credential_property in {"0", "false", "no"}
        else "unknown"
    )
    platform = " ".join(
        (
            properties.get("ro.board.platform", ""),
            properties.get("ro.hardware", ""),
            properties.get("ro.soc.manufacturer", ""),
        )
    ).lower()
    chipset_family = (
        "qualcomm"
        if any(
            marker in platform for marker in ("qualcomm", "qcom", "msm", "sdm", "sm6", "sm7", "sm8")
        )
        else "mediatek"
        if any(marker in platform for marker in ("mediatek", "mtk", "mt67", "mt68", "mt69"))
        else "samsung_exynos"
        if "exynos" in platform
        else "google_tensor"
        if "tensor" in platform
        else "unisoc"
        if any(marker in platform for marker in ("unisoc", "spreadtrum", "ums", "sc98"))
        else "kirin"
        if any(marker in platform for marker in ("kirin", "hi3660", "hi3670"))
        else "rockchip"
        if any(marker in platform for marker in ("rockchip", "rk3562"))
        else "unknown"
    )
    if credential_storage_state == "locked":
        filesystem_status = "unlock_required"
        explanation = (
            "Credential-encrypted user storage is locked. Unlock the device before any "
            "root-assisted plaintext filesystem snapshot."
        )
    elif credential_storage_state == "unlocked" and sdk_level is not None and 28 <= sdk_level <= 34:
        filesystem_status = "root_required"
        explanation = (
            "Credential storage is unlocked on Android 9-14. A fresh authorized root proof is "
            "still required to access private application and system paths."
        )
    elif credential_storage_state == "unlocked":
        filesystem_status = "root_required_unvalidated_version"
        explanation = (
            "Credential storage is unlocked, but this Android version is outside the validated "
            "Android 9-14 range; root-assisted collection may be incomplete."
        )
    else:
        filesystem_status = "root_and_unlock_verification_required"
        explanation = (
            "Android did not expose a reliable credential-storage state. Confirm the device is "
            "unlocked and obtain a fresh authorized root proof before filesystem collection."
        )
    return AcquisitionReadiness(
        encryption_type=encryption_type,
        credential_storage_state=credential_storage_state,
        chipset_family=chipset_family,
        filesystem_status=filesystem_status,
        explanation=explanation,
    )


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
