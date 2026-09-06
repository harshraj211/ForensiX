import logging
from datetime import UTC, date, datetime
from typing import Any

from forensix_forensic.adb import (
    AdbClient,
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    ContentProviderAccessProbe,
    ContentProviderAccessStatus,
    ContentProviderProfile,
    DeviceState,
)

from .locked_device import assess_locked_device
from .models import (
    AcquisitionReadiness,
    AndroidDeviceState,
    CapabilityDecision,
    CapabilityStatus,
    DeviceCapabilitySnapshot,
    LockedDeviceReadiness,
    TemporaryRootReadiness,
)
from .temporary_root import (
    TEMPORARY_ROOT_PROFILES,
    find_temporary_root_profile,
    find_temporary_root_research_candidate,
)

logger = logging.getLogger(__name__)

_TEMPORARY_ROOT_MIN_ANDROID = 4
_TEMPORARY_ROOT_MAX_ANDROID = 10
_TEMPORARY_ROOT_MAX_SECURITY_PATCH = date(2019, 10, 31)


class DeviceCapabilityAssessor:
    """Non-destructive read-only device state and capability assessor."""

    def __init__(self, adb_client: AdbClient) -> None:
        self._adb_client = adb_client

    async def assess(
        self, serial: str, *, allow_unauthorized: bool = False
    ) -> DeviceCapabilitySnapshot:
        transports = await self._adb_client.list_transports()
        transport = next((item for item in transports if item.serial == serial), None)
        if transport is None:
            raise AdbDeviceNotFoundError

        if transport.state is not DeviceState.AUTHORIZED and not allow_unauthorized:
            raise AdbDeviceNotAuthorizedError(transport.state.value)

        is_authorized = transport.state is DeviceState.AUTHORIZED

        properties: dict[str, str] = {}
        battery_level: int | None = None
        battery_status: str | None = None
        packages: tuple[str, ...] = ()
        storage_roots: tuple[Any, ...] = ()
        provider_probes: dict[ContentProviderProfile, ContentProviderAccessProbe] = {}
        secure_settings: dict[str, str] = {}
        root_verified = False

        if is_authorized:
            try:
                properties = await self._adb_client.get_properties(serial)
            except Exception:
                properties = {}

            try:
                battery_info = await self._adb_client.get_battery(serial)
                battery_level_str = battery_info.get("level")
                battery_level = (
                    int(battery_level_str)
                    if battery_level_str and battery_level_str.isdigit()
                    else None
                )
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

            try:
                packages = await self._adb_client.list_packages(serial)
            except Exception:
                packages = ()

            try:
                storage_roots = await self._adb_client.probe_shared_storage(serial)
            except Exception:
                storage_roots = ()

            for profile in ContentProviderProfile:
                try:
                    provider_probes[profile] = await self._adb_client.probe_content_provider(
                        serial, profile
                    )
                except Exception:
                    provider_probes[profile] = ContentProviderAccessProbe(
                        profile=profile.value if hasattr(profile, "value") else str(profile),
                        status=ContentProviderAccessStatus.MISSING,
                        reason_code="PROBE_FAILED",
                        explanation=f"Content provider probe for {profile.value} failed.",
                        exit_code=1,
                    )

            secure_settings = await self._probe_secure_settings(serial)
            root_verified = await self._probe_root_verified(serial)

        sdk_level = _parse_sdk_level(properties.get("ro.build.version.sdk"))
        acquisition_readiness = _acquisition_readiness(properties, sdk_level)
        temporary_root_readiness = _temporary_root_readiness(properties)
        locked_device_readiness = assess_locked_device(
            android_api=sdk_level,
            android_release=properties.get("ro.build.version.release"),
            manufacturer=properties.get("ro.product.manufacturer"),
            model=properties.get("ro.product.model"),
            chipset_family=acquisition_readiness.chipset_family,
            chipset_model=properties.get("ro.soc.model") or properties.get("ro.hardware"),
            encryption_type=acquisition_readiness.encryption_type,
            security_patch=properties.get("ro.build.version.security_patch"),
        )
        accessible_roots = tuple(root for root in storage_roots if getattr(root, "readable", False))

        device_state = _derive_device_state(
            properties=properties,
            transport_state=transport.state.value if transport else "unknown",
            is_authorized=is_authorized,
            sdk_level=sdk_level,
            acquisition_readiness=acquisition_readiness,
            temporary_root_readiness=temporary_root_readiness,
            accessible_roots=accessible_roots,
            root_verified=root_verified,
            secure_settings=secure_settings,
        )

        capabilities = _build_capabilities(
            is_authorized=is_authorized,
            sdk_level=sdk_level,
            accessible_roots=accessible_roots,
            provider_probes=provider_probes,
            device_state=device_state,
            temporary_root_readiness=temporary_root_readiness,
            locked_device_readiness=locked_device_readiness,
            root_verified=root_verified,
        )

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
            device_state=device_state,
            acquisition_readiness=acquisition_readiness,
            temporary_root_readiness=temporary_root_readiness,
            locked_device_readiness=locked_device_readiness,
            capabilities=capabilities,
            warnings=_build_warnings(is_authorized, root_verified, accessible_roots),
        )

    async def _probe_secure_settings(self, serial: str) -> dict[str, str]:
        results: dict[str, str] = {}
        for setting_key in (
            "enabled_accessibility_services",
            "enabled_notification_listeners",
        ):
            try:
                val = await self._adb_client.shell(serial, f"settings get secure {setting_key}")
                clean_val = val.strip()
                if (
                    clean_val
                    and "error" not in clean_val.lower()
                    and "null" not in clean_val.lower()
                ):
                    results[setting_key] = clean_val
            except Exception as exc:
                logger.debug("Failed querying setting %s: %s", setting_key, exc)
        return results

    async def _probe_root_verified(self, serial: str) -> bool:
        try:
            output = await self._adb_client.shell(serial, "id")
            if "uid=0(root)" in output.lower():
                return True
        except Exception as exc:
            logger.debug("Root probe shell failed: %s", exc)
        return False


def _derive_device_state(
    *,
    properties: dict[str, str],
    transport_state: str,
    is_authorized: bool,
    sdk_level: int | None,
    acquisition_readiness: AcquisitionReadiness,
    temporary_root_readiness: TemporaryRootReadiness,
    accessible_roots: tuple[Any, ...],
    root_verified: bool,
    secure_settings: dict[str, str],
) -> AndroidDeviceState:
    ce_prop = properties.get("sys.user.0.ce_available", "").strip().lower()
    if ce_prop in {"1", "true", "yes"}:
        lock_state = "unlocked"
    elif ce_prop in {"0", "false", "no"}:
        lock_state = "locked"
    elif not is_authorized:
        lock_state = "unknown"
    else:
        lock_state = "unknown"

    if root_verified:
        root_state = "rooted"
    elif temporary_root_readiness.eligibility_status in {
        "exact_profile_match",
        "candidate_requires_validated_profile",
    }:
        root_state = "temporary_root_eligible"
    elif is_authorized:
        root_state = "non_rooted"
    else:
        root_state = "unknown"

    if accessible_roots:
        storage_access_state = "readable"
        shared_storage_state = (
            "full_access" if (sdk_level is not None and sdk_level < 30) else "scoped_access"
        )
    elif is_authorized:
        storage_access_state = "restricted"
        shared_storage_state = "denied"
    else:
        storage_access_state = "inaccessible"
        shared_storage_state = "unknown"

    accessibility_setting = secure_settings.get("enabled_accessibility_services", "")
    if "forensix" in accessibility_setting.lower():
        accessibility_state = "enabled_authorized"
    elif accessibility_setting:
        accessibility_state = "installed_unauthorized"
    elif is_authorized:
        accessibility_state = "not_installed"
    else:
        accessibility_state = "unknown"

    notification_setting = secure_settings.get("enabled_notification_listeners", "")
    if "forensix" in notification_setting.lower():
        notification_listener_state = "granted"
    elif is_authorized:
        notification_listener_state = "not_granted"
    else:
        notification_listener_state = "unknown"

    bootloader_prop = (
        properties.get("ro.boot.flash.locked", properties.get("ro.boot.verifiedbootstate", ""))
        .strip()
        .lower()
    )
    if bootloader_prop in {"0", "unlocked", "orange", "yellow"}:
        bootloader_state = "unlocked"
    elif bootloader_prop in {"1", "locked", "green"}:
        bootloader_state = "locked"
    else:
        bootloader_state = "unknown"

    return AndroidDeviceState(
        adb_state=transport_state,
        authorization_state="authorized" if is_authorized else "unauthorized",
        lock_state=lock_state,
        root_state=root_state,
        encryption_state=acquisition_readiness.encryption_type,
        storage_access_state=storage_access_state,
        accessibility_state=accessibility_state,
        usage_stats_state="granted" if is_authorized else "unknown",
        notification_listener_state=notification_listener_state,
        shared_storage_state=shared_storage_state,
        bootloader_state=bootloader_state,
        chipset_family=acquisition_readiness.chipset_family,
        chipset_model=properties.get("ro.soc.model") or properties.get("ro.hardware"),
    )


def _build_capabilities(
    *,
    is_authorized: bool,
    sdk_level: int | None,
    accessible_roots: tuple[Any, ...],
    provider_probes: dict[ContentProviderProfile, ContentProviderAccessProbe],
    device_state: AndroidDeviceState,
    temporary_root_readiness: TemporaryRootReadiness,
    locked_device_readiness: LockedDeviceReadiness,
    root_verified: bool,
) -> dict[str, CapabilityDecision]:
    shared_file_decision = (
        _decision(
            status=CapabilityStatus.SUPPORTED,
            reason_code="SHARED_STORAGE_ROOT_READABLE",
            explanation="Accessible shared storage can be filtered for this artifact category.",
            capability="SHARED_STORAGE",
            evidence=f"Shared storage state is {device_state.shared_storage_state}.",
            limitations="Limited to public media and documents.",
        )
        if accessible_roots
        else _decision(
            status=CapabilityStatus.BLOCKED if is_authorized else CapabilityStatus.UNKNOWN,
            reason_code="SHARED_STORAGE_NOT_READABLE",
            explanation="No approved shared-storage root is currently readable.",
            capability="SHARED_STORAGE",
            evidence="Shared storage probes returned 0 readable roots.",
            limitations="Public shared files cannot be retrieved.",
        )
    )

    capabilities: dict[str, CapabilityDecision] = {
        # 10 Acquisition Capability Categories
        "LOGICAL_AGENT": _decision_logical_agent(is_authorized, sdk_level),
        "SHARED_STORAGE": shared_file_decision,
        "ADB_LOGICAL": _decision_adb_logical(is_authorized),
        "ACCESSIBILITY_COLLECTION": _decision_accessibility(
            device_state.accessibility_state, is_authorized
        ),
        "NOTIFICATION_COLLECTION": _decision_notification(
            device_state.notification_listener_state, is_authorized
        ),
        "USAGE_STATISTICS": _decision_usage_stats(is_authorized),
        "ROOTED_COLLECTION": _decision_rooted(
            root_verified, temporary_root_readiness, is_authorized
        ),
        "PHYSICAL_ACQUISITION": _decision_physical(
            locked_device_readiness, device_state.chipset_family
        ),
        "CLOUD_IMPORT": _decision_cloud_import(),
        "APK_DOWNGRADE": _decision_apk_downgrade(sdk_level, is_authorized),
        # Legacy capability keys for backward compatibility
        "device_metadata": _decision(
            status=CapabilityStatus.SUPPORTED if is_authorized else CapabilityStatus.BLOCKED,
            reason_code="ADB_PROPERTY_ACCESS" if is_authorized else "ADB_UNAUTHORIZED",
            explanation=(
                "Core Android build properties retrieved through approved ADB operation."
                if is_authorized
                else "ADB authorization not granted."
            ),
            capability="ADB_LOGICAL",
        ),
        "package_inventory": _decision(
            status=CapabilityStatus.SUPPORTED if is_authorized else CapabilityStatus.BLOCKED,
            reason_code="ADB_PACKAGE_LIST_ACCESS" if is_authorized else "ADB_UNAUTHORIZED",
            explanation=(
                "Package identifiers are accessible; Android visibility rules may limit coverage."
                if is_authorized
                else "ADB authorization not granted."
            ),
            capability="ADB_LOGICAL",
        ),
        "shared_storage": shared_file_decision,
        "private_app_data": _decision(
            status=CapabilityStatus.UNSUPPORTED if is_authorized else CapabilityStatus.BLOCKED,
            reason_code="PRIVATE_APP_DATA_INACCESSIBLE",
            explanation="ADB authorization does not grant access to private application sandboxes.",
            capability="ROOTED_COLLECTION",
            limitations="Private application databases require root privileges.",
        ),
        "download_files": shared_file_decision,
        "media_files": shared_file_decision,
        "document_files": shared_file_decision,
        "contacts": _provider_decision(provider_probes.get(ContentProviderProfile.CONTACTS)),
        "sms_mms": _provider_decision(provider_probes.get(ContentProviderProfile.SMS)),
        "call_logs": _provider_decision(provider_probes.get(ContentProviderProfile.CALL_LOG)),
        "calendar": _elevated_only("READ_CALENDAR_REQUIRED"),
        "notifications": _decision_notification(
            device_state.notification_listener_state, is_authorized
        ),
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
        "deleted_data_recovery": _decision(
            status=CapabilityStatus.UNSUPPORTED,
            reason_code="BLOCK_ACCESS_UNAVAILABLE",
            explanation="Ordinary ADB does not provide raw block-level access.",
            capability="PHYSICAL_ACQUISITION",
            limitations="Requires physical memory dump.",
        ),
    }

    return capabilities


def _decision_logical_agent(is_authorized: bool, sdk_level: int | None) -> CapabilityDecision:
    if not is_authorized:
        return _decision(
            status=CapabilityStatus.BLOCKED,
            reason_code="ADB_UNAUTHORIZED",
            explanation="ADB authorization has not been granted on the target device.",
            capability="LOGICAL_AGENT",
            evidence="ADB transport state is UNAUTHORIZED.",
            limitations="Logical agent deployment cannot be initiated.",
        )
    if sdk_level is not None and sdk_level < 21:
        return _decision(
            status=CapabilityStatus.UNSUPPORTED,
            reason_code="AGENT_API_TOO_LOW",
            explanation=f"Android API level {sdk_level} is below agent minimum API 21.",
            capability="LOGICAL_AGENT",
            evidence=f"Device API level: {sdk_level}.",
            limitations="Agent deployment unsupported on Android < 5.0.",
        )
    return _decision(
        status=CapabilityStatus.SUPPORTED,
        reason_code="AGENT_EXECUTION_SUPPORTED",
        explanation="Logical agent can be installed and executed via authorized ADB.",
        capability="LOGICAL_AGENT",
        evidence=f"ADB device state is AUTHORIZED, API level is {sdk_level}.",
        limitations=(
            "Agent can collect public data and user-granted permissions; "
            "private app data requires root."
        ),
    )


def _decision_adb_logical(is_authorized: bool) -> CapabilityDecision:
    if not is_authorized:
        return _decision(
            status=CapabilityStatus.BLOCKED,
            reason_code="ADB_UNAUTHORIZED",
            explanation="ADB authorization has not been granted on the target device.",
            capability="ADB_LOGICAL",
            evidence="ADB transport state is UNAUTHORIZED.",
            limitations="ADB commands cannot be executed.",
        )
    return _decision(
        status=CapabilityStatus.SUPPORTED,
        reason_code="ADB_LOGICAL_AVAILABLE",
        explanation=(
            "ADB logical extraction (properties, packages, content providers) is supported."
        ),
        capability="ADB_LOGICAL",
        evidence="ADB session is AUTHORIZED.",
        limitations="Restricted by Android permission model; private app sandboxes inaccessible.",
    )


def _decision_accessibility(accessibility_state: str, is_authorized: bool) -> CapabilityDecision:
    if not is_authorized:
        return _decision(
            status=CapabilityStatus.BLOCKED,
            reason_code="ADB_UNAUTHORIZED",
            explanation="ADB authorization has not been granted on the target device.",
            capability="ACCESSIBILITY_COLLECTION",
            evidence="ADB transport state is UNAUTHORIZED.",
            limitations="Accessibility status cannot be inspected or configured.",
        )
    if accessibility_state == "enabled_authorized":
        return _decision(
            status=CapabilityStatus.SUPPORTED,
            reason_code="ACCESSIBILITY_SERVICE_ACTIVE",
            explanation="Accessibility service is active and authorized for app scraping.",
            capability="ACCESSIBILITY_COLLECTION",
            evidence="Accessibility service registered in secure settings.",
            limitations="Dependent on active UI interaction.",
        )
    return _decision(
        status=CapabilityStatus.UNSUPPORTED,
        reason_code="ACCESSIBILITY_NOT_GRANTED",
        explanation="Accessibility authorization has not been granted.",
        capability="ACCESSIBILITY_COLLECTION",
        evidence="ADB device state indicates accessibility service is not confirmed or enabled.",
        limitations="UI-based application acquisition cannot be attempted.",
    )


def _decision_notification(notification_state: str, is_authorized: bool) -> CapabilityDecision:
    if not is_authorized:
        return _decision(
            status=CapabilityStatus.BLOCKED,
            reason_code="ADB_UNAUTHORIZED",
            explanation="ADB authorization has not been granted on the target device.",
            capability="NOTIFICATION_COLLECTION",
            evidence="ADB transport state is UNAUTHORIZED.",
            limitations="Notification listener access cannot be verified.",
        )
    if notification_state == "granted":
        return _decision(
            status=CapabilityStatus.SUPPORTED,
            reason_code="NOTIFICATION_LISTENER_ACTIVE",
            explanation="Notification listener access is granted to the agent.",
            capability="NOTIFICATION_COLLECTION",
            evidence="Notification listener service confirmed in secure settings.",
            limitations="Captures live notifications posted while listener is active.",
        )
    return _decision(
        status=CapabilityStatus.UNSUPPORTED,
        reason_code="NOTIFICATION_LISTENER_NOT_GRANTED",
        explanation="Notification listener access has not been granted.",
        capability="NOTIFICATION_COLLECTION",
        evidence="Notification listener service not confirmed in secure settings.",
        limitations="Notification interception is unavailable.",
    )


def _decision_usage_stats(is_authorized: bool) -> CapabilityDecision:
    if not is_authorized:
        return _decision(
            status=CapabilityStatus.BLOCKED,
            reason_code="ADB_UNAUTHORIZED",
            explanation="ADB authorization has not been granted on the target device.",
            capability="USAGE_STATISTICS",
            evidence="ADB transport state is UNAUTHORIZED.",
            limitations="Usage statistics dumpsys cannot be queried.",
        )
    return _decision(
        status=CapabilityStatus.SUPPORTED,
        reason_code="USAGE_STATS_ACCESSIBLE",
        explanation="Application usage statistics are accessible via ADB dumpsys.",
        capability="USAGE_STATISTICS",
        evidence="ADB dumpsys usagestats available.",
        limitations="Retention period is controlled by Android system policy.",
    )


def _decision_rooted(
    root_verified: bool,
    temporary_root_readiness: TemporaryRootReadiness,
    is_authorized: bool,
) -> CapabilityDecision:
    if root_verified:
        return _decision(
            status=CapabilityStatus.SUPPORTED,
            reason_code="ROOT_ACCESS_VERIFIED",
            explanation="Full root privileges (uid 0) verified on target device.",
            capability="ROOTED_COLLECTION",
            evidence="Active uid 0 shell execution confirmed.",
            limitations="Credential storage must be unlocked for FBE plaintext databases.",
        )
    if temporary_root_readiness.eligibility_status in {
        "exact_profile_match",
        "candidate_requires_validated_profile",
    }:
        return _decision(
            status=CapabilityStatus.BLOCKED,
            reason_code="TEMPORARY_ROOT_ELIGIBLE",
            explanation=(
                f"Device matches temporary root candidate/profile "
                f"({temporary_root_readiness.research_profile_id or 'reference range'}). "
                "Provider execution required."
            ),
            capability="ROOTED_COLLECTION",
            evidence="Firmware and patch level match temporary root candidate criteria.",
            limitations="Requires running validated temporary root workflow before collection.",
        )
    if not is_authorized:
        return _decision(
            status=CapabilityStatus.UNKNOWN,
            reason_code="ADB_UNAUTHORIZED",
            explanation="ADB authorization missing; root status cannot be evaluated.",
            capability="ROOTED_COLLECTION",
            evidence="ADB state is UNAUTHORIZED.",
            limitations="Root status unknown until ADB is authorized.",
        )
    return _decision(
        status=CapabilityStatus.UNSUPPORTED,
        reason_code="ROOT_NOT_AVAILABLE",
        explanation="Device is non-rooted and no validated temporary-root provider is available.",
        capability="ROOTED_COLLECTION",
        evidence="su binary absent; firmware outside temporary root reference range.",
        limitations="Direct extraction of private application databases is unavailable.",
    )


def _decision_physical(
    locked_readiness: LockedDeviceReadiness, chipset_family: str
) -> CapabilityDecision:
    if locked_readiness.support_status in {
        "supported",
        "validated_offline_recovery_profile",
        "exact_validated_profile",
    }:
        return _decision(
            status=CapabilityStatus.SUPPORTED,
            reason_code="PHYSICAL_PROFILE_MATCHED",
            explanation=f"Hardware profile matched for chipset {chipset_family}.",
            capability="PHYSICAL_ACQUISITION",
            evidence=f"Chipset family: {chipset_family}.",
            limitations="Requires offline boot mode or hardware provider execution.",
        )
    if chipset_family != "unknown":
        return _decision(
            status=CapabilityStatus.UNSUPPORTED,
            reason_code="PHYSICAL_PROFILE_UNAVAILABLE",
            explanation=(
                "No validated physical acquisition profile is catalogued "
                f"for chipset {chipset_family}."
            ),
            capability="PHYSICAL_ACQUISITION",
            evidence=f"Chipset family: {chipset_family}.",
            limitations="Physical memory dump cannot be performed safely.",
        )
    return _decision(
        status=CapabilityStatus.UNKNOWN,
        reason_code="CHIPSET_UNKNOWN",
        explanation="Chipset family could not be determined from device properties.",
        capability="PHYSICAL_ACQUISITION",
        evidence="ro.board.platform / ro.hardware properties unavailable.",
        limitations="Physical acquisition readiness cannot be evaluated.",
    )


def _decision_cloud_import() -> CapabilityDecision:
    return _decision(
        status=CapabilityStatus.SUPPORTED,
        reason_code="CLOUD_IMPORT_SUPPORTED",
        explanation="Auxiliary cloud evidence import is supported.",
        capability="CLOUD_IMPORT",
        evidence="Cloud backup router and takeout downloader available.",
        limitations="Requires valid user credentials or extracted OAuth tokens.",
    )


def _decision_apk_downgrade(sdk_level: int | None, is_authorized: bool) -> CapabilityDecision:
    if not is_authorized:
        return _decision(
            status=CapabilityStatus.BLOCKED,
            reason_code="ADB_UNAUTHORIZED",
            explanation="ADB authorization has not been granted on target device.",
            capability="APK_DOWNGRADE",
            evidence="ADB state is UNAUTHORIZED.",
            limitations="APK downgrade cannot be evaluated without ADB.",
        )
    if sdk_level is None:
        return _decision(
            status=CapabilityStatus.UNKNOWN,
            reason_code="SDK_LEVEL_UNKNOWN",
            explanation="Android SDK level could not be determined from device properties.",
            capability="APK_DOWNGRADE",
            evidence="ro.build.version.sdk property missing or invalid.",
            limitations="APK downgrade capability cannot be evaluated.",
        )
    if 21 <= sdk_level <= 30:
        return _decision(
            status=CapabilityStatus.LEGACY_SUPPORTED,
            reason_code="APK_DOWNGRADE_LEGACY_SUPPORTED",
            explanation=f"Legacy Android API {sdk_level} supports APK downgrade extraction.",
            capability="APK_DOWNGRADE",
            evidence=f"Android API {sdk_level} (Android 5.0-11).",
            limitations="Requires temporary application replacement and original APK restoration.",
        )
    if sdk_level >= 31:
        return _decision(
            status=CapabilityStatus.UNSUPPORTED,
            reason_code="APK_DOWNGRADE_REMOVED_ON_MODERN_ANDROID",
            explanation=(
                f"Android 12+ (API {sdk_level}) does not support third-party ADB backup; "
                "APK downgrade is unsupported on modern Android."
            ),
            capability="APK_DOWNGRADE",
            evidence=f"Device API level is {sdk_level} (>= 31).",
            limitations="Downgrade acquisition cannot be attempted on modern Android.",
        )
    return _decision(
        status=CapabilityStatus.UNSUPPORTED,
        reason_code="APK_DOWNGRADE_UNSUPPORTED_API",
        explanation=f"Android API {sdk_level} is below minimum supported API level 21.",
        capability="APK_DOWNGRADE",
        evidence=f"Device API level is {sdk_level}.",
        limitations="APK downgrade unsupported below API 21.",
    )


def _decision(
    *,
    status: CapabilityStatus,
    reason_code: str,
    explanation: str,
    capability: str | None = None,
    evidence: str | None = None,
    limitations: str | None = None,
) -> CapabilityDecision:
    return CapabilityDecision(
        status=status,
        reason_code=reason_code,
        explanation=explanation,
        capability=capability,
        evidence=evidence,
        limitations=limitations,
    )


def _elevated_only(reason_code: str) -> CapabilityDecision:
    return _decision(
        status=CapabilityStatus.UNSUPPORTED,
        reason_code=reason_code,
        explanation=(
            "Ordinary non-rooted ADB shell access does not hold the Android permission "
            "required for this provider."
        ),
        capability="ADB_LOGICAL",
        limitations="Requires elevated permissions.",
    )


def _provider_decision(probe: ContentProviderAccessProbe | None) -> CapabilityDecision:
    if probe is None:
        return _decision(
            status=CapabilityStatus.UNKNOWN,
            reason_code="PROVIDER_NOT_PROBED",
            explanation="Content provider access was not probed.",
            capability="ADB_LOGICAL",
        )
    if probe.status is ContentProviderAccessStatus.AVAILABLE:
        return _decision(
            status=CapabilityStatus.SUPPORTED,
            reason_code=probe.reason_code,
            explanation=probe.explanation,
            capability="ADB_LOGICAL",
        )
    if probe.status in {ContentProviderAccessStatus.DENIED, ContentProviderAccessStatus.MISSING}:
        return _decision(
            status=CapabilityStatus.UNSUPPORTED,
            reason_code=probe.reason_code,
            explanation=probe.explanation,
            capability="ADB_LOGICAL",
        )
    return _decision(
        status=CapabilityStatus.UNKNOWN,
        reason_code=probe.reason_code,
        explanation=probe.explanation,
        capability="ADB_LOGICAL",
    )


def _private_app_only(application_name: str) -> CapabilityDecision:
    return _decision(
        status=CapabilityStatus.UNSUPPORTED,
        reason_code="PRIVATE_APP_SANDBOX_INACCESSIBLE",
        explanation=(
            f"{application_name} private databases are sandboxed and unavailable to ordinary "
            "non-rooted ADB."
        ),
        capability="ROOTED_COLLECTION",
        limitations=f"{application_name} extraction requires root or application-specific backup.",
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


def _build_warnings(
    is_authorized: bool, root_verified: bool, accessible_roots: tuple[Any, ...]
) -> tuple[str, ...]:
    warnings = []
    if not is_authorized:
        warnings.append("Target device ADB transport is unauthorized.")
    elif not root_verified:
        warnings.append(
            "Private application data is not accessible on this non-rooted logical transport."
        )
    warnings.append(
        "Capability results apply only to this observed device state and can become stale."
    )
    warnings.append(
        "Storage probing checks fixed root accessibility only; it does not enumerate, "
        "copy, or prove completeness of any evidence content."
    )
    return tuple(warnings)
