"""Conservative locked-Android support classification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .models import LockedDeviceReadiness

LEGACY_MIN_API = 21
LEGACY_MAX_API = 28
BFU_MAX_API = 33
INITIAL_LAB_TARGET_CHIPSETS: tuple[str, ...] = (
    "MT6580",
    "MT6737",
    "MT6739",
    "MT6753",
)


@dataclass(frozen=True, slots=True)
class LockedDeviceProfile:
    profile_id: str
    manufacturer: str
    model: str
    chipset_family: str
    min_api: int
    max_api: int
    max_security_patch: date
    provider_name: str


@dataclass(frozen=True, slots=True)
class LockedDeviceResearchProfile:
    profile_id: str
    display_name: str
    chipset_family: str
    chipset_models: tuple[str, ...]
    reference_android_range: str
    encryption_scope: tuple[str, ...]
    forensix_status: str
    safe_capabilities: tuple[str, ...]
    source_urls: tuple[str, ...]


LOCKED_DEVICE_PROFILES: tuple[LockedDeviceProfile, ...] = ()

LOCKED_DEVICE_RESEARCH_PROFILES: tuple[LockedDeviceResearchProfile, ...] = (
    LockedDeviceResearchProfile(
        profile_id="mediatek_legacy_fde",
        display_name="MediaTek legacy FDE research",
        chipset_family="mediatek",
        chipset_models=("MT6580", "MT6737", "MT6739", "MT6753"),
        reference_android_range="5-9",
        encryption_scope=("full_disk", "unencrypted", "unknown"),
        forensix_status="lab_candidate",
        safe_capabilities=(
            "Metadata assessment",
            "Sealed encrypted-image import",
            "Known-passcode workflow",
            "Synthetic validation",
        ),
        source_urls=(
            "https://oxygenforensics.com/uploads/press_kit/Device_Extraction_Methods.pdf",
            "https://github.com/bkerler/mtkclient",
        ),
    ),
    LockedDeviceResearchProfile(
        profile_id="mediatek_fbe",
        display_name="MediaTek FBE research",
        chipset_family="mediatek",
        chipset_models=(
            "MT6761",
            "MT6762",
            "MT6765",
            "MT6768",
            "MT6771",
            "MT6779",
            "MT6781",
            "MT6785",
            "MT6833",
            "MT6853",
            "MT6873",
            "MT6877",
            "MT6893",
        ),
        reference_android_range="8-13",
        encryption_scope=("file_based",),
        forensix_status="external_provider_only",
        safe_capabilities=(
            "Metadata assessment",
            "BFU encrypted-image import",
            "External-provider output preservation",
        ),
        source_urls=(
            "https://oxygenforensics.com/uploads/press_kit/Device_Extraction_Methods.pdf",
            "https://belkasoft.com/brute",
        ),
    ),
    LockedDeviceResearchProfile(
        profile_id="unisoc_fbe",
        display_name="Unisoc/Spreadtrum research",
        chipset_family="unisoc",
        chipset_models=(
            "SC7731E",
            "SC9832E",
            "SC9863A",
            "T310",
            "T606",
            "T610",
            "T612",
            "T616",
            "T618",
            "T700",
        ),
        reference_android_range="9-13",
        encryption_scope=("file_based", "full_disk"),
        forensix_status="external_provider_only",
        safe_capabilities=(
            "Metadata assessment",
            "BFU encrypted-image import",
            "External-provider result preservation",
        ),
        source_urls=(
            "https://support.passware.com/hc/en-us/articles/23668785582871-Unisoc-based-devices",
            "https://belkasoft.com/brute",
        ),
    ),
    LockedDeviceResearchProfile(
        profile_id="qualcomm_legacy_edl",
        display_name="Qualcomm legacy EDL research",
        chipset_family="qualcomm",
        chipset_models=(
            "MSM8909",
            "MSM8916",
            "MSM8917",
            "MSM8937",
            "MSM8939",
            "MSM8940",
            "MSM8952",
            "MSM8953",
            "SDM450",
        ),
        reference_android_range="5-10",
        encryption_scope=("full_disk", "file_based"),
        forensix_status="external_provider_only",
        safe_capabilities=(
            "Metadata assessment",
            "Sealed EDL image import",
            "External-provider output preservation",
        ),
        source_urls=(
            "https://www.oxygenforensics.com/en/resources/emergency-download-method/",
            "https://github.com/bkerler/edl",
        ),
    ),
    LockedDeviceResearchProfile(
        profile_id="kirin_selected",
        display_name="Huawei/Honor Kirin research",
        chipset_family="kirin",
        chipset_models=("KIRIN659", "KIRIN710", "KIRIN960", "KIRIN970", "KIRIN980"),
        reference_android_range="7-10",
        encryption_scope=("file_based", "full_disk"),
        forensix_status="external_provider_only",
        safe_capabilities=(
            "Metadata assessment",
            "Commercial-provider evidence import",
            "Known-passcode workflow",
        ),
        source_urls=(
            "https://belkasoft.com/unlocking-android-devices-with-brute-force",
            "https://support.passware.com/hc/en-us/articles/7403202319639-Passware-Kit-Mobile-Release-Notes",
        ),
    ),
    LockedDeviceResearchProfile(
        profile_id="samsung_exynos_selected",
        display_name="Samsung Exynos research",
        chipset_family="samsung_exynos",
        chipset_models=(
            "EXYNOS850",
            "EXYNOS9610",
            "EXYNOS9611",
            "EXYNOS9810",
            "EXYNOS9820",
            "EXYNOS9825",
            "EXYNOS990",
        ),
        reference_android_range="7-13",
        encryption_scope=("file_based", "full_disk"),
        forensix_status="external_provider_only",
        safe_capabilities=(
            "Metadata assessment",
            "Commercial-provider evidence import",
            "Known-passcode workflow",
        ),
        source_urls=(
            "https://support.passware.com/hc/en-us/articles/7403202319639-Passware-Kit-Mobile-Release-Notes",
            "https://oxygenforensics.com/uploads/press_kit/Device_Extraction_Methods.pdf",
        ),
    ),
    LockedDeviceResearchProfile(
        profile_id="rockchip_limited",
        display_name="Rockchip limited tablet research",
        chipset_family="rockchip",
        chipset_models=("RK3562",),
        reference_android_range="model-specific",
        encryption_scope=("file_based", "full_disk", "unknown"),
        forensix_status="external_provider_only",
        safe_capabilities=(
            "Metadata assessment",
            "Commercial-provider evidence import",
        ),
        source_urls=(
            "https://support.passware.com/hc/en-us/articles/7403202319639-Passware-Kit-Mobile-Release-Notes",
        ),
    ),
)


def assess_locked_device(
    *,
    android_api: int | None,
    android_release: str | None,
    manufacturer: str | None,
    model: str | None,
    chipset_family: str,
    chipset_model: str | None = None,
    encryption_type: str,
    security_patch: str | None,
    credential_known: bool = False,
) -> LockedDeviceReadiness:
    """Classify support without attempting credentials or modifying the device."""
    profile = _find_profile(
        android_api=android_api,
        manufacturer=manufacturer,
        model=model,
        chipset_family=chipset_family,
        security_patch=security_patch,
    )
    research_profile = find_locked_device_research_profile(chipset_family, chipset_model)
    if android_api is None:
        return _readiness(
            support_status="unknown",
            operating_mode="metadata_only",
            profile=profile,
            research_profile=research_profile,
            supported_actions=("Record device identifiers and observed boot state",),
            explanation=(
                "Android API level is required before locked-device support can be assessed."
            ),
        )
    if not LEGACY_MIN_API <= android_api <= BFU_MAX_API:
        return _readiness(
            support_status="outside_supported_range",
            operating_mode="metadata_only",
            profile=profile,
            research_profile=research_profile,
            supported_actions=("Record device identifiers and preserve external media",),
            explanation=(
                f"Android {android_release or android_api} is outside the limited Android 5-13 "
                "locked-device assessment range."
            ),
        )
    if credential_known:
        return _readiness(
            support_status="supported",
            operating_mode="known_passcode_workflow",
            profile=profile,
            research_profile=research_profile,
            supported_actions=(
                "Examiner-authorized credential entry",
                "Logical or filesystem acquisition after confirmed unlock",
                "Encrypted-image preservation with SHA-256 verification",
            ),
            explanation=(
                "The credential is known. ForensiX may guide an authorized unlock and then use "
                "its existing acquisition workflows; it does not bypass the lock screen."
            ),
        )
    if profile is not None:
        return _readiness(
            support_status="supported",
            operating_mode="validated_offline_recovery_profile",
            profile=profile,
            research_profile=research_profile,
            supported_actions=(
                "Acquire an encrypted image through the validated provider",
                "Verify image integrity before offline recovery",
                "Run provider-bounded offline passcode recovery",
            ),
            explanation=(
                f"Exact laboratory profile {profile.profile_id} matches. Only provider "
                f"{profile.provider_name} may perform the bounded workflow."
            ),
        )
    if LEGACY_MIN_API <= android_api <= LEGACY_MAX_API and encryption_type != "file_based":
        return _readiness(
            support_status="candidate_requires_validated_profile",
            operating_mode="encrypted_preservation_only",
            profile=profile,
            research_profile=research_profile,
            supported_actions=(
                "Record identifiers, firmware, chipset, and security patch",
                "Preserve an encrypted image through an already approved acquisition method",
                "Hash and retain the image for future validated recovery",
            ),
            explanation=(
                "Android 5-9 with non-FBE or unknown encryption is a research candidate, but "
                "offline passcode recovery remains disabled until the exact model, firmware, "
                "chipset, and patch level match a laboratory-validated profile."
            ),
        )
    return _readiness(
        support_status="bfu_preservation_only",
        operating_mode="bfu_encrypted_preservation",
        profile=profile,
        research_profile=research_profile,
        supported_actions=(
            "Record BFU device metadata and boot state",
            "Preserve supported encrypted images without claiming decryption",
            "Continue only through a known-passcode or exact validated profile workflow",
        ),
        explanation=(
            "No exact passcode-recovery profile is configured. ForensiX limits this device to "
            "BFU metadata and encrypted-image preservation and does not attempt lock-screen "
            "guesses."
        ),
    )


def _readiness(
    *,
    support_status: str,
    operating_mode: str,
    profile: LockedDeviceProfile | None,
    research_profile: LockedDeviceResearchProfile | None,
    supported_actions: tuple[str, ...],
    explanation: str,
) -> LockedDeviceReadiness:
    return LockedDeviceReadiness(
        support_status=support_status,
        operating_mode=operating_mode,
        reference_android_range="5-13",
        profile_status="exact_validated_profile" if profile else "no_validated_profile",
        research_profile_id=research_profile.profile_id if research_profile else None,
        research_status=(
            research_profile.forensix_status if research_profile else "not_catalogued"
        ),
        destructive_guessing_blocked=True,
        supported_actions=supported_actions,
        prohibited_actions=(
            "Automated passcode entry on the device",
            "Changing lock-screen or security settings",
            "Factory reset, bootloader unlock, or unvalidated exploit execution",
        ),
        explanation=explanation,
    )


def find_locked_device_research_profile(
    chipset_family: str, chipset_model: str | None
) -> LockedDeviceResearchProfile | None:
    if not chipset_model:
        return None
    model_key = _normalize_chipset(chipset_model)
    return next(
        (
            profile
            for profile in LOCKED_DEVICE_RESEARCH_PROFILES
            if profile.chipset_family == chipset_family
            and model_key in {_normalize_chipset(item) for item in profile.chipset_models}
        ),
        None,
    )


def _normalize_chipset(value: str) -> str:
    return "".join(character for character in value.upper() if character.isalnum())


def _find_profile(
    *,
    android_api: int | None,
    manufacturer: str | None,
    model: str | None,
    chipset_family: str,
    security_patch: str | None,
) -> LockedDeviceProfile | None:
    if android_api is None or not manufacturer or not model or not security_patch:
        return None
    try:
        patch_date = date.fromisoformat(security_patch)
    except ValueError:
        return None
    manufacturer_key = manufacturer.casefold().strip()
    model_key = model.casefold().strip()
    return next(
        (
            profile
            for profile in LOCKED_DEVICE_PROFILES
            if profile.manufacturer.casefold() == manufacturer_key
            and profile.model.casefold() == model_key
            and profile.chipset_family == chipset_family
            and profile.min_api <= android_api <= profile.max_api
            and patch_date <= profile.max_security_patch
        ),
        None,
    )
