from forensix_forensic.capabilities.locked_device import (
    INITIAL_LAB_TARGET_CHIPSETS,
    LOCKED_DEVICE_PROFILES,
    LOCKED_DEVICE_RESEARCH_PROFILES,
    assess_locked_device,
    find_locked_device_research_profile,
)
from forensix_forensic.capabilities.models import LockedDeviceReadiness


def _assess(
    api: int,
    *,
    encryption: str,
    credential_known: bool = False,
) -> LockedDeviceReadiness:
    return assess_locked_device(
        android_api=api,
        android_release=str(api),
        manufacturer="Example",
        model="Device",
        chipset_family="unisoc",
        chipset_model="SC9863A",
        encryption_type=encryption,
        security_patch="2019-01-01",
        credential_known=credential_known,
    )


def test_android_5_legacy_device_is_only_a_candidate_without_exact_profile() -> None:
    readiness = _assess(21, encryption="full_disk")

    assert readiness.support_status == "candidate_requires_validated_profile"
    assert readiness.operating_mode == "encrypted_preservation_only"
    assert readiness.profile_status == "no_validated_profile"
    assert readiness.destructive_guessing_blocked is True


def test_android_9_fbe_device_is_limited_to_bfu_preservation() -> None:
    readiness = _assess(28, encryption="file_based")

    assert readiness.support_status == "bfu_preservation_only"
    assert readiness.operating_mode == "bfu_encrypted_preservation"


def test_android_13_unknown_passcode_is_limited_to_bfu_preservation() -> None:
    readiness = _assess(33, encryption="file_based")

    assert readiness.support_status == "bfu_preservation_only"
    assert "Automated passcode entry on the device" in readiness.prohibited_actions
    assert readiness.research_profile_id == "unisoc_fbe"
    assert readiness.research_status == "external_provider_only"


def test_known_passcode_enables_normal_authorized_acquisition() -> None:
    readiness = _assess(33, encryption="file_based", credential_known=True)

    assert readiness.support_status == "supported"
    assert readiness.operating_mode == "known_passcode_workflow"


def test_android_14_is_outside_limited_claim() -> None:
    readiness = _assess(34, encryption="file_based")

    assert readiness.support_status == "outside_supported_range"
    assert readiness.operating_mode == "metadata_only"


def test_no_offline_recovery_profile_is_claimed_before_lab_validation() -> None:
    assert LOCKED_DEVICE_PROFILES == ()


def test_research_catalog_covers_every_documented_family_without_enabling_recovery() -> None:
    families = {profile.chipset_family for profile in LOCKED_DEVICE_RESEARCH_PROFILES}

    assert families == {
        "mediatek",
        "unisoc",
        "qualcomm",
        "kirin",
        "samsung_exynos",
        "rockchip",
    }
    assert all(
        profile.forensix_status in {"lab_candidate", "external_provider_only"}
        for profile in LOCKED_DEVICE_RESEARCH_PROFILES
    )


def test_initial_lab_target_is_the_legacy_mediatek_fde_group() -> None:
    profile = next(
        item for item in LOCKED_DEVICE_RESEARCH_PROFILES if item.profile_id == "mediatek_legacy_fde"
    )

    assert profile.chipset_models == INITIAL_LAB_TARGET_CHIPSETS
    assert profile.forensix_status == "lab_candidate"


def test_chipset_matching_is_normalized_but_family_bounded() -> None:
    assert find_locked_device_research_profile("mediatek", "MediaTek MT6739") is None
    assert find_locked_device_research_profile("mediatek", "mt-6739") is not None
    assert find_locked_device_research_profile("qualcomm", "MT6739") is None
