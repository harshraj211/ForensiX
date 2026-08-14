from forensix_forensic.capabilities.assessor import (
    _acquisition_readiness,
    _temporary_root_readiness,
)


def test_android_fbe_unlocked_qualcomm_is_ready_for_authorized_root_probe() -> None:
    readiness = _acquisition_readiness(
        {
            "ro.crypto.type": "file",
            "ro.crypto.state": "encrypted",
            "sys.user.0.ce_available": "true",
            "ro.board.platform": "sm7150",
            "ro.soc.manufacturer": "Qualcomm",
        },
        30,
    )

    assert readiness.encryption_type == "file_based"
    assert readiness.credential_storage_state == "unlocked"
    assert readiness.chipset_family == "qualcomm"
    assert readiness.filesystem_status == "root_required"


def test_locked_credential_storage_blocks_plaintext_filesystem_snapshot() -> None:
    readiness = _acquisition_readiness(
        {
            "ro.crypto.type": "file",
            "ro.crypto.state": "encrypted",
            "sys.user.0.ce_available": "0",
        },
        29,
    )

    assert readiness.credential_storage_state == "locked"
    assert readiness.filesystem_status == "unlock_required"


def test_unknown_credential_state_is_not_reported_as_ready() -> None:
    readiness = _acquisition_readiness(
        {"ro.crypto.type": "file", "ro.crypto.state": "encrypted"},
        34,
    )

    assert readiness.credential_storage_state == "unknown"
    assert readiness.filesystem_status == "root_and_unlock_verification_required"


def test_temporary_root_reference_candidate_still_requires_validated_provider() -> None:
    readiness = _temporary_root_readiness(
        {
            "ro.build.version.release": "10",
            "ro.build.version.security_patch": "2019-10-01",
        }
    )

    assert readiness.eligibility_status == "candidate_requires_validated_profile"
    assert readiness.provider_status == "not_configured"
    assert readiness.reference_max_security_patch == "2019-10-31"


def test_temporary_root_rejects_security_patch_newer_than_reference_limit() -> None:
    readiness = _temporary_root_readiness(
        {
            "ro.build.version.release": "9",
            "ro.build.version.security_patch": "2019-11-01",
        }
    )

    assert readiness.eligibility_status == "patch_too_new"


def test_temporary_root_rejects_android_above_reference_range() -> None:
    readiness = _temporary_root_readiness(
        {
            "ro.build.version.release": "14",
            "ro.build.version.security_patch": "2019-01-01",
        }
    )

    assert readiness.eligibility_status == "outside_reference_range"


def test_temporary_root_requires_verification_when_patch_is_missing() -> None:
    readiness = _temporary_root_readiness({"ro.build.version.release": "6.0.1"})

    assert readiness.eligibility_status == "reference_range_requires_verification"
