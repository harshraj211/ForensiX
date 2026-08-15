import pytest

from forensix_forensic.capabilities import temporary_root
from forensix_forensic.capabilities.temporary_root import TemporaryRootProfile


def test_profile_registry_requires_exact_build_and_patch_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = TemporaryRootProfile(
        profile_id="controlled-pixel-profile",
        provider_id="validated-provider",
        manufacturer="Example",
        model="Controlled Device",
        build_fingerprint="example/device/build:10/TEST/1:user/release-keys",
        security_patch="2019-10-01",
        validation_record_sha256="a" * 64,
        kernel_build_id="4.4.177-controlled",
    )
    monkeypatch.setattr(temporary_root, "TEMPORARY_ROOT_PROFILES", (profile,))
    properties = {
        "ro.product.manufacturer": "example",
        "ro.product.model": "controlled device",
        "ro.build.fingerprint": profile.build_fingerprint,
        "ro.build.version.security_patch": profile.security_patch,
    }

    assert temporary_root.find_temporary_root_profile(properties) == profile
    assert (
        temporary_root.find_temporary_root_profile(properties, kernel_build_id="4.4.177-controlled")
        == profile
    )
    assert (
        temporary_root.find_temporary_root_profile(properties, kernel_build_id="4.4.178-other")
        is None
    )
    properties["ro.build.version.security_patch"] = "2019-10-05"
    assert temporary_root.find_temporary_root_profile(properties) is None


def test_profile_registry_rejects_incomplete_observation() -> None:
    assert temporary_root.find_temporary_root_profile({"ro.product.model": "Unknown"}) is None


def test_research_candidate_matches_exact_pixel_2_build_without_enabling_execution() -> None:
    candidate = temporary_root.find_temporary_root_research_candidate(
        {
            "ro.product.manufacturer": "Google",
            "ro.product.model": "Pixel 2",
            "ro.build.fingerprint": (
                "google/walleye/walleye:10/QP1A.190711.020/5800535:user/release-keys"
            ),
            "ro.build.version.security_patch": "2019-09-05",
        }
    )

    assert candidate is not None
    assert candidate.cve == "CVE-2019-2215"
    assert candidate.kernel_build_id == "4.4.177-g83bee1dc48e8"
    assert temporary_root.TEMPORARY_ROOT_PROFILES == ()
