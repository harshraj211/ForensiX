"""Closed metadata registry for separately validated temporary-root providers.

This module deliberately contains no exploit payload or arbitrary command hook. A provider may
only become selectable after its exact device/build metadata has been registered and validated.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TemporaryRootProfile:
    profile_id: str
    provider_id: str
    manufacturer: str
    model: str
    build_fingerprint: str
    security_patch: str
    validation_record_sha256: str


@dataclass(frozen=True, slots=True)
class TemporaryRootResearchCandidate:
    candidate_id: str
    cve: str
    manufacturer: str
    model: str
    build_fingerprint: str
    security_patch: str
    chipset_family: str
    kernel_build_id: str
    source_url: str


# Research references are deliberately separate from TEMPORARY_ROOT_PROFILES. They must never
# enable execution until the exact kernel, binary provenance, license, and controlled-device
# validation record have been reviewed.
TEMPORARY_ROOT_RESEARCH_CANDIDATES: tuple[TemporaryRootResearchCandidate, ...] = (
    TemporaryRootResearchCandidate(
        candidate_id="cve-2019-2215-pixel2-qp1a-190711-020",
        cve="CVE-2019-2215",
        manufacturer="Google",
        model="Pixel 2",
        build_fingerprint=("google/walleye/walleye:10/QP1A.190711.020/5800535:user/release-keys"),
        security_patch="2019-09-05",
        chipset_family="qualcomm",
        kernel_build_id="4.4.177-g83bee1dc48e8",
        source_url="https://github.com/kangtastic/cve-2019-2215",
    ),
    TemporaryRootResearchCandidate(
        candidate_id="cve-2019-2215-pixel2xl-qp1a-190711-020",
        cve="CVE-2019-2215",
        manufacturer="Google",
        model="Pixel 2 XL",
        build_fingerprint=("google/taimen/taimen:10/QP1A.190711.020/5800535:user/release-keys"),
        security_patch="2019-09-05",
        chipset_family="qualcomm",
        kernel_build_id="4.4.177-g83bee1dc48e8",
        source_url="https://github.com/kangtastic/cve-2019-2215",
    ),
)


# Profiles must be added through a reviewed release after controlled-device validation.
TEMPORARY_ROOT_PROFILES: tuple[TemporaryRootProfile, ...] = ()


def find_temporary_root_research_candidate(
    properties: dict[str, str],
) -> TemporaryRootResearchCandidate | None:
    observed = (
        properties.get("ro.product.manufacturer", "").strip().casefold(),
        properties.get("ro.product.model", "").strip().casefold(),
        properties.get("ro.build.fingerprint", "").strip(),
        properties.get("ro.build.version.security_patch", "").strip(),
    )
    if not all(observed):
        return None
    for candidate in TEMPORARY_ROOT_RESEARCH_CANDIDATES:
        expected = (
            candidate.manufacturer.strip().casefold(),
            candidate.model.strip().casefold(),
            candidate.build_fingerprint.strip(),
            candidate.security_patch.strip(),
        )
        if observed == expected:
            return candidate
    return None


def find_temporary_root_profile(
    properties: dict[str, str],
) -> TemporaryRootProfile | None:
    observed = (
        properties.get("ro.product.manufacturer", "").strip().casefold(),
        properties.get("ro.product.model", "").strip().casefold(),
        properties.get("ro.build.fingerprint", "").strip(),
        properties.get("ro.build.version.security_patch", "").strip(),
    )
    if not all(observed):
        return None
    for profile in TEMPORARY_ROOT_PROFILES:
        expected = (
            profile.manufacturer.strip().casefold(),
            profile.model.strip().casefold(),
            profile.build_fingerprint.strip(),
            profile.security_patch.strip(),
        )
        if observed == expected:
            return profile
    return None


def get_temporary_root_profile(profile_id: str) -> TemporaryRootProfile | None:
    return next(
        (profile for profile in TEMPORARY_ROOT_PROFILES if profile.profile_id == profile_id),
        None,
    )
