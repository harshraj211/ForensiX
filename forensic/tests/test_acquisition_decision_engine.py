from datetime import UTC, datetime

from forensix_forensic.capabilities import (
    AcquisitionReadiness,
    AcquisitionVector,
    AcquisitionVectorDecisionEngine,
    AndroidDeviceState,
    DeviceCapabilitySnapshot,
    LockedDeviceReadiness,
    TemporaryRootReadiness,
    VectorStatus,
)
from forensix_forensic.extractors.agent_apk.agent_result import AgentAppArtifact, AgentInstalledApp


def _create_test_snapshot(
    *,
    serial: str = "FX-TEST-DECISION",
    sdk_level: int = 33,
    android_version: str = "13",
    root_state: str = "non_rooted",
    authorization_state: str = "authorized",
    lock_state: str = "unlocked",
    security_patch: str = "2023-08-01",
    chipset_family: str = "gs201",
    temp_root_status: str = "ineligible",
    temp_root_provider: str = "not_configured",
    locked_support_status: str = "unknown",
    accessibility_state: str = "not_installed",
) -> DeviceCapabilitySnapshot:
    device_state = AndroidDeviceState(
        adb_state="authorized" if authorization_state == "authorized" else "unauthorized",
        authorization_state=authorization_state,
        lock_state=lock_state,
        root_state=root_state,
        encryption_state="file_based",
        storage_access_state="readable",
        accessibility_state=accessibility_state,
        chipset_family=chipset_family,
    )
    temp_root_readiness = TemporaryRootReadiness(
        eligibility_status=temp_root_status,
        provider_status=temp_root_provider,
        reference_android_range="4.0-10.0",
        reference_max_security_patch="2019-10-31",
        research_profile_id="FX-TEMP-01" if temp_root_status != "ineligible" else None,
        explanation="Test temp root readiness.",
    )
    locked_readiness = LockedDeviceReadiness(
        support_status=locked_support_status,
        operating_mode="offline_recovery"
        if locked_support_status != "unknown"
        else "metadata_only",
        reference_android_range="5-13",
        profile_status="validated" if locked_support_status != "unknown" else "no_profile",
        destructive_guessing_blocked=True,
        supported_actions=("dump",),
        prohibited_actions=(),
        explanation="Test locked readiness.",
    )
    return DeviceCapabilitySnapshot(
        assessed_at=datetime.now(UTC),
        serial=serial,
        manufacturer="Google",
        model="Pixel Test",
        android_version=android_version,
        sdk_level=sdk_level,
        build_fingerprint="google/pixel/test",
        security_patch=security_patch,
        package_count=10,
        device_state=device_state,
        acquisition_readiness=AcquisitionReadiness(
            encryption_type="file_based",
            credential_storage_state="unlocked",
            chipset_family=chipset_family,
            filesystem_status="verified",
            explanation="Test readiness",
        ),
        temporary_root_readiness=temp_root_readiness,
        locked_device_readiness=locked_readiness,
        capabilities={},
        warnings=(),
    )


def test_modern_non_rooted_android_13_pixel_7() -> None:
    snapshot = _create_test_snapshot(sdk_level=33, android_version="13", root_state="non_rooted")
    engine = AcquisitionVectorDecisionEngine()
    recommendation = engine.evaluate(snapshot)

    assert recommendation.primary_vector == AcquisitionVector.AGENT_LOGICAL
    assert (
        recommendation.vector_evaluations[AcquisitionVector.AGENT_LOGICAL.value].status
        == VectorStatus.RECOMMENDED
    )
    assert (
        recommendation.vector_evaluations[AcquisitionVector.AGENT_LOGICAL.value].yield_score == 60
    )

    # Modern Android (API 33) blocks APK downgrade
    downgrade_eval = recommendation.vector_evaluations[AcquisitionVector.APK_DOWNGRADE.value]
    assert downgrade_eval.status == VectorStatus.UNSUPPORTED
    assert downgrade_eval.reason_code == "REMOVED_ON_MODERN_ANDROID"

    # Non-rooted blocks Rooted Logical
    rooted_eval = recommendation.vector_evaluations[AcquisitionVector.ROOTED_LOGICAL.value]
    assert rooted_eval.status == VectorStatus.UNSUPPORTED


def test_rooted_android_11_pixel_4() -> None:
    snapshot = _create_test_snapshot(sdk_level=30, android_version="11", root_state="rooted")
    engine = AcquisitionVectorDecisionEngine()
    recommendation = engine.evaluate(snapshot)

    assert recommendation.primary_vector == AcquisitionVector.ROOTED_LOGICAL
    assert (
        recommendation.vector_evaluations[AcquisitionVector.ROOTED_LOGICAL.value].status
        == VectorStatus.RECOMMENDED
    )
    assert (
        recommendation.vector_evaluations[AcquisitionVector.ROOTED_LOGICAL.value].yield_score == 95
    )

    # API 30 allows legacy APK downgrade
    downgrade_eval = recommendation.vector_evaluations[AcquisitionVector.APK_DOWNGRADE.value]
    assert downgrade_eval.status == VectorStatus.VIABLE
    assert downgrade_eval.reason_code == "LEGACY_DOWNGRADE_SUPPORTED"


def test_unauthorized_adb_device() -> None:
    snapshot = _create_test_snapshot(authorization_state="unauthorized")
    engine = AcquisitionVectorDecisionEngine()
    recommendation = engine.evaluate(snapshot)

    assert recommendation.primary_vector == AcquisitionVector.METADATA_ONLY
    assert (
        recommendation.vector_evaluations[AcquisitionVector.AGENT_LOGICAL.value].status
        == VectorStatus.BLOCKED
    )
    assert (
        recommendation.vector_evaluations[AcquisitionVector.APK_DOWNGRADE.value].status
        == VectorStatus.BLOCKED
    )


def test_temporary_root_eligible_device() -> None:
    snapshot = _create_test_snapshot(
        sdk_level=27,
        android_version="8.1",
        security_patch="2018-05-01",
        temp_root_status="exact_profile_match",
        temp_root_provider="exact_profile_match",
    )
    engine = AcquisitionVectorDecisionEngine()
    recommendation = engine.evaluate(snapshot)

    assert recommendation.primary_vector == AcquisitionVector.TEMPORARY_ROOT
    assert (
        recommendation.vector_evaluations[AcquisitionVector.TEMPORARY_ROOT.value].status
        == VectorStatus.RECOMMENDED
    )
    assert (
        recommendation.vector_evaluations[AcquisitionVector.TEMPORARY_ROOT.value].yield_score == 90
    )


def test_hardware_physical_profile_matched_device() -> None:
    snapshot = _create_test_snapshot(
        sdk_level=29,
        lock_state="locked",
        chipset_family="mt6765",
        locked_support_status="validated_offline_recovery_profile",
    )
    engine = AcquisitionVectorDecisionEngine()
    recommendation = engine.evaluate(snapshot)

    assert recommendation.primary_vector == AcquisitionVector.PHYSICAL_HARDWARE
    assert (
        recommendation.vector_evaluations[AcquisitionVector.PHYSICAL_HARDWARE.value].status
        == VectorStatus.RECOMMENDED
    )
    assert (
        recommendation.vector_evaluations[AcquisitionVector.PHYSICAL_HARDWARE.value].yield_score
        == 100
    )


def test_app_route_mapping() -> None:
    snapshot = _create_test_snapshot(sdk_level=33, root_state="non_rooted")
    engine = AcquisitionVectorDecisionEngine()

    installed_apps = (
        AgentInstalledApp(
            package_name="com.whatsapp",
            app_label="WhatsApp",
            version_name="2.23.1",
            install_time_ms=100000,
            is_system=False,
            allow_backup=False,
        ),
        AgentInstalledApp(
            package_name="com.example.other",
            app_label="Other App",
            version_name="1.0.0",
            install_time_ms=200000,
            is_system=False,
            allow_backup=True,
        ),
    )
    app_artifacts = (
        AgentAppArtifact(
            package_name="com.whatsapp",
            artifact_category="backup",
            relative_path="WhatsApp/Databases/msgstore.db.crypt14",
            absolute_path="/sdcard/WhatsApp/Databases/msgstore.db.crypt14",
            size_bytes=1024,
            last_modified_ms=1700000000000,
            mime_type="application/octet-stream",
            sha256_hash="abc123hash",
            accessibility_status="accessible",
        ),
    )

    recommendation = engine.evaluate(
        snapshot, app_artifacts=app_artifacts, installed_apps=installed_apps
    )

    # WhatsApp has accessible artifacts in shared storage
    wa_route = recommendation.app_routes["com.whatsapp"]
    assert wa_route.recommended_surface == "shared_storage"
    assert wa_route.expected_yield == "accessible_artifacts_only"

    # Other app has no accessible artifacts and API 33 prevents downgrade ->
    # private_app_storage yield none
    other_route = recommendation.app_routes["com.example.other"]
    assert other_route.recommended_surface == "private_app_storage"
    assert other_route.expected_yield == "none"
