"""Acquisition Vector Decision Engine.

Synthesizes device state, security status, capability assessments, downgrade policies,
and application intelligence into an automated, deterministic acquisition recommendation.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from forensix_forensic.extractors.agent_apk.agent_result import AgentAppArtifact, AgentInstalledApp

from .models import DeviceCapabilitySnapshot


class AcquisitionVector(StrEnum):
    PHYSICAL_HARDWARE = "PHYSICAL_HARDWARE"
    TEMPORARY_ROOT = "TEMPORARY_ROOT"
    ROOTED_LOGICAL = "ROOTED_LOGICAL"
    APK_DOWNGRADE = "APK_DOWNGRADE"
    AGENT_LOGICAL = "AGENT_LOGICAL"
    ACCESSIBILITY_SCRAPING = "ACCESSIBILITY_SCRAPING"
    CLOUD_IMPORT = "CLOUD_IMPORT"
    METADATA_ONLY = "METADATA_ONLY"


class VectorStatus(StrEnum):
    RECOMMENDED = "RECOMMENDED"
    VIABLE = "VIABLE"
    BLOCKED = "BLOCKED"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class VectorRiskLevel(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class VectorEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True)

    vector: AcquisitionVector
    status: VectorStatus
    yield_score: int = Field(ge=0, le=100)
    risk_level: VectorRiskLevel
    reason_code: str
    explanation: str
    evidence: str
    prerequisites: tuple[str, ...] = ()
    target_surfaces: tuple[str, ...] = ()


class AppAcquisitionRoute(BaseModel):
    model_config = ConfigDict(frozen=True)

    package_name: str
    app_name: str | None = None
    recommended_surface: str
    vector: AcquisitionVector
    expected_yield: str  # "full_sandbox", "accessible_artifacts_only", "export_only", "none"
    explanation: str


class AcquisitionPlanRecommendation(BaseModel):
    model_config = ConfigDict(frozen=True)

    primary_vector: AcquisitionVector
    fallback_vectors: tuple[AcquisitionVector, ...]
    vector_evaluations: dict[str, VectorEvaluation]
    app_routes: dict[str, AppAcquisitionRoute]
    warnings: tuple[str, ...]
    limitations: tuple[str, ...]
    assessed_serial: str
    recommended_at_iso: str | None = None


class AcquisitionVectorDecisionEngine:
    """Deterministic decision engine mapping device state to optimal acquisition vectors."""

    def evaluate(
        self,
        snapshot: DeviceCapabilitySnapshot,
        *,
        app_artifacts: tuple[AgentAppArtifact, ...] = (),
        installed_apps: tuple[AgentInstalledApp, ...] = (),
    ) -> AcquisitionPlanRecommendation:
        evaluations: dict[str, VectorEvaluation] = {}

        # 1. Metadata Only
        evaluations[AcquisitionVector.METADATA_ONLY.value] = self._eval_metadata_only(snapshot)

        # 2. Agent Logical
        evaluations[AcquisitionVector.AGENT_LOGICAL.value] = self._eval_agent_logical(snapshot)

        # 3. Rooted Logical
        evaluations[AcquisitionVector.ROOTED_LOGICAL.value] = self._eval_rooted_logical(snapshot)

        # 4. APK Downgrade
        evaluations[AcquisitionVector.APK_DOWNGRADE.value] = self._eval_apk_downgrade(snapshot)

        # 5. Temporary Root
        evaluations[AcquisitionVector.TEMPORARY_ROOT.value] = self._eval_temporary_root(snapshot)

        # 6. Physical Hardware
        evaluations[AcquisitionVector.PHYSICAL_HARDWARE.value] = self._eval_physical_hardware(
            snapshot
        )

        # 7. Accessibility Scraping
        evaluations[AcquisitionVector.ACCESSIBILITY_SCRAPING.value] = self._eval_accessibility(
            snapshot
        )

        # 8. Cloud Import
        evaluations[AcquisitionVector.CLOUD_IMPORT.value] = self._eval_cloud_import(snapshot)

        # Select Primary & Fallback Vectors
        primary_vector, fallbacks = self._select_vectors(evaluations)

        # Per-app acquisition route mapping
        app_routes = self._build_app_routes(
            primary_vector=primary_vector,
            installed_apps=installed_apps,
            app_artifacts=app_artifacts,
        )

        # Aggregate warnings and limitations
        warnings = list(snapshot.warnings)
        limitations = [
            "Logical operations do not bypass device lock screens or extract hardware keys.",
            "Private app sandboxes (/data/data/) require root privileges.",
            *self._collect_vector_limitations(primary_vector, evaluations),
        ]

        assessed_at_str = (
            snapshot.assessed_at.isoformat()
            if hasattr(snapshot.assessed_at, "isoformat")
            else str(snapshot.assessed_at)
        )

        return AcquisitionPlanRecommendation(
            primary_vector=primary_vector,
            fallback_vectors=tuple(fallbacks),
            vector_evaluations=evaluations,
            app_routes=app_routes,
            warnings=tuple(warnings),
            limitations=tuple(limitations),
            assessed_serial=snapshot.serial,
            recommended_at_iso=assessed_at_str,
        )

    def _eval_metadata_only(self, snapshot: DeviceCapabilitySnapshot) -> VectorEvaluation:
        if snapshot.device_state.authorization_state == "unauthorized":
            return VectorEvaluation(
                vector=AcquisitionVector.METADATA_ONLY,
                status=VectorStatus.RECOMMENDED,
                yield_score=10,
                risk_level=VectorRiskLevel.NONE,
                reason_code="ADB_UNAUTHORIZED",
                explanation="ADB authorization missing. Metadata-only identification recommended.",
                evidence="Device state is UNAUTHORIZED.",
                prerequisites=("USB connection",),
                target_surfaces=("device_properties",),
            )
        return VectorEvaluation(
            vector=AcquisitionVector.METADATA_ONLY,
            status=VectorStatus.VIABLE,
            yield_score=10,
            risk_level=VectorRiskLevel.NONE,
            reason_code="METADATA_ALWAYS_AVAILABLE",
            explanation="Basic device properties and state can be queried.",
            evidence=f"Serial {snapshot.serial} observed.",
            prerequisites=(),
            target_surfaces=("device_properties",),
        )

    def _eval_agent_logical(self, snapshot: DeviceCapabilitySnapshot) -> VectorEvaluation:
        if snapshot.device_state.authorization_state != "authorized":
            return VectorEvaluation(
                vector=AcquisitionVector.AGENT_LOGICAL,
                status=VectorStatus.BLOCKED,
                yield_score=0,
                risk_level=VectorRiskLevel.LOW,
                reason_code="ADB_UNAUTHORIZED",
                explanation="ADB authorization required for logical agent installation.",
                evidence="ADB transport state is UNAUTHORIZED.",
                prerequisites=("Authorize ADB prompt on device",),
            )

        if snapshot.sdk_level is not None and snapshot.sdk_level < 21:
            return VectorEvaluation(
                vector=AcquisitionVector.AGENT_LOGICAL,
                status=VectorStatus.UNSUPPORTED,
                yield_score=0,
                risk_level=VectorRiskLevel.LOW,
                reason_code="SDK_TOO_LOW",
                explanation=f"Android SDK level {snapshot.sdk_level} below Agent minimum API 21.",
                evidence=f"SDK Level: {snapshot.sdk_level}",
            )

        is_non_rooted = snapshot.device_state.root_state != "rooted"
        yield_score = 60 if is_non_rooted else 85
        return VectorEvaluation(
            vector=AcquisitionVector.AGENT_LOGICAL,
            status=VectorStatus.RECOMMENDED if is_non_rooted else VectorStatus.VIABLE,
            yield_score=yield_score,
            risk_level=VectorRiskLevel.LOW,
            reason_code="AGENT_LOGICAL_AVAILABLE",
            explanation=(
                "Agent APK deployment ready for contacts, SMS, call logs, app inventory, "
                "and accessible shared storage."
            ),
            evidence=f"Authorized ADB session, SDK level {snapshot.sdk_level}.",
            prerequisites=("ADB authorized", "Agent service execution"),
            target_surfaces=(
                "contacts",
                "sms",
                "call_logs",
                "device_metadata",
                "accessible_app_artifacts",
            ),
        )

    def _eval_rooted_logical(self, snapshot: DeviceCapabilitySnapshot) -> VectorEvaluation:
        if snapshot.device_state.root_state == "rooted":
            return VectorEvaluation(
                vector=AcquisitionVector.ROOTED_LOGICAL,
                status=VectorStatus.RECOMMENDED,
                yield_score=95,
                risk_level=VectorRiskLevel.LOW,
                reason_code="ROOT_VERIFIED",
                explanation=(
                    "Full root access (uid 0) verified. Direct extraction of private app "
                    "sandboxes enabled."
                ),
                evidence="Active root privileges confirmed.",
                prerequisites=("Root access", "CE user credential unlocked if FBE"),
                target_surfaces=("private_app_storage", "system_databases", "keychain_keys"),
            )
        return VectorEvaluation(
            vector=AcquisitionVector.ROOTED_LOGICAL,
            status=VectorStatus.UNSUPPORTED,
            yield_score=0,
            risk_level=VectorRiskLevel.LOW,
            reason_code="ROOT_NOT_AVAILABLE",
            explanation="Device is non-rooted; direct sandbox extraction inaccessible.",
            evidence=f"Root state: {snapshot.device_state.root_state}",
        )

    def _eval_apk_downgrade(self, snapshot: DeviceCapabilitySnapshot) -> VectorEvaluation:
        if snapshot.device_state.authorization_state != "authorized":
            return VectorEvaluation(
                vector=AcquisitionVector.APK_DOWNGRADE,
                status=VectorStatus.BLOCKED,
                yield_score=0,
                risk_level=VectorRiskLevel.MEDIUM,
                reason_code="ADB_UNAUTHORIZED",
                explanation="ADB authorization missing for APK downgrade.",
                evidence="ADB transport state is UNAUTHORIZED.",
            )

        if snapshot.sdk_level is not None and snapshot.sdk_level >= 31:
            return VectorEvaluation(
                vector=AcquisitionVector.APK_DOWNGRADE,
                status=VectorStatus.UNSUPPORTED,
                yield_score=0,
                risk_level=VectorRiskLevel.MEDIUM,
                reason_code="REMOVED_ON_MODERN_ANDROID",
                explanation=(
                    f"Android 12+ (SDK {snapshot.sdk_level}) blocks third-party ADB "
                    "backup downgrade."
                ),
                evidence=f"SDK Level: {snapshot.sdk_level} (>= 31).",
            )

        if snapshot.sdk_level is not None and 21 <= snapshot.sdk_level <= 30:
            return VectorEvaluation(
                vector=AcquisitionVector.APK_DOWNGRADE,
                status=VectorStatus.VIABLE,
                yield_score=75,
                risk_level=VectorRiskLevel.MEDIUM,
                reason_code="LEGACY_DOWNGRADE_SUPPORTED",
                explanation=(
                    f"Legacy Android (SDK {snapshot.sdk_level}) supports APK downgrade "
                    "backup acquisition."
                ),
                evidence=f"SDK Level: {snapshot.sdk_level} (21–30).",
                prerequisites=("Application downgrade approval", "Backup APK target staging"),
                target_surfaces=("legacy_app_backup",),
            )

        return VectorEvaluation(
            vector=AcquisitionVector.APK_DOWNGRADE,
            status=VectorStatus.UNSUPPORTED,
            yield_score=0,
            risk_level=VectorRiskLevel.MEDIUM,
            reason_code="SDK_UNSUPPORTED",
            explanation="SDK level outside legacy downgrade range.",
            evidence=f"SDK Level: {snapshot.sdk_level}",
        )

    def _eval_temporary_root(self, snapshot: DeviceCapabilitySnapshot) -> VectorEvaluation:
        readiness = snapshot.temporary_root_readiness
        if readiness.eligibility_status in (
            "exact_profile_match",
            "candidate_requires_validated_profile",
        ):
            is_matched = readiness.provider_status == "exact_profile_match"
            return VectorEvaluation(
                vector=AcquisitionVector.TEMPORARY_ROOT,
                status=VectorStatus.RECOMMENDED if is_matched else VectorStatus.BLOCKED,
                yield_score=90,
                risk_level=VectorRiskLevel.MEDIUM,
                reason_code="TEMP_ROOT_ELIGIBLE",
                explanation=(
                    f"Device eligible for in-memory temporary root exploit ("
                    f"{readiness.research_profile_id or 'reference range'})."
                ),
                evidence=f"Eligibility status: {readiness.eligibility_status}",
                prerequisites=("Temporary root provider execution", "Validated exploit binary"),
                target_surfaces=("temp_root_shell", "private_app_storage"),
            )
        return VectorEvaluation(
            vector=AcquisitionVector.TEMPORARY_ROOT,
            status=VectorStatus.UNSUPPORTED,
            yield_score=0,
            risk_level=VectorRiskLevel.MEDIUM,
            reason_code="TEMP_ROOT_INELIGIBLE",
            explanation=(
                "Firmware security patch date or API level outside temporary root reference window."
            ),
            evidence=f"Patch date: {snapshot.security_patch}, SDK: {snapshot.sdk_level}",
        )

    def _eval_physical_hardware(self, snapshot: DeviceCapabilitySnapshot) -> VectorEvaluation:
        locked_readiness = snapshot.locked_device_readiness
        if locked_readiness.support_status in (
            "supported",
            "validated_offline_recovery_profile",
            "exact_validated_profile",
        ):
            return VectorEvaluation(
                vector=AcquisitionVector.PHYSICAL_HARDWARE,
                status=VectorStatus.RECOMMENDED
                if snapshot.device_state.lock_state == "locked"
                else VectorStatus.VIABLE,
                yield_score=100,
                risk_level=VectorRiskLevel.HIGH,
                reason_code="PHYSICAL_PROFILE_MATCHED",
                explanation=(
                    "Validated hardware acquisition profile matched for chipset "
                    f"{snapshot.device_state.chipset_family}."
                ),
                evidence=f"Chipset family: {snapshot.device_state.chipset_family}",
                prerequisites=("Offline boot mode (EDL/BROM)", "Hardware protocol harness"),
                target_surfaces=("raw_emmc_ufs_blocks", "unencrypted_partitions"),
            )
        return VectorEvaluation(
            vector=AcquisitionVector.PHYSICAL_HARDWARE,
            status=VectorStatus.UNSUPPORTED,
            yield_score=0,
            risk_level=VectorRiskLevel.HIGH,
            reason_code="NO_HARDWARE_PROFILE",
            explanation=(
                "No validated physical acquisition profile catalogued for chipset "
                f"{snapshot.device_state.chipset_family}."
            ),
            evidence=f"Chipset family: {snapshot.device_state.chipset_family}",
        )

    def _eval_accessibility(self, snapshot: DeviceCapabilitySnapshot) -> VectorEvaluation:
        if snapshot.device_state.accessibility_state == "enabled_authorized":
            return VectorEvaluation(
                vector=AcquisitionVector.ACCESSIBILITY_SCRAPING,
                status=VectorStatus.VIABLE,
                yield_score=50,
                risk_level=VectorRiskLevel.LOW,
                reason_code="ACCESSIBILITY_ACTIVE",
                explanation="Accessibility service is authorized and active for UI app scraping.",
                evidence="Accessibility service enabled in secure settings.",
                prerequisites=("Active screen UI interaction",),
                target_surfaces=("ui_scraped_text",),
            )
        return VectorEvaluation(
            vector=AcquisitionVector.ACCESSIBILITY_SCRAPING,
            status=VectorStatus.UNSUPPORTED,
            yield_score=0,
            risk_level=VectorRiskLevel.LOW,
            reason_code="ACCESSIBILITY_NOT_ENABLED",
            explanation="Accessibility service is not granted or enabled on target device.",
            evidence=f"Accessibility state: {snapshot.device_state.accessibility_state}",
        )

    def _eval_cloud_import(self, snapshot: DeviceCapabilitySnapshot) -> VectorEvaluation:
        return VectorEvaluation(
            vector=AcquisitionVector.CLOUD_IMPORT,
            status=VectorStatus.VIABLE,
            yield_score=40,
            risk_level=VectorRiskLevel.NONE,
            reason_code="AUXILIARY_CLOUD_IMPORT",
            explanation="Cloud import available for auxiliary account backups and takeout data.",
            evidence="Cloud router available.",
            prerequisites=("Extracted OAuth tokens or user credentials",),
            target_surfaces=("cloud_backups",),
        )

    def _select_vectors(
        self, evaluations: dict[str, VectorEvaluation]
    ) -> tuple[AcquisitionVector, list[AcquisitionVector]]:
        status_priority = {
            VectorStatus.RECOMMENDED: 4,
            VectorStatus.VIABLE: 3,
            VectorStatus.BLOCKED: 2,
            VectorStatus.UNSUPPORTED: 1,
            VectorStatus.NOT_APPLICABLE: 0,
        }

        candidates = list(evaluations.values())
        candidates.sort(
            key=lambda item: (status_priority[item.status], item.yield_score),
            reverse=True,
        )

        primary = candidates[0].vector
        fallbacks = [
            cand.vector
            for cand in candidates[1:]
            if cand.status in (VectorStatus.RECOMMENDED, VectorStatus.VIABLE, VectorStatus.BLOCKED)
        ]
        return primary, fallbacks

    def _build_app_routes(
        self,
        primary_vector: AcquisitionVector,
        installed_apps: tuple[AgentInstalledApp, ...],
        app_artifacts: tuple[AgentAppArtifact, ...],
    ) -> dict[str, AppAcquisitionRoute]:
        routes: dict[str, AppAcquisitionRoute] = {}

        packages_with_artifacts = {art.package_name for art in app_artifacts if art.package_name}

        for app in installed_apps:
            pkg = app.package_name
            if primary_vector == AcquisitionVector.ROOTED_LOGICAL:
                routes[pkg] = AppAcquisitionRoute(
                    package_name=pkg,
                    app_name=app.app_label,
                    recommended_surface="private_app_storage",
                    vector=AcquisitionVector.ROOTED_LOGICAL,
                    expected_yield="full_sandbox",
                    explanation="Direct sandbox database extraction via root.",
                )
            elif primary_vector == AcquisitionVector.APK_DOWNGRADE and app.allow_backup:
                routes[pkg] = AppAcquisitionRoute(
                    package_name=pkg,
                    app_name=app.app_label,
                    recommended_surface="backup_surface",
                    vector=AcquisitionVector.APK_DOWNGRADE,
                    expected_yield="full_sandbox",
                    explanation="Legacy APK downgrade backup extraction.",
                )
            elif pkg in packages_with_artifacts:
                routes[pkg] = AppAcquisitionRoute(
                    package_name=pkg,
                    app_name=app.app_label,
                    recommended_surface="shared_storage",
                    vector=AcquisitionVector.AGENT_LOGICAL,
                    expected_yield="accessible_artifacts_only",
                    explanation="Discovered accessible media/backup files in shared storage.",
                )
            else:
                routes[pkg] = AppAcquisitionRoute(
                    package_name=pkg,
                    app_name=app.app_label,
                    recommended_surface="private_app_storage",
                    vector=primary_vector,
                    expected_yield="none",
                    explanation="Private app storage is restricted on non-rooted Android.",
                )

        return routes

    def _collect_vector_limitations(
        self, primary_vector: AcquisitionVector, evaluations: dict[str, VectorEvaluation]
    ) -> list[str]:
        eval_item = evaluations.get(primary_vector.value)
        if eval_item and eval_item.status == VectorStatus.RECOMMENDED:
            return [f"Selected primary vector ({primary_vector.value}): {eval_item.explanation}"]
        return []
