"""Capability-gated device assessment."""

from .assessor import DeviceCapabilityAssessor
from .decision_engine import (
    AcquisitionPlanRecommendation,
    AcquisitionVector,
    AcquisitionVectorDecisionEngine,
    AppAcquisitionRoute,
    VectorEvaluation,
    VectorRiskLevel,
    VectorStatus,
)
from .locked_device import (
    INITIAL_LAB_TARGET_CHIPSETS,
    LOCKED_DEVICE_PROFILES,
    LOCKED_DEVICE_RESEARCH_PROFILES,
    LockedDeviceProfile,
    LockedDeviceResearchProfile,
    assess_locked_device,
    find_locked_device_research_profile,
)
from .models import (
    AcquisitionReadiness,
    AndroidDeviceState,
    CapabilityDecision,
    CapabilityStatus,
    DeviceCapabilitySnapshot,
    LockedDeviceReadiness,
    TemporaryRootReadiness,
)
from .temporary_root_provider import (
    HashPinnedTemporaryRootProvider,
    TemporaryRootProviderError,
    TemporaryRootProviderPackage,
    TemporaryRootProviderResult,
)
from .temporary_root_workflow import (
    TemporaryRootProfileMismatchError,
    TemporaryRootWorkflow,
    TemporaryRootWorkflowResult,
)

__all__ = [
    "AcquisitionPlanRecommendation",
    "AcquisitionReadiness",
    "AcquisitionVector",
    "AcquisitionVectorDecisionEngine",
    "AndroidDeviceState",
    "AppAcquisitionRoute",
    "CapabilityDecision",
    "CapabilityStatus",
    "DeviceCapabilityAssessor",
    "DeviceCapabilitySnapshot",
    "LOCKED_DEVICE_PROFILES",
    "LOCKED_DEVICE_RESEARCH_PROFILES",
    "INITIAL_LAB_TARGET_CHIPSETS",
    "LockedDeviceProfile",
    "LockedDeviceResearchProfile",
    "LockedDeviceReadiness",
    "assess_locked_device",
    "find_locked_device_research_profile",
    "TemporaryRootReadiness",
    "HashPinnedTemporaryRootProvider",
    "TemporaryRootProviderError",
    "TemporaryRootProviderPackage",
    "TemporaryRootProviderResult",
    "TemporaryRootProfileMismatchError",
    "TemporaryRootWorkflow",
    "TemporaryRootWorkflowResult",
    "VectorEvaluation",
    "VectorRiskLevel",
    "VectorStatus",
]
