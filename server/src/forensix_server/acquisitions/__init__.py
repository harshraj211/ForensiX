"""Capability-gated acquisition planning."""

from .domain import AcquisitionModule, AcquisitionScope
from .execution import (
    AcquisitionExecutionService,
    AcquisitionJobInvalidStateError,
    AcquisitionJobNotFoundError,
    event_checkpoint,
    job_checkpoint,
)
from .files import AcquisitionFileError, AcquisitionFileService, EvidenceDiskSpaceError
from .inventory import (
    AcquisitionInventoryError,
    AcquisitionInventoryService,
    DeviceIdentityChangedError,
    InventoryCancelledError,
    InventoryDiskSpaceError,
)
from .recovery import (
    AcquisitionRecoveryError,
    AcquisitionRecoveryService,
    PartialIntegrityChangedError,
)
from .service import (
    AcquisitionPlanNotFoundError,
    AcquisitionPlanService,
    AcquisitionPlanValidationError,
    plan_limitations,
    plan_modules,
)
from .verification import EvidenceVerificationError, EvidenceVerificationService

__all__ = [
    "AcquisitionModule",
    "AcquisitionExecutionService",
    "AcquisitionFileError",
    "AcquisitionFileService",
    "AcquisitionJobInvalidStateError",
    "AcquisitionJobNotFoundError",
    "AcquisitionInventoryError",
    "AcquisitionInventoryService",
    "AcquisitionPlanNotFoundError",
    "AcquisitionPlanService",
    "AcquisitionPlanValidationError",
    "AcquisitionRecoveryError",
    "AcquisitionRecoveryService",
    "AcquisitionScope",
    "DeviceIdentityChangedError",
    "EvidenceDiskSpaceError",
    "EvidenceVerificationError",
    "EvidenceVerificationService",
    "event_checkpoint",
    "job_checkpoint",
    "InventoryCancelledError",
    "InventoryDiskSpaceError",
    "PartialIntegrityChangedError",
    "plan_limitations",
    "plan_modules",
]
