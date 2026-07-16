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
from .service import (
    AcquisitionPlanNotFoundError,
    AcquisitionPlanService,
    AcquisitionPlanValidationError,
    plan_limitations,
    plan_modules,
)

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
    "AcquisitionScope",
    "DeviceIdentityChangedError",
    "EvidenceDiskSpaceError",
    "event_checkpoint",
    "job_checkpoint",
    "InventoryCancelledError",
    "InventoryDiskSpaceError",
    "plan_limitations",
    "plan_modules",
]
