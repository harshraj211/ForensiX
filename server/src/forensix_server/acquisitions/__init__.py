"""Capability-gated acquisition planning."""

from .domain import AcquisitionModule, AcquisitionScope
from .service import (
    AcquisitionPlanNotFoundError,
    AcquisitionPlanService,
    AcquisitionPlanValidationError,
    plan_limitations,
    plan_modules,
)

__all__ = [
    "AcquisitionModule",
    "AcquisitionPlanNotFoundError",
    "AcquisitionPlanService",
    "AcquisitionPlanValidationError",
    "AcquisitionScope",
    "plan_limitations",
    "plan_modules",
]
