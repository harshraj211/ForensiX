"""Repeatable, privacy-preserving forensic validation records."""

from .matrix import (
    PhysicalMatrixCoverage,
    PhysicalMatrixPolicy,
    PhysicalMatrixReport,
    SealedPhysicalMatrixReport,
    build_physical_matrix,
    verify_physical_matrix,
)
from .models import (
    SealedValidationReport,
    ValidationCheck,
    ValidationConnectionType,
    ValidationEnvironment,
    ValidationOutcome,
    ValidationReport,
    ValidationRunContext,
    ValidationStatus,
)
from .runner import run_adb_validation, verify_validation_report

__all__ = [
    "SealedValidationReport",
    "SealedPhysicalMatrixReport",
    "PhysicalMatrixCoverage",
    "PhysicalMatrixPolicy",
    "PhysicalMatrixReport",
    "ValidationCheck",
    "ValidationConnectionType",
    "ValidationEnvironment",
    "ValidationOutcome",
    "ValidationReport",
    "ValidationRunContext",
    "ValidationStatus",
    "run_adb_validation",
    "build_physical_matrix",
    "verify_physical_matrix",
    "verify_validation_report",
]
