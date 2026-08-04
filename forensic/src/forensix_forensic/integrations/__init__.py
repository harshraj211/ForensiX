"""Optional, explicitly configured third-party forensic tool adapters."""

from .aleapp import (
    AleappConfiguration,
    AleappDiagnostic,
    AleappExecutionError,
    AleappOutputFile,
    AleappRunner,
    AleappRunResult,
)
from .photorec import (
    PhotoRecConfiguration,
    PhotoRecController,
    PhotoRecDiagnostic,
    PhotoRecExecution,
    PhotoRecIntegrationError,
    PhotoRecOutputFile,
)
from .scrcpy import (
    ScrcpyController,
    ScrcpyDiagnostic,
    ScrcpyIntegrationError,
    ScrcpyLaunchResult,
)

__all__ = [
    "AleappConfiguration",
    "AleappDiagnostic",
    "AleappExecutionError",
    "AleappOutputFile",
    "AleappRunResult",
    "PhotoRecConfiguration",
    "PhotoRecController",
    "PhotoRecDiagnostic",
    "PhotoRecExecution",
    "PhotoRecIntegrationError",
    "PhotoRecOutputFile",
    "AleappRunner",
    "ScrcpyController",
    "ScrcpyDiagnostic",
    "ScrcpyIntegrationError",
    "ScrcpyLaunchResult",
]
