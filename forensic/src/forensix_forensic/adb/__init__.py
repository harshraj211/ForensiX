"""Typed, policy-bounded Android Debug Bridge access."""

from .client import AdbClient, SystemAdbClient
from .discovery import AdbBinaryResolver
from .errors import (
    AdbBinaryNotFoundError,
    AdbCommandError,
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    AdbError,
    AdbOutputLimitError,
    AdbTimeoutError,
)
from .mock import MockAdbClient, MockAdbScenario
from .models import (
    AdbServerInfo,
    DeviceState,
    DeviceTransport,
    SharedStorageRootProbe,
    StorageProbeStatus,
)
from .policy import AdbCommandPolicy, AdbOperation, ApprovedAdbCommand, SharedStorageRoot
from .runner import AdbCommandResult, SubprocessAdbRunner

__all__ = [
    "AdbBinaryNotFoundError",
    "AdbBinaryResolver",
    "AdbClient",
    "AdbCommandError",
    "AdbCommandResult",
    "AdbCommandPolicy",
    "AdbDeviceNotAuthorizedError",
    "AdbDeviceNotFoundError",
    "AdbError",
    "AdbOutputLimitError",
    "AdbOperation",
    "AdbServerInfo",
    "AdbTimeoutError",
    "DeviceState",
    "DeviceTransport",
    "MockAdbClient",
    "MockAdbScenario",
    "ApprovedAdbCommand",
    "SharedStorageRoot",
    "SharedStorageRootProbe",
    "StorageProbeStatus",
    "SubprocessAdbRunner",
    "SystemAdbClient",
]
