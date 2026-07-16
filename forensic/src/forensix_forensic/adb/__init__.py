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
    StorageInventoryEntry,
    StorageInventoryResult,
    StorageProbeStatus,
)
from .policy import (
    INVENTORY_MAX_DEPTH,
    INVENTORY_MAX_ITEMS,
    AdbCommandPolicy,
    AdbOperation,
    ApprovedAdbCommand,
    SharedStorageRoot,
)
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
    "INVENTORY_MAX_DEPTH",
    "INVENTORY_MAX_ITEMS",
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
    "StorageInventoryEntry",
    "StorageInventoryResult",
    "StorageProbeStatus",
    "SubprocessAdbRunner",
    "SystemAdbClient",
]
