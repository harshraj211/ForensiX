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
    AdbTransferLimitError,
)
from .mock import MockAdbClient, MockAdbScenario
from .models import (
    AdbServerInfo,
    DeviceState,
    DeviceTransport,
    PulledFileResult,
    RootAccessProbe,
    RootAccessStatus,
    RootedBundleResult,
    SharedStorageRootProbe,
    StorageInventoryEntry,
    StorageInventoryResult,
    StorageProbeStatus,
)
from .policy import (
    INVENTORY_MAX_DEPTH,
    INVENTORY_MAX_ITEMS,
    MAX_ACQUIRED_FILE_BYTES,
    MAX_ROOTED_BUNDLE_BYTES,
    AdbCommandPolicy,
    AdbOperation,
    ApprovedAdbCommand,
    RootedCollectionProfile,
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
    "MAX_ACQUIRED_FILE_BYTES",
    "MAX_ROOTED_BUNDLE_BYTES",
    "AdbOutputLimitError",
    "AdbTransferLimitError",
    "AdbOperation",
    "AdbServerInfo",
    "AdbTimeoutError",
    "DeviceState",
    "DeviceTransport",
    "PulledFileResult",
    "RootAccessProbe",
    "RootAccessStatus",
    "RootedBundleResult",
    "MockAdbClient",
    "MockAdbScenario",
    "ApprovedAdbCommand",
    "RootedCollectionProfile",
    "SharedStorageRoot",
    "SharedStorageRootProbe",
    "StorageInventoryEntry",
    "StorageInventoryResult",
    "StorageProbeStatus",
    "SubprocessAdbRunner",
    "SystemAdbClient",
]
