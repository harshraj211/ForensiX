"""Typed, policy-bounded Android Debug Bridge access."""

from .client import AdbClient, SystemAdbClient
from .discovery import AdbBinaryResolver
from .errors import (
    AdbBinaryNotFoundError,
    AdbCommandError,
    AdbError,
    AdbOutputLimitError,
    AdbTimeoutError,
)
from .mock import MockAdbClient, MockAdbScenario
from .models import AdbServerInfo, DeviceState, DeviceTransport
from .runner import AdbCommandResult, SubprocessAdbRunner

__all__ = [
    "AdbBinaryNotFoundError",
    "AdbBinaryResolver",
    "AdbClient",
    "AdbCommandError",
    "AdbCommandResult",
    "AdbError",
    "AdbOutputLimitError",
    "AdbServerInfo",
    "AdbTimeoutError",
    "DeviceState",
    "DeviceTransport",
    "MockAdbClient",
    "MockAdbScenario",
    "SubprocessAdbRunner",
    "SystemAdbClient",
]
