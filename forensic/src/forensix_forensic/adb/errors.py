"""Stable ADB error types suitable for safe API mapping."""

from pathlib import Path


class AdbError(RuntimeError):
    """Base class for failures in the controlled ADB subsystem."""

    code = "ADB_ERROR"


class AdbBinaryNotFoundError(AdbError):
    code = "ADB_NOT_FOUND"

    def __init__(self, configured_path: Path | None = None) -> None:
        location = f" at configured path {configured_path}" if configured_path else ""
        super().__init__(f"Android Platform Tools ADB was not found{location}.")
        self.configured_path = configured_path


class AdbTimeoutError(AdbError):
    code = "ADB_TIMEOUT"

    def __init__(self, timeout_seconds: float) -> None:
        super().__init__(f"ADB operation exceeded the {timeout_seconds:g} second timeout.")
        self.timeout_seconds = timeout_seconds


class AdbOutputLimitError(AdbError):
    code = "ADB_OUTPUT_LIMIT_EXCEEDED"

    def __init__(self, limit_bytes: int) -> None:
        super().__init__(f"ADB output exceeded the configured {limit_bytes} byte limit.")
        self.limit_bytes = limit_bytes


class AdbCommandError(AdbError):
    code = "ADB_COMMAND_FAILED"

    def __init__(self, exit_code: int, error_summary: str) -> None:
        super().__init__(f"ADB operation failed with exit code {exit_code}: {error_summary}")
        self.exit_code = exit_code
        self.error_summary = error_summary


class AdbProtocolError(AdbError):
    code = "ADB_PROTOCOL_ERROR"


class AdbDeviceNotFoundError(AdbError):
    code = "DEVICE_NOT_FOUND"

    def __init__(self) -> None:
        super().__init__("The selected Android transport is no longer connected.")


class AdbDeviceNotAuthorizedError(AdbError):
    code = "DEVICE_NOT_AUTHORIZED"

    def __init__(self, state: str) -> None:
        super().__init__(
            f"The selected Android transport is {state} and cannot be assessed until authorized."
        )
        self.state = state
