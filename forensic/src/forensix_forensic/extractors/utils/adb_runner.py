import asyncio
import logging
from typing import Any

from .errors import AccessDeniedError, AdbCommandError, DeviceNotConnectedError

logger = logging.getLogger(__name__)


class ADBCommandRunner:
    """Utility class to run ADB commands robustly with timeouts and retries."""

    def __init__(self, adb: Any):
        self.adb = adb

    async def run_shell_command(
        self,
        serial: str,
        command: str,
        timeout: int = 15,
        retries: int = 1,
        require_root: bool = False,
    ) -> str:
        """
        Execute an ADB shell command with timeouts and retries.
        """
        if not self.adb or not hasattr(self.adb, "shell"):
            raise AdbCommandError("ADB transport is not available.")

        final_command = command
        if require_root:
            final_command = f"su -c '{command}'"

        for attempt in range(retries + 1):
            try:
                # Assuming self.adb.shell is an async function
                # We wrap it in wait_for to enforce timeout
                output = await asyncio.wait_for(
                    self.adb.shell(serial, final_command), timeout=timeout
                )

                output_str = str(output).strip()

                if "device" in output_str.lower() and (
                    "device offline" in output_str.lower() or "not found" in output_str.lower()
                ):
                    raise DeviceNotConnectedError(f"Device {serial} is disconnected or offline.")

                if (
                    "permission denied" in output_str.lower()
                    or "inaccessible" in output_str.lower()
                ):
                    raise AccessDeniedError(f"Access denied executing '{command}'.")

                return output_str

            except TimeoutError:
                if attempt == retries:
                    raise AdbCommandError(
                        f"Command '{command}' timed out after {timeout}s."
                    ) from None
                logger.warning(
                    f"ADB command '{command}' timed out. Retrying ({attempt + 1}/{retries})..."
                )
                await asyncio.sleep(1)
            except Exception as e:
                if isinstance(e, (AdbCommandError, DeviceNotConnectedError, AccessDeniedError)):
                    raise
                if attempt == retries:
                    raise AdbCommandError(f"Command '{command}' failed: {e}") from e
                logger.warning(
                    f"ADB command '{command}' failed: {e}. Retrying ({attempt + 1}/{retries})..."
                )
                await asyncio.sleep(1)

        return ""
