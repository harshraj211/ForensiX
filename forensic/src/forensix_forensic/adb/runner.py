"""Bounded asynchronous subprocess execution for approved ADB operations."""

import asyncio
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .errors import AdbOutputLimitError, AdbTimeoutError


@dataclass(frozen=True, slots=True)
class AdbCommandResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float


class SubprocessAdbRunner:
    """Run an already policy-approved ADB argument vector without a shell."""

    def __init__(
        self,
        adb_path: Path,
        *,
        default_timeout_seconds: float = 10.0,
        output_limit_bytes: int = 1_048_576,
    ) -> None:
        if default_timeout_seconds <= 0:
            raise ValueError("default_timeout_seconds must be positive")
        if output_limit_bytes <= 0:
            raise ValueError("output_limit_bytes must be positive")
        self._adb_path = adb_path.resolve()
        self._default_timeout_seconds = default_timeout_seconds
        self._output_limit_bytes = output_limit_bytes

    @property
    def adb_path(self) -> Path:
        return self._adb_path

    async def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float | None = None,
    ) -> AdbCommandResult:
        argv = tuple(arguments)
        self._validate_arguments(argv)
        timeout = timeout_seconds or self._default_timeout_seconds
        started = time.monotonic()
        creation_flags = 0
        if os.name == "nt":
            creation_flags = 0x08000000 | 0x00000200  # CREATE_NO_WINDOW | NEW_PROCESS_GROUP
        process = await asyncio.create_subprocess_exec(  # noqa: S603
            str(self._adb_path),
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=creation_flags,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            async with asyncio.timeout(timeout):
                stdout_bytes, stderr_bytes = await asyncio.gather(
                    self._read_limited(process.stdout),
                    self._read_limited(process.stderr),
                )
                exit_code = await process.wait()
        except TimeoutError as error:
            await self._terminate(process)
            raise AdbTimeoutError(timeout) from error
        except AdbOutputLimitError:
            await self._terminate(process)
            raise
        return AdbCommandResult(
            argv=argv,
            exit_code=exit_code,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_seconds=time.monotonic() - started,
        )

    async def _read_limited(self, stream: asyncio.StreamReader) -> bytes:
        chunks: list[bytes] = []
        size = 0
        while chunk := await stream.read(65_536):
            size += len(chunk)
            if size > self._output_limit_bytes:
                raise AdbOutputLimitError(self._output_limit_bytes)
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        process.kill()
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except TimeoutError:
            return

    @staticmethod
    def _validate_arguments(arguments: tuple[str, ...]) -> None:
        for argument in arguments:
            if "\x00" in argument or "\r" in argument or "\n" in argument:
                raise ValueError("ADB arguments may not contain control separators")
