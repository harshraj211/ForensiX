"""Bounded asynchronous subprocess execution for approved ADB operations."""

import asyncio
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .errors import AdbOutputLimitError, AdbTimeoutError, AdbTransferLimitError


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

    async def run_to_file(
        self,
        arguments: Sequence[str],
        destination: Path,
        *,
        timeout_seconds: float,
        max_file_bytes: int,
    ) -> AdbCommandResult:
        """Run an approved pull while enforcing a local partial-file size ceiling."""
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")
        argv = tuple(arguments)
        self._validate_arguments(argv)
        started = time.monotonic()
        creation_flags = 0
        if os.name == "nt":
            creation_flags = 0x08000000 | 0x00000200
        process = await asyncio.create_subprocess_exec(  # noqa: S603
            str(self._adb_path),
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=creation_flags,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        communication = asyncio.gather(
            self._read_limited(process.stdout),
            self._read_limited(process.stderr),
        )
        try:
            async with asyncio.timeout(timeout_seconds):
                while not communication.done():
                    await asyncio.sleep(0.05)
                    size_bytes = await asyncio.to_thread(_file_size, destination)
                    if size_bytes is not None and size_bytes > max_file_bytes:
                        await self._terminate(process)
                        raise AdbTransferLimitError(max_file_bytes)
                stdout_bytes, stderr_bytes = await communication
                exit_code = await process.wait()
        except TimeoutError as error:
            await self._terminate(process)
            communication.cancel()
            raise AdbTimeoutError(timeout_seconds) from error
        except (AdbOutputLimitError, AdbTransferLimitError):
            await self._terminate(process)
            communication.cancel()
            raise
        size_bytes = await asyncio.to_thread(_file_size, destination)
        if size_bytes is not None and size_bytes > max_file_bytes:
            raise AdbTransferLimitError(max_file_bytes)
        return AdbCommandResult(
            argv=argv,
            exit_code=exit_code,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_seconds=time.monotonic() - started,
        )

    async def run_stdout_to_file(
        self,
        arguments: Sequence[str],
        destination: Path,
        *,
        timeout_seconds: float,
        max_file_bytes: int,
    ) -> AdbCommandResult:
        """Stream binary stdout into a new partial file with strict limits."""
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")
        argv = tuple(arguments)
        self._validate_arguments(argv)
        started = time.monotonic()
        creation_flags = 0
        if os.name == "nt":
            creation_flags = 0x08000000 | 0x00000200
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
            with destination.open("xb") as output:
                async with asyncio.timeout(timeout_seconds):
                    _, stderr_bytes = await asyncio.gather(
                        self._copy_limited(process.stdout, output, max_file_bytes),
                        self._read_limited(process.stderr),
                    )
                    exit_code = await process.wait()
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            await self._terminate(process)
            raise
        except TimeoutError as error:
            await self._terminate(process)
            raise AdbTimeoutError(timeout_seconds) from error
        except (AdbOutputLimitError, AdbTransferLimitError):
            await self._terminate(process)
            raise
        return AdbCommandResult(
            argv=argv,
            exit_code=exit_code,
            stdout="",
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_seconds=time.monotonic() - started,
        )

    @staticmethod
    async def _copy_limited(
        stream: asyncio.StreamReader, output: BinaryIO, max_file_bytes: int
    ) -> None:
        size = 0
        while chunk := await stream.read(65_536):
            size += len(chunk)
            if size > max_file_bytes:
                raise AdbTransferLimitError(max_file_bytes)
            await asyncio.to_thread(output.write, chunk)

    async def _read_limited(self, stream: asyncio.StreamReader) -> bytes:
        chunks: list[bytes] = []
        size = 0
        while chunk := await stream.read(min(65_536, self._output_limit_bytes - size + 1)):
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


def _file_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return None
