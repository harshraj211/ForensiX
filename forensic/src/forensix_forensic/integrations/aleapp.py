"""Version-pinned, shell-free ALEAPP CLI execution with bounded outputs."""

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread
from typing import BinaryIO, Literal

from forensix_forensic.storage import sha256_file


class AleappExecutionError(RuntimeError):
    """Raised when configured ALEAPP execution violates integration policy."""


@dataclass(frozen=True, slots=True)
class AleappConfiguration:
    program_path: Path
    expected_sha256: str
    release_label: str
    python_executable: Path | None = None
    timeout_seconds: float = 30 * 60
    max_console_bytes: int = 2 * 1024 * 1024
    max_result_files: int = 50_000
    max_result_bytes: int = 2 * 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        if len(self.expected_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.expected_sha256
        ):
            raise ValueError("ALEAPP expected SHA-256 must be lowercase hexadecimal.")
        if not self.release_label.strip() or len(self.release_label) > 64:
            raise ValueError("ALEAPP release label is invalid.")
        if (
            min(
                self.timeout_seconds,
                self.max_console_bytes,
                self.max_result_files,
                self.max_result_bytes,
            )
            <= 0
        ):
            raise ValueError("ALEAPP execution limits must be positive.")


@dataclass(frozen=True, slots=True)
class AleappDiagnostic:
    available: bool
    hash_verified: bool
    release_label: str
    program_path: str
    observed_sha256: str | None
    message: str


@dataclass(frozen=True, slots=True)
class AleappOutputFile:
    relative_path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class AleappRunResult:
    release_label: str
    program_sha256: str
    input_type: Literal["zip", "tar", "fs", "gz"]
    exit_code: int
    duration_seconds: float
    stdout: str
    stderr: str
    outputs: tuple[AleappOutputFile, ...]


class AleappRunner:
    """Runs a preinstalled ALEAPP artifact after checking its pinned digest."""

    def __init__(self, configuration: AleappConfiguration) -> None:
        self.configuration = configuration

    def diagnose(self) -> AleappDiagnostic:
        path = self.configuration.program_path.expanduser().absolute()
        if path.is_symlink() or not path.is_file():
            return AleappDiagnostic(
                available=False,
                hash_verified=False,
                release_label=self.configuration.release_label,
                program_path=str(path),
                observed_sha256=None,
                message="The configured ALEAPP program is missing or is not a regular file.",
            )
        observed = sha256_file(path).hexdigest
        matches = observed == self.configuration.expected_sha256
        return AleappDiagnostic(
            available=True,
            hash_verified=matches,
            release_label=self.configuration.release_label,
            program_path=str(path),
            observed_sha256=observed,
            message=(
                "The configured ALEAPP program matches its pinned SHA-256."
                if matches
                else "The configured ALEAPP program does not match its pinned SHA-256."
            ),
        )

    def run(
        self,
        input_path: Path,
        output_directory: Path,
        workspace_root: Path,
        *,
        input_type: Literal["zip", "tar", "fs", "gz"],
    ) -> AleappRunResult:
        diagnostic = self.diagnose()
        if not diagnostic.available or not diagnostic.hash_verified:
            raise AleappExecutionError(diagnostic.message)
        source = input_path.expanduser().absolute()
        if input_type == "fs":
            if source.is_symlink() or not source.is_dir():
                raise AleappExecutionError("ALEAPP filesystem input must be a regular directory.")
        elif source.is_symlink() or not source.is_file():
            raise AleappExecutionError("ALEAPP archive input must be a regular non-link file.")
        workspace = workspace_root.expanduser().absolute().resolve(strict=True)
        output = output_directory.expanduser().absolute()
        if output.exists() or output.is_symlink():
            raise AleappExecutionError("ALEAPP output directory must not already exist.")
        try:
            output.relative_to(workspace)
        except ValueError as error:
            raise AleappExecutionError("ALEAPP output must remain inside its workspace.") from error
        output.mkdir(parents=True, mode=0o700)
        command = self._command(source, output, input_type)
        started = time.monotonic()
        capture_out = _BoundedCapture(self.configuration.max_console_bytes)
        capture_err = _BoundedCapture(self.configuration.max_console_bytes)
        process = subprocess.Popen(  # noqa: S603 -- command is built only from validated local paths.
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            cwd=workspace,
            env=_subprocess_environment(),
            creationflags=_hidden_window_flags(),
        )
        assert process.stdout is not None and process.stderr is not None
        stdout_thread = Thread(target=capture_out.consume, args=(process.stdout,), daemon=True)
        stderr_thread = Thread(target=capture_err.consume, args=(process.stderr,), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        failure: str | None = None
        while process.poll() is None:
            if capture_out.exceeded.is_set() or capture_err.exceeded.is_set():
                failure = "ALEAPP console output exceeded its byte limit."
                break
            if time.monotonic() - started > self.configuration.timeout_seconds:
                failure = "ALEAPP exceeded its execution timeout."
                break
            time.sleep(0.02)
        if failure:
            process.kill()
        exit_code = process.wait(timeout=10)
        stdout_thread.join(timeout=10)
        stderr_thread.join(timeout=10)
        duration = time.monotonic() - started
        if failure:
            raise AleappExecutionError(failure)
        outputs = self._inventory_outputs(output)
        return AleappRunResult(
            release_label=self.configuration.release_label,
            program_sha256=self.configuration.expected_sha256,
            input_type=input_type,
            exit_code=exit_code,
            duration_seconds=duration,
            stdout=capture_out.text(),
            stderr=capture_err.text(),
            outputs=outputs,
        )

    def _command(
        self,
        input_path: Path,
        output_directory: Path,
        input_type: Literal["zip", "tar", "fs", "gz"],
    ) -> list[str]:
        program = self.configuration.program_path.expanduser().absolute()
        if self.configuration.python_executable is None:
            prefix = [str(program)]
        else:
            python = self.configuration.python_executable.expanduser().absolute()
            if python.is_symlink() or not python.is_file():
                raise AleappExecutionError(
                    "The configured Python executable is missing or is not a regular file."
                )
            prefix = [str(python), str(program)]
        return [
            *prefix,
            "-t",
            input_type,
            "-i",
            str(input_path),
            "-o",
            str(output_directory),
        ]

    def _inventory_outputs(self, output: Path) -> tuple[AleappOutputFile, ...]:
        files: list[AleappOutputFile] = []
        total_bytes = 0
        for path in sorted(output.rglob("*")):
            if path.is_symlink():
                raise AleappExecutionError("ALEAPP produced a symbolic link output.")
            if path.is_dir():
                continue
            if not path.is_file():
                raise AleappExecutionError("ALEAPP produced a non-regular output object.")
            if len(files) >= self.configuration.max_result_files:
                raise AleappExecutionError("ALEAPP exceeded its output file-count limit.")
            digest = sha256_file(path)
            total_bytes += digest.size_bytes
            if total_bytes > self.configuration.max_result_bytes:
                raise AleappExecutionError("ALEAPP exceeded its total output byte limit.")
            files.append(
                AleappOutputFile(
                    relative_path=path.relative_to(output).as_posix(),
                    size_bytes=digest.size_bytes,
                    sha256=digest.hexdigest,
                )
            )
        return tuple(files)


class _BoundedCapture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.buffer = bytearray()
        self.exceeded = Event()

    def consume(self, stream: BinaryIO) -> None:
        try:
            while data := stream.read(64 * 1024):
                remaining = self.limit - len(self.buffer)
                if remaining > 0:
                    self.buffer.extend(data[:remaining])
                if len(data) > remaining:
                    self.exceeded.set()
        finally:
            stream.close()

    def text(self) -> str:
        return bytes(self.buffer).decode("utf-8", "replace")


def _subprocess_environment() -> dict[str, str]:
    allowed = (
        "HOME",
        "LANG",
        "LOCALAPPDATA",
        "PATH",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
    )
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _hidden_window_flags() -> int:
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
