"""Pinned, case-launched scrcpy integration for visible Android mirroring."""

import hashlib
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class ScrcpyIntegrationError(RuntimeError):
    pass


class ScrcpyDiagnostic(BaseModel):
    model_config = ConfigDict(frozen=True)

    available: bool
    status: str
    executable_path: str | None = None
    version: str | None = None
    sha256: str | None = None
    guidance: tuple[str, ...] = ()


class ScrcpyLaunchResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    process_id: int = Field(ge=1)
    mode: str
    version: str
    executable_sha256: str
    side_effects: tuple[str, ...]


class ScrcpyRecordingStopResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    process_id: int = Field(ge=1)
    exit_code: int
    already_exited: bool


class ScrcpyController:
    _recording_processes: dict[str, subprocess.Popen[bytes]] = {}
    _recording_lock = threading.Lock()

    def __init__(
        self,
        program_path: Path | None = None,
        expected_sha256: str | None = None,
    ) -> None:
        self._program_path = program_path
        self._expected_sha256 = expected_sha256

    def diagnose(self) -> ScrcpyDiagnostic:
        path = self._resolve()
        if path is None:
            return ScrcpyDiagnostic(
                available=False,
                status="missing",
                guidance=(
                    "Download the official scrcpy Windows release from Genymobile.",
                    "Set FORENSIX_SCRCPY_PATH to the full path of scrcpy.exe.",
                ),
            )
        digest = _sha256_file(path)
        if self._expected_sha256 and digest != self._expected_sha256:
            return ScrcpyDiagnostic(
                available=False,
                status="digest_mismatch",
                executable_path=str(path),
                sha256=digest,
                guidance=("The configured scrcpy executable does not match its pinned SHA-256.",),
            )
        try:
            completed = subprocess.run(  # noqa: S603
                [str(path), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                creationflags=_hidden_creation_flags(),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return ScrcpyDiagnostic(
                available=False,
                status="execution_failed",
                executable_path=str(path),
                sha256=digest,
                guidance=(f"scrcpy version validation failed: {type(error).__name__}.",),
            )
        output = f"{completed.stdout}\n{completed.stderr}"
        match = re.search(r"scrcpy\s+([0-9]+(?:\.[0-9]+){1,3})", output, re.IGNORECASE)
        if completed.returncode != 0 or match is None:
            return ScrcpyDiagnostic(
                available=False,
                status="invalid_executable",
                executable_path=str(path),
                sha256=digest,
                guidance=("The configured executable did not identify itself as scrcpy.",),
            )
        return ScrcpyDiagnostic(
            available=True,
            status="ready",
            executable_path=str(path),
            version=match.group(1),
            sha256=digest,
        )

    def launch(self, serial: str, *, control: bool) -> ScrcpyLaunchResult:
        _validate_serial(serial)
        diagnostic = self.diagnose()
        if (
            not diagnostic.available
            or diagnostic.executable_path is None
            or diagnostic.version is None
            or diagnostic.sha256 is None
        ):
            raise ScrcpyIntegrationError("scrcpy is not configured and validated.")
        arguments = [
            diagnostic.executable_path,
            "--serial",
            serial,
            "--no-audio",
            "--no-clipboard-autosync",
            "--max-size",
            "1600",
            "--max-fps",
            "60",
            "--video-bit-rate",
            "8M",
            "--window-title",
            f"ForensiX Android {serial[-5:]}",
        ]
        if not control:
            arguments.append("--no-control")
        process = subprocess.Popen(  # noqa: S603
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=_visible_process_flags(),
        )
        return ScrcpyLaunchResult(
            process_id=process.pid,
            mode="control" if control else "mirror",
            version=diagnostic.version,
            executable_sha256=diagnostic.sha256,
            side_effects=(
                "scrcpy temporarily starts its server component through ADB.",
                (
                    "Mouse and keyboard actions modify device state."
                    if control
                    else "Read-only mirror mode disables input injection."
                ),
                "Clipboard autosynchronization and audio forwarding are disabled.",
            ),
        )

    def start_recording(
        self,
        recording_id: str,
        serial: str,
        destination: Path,
    ) -> ScrcpyLaunchResult:
        _validate_recording_id(recording_id)
        _validate_serial(serial)
        resolved_destination = destination.expanduser().resolve()
        if resolved_destination.suffix.lower() != ".mp4":
            raise ValueError("scrcpy recordings must use an MP4 destination")
        if resolved_destination.exists():
            raise ValueError("scrcpy recording destination must not already exist")
        resolved_destination.parent.mkdir(parents=True, exist_ok=True)
        diagnostic = self.diagnose()
        if (
            not diagnostic.available
            or diagnostic.executable_path is None
            or diagnostic.version is None
            or diagnostic.sha256 is None
        ):
            raise ScrcpyIntegrationError("scrcpy is not configured and validated.")
        with self._recording_lock:
            if recording_id in self._recording_processes:
                raise ScrcpyIntegrationError("This recording session is already active.")
            arguments = [
                diagnostic.executable_path,
                "--serial",
                serial,
                "--no-audio",
                "--no-clipboard-autosync",
                "--max-size",
                "1600",
                "--max-fps",
                "60",
                "--video-bit-rate",
                "8M",
                "--record",
                str(resolved_destination),
                "--window-title",
                f"ForensiX recorded examination {serial[-5:]}",
            ]
            process = subprocess.Popen(  # noqa: S603
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=_visible_process_flags(),
            )
            self._recording_processes[recording_id] = process
        return ScrcpyLaunchResult(
            process_id=process.pid,
            mode="control",
            version=diagnostic.version,
            executable_sha256=diagnostic.sha256,
            side_effects=(
                "scrcpy records displayed pixels to the local forensic workstation.",
                "Mouse and keyboard actions modify device state.",
                "Clipboard autosynchronization and audio forwarding are disabled.",
            ),
        )

    def stop_recording(
        self, recording_id: str, *, expected_process_id: int
    ) -> ScrcpyRecordingStopResult:
        _validate_recording_id(recording_id)
        with self._recording_lock:
            process = self._recording_processes.pop(recording_id, None)
        if process is None:
            raise ScrcpyIntegrationError(
                "The recording process is not active in this server session."
            )
        if process.pid != expected_process_id:
            with self._recording_lock:
                self._recording_processes[recording_id] = process
            raise ScrcpyIntegrationError("The recording process identity does not match.")
        exit_code = process.poll()
        already_exited = exit_code is not None
        if exit_code is None:
            process.terminate()
            try:
                exit_code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                exit_code = process.wait(timeout=5)
        return ScrcpyRecordingStopResult(
            process_id=process.pid,
            exit_code=exit_code,
            already_exited=already_exited,
        )

    def abandon_recording(self, recording_id: str, *, expected_process_id: int) -> None:
        try:
            self.stop_recording(recording_id, expected_process_id=expected_process_id)
        except ScrcpyIntegrationError:
            return

    def _resolve(self) -> Path | None:
        candidate = self._program_path
        if candidate is None:
            discovered = shutil.which("scrcpy.exe" if os.name == "nt" else "scrcpy")
            candidate = Path(discovered) if discovered else None
        if candidate is None:
            return None
        resolved = candidate.expanduser().resolve()
        return resolved if resolved.is_file() else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_serial(serial: str) -> None:
    if not serial or len(serial) > 255:
        raise ValueError("ADB serial must contain between 1 and 255 characters")
    if any(character.isspace() or ord(character) < 32 for character in serial):
        raise ValueError("ADB serial contains a prohibited control character")


def _validate_recording_id(recording_id: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", recording_id):
        raise ValueError("recording id must be a UUID")


def _hidden_creation_flags() -> int:
    return 0x08000000 if os.name == "nt" else 0


def _visible_process_flags() -> int:
    return 0x00000200 if os.name == "nt" else 0
