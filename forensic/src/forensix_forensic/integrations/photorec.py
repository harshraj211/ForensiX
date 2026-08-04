"""Pinned PhotoRec runner for recovery from verified *working-copy* images.

PhotoRec is supplied by the external TestDisk project.  ForensiX does not distribute, link to,
or modify that GPL-licensed program; an examiner configures a locally installed executable and
pins its SHA-256.  The runner never receives an Android device path or a sealed master path.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class PhotoRecIntegrationError(RuntimeError):
    """Raised when a configured PhotoRec recovery run cannot safely start or finish."""


class PhotoRecDiagnostic(BaseModel):
    model_config = ConfigDict(frozen=True)

    available: bool
    status: str
    executable_path: str | None = None
    version: str | None = None
    sha256: str | None = None
    guidance: tuple[str, ...] = ()


class PhotoRecOutputFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    relative_path: str
    size_bytes: int = Field(ge=0)
    sha256: str


class PhotoRecExecution(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str | None = None
    executable_sha256: str
    command: tuple[str, ...]
    exit_code: int
    output_files: tuple[PhotoRecOutputFile, ...]
    output_total_bytes: int = Field(ge=0)
    console_summary: str


@dataclass(frozen=True, slots=True)
class PhotoRecConfiguration:
    program_path: Path | None
    expected_sha256: str | None
    timeout_seconds: int = 7200
    max_output_files: int = 10_000
    max_output_bytes: int = 16 * 1024 * 1024 * 1024


class PhotoRecController:
    """Strict subprocess wrapper for the official PhotoRec command-line executable."""

    def __init__(self, configuration: PhotoRecConfiguration) -> None:
        self._configuration = configuration

    def diagnose(self) -> PhotoRecDiagnostic:
        path = self._resolve()
        if path is None:
            return PhotoRecDiagnostic(
                available=False,
                status="missing",
                guidance=(
                    "Install TestDisk/PhotoRec from CGSecurity on this workstation.",
                    "Set FORENSIX_PHOTOREC_PATH and pin FORENSIX_PHOTOREC_EXPECTED_SHA256.",
                ),
            )
        digest = _sha256_file(path)
        if self._configuration.expected_sha256 is None:
            return PhotoRecDiagnostic(
                available=False,
                status="untrusted",
                executable_path=str(path),
                sha256=digest,
                guidance=("A PhotoRec executable SHA-256 pin is required before use.",),
            )
        if digest != self._configuration.expected_sha256:
            return PhotoRecDiagnostic(
                available=False,
                status="digest_mismatch",
                executable_path=str(path),
                sha256=digest,
                guidance=("The configured PhotoRec executable does not match its SHA-256 pin.",),
            )
        version = _version(path)
        return PhotoRecDiagnostic(
            available=True,
            status="ready",
            executable_path=str(path),
            version=version,
            sha256=digest,
            guidance=(
                "PhotoRec is an external, GPL-licensed tool operated only on verified "
                "working copies.",
                "Recovered output remains candidate material pending examiner validation.",
            ),
        )

    def recover(
        self,
        source_path: Path,
        output_root: Path,
    ) -> PhotoRecExecution:
        diagnostic = self.diagnose()
        if (
            not diagnostic.available
            or diagnostic.executable_path is None
            or diagnostic.sha256 is None
        ):
            raise PhotoRecIntegrationError("PhotoRec is not configured and hash-validated.")
        source = source_path.expanduser().resolve()
        destination = output_root.expanduser().resolve()
        if source.is_symlink() or not source.is_file():
            raise PhotoRecIntegrationError(
                "Recovery source must be a regular verified working-copy file."
            )
        if destination.exists() and destination.is_symlink():
            raise PhotoRecIntegrationError("Recovery output directory must not be a symbolic link.")
        destination.mkdir(parents=True, exist_ok=True)
        command = (
            diagnostic.executable_path,
            "/logname",
            str(destination / "photorec.log"),
            "/d",
            str(destination / "recovered"),
            "/cmd",
            str(source),
            "partition_none,fileopt,everything,enable,search",
        )
        try:
            completed = subprocess.run(  # noqa: S603
                command,
                cwd=destination,
                capture_output=True,
                text=True,
                timeout=self._configuration.timeout_seconds,
                check=False,
                creationflags=_hidden_creation_flags(),
            )
        except subprocess.TimeoutExpired as error:
            raise PhotoRecIntegrationError(
                "PhotoRec exceeded the configured recovery timeout."
            ) from error
        except OSError as error:
            raise PhotoRecIntegrationError("PhotoRec could not be started.") from error

        files, total = _inventory_outputs(
            destination,
            max_files=self._configuration.max_output_files,
            max_total_bytes=self._configuration.max_output_bytes,
        )
        return PhotoRecExecution(
            version=diagnostic.version,
            executable_sha256=diagnostic.sha256,
            command=(
                "photorec",
                "/logname",
                "photorec.log",
                "/d",
                "recovered",
                "/cmd",
                "verified-working-copy",
                "partition_none,fileopt,everything,enable,search",
            ),
            exit_code=completed.returncode,
            output_files=tuple(files),
            output_total_bytes=total,
            console_summary=_bounded_console(f"{completed.stdout}\n{completed.stderr}"),
        )

    def _resolve(self) -> Path | None:
        candidate = self._configuration.program_path
        if candidate is None:
            command = "photorec_win.exe" if os.name == "nt" else "photorec"
            discovered = shutil.which(command)
            candidate = Path(discovered) if discovered else None
        if candidate is None:
            return None
        resolved = candidate.expanduser().resolve()
        return resolved if resolved.is_file() else None


def _version(path: Path) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603
            [str(path), "/version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=_hidden_creation_flags(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(
        r"(?:PhotoRec|TestDisk)\s+([0-9]+(?:\.[0-9]+){1,3}(?:[-A-Za-z0-9.]*)?)",
        f"{completed.stdout}\n{completed.stderr}",
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def _inventory_outputs(
    root: Path,
    *,
    max_files: int,
    max_total_bytes: int,
) -> tuple[list[PhotoRecOutputFile], int]:
    files: list[PhotoRecOutputFile] = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise PhotoRecIntegrationError("PhotoRec produced a symbolic-link output.")
        if not path.is_file() or path.name == "photorec.log":
            continue
        size = path.stat().st_size
        if len(files) >= max_files:
            raise PhotoRecIntegrationError("PhotoRec exceeded the output file-count policy.")
        if total + size > max_total_bytes:
            raise PhotoRecIntegrationError("PhotoRec exceeded the output byte policy.")
        files.append(
            PhotoRecOutputFile(
                relative_path=path.relative_to(root).as_posix(),
                size_bytes=size,
                sha256=_sha256_file(path),
            )
        )
        total += size
    return files, total


def _bounded_console(value: str) -> str:
    normalized = value.strip()
    return normalized[:16_384] if normalized else "No console output captured."


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _hidden_creation_flags() -> int:
    return 0x08000000 if os.name == "nt" else 0
