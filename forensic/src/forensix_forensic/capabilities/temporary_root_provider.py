"""Hash-pinned executable protocol for validated temporary-root providers.

Provider executables are not bundled here. This adapter only invokes a separately reviewed binary
through a fixed, shell-free protocol after exact profile and SHA-256 validation.
"""

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .temporary_root import TemporaryRootProfile

PROVIDER_TIMEOUT_SECONDS = 300.0
PROVIDER_OUTPUT_LIMIT_BYTES = 64 * 1024


class TemporaryRootProviderError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TemporaryRootProviderPackage:
    profile: TemporaryRootProfile
    executable_path: Path
    executable_sha256: str


@dataclass(frozen=True, slots=True)
class TemporaryRootProviderResult:
    operation: Literal["activate", "cleanup"]
    executable_sha256: str
    return_code: int


class HashPinnedTemporaryRootProvider:
    def __init__(self, package: TemporaryRootProviderPackage, provider_root: Path) -> None:
        self._package = package
        self._provider_root = provider_root.expanduser().resolve()

    @property
    def profile(self) -> TemporaryRootProfile:
        return self._package.profile

    def verify(self) -> str:
        expected = self._package.executable_sha256
        if len(expected) != 64 or any(
            character not in "0123456789abcdef" for character in expected
        ):
            raise TemporaryRootProviderError(
                "The provider SHA-256 must contain 64 lowercase hexadecimal characters."
            )
        executable = self._package.executable_path.expanduser().resolve()
        try:
            executable.relative_to(self._provider_root)
        except ValueError as error:
            raise TemporaryRootProviderError(
                "The provider executable is outside the configured provider directory."
            ) from error
        if self._provider_root.is_symlink() or not self._provider_root.is_dir():
            raise TemporaryRootProviderError("The configured provider directory is unsafe.")
        if executable.is_symlink() or not executable.is_file():
            raise TemporaryRootProviderError("The provider executable is missing or unsafe.")
        observed = _sha256_file(executable)
        if observed != expected:
            raise TemporaryRootProviderError("The provider executable SHA-256 does not match.")
        return observed

    def activate(self, serial: str) -> TemporaryRootProviderResult:
        return self._run("activate", serial)

    def cleanup(self, serial: str) -> TemporaryRootProviderResult:
        return self._run("cleanup", serial)

    def _run(
        self, operation: Literal["activate", "cleanup"], serial: str
    ) -> TemporaryRootProviderResult:
        digest = self.verify()
        if not serial or len(serial) > 255 or any(character in "\r\n\0" for character in serial):
            raise TemporaryRootProviderError("The Android serial is invalid.")
        executable = self._package.executable_path.expanduser().resolve()
        try:
            completed = subprocess.run(  # noqa: S603
                (
                    str(executable),
                    operation,
                    "--protocol-version",
                    "1",
                    "--serial",
                    serial,
                    "--profile",
                    self.profile.profile_id,
                ),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=PROVIDER_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise TemporaryRootProviderError(
                f"The temporary-root provider could not complete {operation}."
            ) from error
        if (
            len(completed.stdout) > PROVIDER_OUTPUT_LIMIT_BYTES
            or len(completed.stderr) > PROVIDER_OUTPUT_LIMIT_BYTES
        ):
            raise TemporaryRootProviderError(
                "The temporary-root provider produced excessive output."
            )
        if completed.returncode != 0:
            raise TemporaryRootProviderError(
                f"The temporary-root provider rejected {operation} with code "
                f"{completed.returncode}."
            )
        return TemporaryRootProviderResult(
            operation=operation,
            executable_sha256=digest,
            return_code=completed.returncode,
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
