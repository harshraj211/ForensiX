"""ADB executable discovery with explicit precedence."""

import os
import shutil
from pathlib import Path

from .errors import AdbBinaryNotFoundError


class AdbBinaryResolver:
    """Resolve ADB from explicit configuration before the process PATH."""

    def __init__(self, configured_path: Path | None = None) -> None:
        self._configured_path = configured_path

    def resolve(self) -> Path:
        if self._configured_path is not None:
            candidate = self._configured_path.expanduser().resolve()
            if candidate.is_file():
                return candidate
            raise AdbBinaryNotFoundError(self._configured_path)

        executable = "adb.exe" if os.name == "nt" else "adb"
        discovered = shutil.which(executable)
        if discovered:
            return Path(discovered).resolve()
        raise AdbBinaryNotFoundError()
