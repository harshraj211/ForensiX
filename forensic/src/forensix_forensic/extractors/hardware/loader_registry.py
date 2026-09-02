"""Lab loader binary registry for hardware forensic acquisition modules.

Hardware acquisition protocols (Sahara/Firehose, MTK BROM, Unisoc FDL,
Kirin eRecovery, Rockchip DFU) require proprietary loader binaries
(programmer `.mbn` / `.elf`, DA `.bin`, FDL `.bin`) that are **never**
bundled with the software.  Examiners must supply their own lab-approved
loader binaries.

This module provides :class:`LoaderStore` — a thin registry that:

1.  Accepts a ``loaders_dir`` path containing the loader binaries.
2.  Validates each loader on first access (file must exist, size > 0).
3.  Optionally cross-checks the SHA-256 of each loader against a
    ``manifest.json`` in the same directory.
4.  Raises :class:`LoaderNotFoundError` with a clear, actionable message
    when a required loader is missing.

Example manifest format (``loaders_dir/manifest.json``)::

    {
        "prog_emmc_firehose_8937.mbn": "aabbcc...hex-sha256",
        "MTK_AllInOne_DA_v6.bin":      "ddeeff...hex-sha256"
    }
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class LoaderNotFoundError(FileNotFoundError):
    """Raised when a required loader binary is not present in the store.

    The error message includes the expected path and instructions for
    obtaining the loader.
    """


class LoaderChecksumError(ValueError):
    """Raised when a loader binary's SHA-256 does not match the manifest."""


# ---------------------------------------------------------------------------
# Loader store
# ---------------------------------------------------------------------------

_MANIFEST_FILENAME = "manifest.json"
_CHUNK_SIZE = 1024 * 1024  # 1 MiB chunks for hashing


class LoaderStore:
    """Registry that locates and validates lab loader binaries at runtime.

    Parameters
    ----------
    loaders_dir:
        Directory that contains the loader binaries.  May be ``None``; if
        so, every :meth:`get` call immediately raises
        :class:`LoaderNotFoundError`.
    validate_checksums:
        If ``True`` and a ``manifest.json`` is present in *loaders_dir*,
        every loader is SHA-256 verified on first access.
    """

    def __init__(
        self,
        loaders_dir: Path | None = None,
        *,
        validate_checksums: bool = True,
    ) -> None:
        self._dir = loaders_dir
        self._validate = validate_checksums
        self._manifest: dict[str, str] = {}
        self._verified: set[str] = set()

        if self._dir is not None:
            self._load_manifest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, filename: str) -> Path:
        """Return the absolute :class:`~pathlib.Path` to *filename*.

        Parameters
        ----------
        filename:
            Basename of the loader binary (e.g.
            ``"prog_emmc_firehose_8937.mbn"``).

        Returns
        -------
        Path
            Absolute path to the loader binary.

        Raises
        ------
        LoaderNotFoundError
            If the file is not present, is empty, or no
            ``loaders_dir`` was configured.
        LoaderChecksumError
            If the file's SHA-256 does not match the manifest entry.
        """
        if self._dir is None:
            raise LoaderNotFoundError(
                f"Loader '{filename}' cannot be located: no loaders_dir configured. "
                "Pass a loaders_dir=Path('/your/lab/loaders') to the extractor."
            )

        path = self._dir / filename

        if not path.exists():
            raise LoaderNotFoundError(
                f"Loader binary not found: {path}\n"
                f"Expected '{filename}' in '{self._dir}'.\n"
                "Obtain the appropriate loader from your lab's approved binary set "
                "and place it in the loaders directory."
            )

        if path.stat().st_size == 0:
            raise LoaderNotFoundError(
                f"Loader binary is empty (0 bytes): {path}\n"
                "The file may be corrupt. Replace it with a valid copy."
            )

        if self._validate and filename not in self._verified:
            self._verify_checksum(filename, path)
            self._verified.add(filename)

        logger.debug("Loader resolved: %s -> %s (%d bytes)", filename, path, path.stat().st_size)
        return path

    def sha256(self, filename: str) -> str:
        """Compute and return the SHA-256 hex digest of a loader binary.

        Calls :meth:`get` first, so all validation applies.
        """
        path = self.get(filename)
        return _file_sha256(path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_manifest(self) -> None:
        """Parse manifest.json from the loaders directory if it exists."""
        assert self._dir is not None  # guarded by caller
        manifest_path = self._dir / _MANIFEST_FILENAME
        if not manifest_path.exists():
            logger.debug(
                "No loader manifest found at %s — checksum validation disabled.",
                manifest_path,
            )
            self._validate = False
            return

        try:
            with manifest_path.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse loader manifest %s: %s", manifest_path, exc)
            self._validate = False
            return

        if not isinstance(data, dict):
            logger.warning(
                "Loader manifest has unexpected format (expected dict): %s",
                manifest_path,
            )
            self._validate = False
            return

        self._manifest = {str(k): str(v).lower() for k, v in data.items()}
        logger.debug(
            "Loader manifest loaded: %d entries from %s",
            len(self._manifest),
            manifest_path,
        )

    def _verify_checksum(self, filename: str, path: Path) -> None:
        """Compare the on-disk SHA-256 of *path* to the manifest entry.

        No-op if *filename* is not listed in the manifest.
        """
        expected = self._manifest.get(filename)
        if expected is None:
            logger.debug("No manifest entry for '%s'; skipping checksum check.", filename)
            return

        actual = _file_sha256(path)
        if actual != expected.lower():
            raise LoaderChecksumError(
                f"Loader checksum mismatch for '{filename}':\n"
                f"  Expected: {expected}\n"
                f"  Actual:   {actual}\n"
                "The file may be corrupt or tampered with. "
                "Replace it with the approved binary from your lab manifest."
            )

        logger.debug("Loader checksum verified: %s = %s", filename, actual)


# ---------------------------------------------------------------------------
# Standalone utility
# ---------------------------------------------------------------------------


def _file_sha256(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of the file at *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()
