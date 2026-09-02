"""Telegram extraction on rooted Android devices via direct sandbox access.

On a rooted device the extraction workflow is:

1.  Verify root access via ``su -c id``.
2.  Locate the ``cache4.db`` database (and WAL/SHM files) inside the
    Telegram application sandbox.
3.  Copy the database files to the workstation via ``su -c cat``.
4.  Each transferred file is SHA-256 hashed and written to the extraction
    manifest for chain-of-custody integrity.
5.  The plaintext ``messages`` table is then available for the existing
    ``TelegramMessageParser``.
"""

# ruff: noqa: E501, SIM105, S110

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from forensix_forensic.adb.client import AdbClient

from .streaming_manifest import ManifestEntry, StreamingManifestCollector

TELEGRAM_PACKAGES = (
    ("org.telegram.messenger", "Telegram"),
    ("org.telegram.messenger.web", "Telegram (Web)"),
)

TELEGRAM_DB_FILES = ("cache4.db", "cache4.db-wal", "cache4.db-shm")


@dataclass(frozen=True, slots=True)
class TelegramExtractionResult:
    """Outcome of a rooted Telegram extraction."""

    extraction_id: str
    package_name: str
    package_display_name: str
    database_files_copied: int
    database_total_size_bytes: int
    database_sha256: str
    database_path: str
    timeline: list[dict[str, str]]
    duration_seconds: float
    success: bool
    error_message: str | None


class TelegramRootedExtractor:
    """Extract Telegram plaintext database on a rooted Android device.

    The extraction proceeds as follows:

    * **Step 1** - Verify root access.
    * **Step 2** - Determine which Telegram package is installed.
    * **Step 3** - Copy ``cache4.db`` (and WAL/SHM) via ``su -c cat``.
    * **Step 4** - Hash every transferred file and record in the manifest.
    """

    def __init__(
        self,
        adb_client: AdbClient,
        work_dir: Path,
        *,
        manifest: StreamingManifestCollector | None = None,
    ) -> None:
        self._adb = adb_client
        self._work_dir = work_dir.resolve()
        self._manifest = manifest or StreamingManifestCollector(work_dir)

    async def extract(
        self,
        serial: str,
        *,
        case_id: str = "",
        operator_id: str = "",
        package_name: str = "",
    ) -> TelegramExtractionResult:
        """Execute the full rooted Telegram extraction workflow."""
        extraction_id = str(uuid4())
        started = time.monotonic()
        timeline: list[dict[str, str]] = []
        db_path: Path | None = None
        db_total_size = 0
        db_hash = ""
        db_files_copied = 0
        success = False
        error_message: str | None = None
        resolved_package = package_name or ""
        display_name = "Telegram"

        try:
            # Step 1: verify root access
            await self._log(timeline, "STEP", "Verifying root access")
            root_result = await self._adb.probe_root_access(serial)
            if root_result.status.value != "available":
                raise RuntimeError(
                    "Root access is not available on this device. "
                    "Telegram extraction requires a rooted device."
                )
            await self._log(timeline, "STEP", "Root access confirmed")

            # Step 2: determine which Telegram package is installed
            if not resolved_package:
                resolved_package, display_name = await self._detect_telegram_package(
                    serial, timeline
                )
            else:
                for pkg_id, display in TELEGRAM_PACKAGES:
                    if pkg_id == resolved_package:
                        display_name = display
                        break

            db_remote_dir = f"/data/user/0/{resolved_package}/files"

            await self._log(
                timeline,
                "STEP",
                f"Targeting Telegram package: {resolved_package}",
            )

            # Step 3: copy database files
            dest_dir = self._work_dir / f"telegram_{extraction_id}"
            dest_dir.mkdir(parents=True, exist_ok=True)
            db_path = dest_dir / "cache4.db"

            for db_file in TELEGRAM_DB_FILES:
                remote = f"{db_remote_dir}/{db_file}"
                dest = dest_dir / db_file
                try:
                    raw_bytes = await self._pull_remote_binary(serial, remote)
                    if raw_bytes:
                        dest.write_bytes(raw_bytes)
                        file_hash = await asyncio.to_thread(self._hash_file, dest)
                        file_size = dest.stat().st_size
                        db_total_size += file_size
                        await self._manifest.add_entry(
                            ManifestEntry(
                                file_path=str(dest),
                                sha256=file_hash,
                                size_bytes=file_size,
                                source_description=f"Telegram database file ({db_file})",
                                case_id=case_id,
                            )
                        )
                        db_files_copied += 1
                        await self._log(
                            timeline,
                            "STEP",
                            f"Copied {db_file}: {file_size} bytes",
                        )
                except Exception as exc:
                    await self._log(
                        timeline,
                        "WARN",
                        f"Could not copy {db_file}: {exc}",
                    )

            # Compute aggregate hash of the primary database
            if db_path and db_path.exists():
                db_hash = await asyncio.to_thread(self._hash_file, db_path)
                await self._log(
                    timeline,
                    "STEP",
                    f"Database hash: {db_hash}",
                )

            # Step 4: also copy shared preferences
            prefs_dir = f"/data/user/0/{resolved_package}/shared_prefs"
            try:
                ls_cmd = f"ls '{prefs_dir}'"
                ls_output = await self._adb.root_exec(serial, ls_cmd)
                pref_files = [f.strip() for f in ls_output.strip().split("\n") if f.strip()]
                for pref_file in pref_files[:10]:
                    remote = f"{prefs_dir}/{pref_file}"
                    dest = dest_dir / f"prefs_{pref_file}"
                    try:
                        raw_bytes = await self._pull_remote_binary(serial, remote)
                        if raw_bytes:
                            dest.write_bytes(raw_bytes)
                            pref_hash = await asyncio.to_thread(self._hash_file, dest)
                            await self._manifest.add_entry(
                                ManifestEntry(
                                    file_path=str(dest),
                                    sha256=pref_hash,
                                    size_bytes=dest.stat().st_size,
                                    source_description=f"Telegram shared preferences ({pref_file})",
                                    case_id=case_id,
                                )
                            )
                    except Exception:
                        await self._log(
                            timeline,
                            "WARN",
                            "A Telegram shared-preferences file could not be copied.",
                        )
            except Exception:
                await self._log(
                    timeline,
                    "WARN",
                    "The Telegram shared-preferences directory could not be listed.",
                )

            success = True

        except Exception as exc:
            error_message = str(exc)
            await self._log(timeline, "ERROR", error_message)

        finally:
            self._manifest.finalize(
                extraction_id=extraction_id,
                case_id=case_id,
                operator_id=operator_id,
            )

        return TelegramExtractionResult(
            extraction_id=extraction_id,
            package_name=resolved_package,
            package_display_name=display_name,
            database_files_copied=db_files_copied,
            database_total_size_bytes=db_total_size,
            database_sha256=db_hash,
            database_path=str(db_path) if db_path else "",
            timeline=timeline,
            duration_seconds=time.monotonic() - started,
            success=success,
            error_message=error_message,
        )

    async def _pull_remote_binary(self, serial: str, remote_path: str) -> bytes:
        """Extract remote binary file via base64 encoded stream to avoid surrogate corruption."""
        import base64

        try:
            b64_output = await self._adb.root_exec(serial, f"base64 '{remote_path}' 2>/dev/null")
            cleaned = "".join(b64_output.split())
            if cleaned:
                return base64.b64decode(cleaned)
        except Exception:
            pass

        # Fallback to cat
        raw_text = await self._adb.root_exec(serial, f"cat '{remote_path}'")
        return raw_text.encode("utf-8", errors="surrogateescape")

    async def _detect_telegram_package(
        self, serial: str, timeline: list[dict[str, str]]
    ) -> tuple[str, str]:
        """Probe the device for an installed Telegram package."""
        packages = await self._adb.list_packages(serial)
        for pkg_id, display in TELEGRAM_PACKAGES:
            if pkg_id in packages:
                return pkg_id, display
        raise RuntimeError("No recognised Telegram package found on this device.")

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = sha256()
        with path.open("rb") as fh:
            while chunk := fh.read(4 * 1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    async def _log(self, timeline: list[dict[str, str]], level: str, message: str) -> None:
        timeline.append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": level,
                "message": message,
            }
        )
