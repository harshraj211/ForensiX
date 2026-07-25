"""Signal extraction on rooted Android devices via SQLCipher key retrieval.

On a rooted device the extraction workflow is:

1.  Verify root access via ``su -c id``.
2.  Copy the Signal shared-preferences file that contains the SQLCipher
    encryption key from the application sandbox.
3.  Copy the Signal encrypted database (``sqlcipher.db``) from the sandbox.
4.  Parse the preferences to extract the 32-byte hex-encoded passphrase.
5.  Decrypt the database using SQLCipher with the extracted passphrase.
6.  Every transferred artefact is hashed with SHA-256 and appended to the
    extraction manifest.
"""

from __future__ import annotations

import asyncio
import re
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

SIGNAL_PACKAGE = "org.thoughtcrime.securesms"
SIGNAL_PREFS_REMOTE = "/data/user/0/org.thoughtcrime.securesms/shared_prefs"
SIGNAL_DB_REMOTE = "/data/user/0/org.thoughtcrime.securesms/databases"
SIGNAL_DB_FILENAME = "sqlcipher.db"
SIGNAL_PREFS_FILENAME = "TextSecurePreferences.xml"

# Patterns in Signal's shared preferences that hold the SQLCipher passphrase.
_PASSPHRASE_PATTERNS = (
    re.compile(r'name="pref_key_database_passphrase"[^>]*value="([^"]+)"'),
    re.compile(r'name="sqlcipher_key"[^>]*value="([^"]+)"'),
    re.compile(r'>([0-9a-fA-F]{64,128})<'),
)


@dataclass(frozen=True, slots=True)
class SignalExtractionResult:
    """Outcome of a rooted Signal extraction."""

    extraction_id: str
    package_name: str
    passphrase_found: bool
    passphrase_sha256: str
    encrypted_database_size_bytes: int
    encrypted_database_sha256: str
    decrypted_database_path: str | None
    preferences_file_path: str
    database_file_path: str
    timeline: list[dict[str, str]]
    duration_seconds: float
    success: bool
    error_message: str | None


class SignalRootedExtractor:
    """Extract Signal's SQLCipher-encrypted database on a rooted Android device.

    The extraction proceeds as follows:

    * **Step 1** - Verify root access.
    * **Step 2** - Copy ``shared_prefs/TextSecurePreferences.xml`` via ``su -c cp``.
    * **Step 3** - Copy ``databases/sqlcipher.db`` (and WAL/SHM) via ``su -c cp``.
    * **Step 4** - Parse the passphrase from the preferences XML.
    * **Step 5** - Decrypt the database with SQLCipher using the passphrase.
    * **Step 6** - Record every transferred artefact in the extraction manifest.
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
    ) -> SignalExtractionResult:
        """Execute the full rooted Signal extraction workflow."""
        extraction_id = str(uuid4())
        started = time.monotonic()
        timeline: list[dict[str, str]] = []
        prefs_path = self._work_dir / f"signal_prefs_{extraction_id}.xml"
        db_path = self._work_dir / f"signal_db_{extraction_id}.db"
        wal_path = self._work_dir / f"signal_db_{extraction_id}.db-wal"
        shm_path = self._work_dir / f"signal_db_{extraction_id}.db-shm"
        decrypted_path: Path | None = None
        passphrase = None
        passphrase_hash = ""
        success = False
        error_message: str | None = None

        try:
            # ------------------------------------------------------------------
            # Step 1: verify root access
            # ------------------------------------------------------------------
            await self._log(timeline, "STEP", "Verifying root access")
            root_result = await self._adb.probe_root_access(serial)
            if root_result.status.value != "available":
                raise RuntimeError(
                    "Root access is not available on this device. "
                    "Signal extraction requires a rooted device."
                )
            await self._log(timeline, "STEP", "Root access confirmed")

            # ------------------------------------------------------------------
            # Step 2: copy shared preferences
            # ------------------------------------------------------------------
            await self._log(timeline, "STEP", "Copying Signal shared preferences")
            prefs_cmd = (
                f"cat '{SIGNAL_PREFS_REMOTE}/{SIGNAL_PREFS_FILENAME}'"
            )
            prefs_content = await self._adb.root_exec(serial, prefs_cmd)
            prefs_path.write_text(prefs_content, encoding="utf-8")
            prefs_hash = await asyncio.to_thread(self._hash_file, prefs_path)
            await self._manifest.add_entry(
                ManifestEntry(
                    file_path=str(prefs_path),
                    sha256=prefs_hash,
                    size_bytes=prefs_path.stat().st_size,
                    source_description="Signal shared preferences (TextSecurePreferences.xml)",
                    case_id=case_id,
                )
            )
            await self._log(
                timeline, "STEP", f"Preferences saved: {prefs_path.name}"
            )

            # ------------------------------------------------------------------
            # Step 3: copy the SQLCipher database
            # ------------------------------------------------------------------
            await self._log(timeline, "STEP", "Copying Signal SQLCipher database")
            db_cmd = f"cat '{SIGNAL_DB_REMOTE}/{SIGNAL_DB_FILENAME}'"
            db_raw = await self._adb.root_exec(serial, db_cmd)
            db_path.write_text(db_raw, encoding="utf-8", errors="surrogateescape")
            db_hash = await asyncio.to_thread(self._hash_file, db_path)
            await self._manifest.add_entry(
                ManifestEntry(
                    file_path=str(db_path),
                    sha256=db_hash,
                    size_bytes=db_path.stat().st_size,
                    source_description="Signal encrypted database (sqlcipher.db)",
                    case_id=case_id,
                )
            )

            # Copy WAL and SHM files if present.
            for suffix, dest in (("-wal", wal_path), ("-shm", shm_path)):
                try:
                    wal_cmd = f"cat '{SIGNAL_DB_REMOTE}/{SIGNAL_DB_FILENAME}{suffix}'"
                    wal_content = await self._adb.root_exec(serial, wal_cmd)
                    dest.write_text(wal_content, encoding="utf-8", errors="surrogateescape")
                    wal_hash = await asyncio.to_thread(self._hash_file, dest)
                    await self._manifest.add_entry(
                        ManifestEntry(
                            file_path=str(dest),
                            sha256=wal_hash,
                            size_bytes=dest.stat().st_size,
                            source_description=f"Signal database WAL ({suffix})",
                            case_id=case_id,
                        )
                    )
                except Exception:
                    pass  # WAL/SHM may not exist

            await self._log(
                timeline, "STEP", f"Database saved: {db_path.name}"
            )

            # ------------------------------------------------------------------
            # Step 4: extract the passphrase from preferences
            # ------------------------------------------------------------------
            await self._log(timeline, "STEP", "Extracting SQLCipher passphrase")
            passphrase = self._extract_passphrase(prefs_content)
            if passphrase:
                passphrase_hash = sha256(passphrase.encode("utf-8")).hexdigest()
                await self._log(
                    timeline, "STEP", "Passphrase extracted from preferences"
                )
            else:
                await self._log(
                    timeline,
                    "WARN",
                    "No passphrase found in Signal preferences; "
                    "decryption will not be attempted.",
                )

            # ------------------------------------------------------------------
            # Step 5: decrypt with SQLCipher
            # ------------------------------------------------------------------
            if passphrase:
                await self._log(timeline, "STEP", "Attempting SQLCipher decryption")
                decrypted_path = await asyncio.to_thread(
                    self._decrypt_sqlcipher, db_path, passphrase, self._work_dir
                )
                if decrypted_path:
                    dec_hash = await asyncio.to_thread(self._hash_file, decrypted_path)
                    await self._manifest.add_entry(
                        ManifestEntry(
                            file_path=str(decrypted_path),
                            sha256=dec_hash,
                            size_bytes=decrypted_path.stat().st_size,
                            source_description="Decrypted Signal database",
                            case_id=case_id,
                        )
                    )
                    await self._log(
                        timeline,
                        "STEP",
                        f"Database decrypted: {decrypted_path.name}",
                    )
                else:
                    await self._log(
                        timeline,
                        "WARN",
                        "SQLCipher decryption failed; "
                        "the database may use an incompatible cipher version.",
                    )

            success = True

        except Exception as exc:
            error_message = str(exc)
            await self._log(timeline, "ERROR", error_message)

        finally:
            elapsed = time.monotonic() - started
            self._manifest.finalize(
                extraction_id=extraction_id,
                case_id=case_id,
                operator_id=operator_id,
            )

        return SignalExtractionResult(
            extraction_id=extraction_id,
            package_name=SIGNAL_PACKAGE,
            passphrase_found=passphrase is not None,
            passphrase_sha256=passphrase_hash,
            encrypted_database_size_bytes=db_path.stat().st_size if db_path.exists() else 0,
            encrypted_database_sha256=db_hash if db_path.exists() else "",
            decrypted_database_path=str(decrypted_path) if decrypted_path else None,
            preferences_file_path=str(prefs_path),
            database_file_path=str(db_path),
            timeline=timeline,
            duration_seconds=elapsed,
            success=success,
            error_message=error_message,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_passphrase(xml_content: str) -> str | None:
        """Extract the SQLCipher passphrase from Signal's shared preferences XML."""
        for pattern in _PASSPHRASE_PATTERNS:
            match = pattern.search(xml_content)
            if match:
                candidate = match.group(1).strip()
                # Validate it looks like a hex passphrase
                if len(candidate) >= 32 and all(
                    c in "0123456789abcdefABCDEF" for c in candidate
                ):
                    return candidate.lower()
        return None

    @staticmethod
    def _decrypt_sqlcipher(
        db_path: Path, passphrase: str, dest_dir: Path
    ) -> Path | None:
        """Decrypt a SQLCipher database using the extracted passphrase.

        Returns the decrypted file path on success, ``None`` on failure.
        """
        try:
            # Try pysqlcipher3 first (preferred for SQLCipher 4).
            try:
                from pysqlcipher3 import dbapi2 as sqlcipher

                conn = sqlcipher.connect(str(db_path))
                conn.execute(f"PRAGMA key = \"x'{passphrase}'\"")
                conn.execute("PRAGMA cipher_compatibility = 4")
                test = conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
                if test and test[0] >= 0:
                    out_path = dest_dir / "signal_decrypted.db"
                    conn.execute(f"VACUUM INTO '{out_path}'")
                    conn.close()
                    return out_path
                conn.close()
            except ImportError:
                pass

            # Fallback: try sqlcipher CLI tool.
            import subprocess

            out_path = dest_dir / "signal_decrypted.db"
            result = subprocess.run(  # noqa: S603
                [
                    "sqlcipher",
                    str(db_path),
                    f"PRAGMA key = \"x'{passphrase}'\";",
                    ".dump",
                ],
                capture_output=True,
                timeout=60,
            )
            if result.returncode == 0 and result.stdout:
                out_path.write_bytes(result.stdout)
                return out_path

            return None
        except Exception:
            return None

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = sha256()
        with path.open("rb") as fh:
            while chunk := fh.read(4 * 1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    async def _log(
        self, timeline: list[dict[str, str]], level: str, message: str
    ) -> None:
        timeline.append({
            "timestamp": datetime.now(UTC).isoformat(),
            "level": level,
            "message": message,
        })
