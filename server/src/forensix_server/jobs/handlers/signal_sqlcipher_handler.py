# ruff: noqa: S603, S607
"""Signal SQLCipher Handler — rooted extraction with full key derivation."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from sqlalchemy.orm import Session

from forensix_server.db.models import JobRecord
from forensix_server.jobs.domain import JobState
from forensix_server.jobs.service import JobService

from ._common import (
    AcquisitionError,
    resolve_vault,
    update_progress,
    verify_device_online,
    write_result,
)

logger = logging.getLogger(__name__)

SIGNAL_PACKAGE = "org.thoughtcrime.securesms"
_SIGNAL_DB_REMOTE = f"/data/data/{SIGNAL_PACKAGE}/databases/signal.db"
_SIGNAL_PREFS_REMOTE = f"/data/data/{SIGNAL_PACKAGE}/shared_prefs/{SIGNAL_PACKAGE}_preferences.xml"

# Signal uses "sqlcipher.db" on some versions
_SIGNAL_DB_ALTERNATES = (
    f"/data/data/{SIGNAL_PACKAGE}/databases/signal.db",
    f"/data/data/{SIGNAL_PACKAGE}/databases/sqlcipher.db",
    f"/data/user/0/{SIGNAL_PACKAGE}/databases/signal.db",
    f"/data/user/0/{SIGNAL_PACKAGE}/databases/sqlcipher.db",
)
_SIGNAL_PREFS_ALTERNATES = (
    f"/data/data/{SIGNAL_PACKAGE}/shared_prefs/{SIGNAL_PACKAGE}_preferences.xml",
    f"/data/user/0/{SIGNAL_PACKAGE}/shared_prefs/TextSecurePreferences.xml",
    f"/data/data/{SIGNAL_PACKAGE}/shared_prefs/TextSecurePreferences.xml",
)


def handle_signal_sqlcipher(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """Extract and decrypt Signal's SQLCipher database on a rooted device.

    Steps:
      1. Pull signal.db + WAL/SHM via root staging
      2. Pull shared_prefs XML to extract SQLCipher key
      3. Decrypt signal.db using pysqlcipher3 or sqlcipher binary
      4. Extract messages from decrypted DB
      5. Write to vault + update timeline
    """
    serial: str = params.get("serial", "emulator-5554")
    case_id: str = job.case_id or params.get("case_id", "unknown")
    operator_id: str = params.get("operator_id", "forensix_examiner")
    vault = resolve_vault(params, case_id)
    signal_vault = vault / "signal"
    signal_vault.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "serial": serial,
        "case_id": case_id,
        "steps": {},
        "started_at": datetime.now(UTC).isoformat(),
    }

    svc = JobService()
    svc.transition(session, job.id, JobState.RUNNING)
    session.commit()

    try:
        # ── Step 1: Verify + use forensix_forensic extractor ─────────────────
        update_progress(session, job, 5, step="[1/5] Verifying device and root access")
        verify_device_online(serial)

        update_progress(session, job, 20, step="[2/5] Pulling Signal databases (root)")
        extraction_result = _run_signal_extractor(serial, case_id, operator_id, signal_vault)
        result["steps"]["extraction"] = extraction_result

        db_path = _locate_signal_db(signal_vault)
        prefs_path = _locate_signal_prefs(signal_vault)

        # ── Step 2: Extract SQLCipher key from shared_prefs ───────────────────
        update_progress(session, job, 45, step="[3/5] Extracting SQLCipher key")
        key_result = _extract_sqlcipher_key(prefs_path)
        result["steps"]["key_extraction"] = key_result
        key_hex: str | None = key_result.get("key_hex")

        # ── Step 3: Decrypt signal.db ─────────────────────────────────────────
        update_progress(session, job, 60, step="[4/5] Decrypting signal.db")
        decrypted_path = signal_vault / "signal_decrypted.db"
        if db_path and key_hex:
            decrypt_result = _decrypt_signal_db(db_path, decrypted_path, key_hex)
        else:
            decrypt_result = {
                "status": "skipped",
                "reason": "DB or key not available",
                "db_found": db_path is not None,
                "key_found": key_hex is not None,
            }
        result["steps"]["decryption"] = decrypt_result

        # ── Step 4: Extract messages from decrypted DB ────────────────────────
        update_progress(session, job, 80, step="[5/5] Extracting messages")
        target_db = decrypted_path if decrypted_path.exists() else db_path
        messages_result = _extract_messages(target_db, signal_vault, case_id)
        result["steps"]["messages"] = messages_result

        result["completed_at"] = datetime.now(UTC).isoformat()
        write_result(session, job, result)
        svc.update_progress(session, job.id, 100, current_step="Signal SQLCipher completed")
        svc.transition(session, job.id, JobState.COMPLETED)
        session.commit()
        logger.info("Signal SQLCipher: completed for case %s", case_id)

    except AcquisitionError as exc:
        logger.error("SignalSQLCipher AcquisitionError: %s", exc)
        result["error"] = str(exc)
        write_result(session, job, result)
        svc.transition(
            session,
            job.id,
            JobState.FAILED,
            error_code="ACQUISITION_ERROR",
            error_message=str(exc),
        )
        session.commit()
        raise

    except subprocess.TimeoutExpired as exc:
        msg = f"ADB timeout: {exc}"
        result["error"] = msg
        write_result(session, job, result)
        svc.transition(
            session,
            job.id,
            JobState.FAILED,
            error_code="ADB_TIMEOUT",
            error_message=msg,
        )
        session.commit()
        raise AcquisitionError(msg) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_signal_extractor(
    serial: str, case_id: str, operator_id: str, vault: Path
) -> dict[str, Any]:
    """Use SignalRootedExtractor from forensix_forensic for the heavy lifting."""

    async def _run() -> dict[str, Any]:
        from forensix_forensic.adb import (
            AdbBinaryResolver,
            SubprocessAdbRunner,
            SystemAdbClient,
        )
        from forensix_forensic.extractors import SignalRootedExtractor, StreamingManifestCollector

        resolver = AdbBinaryResolver()
        adb_bin = resolver.resolve()
        adb_client = SystemAdbClient(SubprocessAdbRunner(adb_bin))
        manifest = StreamingManifestCollector(vault)
        extractor = SignalRootedExtractor(adb_client, vault, manifest=manifest)
        res = await extractor.extract(serial, case_id=case_id, operator_id=operator_id)
        return {
            "status": "completed" if res.success else "failed",
            "passphrase_found": res.passphrase_found,
            "encrypted_db_size_bytes": res.encrypted_database_size_bytes,
            "encrypted_db_sha256": res.encrypted_database_sha256,
            "decrypted_path": res.decrypted_database_path,
            "prefs_path": res.preferences_file_path,
            "duration_seconds": res.duration_seconds,
            "error": res.error_message,
        }

    try:
        return asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Signal extractor async error: %s", exc)
        return {"status": "failed", "error": str(exc)}


def _locate_signal_db(vault: Path) -> Path | None:
    for name in ("signal.db", "sqlcipher.db"):
        p = vault / name
        if p.exists() and p.stat().st_size > 0:
            return p
    return None


def _locate_signal_prefs(vault: Path) -> Path | None:
    for name in (
        f"{SIGNAL_PACKAGE}_preferences.xml",
        "TextSecurePreferences.xml",
        "prefs.xml",
    ):
        p = vault / name
        if p.exists():
            return p
    return None


def _extract_sqlcipher_key(prefs_path: Path | None) -> dict[str, Any]:
    """Parse Signal shared_prefs XML to find the SQLCipher passphrase."""
    if not prefs_path or not prefs_path.exists():
        return {"status": "not_found", "key_hex": None}

    # Patterns Signal uses for the database key
    _KEY_NAMES = (
        "pref_database_unencrypted_secret",
        "pref_key_database_passphrase",
        "sqlcipher_key",
        "database_secret_v2",
    )

    try:
        tree = ElementTree.parse(prefs_path)  # noqa: S314
        root = tree.getroot()
        for elem in root.iter():
            name = elem.get("name", "")
            if name in _KEY_NAMES and elem.text:
                raw_text = elem.text.strip()
                # Try base64 decode (Signal stores as base64)
                try:
                    key_bytes = base64.b64decode(raw_text)
                    key_hex = key_bytes.hex()
                    return {
                        "status": "found",
                        "source_pref": name,
                        "key_hex": key_hex,
                        "key_length_bytes": len(key_bytes),
                    }
                except Exception:  # noqa: BLE001
                    # Already hex?
                    if all(c in "0123456789abcdefABCDEF" for c in raw_text):
                        return {
                            "status": "found",
                            "source_pref": name,
                            "key_hex": raw_text.lower(),
                        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc), "key_hex": None}

    return {"status": "not_found", "key_hex": None}


def _decrypt_signal_db(db_path: Path, out_path: Path, key_hex: str) -> dict[str, Any]:
    """Decrypt signal.db using pysqlcipher3; fallback to sqlcipher binary."""
    # Attempt 1: pysqlcipher3
    try:
        from pysqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-not-found]

        conn = sqlcipher.connect(str(db_path))
        conn.execute(f"PRAGMA key=\"x'{key_hex}'\"")
        conn.execute("PRAGMA cipher_page_size=4096")
        conn.execute("PRAGMA kdf_iter=1")
        conn.execute("PRAGMA cipher_hmac_algorithm=HMAC_SHA512")
        conn.execute("PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512")
        # Export to plain SQLite
        conn.execute(f"ATTACH DATABASE '{out_path}' AS plaintext KEY ''")
        conn.execute("SELECT sqlcipher_export('plaintext')")
        conn.execute("DETACH DATABASE plaintext")
        conn.close()

        if out_path.exists() and out_path.stat().st_size > 0:
            return {
                "status": "completed",
                "method": "pysqlcipher3",
                "output_path": str(out_path),
                "size_bytes": out_path.stat().st_size,
            }
    except ImportError:
        logger.debug("pysqlcipher3 not available — trying sqlcipher binary")
    except Exception as exc:  # noqa: BLE001
        logger.warning("pysqlcipher3 decrypt failed: %s", exc)

    # Attempt 2: sqlcipher binary
    try:
        res = subprocess.run(
            [
                "sqlcipher",
                str(db_path),
                f".param set @key \"x'{key_hex}'\"",
                "PRAGMA key=@key;",
                "PRAGMA cipher_page_size=4096;",
                "PRAGMA kdf_iter=1;",
                f".output {out_path}",
                ".dump",
                ".quit",
            ],
            capture_output=True,
            timeout=120,
            text=True,
        )
        if out_path.exists() and out_path.stat().st_size > 0:
            return {
                "status": "completed",
                "method": "sqlcipher_binary",
                "output_path": str(out_path),
                "size_bytes": out_path.stat().st_size,
            }
        return {
            "status": "failed",
            "method": "sqlcipher_binary",
            "stderr": res.stderr[:500],
        }
    except FileNotFoundError:
        return {
            "status": "failed",
            "error": "Neither pysqlcipher3 nor sqlcipher binary available",
        }
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "sqlcipher binary timeout"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def _extract_messages(db_path: Path | None, vault: Path, case_id: str) -> dict[str, Any]:
    """Extract messages from the decrypted (or raw) Signal DB."""
    if not db_path or not db_path.exists():
        return {"status": "skipped", "reason": "no database available"}

    import sqlite3

    messages: list[dict[str, Any]] = []
    try:
        con = sqlite3.connect(str(db_path))
        con.row_factory = sqlite3.Row
        try:
            # Try modern Signal schema
            for row in con.execute(
                "SELECT body, date, date_received, type, address "
                "FROM sms ORDER BY date DESC LIMIT 1000"  # noqa: S608
            ):
                messages.append(
                    {
                        "source": "sms",
                        "body": row["body"],
                        "date": row["date"],
                        "type": row["type"],
                        "contact": row["address"],
                    }
                )
        except sqlite3.OperationalError:
            try:
                for row in con.execute(
                    "SELECT body, date, date_received, msg_box "
                    "FROM mms ORDER BY date DESC LIMIT 1000"  # noqa: S608
                ):
                    messages.append(
                        {
                            "source": "mms",
                            "body": row["body"],
                            "date": row["date"],
                            "type": row["msg_box"],
                        }
                    )
            except sqlite3.OperationalError:
                pass
        finally:
            con.close()

        output_path = vault / "signal_messages.json"
        output_path.write_text(
            json.dumps(
                {"case_id": case_id, "message_count": len(messages), "messages": messages[:500]},
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return {
            "status": "completed",
            "message_count": len(messages),
            "output_file": str(output_path),
        }

    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}
