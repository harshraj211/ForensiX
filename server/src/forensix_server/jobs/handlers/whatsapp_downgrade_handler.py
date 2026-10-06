# ruff: noqa: S603, S607
"""WhatsApp Downgrade Handler — safe rollback guaranteed via try/finally."""

from __future__ import annotations

import io
import logging
import subprocess
import tarfile
import time
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from forensix_server.db.models import JobRecord
from forensix_server.jobs.domain import JobState
from forensix_server.jobs.service import JobService

from ._common import (
    AcquisitionError,
    _adb,
    resolve_vault,
    update_progress,
    verify_device_online,
    write_result,
)

logger = logging.getLogger(__name__)

WHATSAPP_PACKAGE = "com.whatsapp"
_MIN_ORIGINAL_APK_BYTES = 5 * 1024 * 1024  # 5 MB
_MIN_BACKUP_BYTES = 100 * 1024  # 100 KB


def handle_whatsapp_downgrade(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """WhatsApp downgrade extraction with unconditional APK restoration.

    Steps:
      1. Save original APK path & pull to vault (MUST succeed before mutation)
      2. Install legacy APK from assets/
      3. Trigger WA to initialise (monkey)
      4. ADB backup of com.whatsapp
      5. Extract msgstore.db from .ab archive
      6. ALWAYS restore original APK (try/finally)
      7. Decode extracted msgstore.db
    """
    serial: str = params.get("serial", "emulator-5554")
    case_id: str = job.case_id or params.get("case_id", "unknown")
    vault = resolve_vault(params, case_id)

    # Locate project root (two levels up from this file's package)
    project_root = Path(__file__).resolve().parents[6]
    legacy_apk = project_root / "assets" / "whatsapp_legacy_2_22.apk"

    result: dict[str, Any] = {
        "serial": serial,
        "case_id": case_id,
        "steps": {},
        "started_at": datetime.now(UTC).isoformat(),
    }

    svc = JobService()
    svc.transition(session, job.id, JobState.RUNNING)
    session.commit()

    original_apk_path: str | None = None
    original_local: Path = vault / "whatsapp_original.apk"

    try:
        # ── Step 1: Verify + Save original APK ───────────────────────────────
        update_progress(session, job, 5, step="[1/7] Verifying device & saving original APK")
        verify_device_online(serial)

        pm_out = _adb(serial, "shell", f"pm path {WHATSAPP_PACKAGE}", timeout=30)
        if "package:" not in pm_out:
            raise AcquisitionError(f"{WHATSAPP_PACKAGE} not installed on device")
        original_apk_path = pm_out.split("package:")[1].strip()

        _adb(serial, "pull", original_apk_path, str(original_local), timeout=120)
        if not original_local.exists() or original_local.stat().st_size < _MIN_ORIGINAL_APK_BYTES:
            raise AcquisitionError(
                f"Original APK too small ({original_local.stat().st_size if original_local.exists() else 0} bytes). "
                "Aborting before any device mutation."
            )

        result["steps"]["save_original"] = {
            "status": "completed",
            "original_apk_path": original_apk_path,
            "local_path": str(original_local),
            "size_bytes": original_local.stat().st_size,
        }
        logger.info("WA-Downgrade: original APK saved (%d bytes)", original_local.stat().st_size)

        # ── All subsequent steps wrapped in try/finally for guaranteed restore ─
        ab_path = vault / "wa_backup.ab"
        msgstore_path = vault / "msgstore_downgraded.db"
        try:
            # Step 2: Install legacy APK
            update_progress(session, job, 20, step="[2/7] Installing legacy APK")
            if not legacy_apk.exists():
                raise AcquisitionError(
                    f"Legacy APK not found at {legacy_apk}. "
                    "Place whatsapp_legacy_2_22.apk in assets/ directory."
                )

            _adb(serial, "install", "-r", "-d", str(legacy_apk), timeout=60)
            # Verify install
            verify_out = _adb(serial, "shell", f"pm path {WHATSAPP_PACKAGE}", timeout=15)
            if "package:" not in verify_out:
                raise AcquisitionError("Legacy APK install reported success but package not found")
            result["steps"]["install_legacy"] = {"status": "completed"}
            logger.info("WA-Downgrade: legacy APK installed")

            # Step 3: Trigger WA initialisation
            update_progress(session, job, 35, step="[3/7] Triggering WA initialisation")
            try:
                _adb(serial, "shell", f"monkey -p {WHATSAPP_PACKAGE} 1", timeout=15)
                time.sleep(5)
                result["steps"]["wa_init"] = {"status": "completed"}
            except AcquisitionError as exc:
                logger.warning("WA-Downgrade: monkey trigger failed (non-fatal): %s", exc)
                result["steps"]["wa_init"] = {"status": "skipped", "reason": str(exc)}

            # Step 4: ADB backup
            update_progress(session, job, 50, step="[4/7] Running adb backup for WhatsApp")
            subprocess.run(
                ["adb", "-s", serial, "backup", "-f", str(ab_path), WHATSAPP_PACKAGE],
                capture_output=True,
                timeout=90,
            )
            if not ab_path.exists() or ab_path.stat().st_size < _MIN_BACKUP_BYTES:
                size = ab_path.stat().st_size if ab_path.exists() else 0
                raise AcquisitionError(
                    f"WhatsApp backup too small ({size} bytes). "
                    "Check device screen — manual accept may be required."
                )
            result["steps"]["adb_backup"] = {
                "status": "completed",
                "file": "wa_backup.ab",
                "bytes": ab_path.stat().st_size,
            }
            logger.info("WA-Downgrade: backup complete (%d bytes)", ab_path.stat().st_size)

            # Step 5: Extract msgstore.db
            update_progress(session, job, 70, step="[5/7] Extracting msgstore.db from backup")
            result["steps"]["extract_msgstore"] = _extract_msgstore_from_ab(ab_path, msgstore_path)

        finally:
            # ── Step 6: ALWAYS restore original APK ──────────────────────────
            update_progress(session, job, 85, step="[6/7] Restoring original WhatsApp APK")
            restore_status = _restore_original_apk(serial, original_local)
            result["steps"]["restore_original"] = restore_status
            logger.info("WA-Downgrade: restore result: %s", restore_status)

        # ── Step 7: Decode msgstore.db ────────────────────────────────────────
        update_progress(session, job, 92, step="[7/7] Decoding WhatsApp messages")
        if msgstore_path.exists() and msgstore_path.stat().st_size > 0:
            decode_result = _decode_msgstore(msgstore_path)
            result["steps"]["decode_messages"] = decode_result
        else:
            result["steps"]["decode_messages"] = {
                "status": "skipped",
                "reason": "msgstore.db not available",
            }

        result["completed_at"] = datetime.now(UTC).isoformat()
        write_result(session, job, result)
        svc.update_progress(session, job.id, 100, current_step="WhatsApp Downgrade completed")
        svc.transition(session, job.id, JobState.COMPLETED)
        session.commit()
        logger.info("WA-Downgrade: completed for case %s", case_id)

    except AcquisitionError as exc:
        logger.error("WA-Downgrade AcquisitionError: %s", exc)
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
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_msgstore_from_ab(ab_path: Path, out_path: Path) -> dict[str, Any]:
    """Decompress a .ab file and extract msgstore.db from the tar stream."""
    try:
        raw = ab_path.read_bytes()
        # Locate compressed data after header (find 4th newline)
        header_end = 24
        nl_count = 0
        for i, b in enumerate(raw[:200]):
            if b == ord("\n"):
                nl_count += 1
                if nl_count == 4:
                    header_end = i + 1
                    break

        compressed = raw[header_end:]
        try:
            decompressed = zlib.decompress(compressed, -15)
        except zlib.error:
            decompressed = zlib.decompress(compressed)

        found = False
        with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:") as tf:
            for member in tf.getmembers():
                if "msgstore.db" in member.name and not member.name.endswith(".crypt15"):
                    f = tf.extractfile(member)
                    if f:
                        out_path.write_bytes(f.read())
                        found = True
                        break

        if found:
            return {
                "status": "completed",
                "file": "msgstore_downgraded.db",
                "bytes": out_path.stat().st_size,
            }
        return {"status": "failed", "error": "msgstore.db not found in backup archive"}

    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def _restore_original_apk(serial: str, local_apk: Path) -> dict[str, Any]:
    """Install the saved original APK back onto the device."""
    if not local_apk.exists():
        return {"status": "failed", "error": "original APK not found locally"}
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "install", "-r", str(local_apk)],
            capture_output=True,
            timeout=90,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            return {"status": "failed", "error": result.stderr.strip()}
        # Verify version
        try:
            ver_out = _adb(
                serial,
                "shell",
                "dumpsys package com.whatsapp | grep versionName",
                timeout=15,
            )
        except AcquisitionError:
            ver_out = "unknown"
        return {
            "status": "completed",
            "version_after_restore": ver_out.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "restore timeout (90s)"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def _decode_msgstore(db_path: Path) -> dict[str, Any]:
    """Extract basic message count from msgstore.db for the result record."""
    import sqlite3

    try:
        con = sqlite3.connect(str(db_path))
        try:
            count = con.execute("SELECT COUNT(*) FROM messages").fetchone()
            msg_count = count[0] if count else 0
        except sqlite3.OperationalError:
            try:
                count = con.execute("SELECT COUNT(*) FROM message").fetchone()
                msg_count = count[0] if count else 0
            except sqlite3.OperationalError:
                msg_count = -1
        finally:
            con.close()
        return {"status": "completed", "message_count": msg_count}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}
