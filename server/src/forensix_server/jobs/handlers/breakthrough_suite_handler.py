"""Breakthrough Suite Handler — rooted cloud token + PIN + EXT4 image acquisition."""

from __future__ import annotations

import logging
import subprocess
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
    _adb_raw_binary,
    _root_pull,
    resolve_vault,
    update_progress,
    verify_device_online,
    write_result,
)

logger = logging.getLogger(__name__)


def handle_breakthrough_suite(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """Execute the full Breakthrough Suite acquisition pipeline.

    params keys:
      serial        — ADB device serial (e.g. "emulator-5554")
      vault_base_dir — base directory for vault storage
      case_id       — case identifier (falls back to job.case_id)
      operator_id   — examiner identifier

    Steps:
      1. Verify ADB connection
      2. Cloud token extraction (accounts.db via root)
      3. Gesture/PIN hash acquisition
      4. EXT4 userdata raw image via dd
      5. Token extraction from accounts.db
      6. Mark job completed
    """
    serial: str = params.get("serial", "emulator-5554")
    case_id: str = job.case_id or params.get("case_id", "unknown")
    vault = resolve_vault(params, case_id)
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
        # ── Step 1: Verify ADB connection ────────────────────────────────────
        update_progress(session, job, 5, step="[1/6] Verifying ADB connection")
        verify_device_online(serial)
        result["steps"]["adb_verify"] = "ok"
        logger.info("BT-Suite [%s]: device online", serial)

        # ── Step 2: Cloud token — accounts.db ────────────────────────────────
        update_progress(session, job, 15, step="[2/6] Extracting accounts.db (root)")
        accounts_local = vault / "accounts.db"
        try:
            sha256 = _root_pull(
                serial,
                "/data/system/accounts.db",
                accounts_local,
                tmp_suffix="accounts_db",
            )
            result["steps"]["accounts_db"] = {
                "status": "completed",
                "vault_path": str(accounts_local),
                "sha256": sha256,
                "size_bytes": accounts_local.stat().st_size,
            }
            logger.info("BT-Suite: accounts.db pulled (%s)", sha256[:12])
        except AcquisitionError as exc:
            logger.warning("BT-Suite: accounts.db pull failed: %s", exc)
            result["steps"]["accounts_db"] = {"status": "failed", "error": str(exc)}

        # ── Step 3: Gesture / PIN hash ────────────────────────────────────────
        update_progress(session, job, 30, step="[3/6] Pulling gesture.key (root)")
        gesture_local = vault / "gesture.key"
        try:
            sha256 = _root_pull(
                serial,
                "/data/system/gesture.key",
                gesture_local,
                tmp_suffix="gk",
            )
            result["steps"]["gesture_key"] = {
                "status": "completed",
                "vault_path": str(gesture_local),
                "sha256": sha256,
                "size_bytes": gesture_local.stat().st_size,
            }
        except AcquisitionError as exc:
            logger.warning("BT-Suite: gesture.key pull failed: %s", exc)
            result["steps"]["gesture_key"] = {"status": "failed", "error": str(exc)}

        # ── Step 4: EXT4 userdata image via dd ───────────────────────────────
        update_progress(session, job, 45, step="[4/6] Locating userdata block device")
        userdata_img = vault / "userdata.img"
        try:
            # Resolve block device path
            ls_out = _adb(
                serial,
                "shell",
                "su -c 'ls -la /dev/block/by-name/userdata'",
                timeout=30,
            )
            # ls -la output: "... -> /dev/block/sda17" or similar
            partition = "/dev/block/by-name/userdata"
            for token in ls_out.split():
                if token.startswith("/dev/block/"):
                    partition = token
                    break

            update_progress(session, job, 55, step=f"[4/6] Streaming {partition} via dd")
            logger.info("BT-Suite: streaming %s → %s", partition, userdata_img)

            # Stream raw block device via dd — binary stdout
            img_bytes = _adb_raw_binary(
                serial,
                "shell",
                f"su -c 'dd if={partition} bs=4096 status=none'",
                timeout=900,
            )
            if img_bytes:
                userdata_img.write_bytes(img_bytes)
                import hashlib as _hl

                sha256 = _hl.sha256(img_bytes).hexdigest()
                result["steps"]["userdata_img"] = {
                    "status": "completed",
                    "vault_path": str(userdata_img),
                    "partition": partition,
                    "sha256": sha256,
                    "size_bytes": len(img_bytes),
                }
                logger.info("BT-Suite: userdata.img written %d bytes", len(img_bytes))
            else:
                result["steps"]["userdata_img"] = {
                    "status": "failed",
                    "error": "dd returned 0 bytes",
                }
        except AcquisitionError as exc:
            logger.warning("BT-Suite: userdata image failed: %s", exc)
            result["steps"]["userdata_img"] = {"status": "failed", "error": str(exc)}

        # ── Step 5: Token extraction from accounts.db ─────────────────────────
        update_progress(session, job, 75, step="[5/6] Extracting cloud tokens")
        try:
            if accounts_local.exists() and accounts_local.stat().st_size > 0:
                # Parse the sqlite accounts.db directly (no ADB needed for local file)
                tokens = _extract_tokens_from_accounts_db(accounts_local)
                result["steps"]["cloud_tokens"] = {
                    "status": "completed",
                    "token_count": len(tokens),
                    "tokens": tokens,
                }
            else:
                result["steps"]["cloud_tokens"] = {
                    "status": "skipped",
                    "reason": "accounts.db not available",
                }
        except Exception as exc:  # noqa: BLE001
            logger.warning("BT-Suite: token extraction failed: %s", exc)
            result["steps"]["cloud_tokens"] = {"status": "failed", "error": str(exc)}

        # ── Step 6: Complete ─────────────────────────────────────────────────
        update_progress(session, job, 95, step="[6/6] Finalising")
        result["completed_at"] = datetime.now(UTC).isoformat()
        write_result(session, job, result)

        svc.update_progress(session, job.id, 100, current_step="Breakthrough Suite completed")
        svc.transition(session, job.id, JobState.COMPLETED)
        session.commit()
        logger.info("BT-Suite: completed for case %s", case_id)

    except AcquisitionError as exc:
        logger.error("BT-Suite AcquisitionError: %s", exc)
        job.error_code = "ACQUISITION_ERROR"
        job.error_message = str(exc)
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
        msg = f"ADB timeout on step: {exc}"
        logger.error("BT-Suite timeout: %s", msg)
        job.error_code = "ADB_TIMEOUT"
        job.error_message = msg
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


def _extract_tokens_from_accounts_db(db_path: Path) -> list[dict[str, Any]]:
    """Parse accounts.db SQLite file and return account rows as dicts."""
    import sqlite3

    tokens: list[dict[str, Any]] = []
    try:
        con = sqlite3.connect(str(db_path))
        con.row_factory = sqlite3.Row
        try:
            for row in con.execute("SELECT name, type, password FROM accounts LIMIT 500"):
                tokens.append(
                    {
                        "account": row["name"],
                        "type": row["type"],
                        "has_password": bool(row["password"]),
                    }
                )
        except sqlite3.OperationalError:
            # Different schema versions
            cursor = con.execute("SELECT * FROM accounts LIMIT 500")
            columns = [description[0] for description in cursor.description]
            for row in cursor:
                tokens.append(dict(zip(columns, row, strict=True)))
        finally:
            con.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("accounts.db parse error: %s", exc)
    return tokens
