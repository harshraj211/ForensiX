"""Next-Gen Suite Handler — Android 15 / Crypt16 metadata, package enumeration, scoped storage."""

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
    _root_pull,
    resolve_vault,
    update_progress,
    verify_device_online,
    write_result,
)

logger = logging.getLogger(__name__)

# Vold encryption metadata files to pull
_VOLD_FILES = [
    "/data/misc/vold/master_key",
    "/data/misc/vold/master_key.sha1",
    "/data/misc/vold/encrypt_progress",
]

# Android crypto properties to capture
_CRYPTO_PROPS = [
    "ro.crypto.type",
    "ro.crypto.state",
    "ro.crypto.fs_crypto_blkdev",
    "vold.decrypt",
]


def handle_nextgen_suite(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """Execute the Next-Gen (Android 15 / Crypt16) forensic pipeline.

    Steps:
      1. Pull Crypt16 vold metadata files via root
      2. Capture encryption properties via getprop
      3. Package enumeration (pm list packages)
      4. Android 15 scoped-storage bypass via MediaStore content provider
      5. Mark job completed
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
        # ── Step 1: Verify ADB ────────────────────────────────────────────────
        update_progress(session, job, 5, step="[1/5] Verifying ADB connection")
        verify_device_online(serial)

        # ── Step 2: Crypt16 vold metadata ────────────────────────────────────
        update_progress(session, job, 15, step="[2/5] Pulling Crypt16 vold metadata")
        vold_results: dict[str, Any] = {}
        for remote_path in _VOLD_FILES:
            name = Path(remote_path).name
            local = vault / name
            try:
                sha256 = _root_pull(
                    serial,
                    remote_path,
                    local,
                    tmp_suffix=f"vold_{name}",
                )
                vold_results[name] = {
                    "status": "completed",
                    "sha256": sha256,
                    "size_bytes": local.stat().st_size,
                }
                logger.info("NextGen: pulled %s", name)
            except AcquisitionError as exc:
                logger.debug("NextGen: optional vold file missing %s: %s", name, exc)
                vold_results[name] = {"status": "skipped", "reason": str(exc)}
        result["steps"]["vold_metadata"] = vold_results

        # ── Step 3: Encryption properties via getprop ─────────────────────────
        update_progress(session, job, 35, step="[3/5] Capturing encryption properties")
        crypto_path = vault / "crypto_type.txt"
        crypto_lines: list[str] = []
        for prop in _CRYPTO_PROPS:
            try:
                val = _adb(serial, "shell", f"getprop {prop}", timeout=10, check=False)
                crypto_lines.append(f"{prop}={val}")
            except AcquisitionError:
                crypto_lines.append(f"{prop}=<error>")
        crypto_path.write_text("\n".join(crypto_lines) + "\n", encoding="utf-8")
        result["steps"]["crypto_props"] = {
            "status": "completed",
            "file": str(crypto_path),
            "props": dict(line.split("=", 1) for line in crypto_lines if "=" in line),
        }

        # ── Step 4: Package enumeration ───────────────────────────────────────
        update_progress(session, job, 55, step="[4/5] Enumerating packages")
        pkg_results: dict[str, Any] = {}
        for flag, filename in [
            ("-f -3", "packages_third_party.txt"),
            ("-f -s", "packages_system.txt"),
        ]:
            local = vault / filename
            try:
                out = _adb(serial, "shell", f"pm list packages {flag}", timeout=60)
                local.write_text(out, encoding="utf-8")
                pkg_results[filename] = {
                    "status": "completed",
                    "package_count": out.count("package:"),
                    "size_bytes": local.stat().st_size,
                }
            except AcquisitionError as exc:
                logger.warning("NextGen: pm list failed for %s: %s", filename, exc)
                pkg_results[filename] = {"status": "failed", "error": str(exc)}

        # dumpsys package
        dumpsys_path = vault / "dumpsys_package.txt"
        try:
            out = _adb(serial, "shell", "dumpsys package", timeout=120)
            dumpsys_path.write_text(out, encoding="utf-8")
            pkg_results["dumpsys_package.txt"] = {
                "status": "completed",
                "size_bytes": dumpsys_path.stat().st_size,
            }
        except AcquisitionError as exc:
            logger.warning("NextGen: dumpsys package failed: %s", exc)
            pkg_results["dumpsys_package.txt"] = {"status": "failed", "error": str(exc)}

        result["steps"]["packages"] = pkg_results

        # ── Step 5: Scoped storage bypass via MediaStore content provider ─────
        update_progress(session, job, 75, step="[5/5] Querying MediaStore external files")
        media_path = vault / "media_store_external.txt"
        try:
            out = _adb(
                serial,
                "shell",
                (
                    "content query --uri content://media/external/file "
                    "--projection _id:_data:mime_type:date_modified"
                ),
                timeout=120,
            )
            media_path.write_text(out, encoding="utf-8")
            result["steps"]["media_store"] = {
                "status": "completed",
                "file": str(media_path),
                "size_bytes": media_path.stat().st_size,
                "row_count": out.count("Row:"),
            }
        except AcquisitionError as exc:
            logger.warning("NextGen: MediaStore query failed: %s", exc)
            result["steps"]["media_store"] = {"status": "failed", "error": str(exc)}

        # ── Complete ─────────────────────────────────────────────────────────
        result["completed_at"] = datetime.now(UTC).isoformat()
        write_result(session, job, result)
        svc.update_progress(session, job.id, 100, current_step="Next-Gen Suite completed")
        svc.transition(session, job.id, JobState.COMPLETED)
        session.commit()
        logger.info("NextGen-Suite: completed for case %s", case_id)

    except AcquisitionError as exc:
        logger.error("NextGen-Suite AcquisitionError: %s", exc)
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
