# ruff: noqa: S603, S607
"""Non-Rooted Suite Handler — Five Pillars: Backup, Logcat, Bugreport, CP, Shared Storage."""

from __future__ import annotations

import io
import logging
import subprocess
import tarfile
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


def handle_non_rooted_suite(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """Execute the Non-Rooted 5-Pillar extraction suite.

    Pillar 1 — ADB Backup (.ab → decompressed .tar)
    Pillar 2 — Logcat dump
    Pillar 3 — Bugreport zip
    Pillar 4 — Content Provider queries (SMS, Contacts, Call log)
    Pillar 5 — Shared storage file manifest + sha256
    """
    serial: str = params.get("serial", "emulator-5554")
    case_id: str = job.case_id or params.get("case_id", "unknown")
    vault = resolve_vault(params, case_id)
    pillar_result: dict[str, Any] = {}

    svc = JobService()
    svc.transition(session, job.id, JobState.RUNNING)
    session.commit()

    try:
        update_progress(session, job, 3, step="[0/5] Verifying ADB connection")
        verify_device_online(serial)

        # ── Pillar 1: ADB Backup ──────────────────────────────────────────────
        update_progress(session, job, 10, step="[1/5] Running adb backup")
        pillar_result["pillar_1"] = _pillar_adb_backup(serial, vault)
        write_result(session, job, {"pillars": pillar_result})

        # ── Pillar 2: Logcat ──────────────────────────────────────────────────
        update_progress(session, job, 30, step="[2/5] Capturing logcat dump")
        pillar_result["pillar_2"] = _pillar_logcat(serial, vault)
        write_result(session, job, {"pillars": pillar_result})

        # ── Pillar 3: Bugreport ───────────────────────────────────────────────
        update_progress(session, job, 50, step="[3/5] Generating bugreport")
        pillar_result["pillar_3"] = _pillar_bugreport(serial, vault)
        write_result(session, job, {"pillars": pillar_result})

        # ── Pillar 4: Content Provider queries ────────────────────────────────
        update_progress(session, job, 70, step="[4/5] Querying content providers")
        pillar_result["pillar_4"] = _pillar_content_providers(serial, vault)
        write_result(session, job, {"pillars": pillar_result})

        # ── Pillar 5: Shared storage manifest ────────────────────────────────
        update_progress(session, job, 85, step="[5/5] Scanning shared storage")
        pillar_result["pillar_5"] = _pillar_shared_storage(serial, vault)

        final = {
            "serial": serial,
            "case_id": case_id,
            "pillars": pillar_result,
            "completed_at": datetime.now(UTC).isoformat(),
        }
        write_result(session, job, final)
        svc.update_progress(session, job.id, 100, current_step="Non-Rooted Suite completed")
        svc.transition(session, job.id, JobState.COMPLETED)
        session.commit()
        logger.info("NonRooted-Suite: completed for case %s", case_id)

    except AcquisitionError as exc:
        logger.error("NonRooted-Suite AcquisitionError: %s", exc)
        write_result(session, job, {"pillars": pillar_result, "error": str(exc)})
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
        write_result(session, job, {"pillars": pillar_result, "error": msg})
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
# Pillar implementations
# ---------------------------------------------------------------------------


def _pillar_adb_backup(serial: str, vault: Path) -> dict[str, Any]:
    """Pillar 1: adb backup → decompress zlib stream → write .tar."""
    ab_path = vault / "adb_backup.ab"
    tar_path = vault / "adb_backup.tar"
    try:
        # Run adb backup; emulator auto-accepts without UI interaction
        subprocess.run(
            ["adb", "-s", serial, "backup", "-noencrypt", "-noapk", "-all", "-f", str(ab_path)],
            capture_output=True,
            timeout=120,
        )
        if not ab_path.exists() or ab_path.stat().st_size < 25:
            return {"status": "failed", "error": "backup file too small or missing"}

        raw = ab_path.read_bytes()
        # ADB backup format: 24-byte header ("ANDROID BACKUP\n<version>\n<compress>\n<encryption>\n")
        # find the header end by looking for the third newline after the first
        header_end = 0
        nl_count = 0
        for i, b in enumerate(raw):
            if b == ord("\n"):
                nl_count += 1
                if nl_count == 4:
                    header_end = i + 1
                    break
        if header_end == 0:
            header_end = 24  # fallback

        compressed_data = raw[header_end:]
        if not compressed_data:
            return {"status": "failed", "error": "no data after backup header"}

        # Decompress the deflate stream (wbits=-15 for raw deflate)
        try:
            decompressed = zlib.decompress(compressed_data, -15)
        except zlib.error:
            # Try without the window bits flag (some devices use gzip wrapper)
            try:
                decompressed = zlib.decompress(compressed_data)
            except zlib.error as ze:
                return {"status": "failed", "error": f"zlib decompress failed: {ze}"}

        tar_path.write_bytes(decompressed)

        # Verify it is a valid tar
        try:
            with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:") as _tf:
                member_count = len(_tf.getmembers())
        except tarfile.TarError:
            member_count = 0

        return {
            "status": "completed",
            "file": "adb_backup.tar",
            "bytes": tar_path.stat().st_size,
            "tar_members": member_count,
        }
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "timeout (120s)"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def _pillar_logcat(serial: str, vault: Path) -> dict[str, Any]:
    """Pillar 2: capture logcat dump."""
    log_path = vault / "logcat.txt"
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", "logcat", "-d", "-v", "threadtime", "*:V"],
            capture_output=True,
            timeout=30,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output = result.stdout
        if not output.strip():
            return {"status": "failed", "error": "logcat returned empty output"}
        log_path.write_text(output, encoding="utf-8")
        size = log_path.stat().st_size
        if size == 0:
            return {"status": "failed", "error": "logcat file is 0 bytes"}
        return {"status": "completed", "file": "logcat.txt", "bytes": size}
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "timeout (30s)"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def _pillar_bugreport(serial: str, vault: Path) -> dict[str, Any]:
    """Pillar 3: adb bugreport (writes to a zip)."""
    br_path = vault / "bugreport.zip"
    try:
        subprocess.run(
            ["adb", "-s", serial, "bugreport", str(br_path)],
            capture_output=True,
            timeout=180,
        )
        if not br_path.exists():
            return {"status": "failed", "error": "bugreport.zip not created"}
        size = br_path.stat().st_size
        if size < 1024 * 1024:  # < 1 MB
            return {
                "status": "failed",
                "error": f"bugreport too small ({size} bytes, expected > 1 MB)",
            }
        return {"status": "completed", "file": "bugreport.zip", "bytes": size}
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "timeout (180s)"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def _pillar_content_providers(serial: str, vault: Path) -> dict[str, Any]:
    """Pillar 4: SMS, Contacts, and Call log content provider queries."""
    queries = [
        (
            "sms_content_provider.txt",
            "content query --uri content://sms --projection _id:address:date:body:type",
        ),
        (
            "contacts_content_provider.txt",
            "content query --uri content://contacts/phones --projection _id:display_name:number",
        ),
        (
            "calls_content_provider.txt",
            "content query --uri content://call_log/calls "
            "--projection _id:number:date:duration:type",
        ),
    ]
    files_written: list[str] = []
    errors: list[str] = []
    for filename, cmd in queries:
        local = vault / filename
        try:
            out = _adb(serial, "shell", cmd, timeout=60)
            local.write_text(out, encoding="utf-8")
            files_written.append(filename)
            logger.debug("ContentProvider: %s → %d bytes", filename, local.stat().st_size)
        except AcquisitionError as exc:
            logger.warning("ContentProvider query failed for %s: %s", filename, exc)
            errors.append(f"{filename}: {exc}")

    status = "completed" if files_written else "failed"
    result: dict[str, Any] = {"status": status, "files": files_written}
    if errors:
        result["errors"] = errors
    return result


def _pillar_shared_storage(serial: str, vault: Path) -> dict[str, Any]:
    """Pillar 5: sha256 manifest of all /sdcard files."""
    manifest_path = vault / "sdcard_file_manifest.txt"
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", "find /sdcard -type f -exec sha256sum {} \\;"],
            capture_output=True,
            timeout=60,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output = result.stdout
        manifest_path.write_text(output, encoding="utf-8")
        line_count = output.count("\n")
        return {
            "status": "completed",
            "file": "sdcard_file_manifest.txt",
            "file_count": line_count,
            "bytes": manifest_path.stat().st_size,
        }
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "timeout (60s)"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}
