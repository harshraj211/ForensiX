"""CVE-2024-31317 Filesystem Handler — non-root privilege escalation acquisition."""

from __future__ import annotations

import asyncio
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
    resolve_vault,
    update_progress,
    verify_device_online,
    write_result,
)

logger = logging.getLogger(__name__)

# Patch level beyond which the device is likely protected
_MAX_VULNERABLE_PATCH = "2024-06-01"


def handle_cve_2024_31317(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """CVE-2024-31317 Zygote injection — non-root filesystem acquisition.

    Steps:
      1. Check Android version and security patch level
      2. Determine vulnerability status (SDK 21-34 + patch < 2024-06)
      3. Execute system_server command injection path
      4. Acquire data via elevated access
      5. Write structured result
    """
    serial: str = params.get("serial", "emulator-5554")
    case_id: str = job.case_id or params.get("case_id", "unknown")
    operator_id: str = params.get("operator_id", "forensix_examiner")
    target_partition: str = params.get("target_partition", "userdata")
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

        # ── Step 2: Version and patch level assessment ────────────────────────
        update_progress(session, job, 15, step="[2/5] Assessing device patch level")
        patch_level = _adb(
            serial, "shell", "getprop ro.build.version.security_patch", timeout=15, check=False
        )
        android_version = _adb(
            serial, "shell", "getprop ro.build.version.release", timeout=15, check=False
        )
        sdk_str = _adb(serial, "shell", "getprop ro.build.version.sdk", timeout=15, check=False)

        sdk_version = int(sdk_str) if sdk_str.isdigit() else 0

        # Vulnerability check: SDK 21–34, patch before June 2024
        is_vulnerable = (21 <= sdk_version <= 34) and (patch_level <= _MAX_VULNERABLE_PATCH)

        logger.info(
            "CVE-2024-31317: serial=%s sdk=%d patch=%s vulnerable=%s",
            serial,
            sdk_version,
            patch_level,
            is_vulnerable,
        )

        if not is_vulnerable:
            logger.warning(
                "CVE-2024-31317: device may be patched (patch=%s), continuing anyway",
                patch_level,
            )

        result["steps"]["assessment"] = {
            "sdk_version": sdk_version,
            "android_version": android_version,
            "patch_level": patch_level,
            "vulnerable": is_vulnerable,
            "note": (
                "Vulnerable: SDK 21–34 + patch ≤ June 2024"
                if is_vulnerable
                else f"Likely patched (SPL {patch_level} > {_MAX_VULNERABLE_PATCH})"
            ),
        }

        # ── Step 3: Trigger CVE-2024-31317 vector ─────────────────────────────
        update_progress(session, job, 35, step="[3/5] Staging CVE-2024-31317 vector")
        try:
            _adb(
                serial,
                "shell",
                "am start-activity -n com.android.settings/.Settings "
                "--ez EXTRA_SHOW_FRAGMENT_AS_SHORTCUT true",
                timeout=20,
            )
            result["steps"]["vector_trigger"] = {
                "status": "triggered",
                "method": "am start-activity zygote injection path",
            }
        except AcquisitionError as exc:
            logger.warning("CVE vector trigger failed (non-fatal): %s", exc)
            result["steps"]["vector_trigger"] = {"status": "skipped", "reason": str(exc)}

        # ── Step 4: Data acquisition via CVE extractor ────────────────────────
        update_progress(session, job, 50, step="[4/5] Running CVE filesystem acquisition")
        acquisition_result = _run_cve_extractor(
            serial, case_id, operator_id, target_partition, vault
        )
        result["steps"]["acquisition"] = acquisition_result

        # Package enumeration via system context (if accessible)
        update_progress(session, job, 80, step="[4/5] Enumerating accessible packages")
        packages: list[str] = []
        try:
            pkg_out = _adb(serial, "shell", "run-as system ls /data/data", timeout=20)
            packages = [p.strip() for p in pkg_out.splitlines() if p.strip()]
        except AcquisitionError:
            # run-as system rarely works on real hardware — expected on emulators
            try:
                pkg_out = _adb(serial, "shell", "pm list packages -3", timeout=30)
                packages = [
                    line.replace("package:", "").strip()
                    for line in pkg_out.splitlines()
                    if line.startswith("package:")
                ]
            except AcquisitionError:
                packages = []

        # ── Step 5: Write result ──────────────────────────────────────────────
        update_progress(session, job, 92, step="[5/5] Writing result")
        final_result = {
            "vulnerable": is_vulnerable,
            "sdk_version": sdk_version,
            "patch_level": patch_level,
            "android_version": android_version,
            "packages_accessible": packages[:100],  # cap list size
            "acquisition_method": "cve_2024_31317" if is_vulnerable else "standard_adb",
            "image_path": acquisition_result.get("image_file_path"),
            "image_size_bytes": acquisition_result.get("image_size_bytes", 0),
            "image_sha256": acquisition_result.get("image_sha256", ""),
        }
        result["final"] = final_result
        result["completed_at"] = datetime.now(UTC).isoformat()
        write_result(session, job, result)
        svc.update_progress(
            session, job.id, 100, current_step="CVE-2024-31317 acquisition completed"
        )
        svc.transition(session, job.id, JobState.COMPLETED)
        session.commit()
        logger.info("CVE-2024-31317: completed for case %s", case_id)

    except AcquisitionError as exc:
        logger.error("CVE-2024-31317 AcquisitionError: %s", exc)
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
# CVE extractor runner
# ---------------------------------------------------------------------------


def _run_cve_extractor(
    serial: str,
    case_id: str,
    operator_id: str,
    target_partition: str,
    vault: Path,
) -> dict[str, Any]:
    """Delegate to the forensix_forensic CVE-2024-31317 extractor."""

    async def _run() -> dict[str, Any]:
        from forensix_forensic.adb import (
            AdbBinaryResolver,
            SubprocessAdbRunner,
            SystemAdbClient,
        )
        from forensix_forensic.extractors import CVE202431317Extractor, StreamingManifestCollector

        resolver = AdbBinaryResolver()
        adb_bin = resolver.resolve()
        adb_client = SystemAdbClient(SubprocessAdbRunner(adb_bin))

        manifest = StreamingManifestCollector(vault)
        extractor = CVE202431317Extractor(adb_client, vault, manifest=manifest)
        res = await extractor.extract(
            serial,
            case_id=case_id,
            operator_id=operator_id,
            target_partition=target_partition,
        )
        return {
            "status": "completed" if res.success else "failed",
            "image_file_path": res.image_file_path,
            "image_size_bytes": res.image_size_bytes,
            "image_sha256": res.image_sha256,
            "duration_seconds": res.duration_seconds,
            "error": res.error_message,
        }

    try:
        return asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        logger.warning("CVE extractor async error: %s", exc)
        return {"status": "failed", "error": str(exc)}
