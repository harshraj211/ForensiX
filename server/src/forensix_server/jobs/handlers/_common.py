"""Shared primitives for all forensic acquisition job handlers.

Cross-cutting helpers referenced by every handler:
  - _adb()            — subprocess wrapper with error surfacing
  - _root_pull()      — root-copy → sdcard staging → pull → sha256
  - update_progress() — writes progress_percent + current_step to JobRecord
  - resolve_vault()   — standardised vault path from job params
  - AcquisitionError  — domain exception raised on forensic failures
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from forensix_server.db.models import JobRecord

logger = logging.getLogger(__name__)

_TOOL_VERSION = "forensix-handlers-1.0"


class AcquisitionError(RuntimeError):
    """Raised when an ADB or forensic acquisition step fails."""


# ---------------------------------------------------------------------------
# ADB subprocess pattern
# ---------------------------------------------------------------------------


def _adb(serial: str, *args: str, timeout: int = 60, check: bool = True) -> str:
    """Run an ADB command against *serial* and return stripped stdout.

    Raises AcquisitionError on non-zero exit codes when *check* is True.
    """
    cmd = ["adb", "-s", serial, *args]
    logger.debug("ADB: %s", " ".join(cmd))
    try:
        result = subprocess.run(  # noqa: S603 - argv is passed without a shell
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(f"ADB timeout ({timeout}s) [{' '.join(args)}]") from exc

    if check and result.returncode != 0:
        stderr = result.stderr.strip()
        raise AcquisitionError(f"ADB failed [{' '.join(args)}]: {stderr or '(no stderr)'}")
    return result.stdout.strip()


def _adb_raw_binary(serial: str, *args: str, timeout: int = 600) -> bytes:
    """Run an ADB command and return raw stdout bytes (for binary streams)."""
    cmd = ["adb", "-s", serial, *args]
    logger.debug("ADB (binary): %s", " ".join(cmd))
    try:
        result = subprocess.run(  # noqa: S603 - argv is passed without a shell
            cmd,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(f"ADB binary timeout ({timeout}s) [{' '.join(args)}]") from exc

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise AcquisitionError(f"ADB binary failed [{' '.join(args)}]: {stderr or '(no stderr)'}")
    return result.stdout


# ---------------------------------------------------------------------------
# Root-copy pattern
# ---------------------------------------------------------------------------


def _root_pull(serial: str, remote: str, local: Path, *, tmp_suffix: str | None = None) -> str:
    """Copy a root-protected file to the vault via sdcard staging.

    Steps:
      1. ``su -c cp "{remote}" "{tmp}"``
      2. ``adb pull {tmp} {local}``
      3. ``adb shell rm "{tmp}"``

    Returns:
      SHA-256 hex digest of the pulled file.

    Raises:
      AcquisitionError if any step fails or the file is missing/empty.
    """
    name = Path(remote).name
    suffix = tmp_suffix or name
    tmp = f"/sdcard/.fx_{suffix}"

    _adb(serial, "shell", f'su -c \'cp "{remote}" "{tmp}"\'')
    _adb(serial, "pull", tmp, str(local))

    with suppress(Exception):
        _adb(serial, "shell", f'rm "{tmp}"', check=False)

    if not local.exists() or local.stat().st_size == 0:
        raise AcquisitionError(f"Pulled file is missing or empty: {local} (remote: {remote})")

    digest = hashlib.sha256(local.read_bytes()).hexdigest()
    logger.info("Pulled %s → %s (SHA-256: %s)", remote, local, digest)
    return digest


# ---------------------------------------------------------------------------
# Progress helper
# ---------------------------------------------------------------------------


def update_progress(
    session: Session,
    job: JobRecord,
    percent: int,
    *,
    step: str | None = None,
    status: str = "running",
) -> None:
    """Commit a progress update to *job* so polling clients see real-time progress."""
    from forensix_server.jobs.domain import ACTIVE_STATES, JobState
    from forensix_server.jobs.service import JobService

    if JobState(job.state) not in ACTIVE_STATES:
        return  # do not update terminal jobs

    clipped = max(0, min(100, percent))
    svc = JobService()
    svc.update_progress(session, job.id, clipped, current_step=step)
    session.commit()
    logger.debug("Job %s progress → %d%% (%s)", job.id[:8], clipped, step or "")


# ---------------------------------------------------------------------------
# Vault path resolver
# ---------------------------------------------------------------------------


def resolve_vault(params: dict[str, Any], case_id: str | None) -> Path:
    """Return the vault directory for the current case, creating it if needed."""
    base = Path(params.get("vault_base_dir", "") or "data/vault")
    vault = base / (case_id or "no_case")
    vault.mkdir(parents=True, exist_ok=True)
    return vault


# ---------------------------------------------------------------------------
# Utility: write job checkpoint JSON
# ---------------------------------------------------------------------------


def write_result(session: Session, job: JobRecord, result_data: dict[str, Any]) -> None:
    """Persist structured *result_data* into job.checkpoint_json and commit."""
    job.checkpoint_json = json.dumps(result_data, ensure_ascii=True, default=str)
    job.updated_at = datetime.now(UTC)
    session.add(job)
    session.commit()


# ---------------------------------------------------------------------------
# Verify device is online
# ---------------------------------------------------------------------------


def verify_device_online(serial: str) -> None:
    """Check that *serial* reports state 'device'.  Raise AcquisitionError otherwise."""
    state = _adb(serial, "get-state", check=False)
    if state != "device":
        raise AcquisitionError(f"Device {serial!r} is offline or unauthorised (state={state!r})")
