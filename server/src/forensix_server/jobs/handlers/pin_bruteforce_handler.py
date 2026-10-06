"""PIN / Lock Screen Brute-Force Handler — hash extraction + offline cracking."""

from __future__ import annotations

import asyncio
import hashlib
import itertools
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

# PIN range to brute-force (4-6 digits — feasible in demo time)
_PIN_LENGTHS = (4, 5, 6)
_MAX_BRUTE_CANDIDATES = 1_000_000  # hard cap to prevent infinite loops


def handle_pin_bruteforce(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """Extract lock-screen hash and attempt offline PIN recovery.

    Steps:
      1. Pull credential files via OfflineHashExtractor (root)
      2. Route by credential type
      3. Brute-force legacy hash (Android 5–9) or export hashcat command
      4. Write result
    """
    serial: str = params.get("serial", "emulator-5554")
    case_id: str = job.case_id or params.get("case_id", "unknown")
    operator_id: str = params.get("operator_id", "forensix_examiner")
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
        # ── Step 1: Verify ADB + extract hashes ───────────────────────────────
        update_progress(session, job, 5, step="[1/4] Verifying ADB connection")
        verify_device_online(serial)

        update_progress(session, job, 20, step="[2/4] Extracting credential hashes (root)")
        hash_dump = _extract_hashes(serial, case_id, operator_id, vault)
        result["steps"]["hash_extraction"] = {
            "lock_type": hash_dump.get("lock_type", "unknown"),
            "has_pattern_hash": hash_dump.get("has_pattern_hash", False),
            "has_password_salt": hash_dump.get("has_password_salt", False),
            "gatekeeper_blobs": hash_dump.get("gatekeeper_blobs_count", 0),
            "success": hash_dump.get("success", False),
            "error": hash_dump.get("error"),
        }

        lock_type = hash_dump.get("lock_type", "unknown")
        pattern_hash_hex: str | None = hash_dump.get("pattern_hash_hex")
        success = hash_dump.get("success", False)

        # ── Step 2: Route by credential type ─────────────────────────────────
        update_progress(session, job, 40, step="[3/4] Routing by credential type")

        if lock_type == "none":
            result["steps"]["cracking"] = {"status": "no_lock_screen"}
            _complete(session, job, svc, result)
            return

        if not success or (not pattern_hash_hex and not hash_dump.get("password_salt")):
            # Android 10+ Gatekeeper HAL — cannot crack without physical access
            result["steps"]["cracking"] = {
                "status": "gatekeeper_hal",
                "note": (
                    "Android 10+ uses Gatekeeper HAL. "
                    "Hash is not extractable without physical chip access."
                ),
            }
            _complete(session, job, svc, result)
            return

        # ── Step 3: Attempt brute-force ───────────────────────────────────────
        update_progress(session, job, 55, step="[4/4] Running PIN brute-force")

        if pattern_hash_hex:
            # Pattern hash — solve via DFS over 3×3 grid
            crack_result = _crack_pattern(pattern_hash_hex)
        else:
            # PIN hash — get device_id for salt
            device_id = _adb(
                serial,
                "shell",
                "settings get secure android_id",
                timeout=15,
                check=False,
            )
            password_salt = hash_dump.get("password_salt", "")
            crack_result = _crack_pin(pattern_hash_hex or "", device_id, password_salt)

        result["steps"]["cracking"] = crack_result

        # If not cracked, export hashcat command for examiner
        if crack_result.get("status") != "cracked":
            device_id = _adb(
                serial,
                "shell",
                "settings get secure android_id",
                timeout=15,
                check=False,
            )
            hash_val = pattern_hash_hex or hash_dump.get("aggregate_sha256", "")
            result["steps"]["cracking"]["hashcat_cmd"] = (
                f"hashcat -m 5800 {hash_val}:{device_id} wordlist.txt"
            )

        _complete(session, job, svc, result)

    except AcquisitionError as exc:
        logger.error("PINBruteforce AcquisitionError: %s", exc)
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


def _extract_hashes(serial: str, case_id: str, operator_id: str, vault: Path) -> dict[str, Any]:
    """Delegate to OfflineHashExtractor from forensix_forensic."""

    async def _run() -> dict[str, Any]:
        from forensix_forensic.adb import (
            AdbBinaryResolver,
            SubprocessAdbRunner,
            SystemAdbClient,
        )
        from forensix_forensic.extractors.hardware import OfflineHashExtractor

        resolver = AdbBinaryResolver()
        adb_bin = resolver.resolve()
        adb_client = SystemAdbClient(SubprocessAdbRunner(adb_bin))
        extractor = OfflineHashExtractor(adb=adb_client, output_dir=vault)
        dump = await extractor.extract(serial, case_id, operator_id)

        pattern_hex: str | None = None
        if dump.pattern_hash:
            pattern_hex = dump.pattern_hash.hex()

        return {
            "lock_type": dump.lock_type,
            "pattern_hash_hex": pattern_hex,
            "password_salt": dump.password_salt,
            "gatekeeper_blobs_count": len(dump.gatekeeper_blobs),
            "has_pattern_hash": dump.pattern_hash is not None,
            "has_password_salt": dump.password_salt is not None,
            "aggregate_sha256": dump.aggregate_sha256,
            "success": dump.success,
            "error": dump.error_message,
        }

    try:
        return asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Hash extraction async error: %s", exc)
        return {
            "lock_type": "unknown",
            "success": False,
            "error": str(exc),
            "pattern_hash_hex": None,
            "password_salt": None,
            "gatekeeper_blobs_count": 0,
            "has_pattern_hash": False,
            "has_password_salt": False,
            "aggregate_sha256": "",
        }


def _crack_pattern(hash_hex: str) -> dict[str, Any]:
    """Brute-force Android 3×3 pattern via DFS — tests all 389,112 legal paths."""
    clean = hash_hex.strip().lower()
    try:
        target = bytes.fromhex(clean)
    except ValueError:
        return {"status": "failed", "error": "invalid hex hash"}

    # Jump-over constraints on the 3×3 grid
    _JUMPS: dict[tuple[int, int], int] = {
        (0, 2): 1,
        (2, 0): 1,
        (0, 6): 3,
        (6, 0): 3,
        (0, 8): 4,
        (8, 0): 4,
        (1, 7): 4,
        (7, 1): 4,
        (2, 6): 4,
        (6, 2): 4,
        (2, 8): 5,
        (8, 2): 5,
        (3, 5): 4,
        (5, 3): 4,
        (6, 8): 7,
        (8, 6): 7,
    }

    found: list[int] | None = None

    def dfs(path: list[int], visited: set[int]) -> bool:
        nonlocal found
        if len(path) >= 4:
            payload = bytes(path)
            if (
                hashlib.sha1(payload).digest() == target  # noqa: S324
                or hashlib.md5(payload).digest() == target  # noqa: S324 - legacy hash evidence
            ):  # noqa: S324
                found = list(path)
                return True
        if len(path) == 9:
            return False
        last = path[-1]
        for nxt in range(9):
            if nxt not in visited:
                mid = _JUMPS.get((last, nxt))
                if mid is None or mid in visited:
                    visited.add(nxt)
                    path.append(nxt)
                    if dfs(path, visited):
                        return True
                    path.pop()
                    visited.remove(nxt)
        return False

    for start in range(9):
        if dfs([start], {start}):
            break

    if found is not None:
        seq = "".join(str(n + 1) for n in found)
        return {"status": "cracked", "pattern_grid": seq, "node_sequence": found}
    return {"status": "not_cracked", "method": "pattern_dfs"}


def _crack_pin(hash_hex: str, device_id: str, password_salt: str) -> dict[str, Any]:
    """Brute-force 4-6 digit PINs using SHA1(salt + pin) for legacy Android."""
    clean = hash_hex.strip().lower()
    if not clean:
        return {"status": "failed", "error": "no hash provided"}

    # Build salt bytes from device_id
    salt_bytes: bytes = b""
    if device_id:
        try:
            salt_bytes = bytes.fromhex(device_id)
        except ValueError:
            salt_bytes = device_id.encode()

    try:
        target = bytes.fromhex(clean)
    except ValueError:
        return {"status": "not_cracked", "method": "pin_sha1_salted"}

    attempts = 0
    for length in _PIN_LENGTHS:
        for combo in itertools.product("0123456789", repeat=length):
            if attempts > _MAX_BRUTE_CANDIDATES:
                break
            pin_bytes = "".join(combo).encode()
            attempt = hashlib.sha1(salt_bytes + pin_bytes).digest()  # noqa: S324
            if attempt == target[: len(attempt)]:
                return {
                    "status": "cracked",
                    "pin": "".join(combo),
                    "method": "pin_sha1_salted",
                    "attempts": attempts,
                }
            attempts += 1

    return {
        "status": "hash_exported",
        "method": "pin_sha1_salted",
        "attempts": attempts,
        "hash_hex": clean,
    }


def _complete(session: Session, job: JobRecord, svc: JobService, result: dict[str, Any]) -> None:
    result["completed_at"] = datetime.now(UTC).isoformat()
    write_result(session, job, result)
    svc.update_progress(session, job.id, 100, current_step="PIN brute-force completed")
    svc.transition(session, job.id, JobState.COMPLETED)
    session.commit()
    logger.info("PINBruteforce: completed")
