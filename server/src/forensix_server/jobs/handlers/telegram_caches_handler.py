"""Telegram Cache Handler — rooted extraction of cache4.db with full WAL/SHM recovery."""

from __future__ import annotations

import asyncio
import json
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
    _root_pull,
    resolve_vault,
    update_progress,
    verify_device_online,
    write_result,
)

logger = logging.getLogger(__name__)

TELEGRAM_PACKAGE = "org.telegram.messenger"

# All Telegram DB files that must be pulled together (WAL/SHM needed for consistency)
_TG_DB_FILES = (
    "cache4.db",
    "cache4.db-wal",
    "cache4.db-shm",
    "usernames.db",
    "usernames.db-wal",
    "usernames.db-shm",
)

_TG_CACHE_BASE = f"/data/data/{TELEGRAM_PACKAGE}/files"
_TG_DB_BASE = f"/data/data/{TELEGRAM_PACKAGE}/files"


def handle_telegram_caches(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """Extract Telegram cache4.db and associated WAL/SHM via rooted ADB pull.

    Steps:
      1. Verify device + root access
      2. Locate Telegram data directory (handles both Telegram and TelegramX)
      3. Pull cache4.db + WAL + SHM via root staging
      4. Pull usernames.db
      5. Extract conversation and media metadata
      6. Write forensic report
    """
    serial: str = params.get("serial", "emulator-5554")
    case_id: str = job.case_id or params.get("case_id", "unknown")
    operator_id: str = params.get("operator_id", "forensix_examiner")
    vault = resolve_vault(params, case_id)
    tg_vault = vault / "telegram"
    tg_vault.mkdir(parents=True, exist_ok=True)

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
        # ── Step 1: Verify + delegate to TelegramRootedExtractor ─────────────
        update_progress(session, job, 5, step="[1/5] Verifying device and root access")
        verify_device_online(serial)

        update_progress(session, job, 20, step="[2/5] Pulling Telegram databases (root)")
        extraction_result = _run_telegram_extractor(serial, case_id, operator_id, tg_vault)
        result["steps"]["extraction"] = extraction_result

        # ── Step 2: Verify DB files and manual fallback pull ──────────────────
        update_progress(session, job, 45, step="[3/5] Verifying pulled database files")
        cache_db = _find_cache4_db(tg_vault)
        pull_details = {}

        if not cache_db:
            logger.warning("TG: cache4.db not found via extractor — trying manual root pull")
            # Try both Telegram and TelegramX packages
            for pkg in (
                TELEGRAM_PACKAGE,
                "org.telegram.messenger.web",
                "org.thunderdog.challegram",
            ):
                for remote_name in ("cache4.db", "cache4.db-wal", "cache4.db-shm"):
                    remote = f"/data/data/{pkg}/files/{remote_name}"
                    local = tg_vault / remote_name
                    try:
                        sha256 = _root_pull(
                            serial,
                            remote,
                            local,
                            tmp_suffix=f"tg_{remote_name.replace('.', '_')}",
                        )
                        pull_details[remote_name] = {
                            "status": "completed",
                            "sha256": sha256,
                            "bytes": local.stat().st_size,
                        }
                        logger.info("TG: pulled %s from %s", remote_name, pkg)
                    except AcquisitionError as exc:
                        logger.debug("TG: optional file %s not found: %s", remote_name, exc)
                        pull_details[remote_name] = {"status": "skipped", "reason": str(exc)}

            cache_db = _find_cache4_db(tg_vault)
            result["steps"]["manual_pull"] = pull_details

        # ── Step 3: Checkpoint WAL into db before reading ─────────────────────
        update_progress(session, job, 60, step="[4/5] Checkpointing WAL journal")
        wal_path = tg_vault / "cache4.db-wal"
        if cache_db and wal_path.exists() and wal_path.stat().st_size > 0:
            wal_result = _checkpoint_wal(cache_db, wal_path)
            result["steps"]["wal_checkpoint"] = wal_result
        else:
            result["steps"]["wal_checkpoint"] = {"status": "skipped", "reason": "no WAL file"}

        # ── Step 4: Extract conversations and media metadata ──────────────────
        update_progress(session, job, 75, step="[5/5] Extracting conversations & media")
        if cache_db:
            msg_result = _extract_telegram_messages(cache_db, tg_vault, case_id)
        else:
            msg_result = {"status": "skipped", "reason": "cache4.db not found after all attempts"}
        result["steps"]["messages"] = msg_result

        result["completed_at"] = datetime.now(UTC).isoformat()
        write_result(session, job, result)
        svc.update_progress(session, job.id, 100, current_step="Telegram Caches completed")
        svc.transition(session, job.id, JobState.COMPLETED)
        session.commit()
        logger.info("Telegram caches: completed for case %s", case_id)

    except AcquisitionError as exc:
        logger.error("TelegramCaches AcquisitionError: %s", exc)
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


def _run_telegram_extractor(
    serial: str, case_id: str, operator_id: str, vault: Path
) -> dict[str, Any]:
    """Use TelegramRootedExtractor from forensix_forensic."""

    async def _run() -> dict[str, Any]:
        from forensix_forensic.adb import (
            AdbBinaryResolver,
            SubprocessAdbRunner,
            SystemAdbClient,
        )
        from forensix_forensic.extractors import (
            StreamingManifestCollector,
            TelegramRootedExtractor,
        )

        resolver = AdbBinaryResolver()
        adb_bin = resolver.resolve()
        adb_client = SystemAdbClient(SubprocessAdbRunner(adb_bin))
        manifest = StreamingManifestCollector(vault)
        extractor = TelegramRootedExtractor(adb_client, vault, manifest=manifest)
        res = await extractor.extract(serial, case_id=case_id, operator_id=operator_id)
        return {
            "status": "completed" if res.success else "failed",
            "files_copied": res.database_files_copied,
            "total_bytes": res.database_total_size_bytes,
            "db_sha256": res.database_sha256,
            "duration_seconds": res.duration_seconds,
            "error": res.error_message,
        }

    try:
        return asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Telegram extractor async error: %s", exc)
        return {"status": "failed", "error": str(exc)}


def _find_cache4_db(vault: Path) -> Path | None:
    """Find cache4.db recursively in the vault directory."""
    for candidate in ("cache4.db",):
        p = vault / candidate
        if p.exists() and p.stat().st_size > 0:
            return p
    # Recursive search
    for p in vault.rglob("cache4.db"):
        if p.stat().st_size > 0:
            return p
    return None


def _checkpoint_wal(db_path: Path, wal_path: Path) -> dict[str, Any]:
    """Run SQLite WAL checkpoint to merge WAL data into the main DB file."""
    import sqlite3

    try:
        # Copy WAL alongside the db if they are not in the same dir
        if wal_path.parent != db_path.parent:
            wal_copy = db_path.parent / "cache4.db-wal"
            wal_copy.write_bytes(wal_path.read_bytes())

        con = sqlite3.connect(str(db_path))
        try:
            mode, log, ckpt = con.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
            return {
                "status": "completed",
                "wal_mode": mode,
                "log_frames": log,
                "ckpt_frames": ckpt,
            }
        finally:
            con.close()
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def _extract_telegram_messages(cache_db: Path, vault: Path, case_id: str) -> dict[str, Any]:
    """Query cache4.db for messages and media metadata."""
    import sqlite3

    messages: list[dict[str, Any]] = []
    media_items: list[dict[str, Any]] = []

    try:
        con = sqlite3.connect(str(cache_db))
        con.row_factory = sqlite3.Row

        # Messages table (Telegram cache schema)
        for table in ("messages", "messages_v2"):
            try:
                for row in con.execute(
                    f"SELECT mid, uid, date, message FROM {table} "  # noqa: S608
                    f"ORDER BY date DESC LIMIT 2000"
                ):
                    messages.append(
                        {
                            "message_id": row["mid"],
                            "user_id": row["uid"],
                            "date": row["date"],
                            "message": row["message"],
                        }
                    )
                break
            except sqlite3.OperationalError:
                continue

        # Media documents table
        for table in ("media_v4", "media_v3", "media_v2", "media"):
            try:
                for row in con.execute(
                    f"SELECT mid, uid, date, type FROM {table} "  # noqa: S608
                    f"ORDER BY date DESC LIMIT 500"
                ):
                    media_items.append(
                        {
                            "message_id": row["mid"],
                            "user_id": row["uid"],
                            "date": row["date"],
                            "media_type": row["type"],
                        }
                    )
                break
            except sqlite3.OperationalError:
                continue

        con.close()

        output_path = vault / "telegram_messages.json"
        output_path.write_text(
            json.dumps(
                {
                    "case_id": case_id,
                    "message_count": len(messages),
                    "media_count": len(media_items),
                    "messages": messages[:1000],
                    "media_items": media_items[:200],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return {
            "status": "completed",
            "message_count": len(messages),
            "media_count": len(media_items),
            "output_file": str(output_path),
        }

    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}
