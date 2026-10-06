"""Tier-1 Deep Forensics & AI Handler — sequential chained pipeline."""

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
    resolve_vault,
    update_progress,
    verify_device_online,
    write_result,
)

logger = logging.getLogger(__name__)


def handle_tier1_deep_forensics(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """Execute the Tier-1 Deep Forensics & AI pipeline (four sequential stages).

    Stage 1 (0→30%):   Deep pull — Signal + Telegram rooted extraction
    Stage 2 (30→70%):  Mega timeline build — aggregate extracted events
    Stage 3 (70→90%):  Social graph build — contact/message graph analysis
    Stage 4 (90→100%): Report generation — forensic narrative output

    Each stage commits its own progress so front-end polling sees live updates.
    """
    serial: str = params.get("serial", "emulator-5554")
    case_id: str = job.case_id or params.get("case_id", "unknown")
    operator_id: str = params.get("operator_id", "forensix_examiner")
    vault = resolve_vault(params, case_id)
    result: dict[str, Any] = {
        "serial": serial,
        "case_id": case_id,
        "stages": {},
        "started_at": datetime.now(UTC).isoformat(),
    }

    svc = JobService()
    svc.transition(session, job.id, JobState.RUNNING)
    session.commit()

    try:
        # ── Stage 1: Deep pull (0 → 30%) ─────────────────────────────────────
        update_progress(session, job, 5, step="[Stage 1/4] Deep pull — verifying device")
        verify_device_online(serial)

        stage1_result = _stage_deep_pull(serial, case_id, operator_id, vault)
        result["stages"]["deep_pull"] = stage1_result

        update_progress(session, job, 30, step="[Stage 1/4] Deep pull complete")
        write_result(session, job, result)

        # ── Stage 2: Mega timeline build (30 → 70%) ───────────────────────────
        update_progress(session, job, 35, step="[Stage 2/4] Building mega timeline")
        stage2_result = _stage_mega_timeline_build(vault, case_id)
        result["stages"]["mega_timeline"] = stage2_result

        update_progress(session, job, 70, step="[Stage 2/4] Timeline build complete")
        write_result(session, job, result)

        # ── Stage 3: Social graph (70 → 90%) ─────────────────────────────────
        update_progress(session, job, 75, step="[Stage 3/4] Building social graph")
        stage3_result = _stage_social_graph(vault, case_id)
        result["stages"]["social_graph"] = stage3_result

        update_progress(session, job, 90, step="[Stage 3/4] Social graph complete")
        write_result(session, job, result)

        # ── Stage 4: Report generation (90 → 100%) ───────────────────────────
        update_progress(session, job, 92, step="[Stage 4/4] Generating forensic report")
        stage4_result = _stage_report_generate(vault, case_id, operator_id, result)
        result["stages"]["report"] = stage4_result

        result["completed_at"] = datetime.now(UTC).isoformat()
        write_result(session, job, result)
        svc.update_progress(session, job.id, 100, current_step="Tier-1 Deep Forensics completed")
        svc.transition(session, job.id, JobState.COMPLETED)
        session.commit()
        logger.info("Tier1: pipeline completed for case %s", case_id)

    except AcquisitionError as exc:
        logger.error("Tier1 AcquisitionError: %s", exc)
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
# Stage implementations
# ---------------------------------------------------------------------------


def _stage_deep_pull(serial: str, case_id: str, operator_id: str, vault: Path) -> dict[str, Any]:
    """Stage 1: Extract Signal and Telegram databases from rooted device."""
    from forensix_forensic.adb import AdbBinaryResolver, SubprocessAdbRunner, SystemAdbClient
    from forensix_forensic.extractors import (
        SignalRootedExtractor,
        StreamingManifestCollector,
        TelegramRootedExtractor,
    )

    result: dict[str, Any] = {"signal": {}, "telegram": {}}

    async def _run() -> None:
        resolver = AdbBinaryResolver()
        adb_bin = resolver.resolve()
        adb_client = SystemAdbClient(SubprocessAdbRunner(adb_bin))

        # Signal extraction
        signal_work = vault / "signal_deep_pull"
        signal_work.mkdir(parents=True, exist_ok=True)
        signal_manifest = StreamingManifestCollector(signal_work)
        signal_extractor = SignalRootedExtractor(adb_client, signal_work, manifest=signal_manifest)
        try:
            sig_res = await signal_extractor.extract(
                serial, case_id=case_id, operator_id=operator_id
            )
            result["signal"] = {
                "status": "completed" if sig_res.success else "failed",
                "passphrase_found": sig_res.passphrase_found,
                "db_size_bytes": sig_res.encrypted_database_size_bytes,
                "db_sha256": sig_res.encrypted_database_sha256,
                "decrypted_path": sig_res.decrypted_database_path,
                "duration_seconds": sig_res.duration_seconds,
                "error": sig_res.error_message,
            }
        except Exception as exc:  # noqa: BLE001
            result["signal"] = {"status": "failed", "error": str(exc)}

        # Telegram extraction
        tg_work = vault / "telegram_deep_pull"
        tg_work.mkdir(parents=True, exist_ok=True)
        tg_manifest = StreamingManifestCollector(tg_work)
        tg_extractor = TelegramRootedExtractor(adb_client, tg_work, manifest=tg_manifest)
        try:
            tg_res = await tg_extractor.extract(serial, case_id=case_id, operator_id=operator_id)
            result["telegram"] = {
                "status": "completed" if tg_res.success else "failed",
                "files_copied": tg_res.database_files_copied,
                "total_bytes": tg_res.database_total_size_bytes,
                "db_sha256": tg_res.database_sha256,
                "duration_seconds": tg_res.duration_seconds,
                "error": tg_res.error_message,
            }
        except Exception as exc:  # noqa: BLE001
            result["telegram"] = {"status": "failed", "error": str(exc)}

    try:
        asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Tier1 deep pull async error: %s", exc)
        if not result["signal"]:
            result["signal"] = {"status": "failed", "error": str(exc)}
        if not result["telegram"]:
            result["telegram"] = {"status": "failed", "error": str(exc)}

    return result


def _stage_mega_timeline_build(vault: Path, case_id: str) -> dict[str, Any]:
    """Stage 2: Aggregate timeline events from extracted databases."""
    events: list[dict[str, Any]] = []

    # Scan vault for known SQLite databases and extract basic event counts
    for db_path in vault.rglob("*.db"):
        try:
            import sqlite3

            con = sqlite3.connect(str(db_path))
            try:
                # Try common message table patterns
                for table in ("message", "messages", "sms", "mms"):
                    try:
                        count = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
                        if count > 0:
                            events.append(
                                {
                                    "source_db": db_path.name,
                                    "table": table,
                                    "event_count": count,
                                }
                            )
                    except sqlite3.OperationalError:
                        continue
            finally:
                con.close()
        except Exception as error:  # noqa: BLE001
            logger.debug("Timeline input skipped for %s: %s", db_path, error)
            continue

    timeline_path = vault / "mega_timeline_summary.json"
    import json

    timeline_path.write_text(
        json.dumps({"case_id": case_id, "events": events}, indent=2),
        encoding="utf-8",
    )

    return {
        "status": "completed",
        "total_event_sources": len(events),
        "total_events": sum(e.get("event_count", 0) for e in events),
        "timeline_file": str(timeline_path),
    }


def _stage_social_graph(vault: Path, case_id: str) -> dict[str, Any]:
    """Stage 3: Build social graph from aggregated contact/message events."""
    # Load timeline summary produced in stage 2
    summary_path = vault / "mega_timeline_summary.json"
    contacts_seen: set[str] = set()

    if summary_path.exists():
        import json as _json

        try:
            data = _json.loads(summary_path.read_text(encoding="utf-8"))
            # Count distinct sources as crude contact nodes
            for ev in data.get("events", []):
                contacts_seen.add(ev.get("source_db", "unknown"))
        except Exception as error:  # noqa: BLE001
            logger.debug("Graph input skipped for %s: %s", summary_path, error)

    graph_path = vault / "social_graph.json"
    import json

    graph = {
        "case_id": case_id,
        "nodes": [{"id": c, "type": "source"} for c in contacts_seen],
        "edges": [],
        "built_at": datetime.now(UTC).isoformat(),
    }
    graph_path.write_text(json.dumps(graph, indent=2), encoding="utf-8")

    return {
        "status": "completed",
        "node_count": len(contacts_seen),
        "edge_count": 0,
        "graph_file": str(graph_path),
    }


def _stage_report_generate(
    vault: Path, case_id: str, operator_id: str, full_result: dict[str, Any]
) -> dict[str, Any]:
    """Stage 4: Write the forensic narrative report."""
    import json

    report_path = vault / "forensic_report.json"
    report = {
        "title": "Tier-1 Deep Forensics Report",
        "case_id": case_id,
        "operator_id": operator_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "pipeline_summary": full_result.get("stages", {}),
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {
        "status": "completed",
        "report_file": str(report_path),
        "size_bytes": report_path.stat().st_size,
    }
