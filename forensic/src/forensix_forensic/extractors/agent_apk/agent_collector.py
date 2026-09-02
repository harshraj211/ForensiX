"""ForensiX Android agent data collector.

Polls the device's staging directory (``/sdcard/forensix_out/``) until the
agent signals completion, then pulls all JSON artifact files via ADB and
deserializes them into :class:`AgentExtractionResult`.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from .agent_result import (
    AgentExtractionResult,
    call_logs_from_json,
    contacts_from_json,
    installed_apps_from_json,
    sms_from_json,
)

if TYPE_CHECKING:
    from forensix_forensic.adb.client import AdbClient


@dataclass(frozen=True, slots=True)
class CollectorConfig:
    """Configuration options for the Agent collector."""

    staging_dir: str = "/sdcard/forensix_out"
    poll_interval_seconds: float = 2.0
    max_wait_seconds: int = 300
    cleanup_after_pull: bool = True


class AgentCollector:
    """Polls ADB device staging area for agent output and deserializes extracted artifacts."""

    def __init__(self, adb: AdbClient, config: CollectorConfig, output_dir: Path) -> None:
        self._adb = adb
        self._cfg = config
        self._output_dir = output_dir
        self._timeline: list[dict[str, str]] = []

    async def collect(
        self, serial: str, case_id: str, extraction_id: str | None = None
    ) -> AgentExtractionResult:
        """Poll staging area on device, pull JSON files, and deserialize."""
        ext_id = extraction_id or str(uuid4())
        started_at = datetime.now(UTC).isoformat()
        t0 = asyncio.get_event_loop().time()

        self._log("collect_start", {"serial": serial, "case_id": case_id, "extraction_id": ext_id})
        self._output_dir.mkdir(parents=True, exist_ok=True)

        try:
            completed = await self._wait_for_completion(serial)
            if not completed:
                raise TimeoutError(f"Agent timed out after {self._cfg.max_wait_seconds} seconds")

            contacts_data = await self._pull_and_parse_json(serial, "contacts.json")
            sms_data = await self._pull_and_parse_json(serial, "sms.json")
            call_log_data = await self._pull_and_parse_json(serial, "call_logs.json")
            apps_data = await self._pull_and_parse_json(serial, "installed_apps.json")

            contacts = contacts_from_json(contacts_data) if isinstance(contacts_data, list) else ()
            sms_msgs = sms_from_json(sms_data) if isinstance(sms_data, list) else ()
            call_logs = call_logs_from_json(call_log_data) if isinstance(call_log_data, list) else ()
            installed_apps = installed_apps_from_json(apps_data) if isinstance(apps_data, list) else ()

            if self._cfg.cleanup_after_pull:
                try:
                    await self._adb.shell(serial, f"rm -rf {self._cfg.staging_dir}")  # type: ignore[attr-defined]
                except Exception:  # noqa: BLE001
                    pass

            finished_at = datetime.now(UTC).isoformat()
            duration = asyncio.get_event_loop().time() - t0

            return AgentExtractionResult(
                extraction_id=ext_id,
                device_serial=serial,
                case_id=case_id,
                contacts=contacts,
                sms_messages=sms_msgs,
                call_logs=call_logs,
                installed_apps=installed_apps,
                media_file_count=0,
                output_dir=str(self._output_dir),
                timeline=list(self._timeline),
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=round(duration, 3),
                success=True,
                error_message=None,
            )

        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                ext_id=ext_id,
                serial=serial,
                case_id=case_id,
                started_at=started_at,
                t0=t0,
                message=str(exc),
            )

    async def _wait_for_completion(self, serial: str) -> bool:
        done_file = f"{self._cfg.staging_dir}/DONE"
        t0 = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - t0) < self._cfg.max_wait_seconds:
            try:
                out = await self._adb.shell(serial, f"test -f {done_file} && echo YES || echo NO")  # type: ignore[attr-defined]
                if "YES" in out:
                    return True
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(self._cfg.poll_interval_seconds)
        return False

    async def _pull_and_parse_json(self, serial: str, filename: str) -> list | dict | None:
        remote_path = f"{self._cfg.staging_dir}/{filename}"
        local_path = self._output_dir / filename
        try:
            await self._adb.pull(serial, remote_path, str(local_path))  # type: ignore[attr-defined]
            if local_path.exists():
                return json.loads(local_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            self._log("pull_json_failed", {"filename": filename, "error": str(exc)})
        return None

    def _log(self, event: str, details: dict[str, str]) -> None:
        self._timeline.append({
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            **details,
        })

    def _error_result(
        self, ext_id: str, serial: str, case_id: str, started_at: str, t0: float, message: str
    ) -> AgentExtractionResult:
        self._log("collect_error", {"error": message})
        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0
        return AgentExtractionResult(
            extraction_id=ext_id,
            device_serial=serial,
            case_id=case_id,
            contacts=(),
            sms_messages=(),
            call_logs=(),
            installed_apps=(),
            media_file_count=0,
            output_dir=str(self._output_dir),
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            success=False,
            error_message=message,
        )
