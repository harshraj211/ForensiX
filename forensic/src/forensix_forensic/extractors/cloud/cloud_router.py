"""Cloud backup download orchestrator.

Top-level entry point that takes a dictionary of extracted device tokens
and dispatches to the appropriate cloud downloader(s).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .google_takeout import GoogleBackupResult, GoogleBackupToken, GoogleTakeoutDownloader
from .whatsapp_cloud import WhatsAppBackupResult, WhatsAppCloudDownloader, WhatsAppCloudToken


@dataclass(frozen=True, slots=True)
class CloudTokenBundle:
    """Bundle of cloud access tokens extracted from target Android device."""

    google_token: GoogleBackupToken | None = None
    whatsapp_token: WhatsAppCloudToken | None = None


@dataclass(frozen=True, slots=True)
class CloudBackupRouterResult:
    """Sealed result of orchestrating cloud backup downloads."""

    router_id: str
    google_result: GoogleBackupResult | None
    whatsapp_result: WhatsAppBackupResult | None
    timeline: list[dict[str, str]]
    started_at: str
    finished_at: str
    duration_seconds: float
    success: bool


class CloudBackupRouter:
    """Orchestrates download of cloud backups using extracted tokens."""

    VERSION = "1.0.0"

    def __init__(self, output_dir: Path) -> None:
        self._output_dir = output_dir
        self._timeline: list[dict[str, str]] = []

    async def download_all(
        self, tokens: CloudTokenBundle, case_id: str, operator_id: str
    ) -> CloudBackupRouterResult:
        """Download all cloud backups supported by the supplied token bundle."""
        router_id = str(uuid4())
        started_at = datetime.now(UTC).isoformat()
        t0 = asyncio.get_event_loop().time()

        self._log("router_start", {
            "router_id": router_id,
            "case_id": case_id,
            "operator_id": operator_id,
            "has_google_token": str(tokens.google_token is not None),
            "has_whatsapp_token": str(tokens.whatsapp_token is not None),
        })

        google_task = None
        whatsapp_task = None

        if tokens.google_token:
            gt_dir = self._output_dir / "google_takeout"
            gt_downloader = GoogleTakeoutDownloader(gt_dir)
            google_task = asyncio.create_task(gt_downloader.download(tokens.google_token, case_id, operator_id))

        if tokens.whatsapp_token:
            wa_dir = self._output_dir / "whatsapp_cloud"
            wa_downloader = WhatsAppCloudDownloader(wa_dir)
            whatsapp_task = asyncio.create_task(wa_downloader.download(tokens.whatsapp_token, case_id, operator_id))

        google_res: GoogleBackupResult | None = None
        whatsapp_res: WhatsAppBackupResult | None = None

        if google_task:
            google_res = await google_task
        if whatsapp_task:
            whatsapp_res = await whatsapp_task

        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0

        g_ok = google_res.success if google_res else True
        w_ok = whatsapp_res.success if whatsapp_res else True
        overall_success = g_ok and w_ok

        self._log("router_complete", {
            "success": str(overall_success),
            "duration_seconds": f"{duration:.2f}",
        })

        return CloudBackupRouterResult(
            router_id=router_id,
            google_result=google_res,
            whatsapp_result=whatsapp_res,
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            success=overall_success,
        )

    def _log(self, event: str, details: dict[str, str]) -> None:
        self._timeline.append({
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            **details,
        })
