"""Vendor backup acquisition capability assessment.

Smart Switch exports are imported through the verified backup intake workflow.
No vendor RPC transport is claimed until a device-specific protocol is validated.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class VendorBackupItem:
    package_name: str
    data_type: str  # e.g., "sms", "call_log", "contacts", "app_bundle"
    file_count: int
    size_bytes: int
    sha256_hash: str


@dataclass(frozen=True, slots=True)
class VendorBackupResult:
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    vendor_type: str  # "samsung_smartswitch", "huawei_hisuite", "xiaomi_miconnect"
    timestamp: str
    extracted_items: list[VendorBackupItem]
    total_size_bytes: int
    duration_seconds: float
    success: bool
    error_message: str | None = None


class VendorBackupExtractor:
    """Reports whether a validated OEM backup transport is available."""

    def __init__(self, adb: Any) -> None:
        self.adb = adb

    async def extract_vendor_backup(
        self, serial: str, case_id: str, operator_id: str, vendor_type: str = "samsung_smartswitch"
    ) -> VendorBackupResult:
        t0 = asyncio.get_event_loop().time()
        extraction_id = str(uuid4())

        duration = asyncio.get_event_loop().time() - t0
        return VendorBackupResult(
            extraction_id=extraction_id,
            serial=serial,
            case_id=case_id,
            operator_id=operator_id,
            vendor_type=vendor_type,
            timestamp=datetime.now(UTC).isoformat(),
            extracted_items=[],
            total_size_bytes=0,
            duration_seconds=round(duration, 3),
            success=False,
            error_message=(
                "No validated live vendor backup transport is configured. Export with the "
                "vendor application and import the backup through Evidence Twin."
            ),
        )

    async def _run_vendor_handshake(self, serial: str, vendor: str) -> str:
        if hasattr(self.adb, "shell"):
            cmd = "getprop ro.product.manufacturer"
            res = await self.adb.shell(serial, cmd)
            return str(res)
        return "samsung"
