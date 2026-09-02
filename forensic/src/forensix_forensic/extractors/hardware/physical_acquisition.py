"""Physical acquisition pipeline — top-level orchestrator.

Routes a connected device to the appropriate hardware acquisition module
based on chipset detection:

* MediaTek → :class:`~forensix_forensic.extractors.hardware.mtk_brom.MtkBromExtractor`
* Qualcomm → :class:`~forensix_forensic.extractors.hardware.qualcomm_edl.QualcommEdlExtractor`
* Unisoc → :class:`~forensix_forensic.extractors.hardware.unisoc_fdl.SpreadtrumBootromExtractor`
* Samsung Exynos →
  :class:`~forensix_forensic.extractors.hardware.samsung_download.SamsungDownloadModeExtractor`

Usage example::

    from forensix_forensic.extractors.hardware.physical_acquisition import (
        PhysicalAcquisitionRouter,
        RouterConfig,
    )
    from pathlib import Path

    config = RouterConfig(
        output_dir=Path('/cases/001/physical'),
        mtk_da_path=Path('/lab/da/DA_v6.bin'),
        qualcomm_programmer_path=Path('/lab/prog_emmc_firehose_8937.mbn'),
        unisoc_fdl1_path=Path('/lab/fdl1.bin'),
        unisoc_fdl2_path=Path('/lab/fdl2.bin'),
    )
    router = PhysicalAcquisitionRouter(config)
    result = await router.acquire(
        partitions=['userdata', 'system', 'boot'],
        case_id='CASE-2025-001',
        operator_id='examiner@lab.example',
    )
    print(result.protocol_used, result.success)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from .chipset_detector import ChipsetProbe, detect_chipset_from_usb

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RouterConfig:
    """Configuration bundle for :class:`PhysicalAcquisitionRouter`.

    Pass ``None`` for any binary path whose chipset you do not have a
    lab-approved image for; the router will skip that protocol and log it.
    """

    output_dir: Path
    """Local directory for acquired partition images and manifest."""

    mtk_da_path: Path | None = None
    """Path to MediaTek Download Agent (DA) binary."""

    qualcomm_programmer_path: Path | None = None
    """Path to Qualcomm Firehose programmer MBN image."""

    unisoc_fdl1_path: Path | None = None
    """Path to Unisoc FDL1 binary."""

    unisoc_fdl2_path: Path | None = None
    """Path to Unisoc FDL2 binary."""

    kirin_recovery_path: Path | None = None
    """Path to Huawei Kirin recovery image."""

    rockchip_loader_path: Path | None = None
    """Path to Rockchip loader binary."""

    usb_timeout_ms: int = 10000
    """USB I/O timeout in milliseconds."""


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PhysicalAcquisitionRouterResult:
    """Aggregate result from the physical acquisition router."""

    router_id: str
    protocol_used: str
    """Protocol that was selected: ``'mtk_brom'``, ``'qualcomm_edl'``,
    ``'unisoc_fdl'``, ``'samsung_odin'``, or ``'unsupported'``."""

    chipset_probe: ChipsetProbe | None
    inner_result: Any  # one of the protocol-specific result dataclasses
    timeline: list[dict[str, str]]
    started_at: str
    finished_at: str
    duration_seconds: float
    success: bool
    error_message: str | None


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


class PhysicalAcquisitionRouter:
    """Top-level physical acquisition orchestrator.

    1.  Calls `detect_chipset_from_usb()` from
        :mod:`~forensix_forensic.extractors.hardware.chipset_detector`
        to identify the device in boot/download mode.
    2.  Instantiates the appropriate protocol extractor.
    3.  Runs the acquisition and returns a
        :class:`PhysicalAcquisitionRouterResult`.
    """

    VERSION = "1.0.0"

    def __init__(self, config: RouterConfig) -> None:
        self._cfg = config
        self._timeline: list[dict[str, str]] = []

    async def acquire(
        self,
        partitions: list[str],
        case_id: str,
        operator_id: str,
    ) -> PhysicalAcquisitionRouterResult:
        """Auto-detect chipset and run the physical acquisition pipeline.

        Parameters
        ----------
        partitions:
            Partition names to acquire, e.g. ``['userdata', 'system', 'boot']``.
            Pass ``['__all__']`` to acquire every discovered partition.
        case_id:
            ForensiX case identifier.
        operator_id:
            Examiner identifier for the chain-of-custody timeline.
        """
        router_id = str(uuid4())
        started_at = datetime.now(UTC).isoformat()
        t0 = asyncio.get_event_loop().time()

        self._log(
            "router_start",
            {
                "router_id": router_id,
                "case_id": case_id,
                "operator_id": operator_id,
                "partitions": ", ".join(partitions),
            },
        )

        # Detect chipset
        probe = detect_chipset_from_usb()
        if probe is None:
            msg = (
                "No device detected in download / BROM mode. "
                "Ensure the device is powered off and in the correct boot mode, "
                "then connect USB."
            )
            self._log("detection_failed", {"reason": msg})
            return self._error_result(router_id, started_at, t0, msg, probe)

        self._log(
            "chipset_detected",
            {
                "family": probe.chipset_family,
                "model": probe.chipset_model or "unknown",
                "method": probe.detection_method,
                "protocol": probe.acquisition_protocol,
            },
        )

        protocol = probe.acquisition_protocol
        try:
            inner = await self._dispatch(protocol, partitions, case_id, operator_id)
        except Exception as exc:  # noqa: BLE001
            return self._error_result(router_id, started_at, t0, str(exc), probe)

        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0

        success = getattr(inner, "success", False)
        self._log(
            "router_complete",
            {
                "protocol": protocol,
                "success": str(success),
                "duration_seconds": f"{duration:.2f}",
            },
        )

        return PhysicalAcquisitionRouterResult(
            router_id=router_id,
            protocol_used=protocol,
            chipset_probe=probe,
            inner_result=inner,
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            success=success,
            error_message=getattr(inner, "error_message", None),
        )

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    async def _dispatch(
        self, protocol: str, partitions: list[str], case_id: str, operator_id: str
    ) -> Any:
        cfg = self._cfg
        out = cfg.output_dir / protocol
        out.mkdir(parents=True, exist_ok=True)

        if protocol == "mtk_brom":
            return await self._run_mtk(partitions, case_id, operator_id, out)
        if protocol == "qualcomm_edl":
            return await self._run_qualcomm(partitions, case_id, operator_id, out)
        if protocol == "unisoc_fdl":
            return await self._run_unisoc(partitions, case_id, operator_id, out)
        if protocol == "kirin_erecovery":
            return await self._run_kirin(partitions, case_id, operator_id, out)
        if protocol == "rockchip_dfu":
            return await self._run_rockchip(partitions, case_id, operator_id, out)

        raise ValueError(f"Unsupported acquisition protocol: {protocol!r}")

    async def _run_mtk(
        self, partitions: list[str], case_id: str, operator_id: str, out: Path
    ) -> Any:
        from .mtk_brom import MtkBromExtractor

        if self._cfg.mtk_da_path is None:
            raise ValueError(
                "mtk_da_path not configured in RouterConfig. Supply a lab-approved DA binary."
            )
        extractor = MtkBromExtractor(
            da_binary_path=self._cfg.mtk_da_path,
            output_dir=out,
            usb_timeout_ms=self._cfg.usb_timeout_ms,
        )
        return await extractor.acquire(partitions, case_id, operator_id)

    async def _run_qualcomm(
        self, partitions: list[str], case_id: str, operator_id: str, out: Path
    ) -> Any:
        from .qualcomm_edl import QualcommEdlExtractor

        if self._cfg.qualcomm_programmer_path is None:
            raise ValueError(
                "qualcomm_programmer_path not configured in RouterConfig. "
                "Supply a lab-approved Firehose programmer MBN."
            )
        extractor = QualcommEdlExtractor(
            programmer_path=self._cfg.qualcomm_programmer_path,
            output_dir=out,
            usb_timeout_ms=self._cfg.usb_timeout_ms,
        )
        return await extractor.acquire(partitions, case_id, operator_id)

    async def _run_unisoc(
        self, partitions: list[str], case_id: str, operator_id: str, out: Path
    ) -> Any:
        from .unisoc_fdl import SpreadtrumBootromExtractor

        if self._cfg.unisoc_fdl1_path is None or self._cfg.unisoc_fdl2_path is None:
            raise ValueError(
                "unisoc_fdl1_path and unisoc_fdl2_path must both be configured. "
                "Supply lab-approved FDL1 and FDL2 binaries."
            )
        extractor = SpreadtrumBootromExtractor(
            fdl1_path=self._cfg.unisoc_fdl1_path,
            fdl2_path=self._cfg.unisoc_fdl2_path,
            output_dir=out,
            usb_timeout_ms=self._cfg.usb_timeout_ms,
        )
        return await extractor.acquire(partitions, case_id, operator_id)

    async def _run_samsung(
        self, partitions: list[str], case_id: str, operator_id: str, out: Path
    ) -> Any:
        from .samsung_download import SamsungDownloadModeExtractor

        extractor = SamsungDownloadModeExtractor(
            output_dir=out,
            usb_timeout_ms=self._cfg.usb_timeout_ms,
        )
        return await extractor.acquire(partitions, case_id, operator_id)

    async def _run_kirin(
        self, partitions: list[str], case_id: str, operator_id: str, out: Path
    ) -> Any:
        from .kirin_hisi import KirinExtractor

        if self._cfg.kirin_recovery_path is None:
            raise ValueError(
                "kirin_recovery_path not configured in RouterConfig. "
                "Supply a lab-approved Huawei Kirin recovery image."
            )
        extractor = KirinExtractor(
            recovery_image_path=self._cfg.kirin_recovery_path,
            output_dir=out,
            usb_timeout_ms=self._cfg.usb_timeout_ms,
        )
        return await extractor.acquire(partitions, case_id, operator_id)

    async def _run_rockchip(
        self, partitions: list[str], case_id: str, operator_id: str, out: Path
    ) -> Any:
        from .rockchip_rkdfu import RockchipExtractor

        if self._cfg.rockchip_loader_path is None:
            raise ValueError(
                "rockchip_loader_path not configured in RouterConfig. "
                "Supply a lab-approved Rockchip loader binary."
            )
        extractor = RockchipExtractor(
            loader_path=self._cfg.rockchip_loader_path,
            output_dir=out,
            usb_timeout_ms=self._cfg.usb_timeout_ms,
        )
        return await extractor.acquire(partitions, case_id, operator_id)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _log(self, event: str, details: dict[str, str]) -> None:
        self._timeline.append(
            {
                "ts": datetime.now(UTC).isoformat(),
                "event": event,
                **details,
            }
        )

    def _error_result(
        self,
        router_id: str,
        started_at: str,
        t0: float,
        message: str,
        probe: ChipsetProbe | None,
    ) -> PhysicalAcquisitionRouterResult:
        self._log("router_error", {"error": message})
        return PhysicalAcquisitionRouterResult(
            router_id=router_id,
            protocol_used="unsupported",
            chipset_probe=probe,
            inner_result=None,
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
            duration_seconds=round(asyncio.get_event_loop().time() - t0, 3),
            success=False,
            error_message=message,
        )
