"""Chipset detection engine for ForensiX hardware acquisition routing.

Detects the chipset family of a connected Android device using two strategies:

1.  **USB VID/PID enumeration** \u2014 identifies devices in bootloader / download
    mode (BROM, EDL, FDL, Odin) from their USB descriptor before Android
    boots.  Uses ``pyusb`` if available; falls back gracefully.

2.  **ADB property fingerprinting** \u2014 reads ``ro.hardware``,
    ``ro.board.platform``, ``ro.product.board``, and ``ro.chipname`` from
    a running Android system to classify the chipset family.

The result is a :class:`ChipsetProbe` dataclass that drives the acquisition
router in :mod:`forensix_forensic.extractors.hardware.physical_acquisition`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forensix_forensic.adb.client import AdbClient

# ---------------------------------------------------------------------------
# Public constants \u2014 USB VID/PID fingerprints
# ---------------------------------------------------------------------------

# Each entry: (vendor_id, product_id, chipset_family, mode_label)
USB_CHIPSET_MAP: tuple[tuple[int, int, str, str], ...] = (
    # MediaTek \u2014 BROM and Preloader modes
    (0x0E8D, 0x0003, "mediatek", "brom"),
    (0x0E8D, 0x2000, "mediatek", "preloader"),
    (0x0E8D, 0x2001, "mediatek", "preloader"),
    # Qualcomm \u2014 EDL / 9008 mode
    (0x05C6, 0x9008, "qualcomm", "edl"),
    (0x05C6, 0x900E, "qualcomm", "edl_alt"),
    # Unisoc / Spreadtrum
    (0x1782, 0x4D00, "unisoc", "fdl"),
    (0x1782, 0x5F00, "unisoc", "fdl_alt"),
    # Samsung Download Mode (Odin/LOKE)
    (0x04E8, 0x685D, "samsung_exynos", "odin"),
    (0x04E8, 0x6601, "samsung_exynos", "odin_legacy"),
    # Huawei HiSilicon (Kirin) \u2014 BootROM USB mode
    (0x12D1, 0x1057, "kirin", "brom"),
    (0x12D1, 0x107E, "kirin", "brom_alt"),
    # Rockchip MaskROM mode
    (0x2207, 0x330C, "rockchip", "maskrom"),
    (0x2207, 0x310B, "rockchip", "maskrom_alt"),
)

# ADB ro.board.platform prefix \u2192 chipset family
_PLATFORM_PREFIX_MAP: tuple[tuple[str, str], ...] = (
    ("mt", "mediatek"),
    ("msm", "qualcomm"),
    ("sdm", "qualcomm"),
    ("sm", "qualcomm"),
    ("sc", "unisoc"),
    ("t", "unisoc"),
    ("exynos", "samsung_exynos"),
    ("universal", "samsung_exynos"),
    ("kirin", "kirin"),
    ("hi", "kirin"),
    ("rk", "rockchip"),
)

# ro.hardware / ro.chipname direct matches \u2192 chipset family
_HARDWARE_KEYWORD_MAP: dict[str, str] = {
    "mt6580": "mediatek",
    "mt6737": "mediatek",
    "mt6739": "mediatek",
    "mt6753": "mediatek",
    "mt6761": "mediatek",
    "mt6765": "mediatek",
    "mt6771": "mediatek",
    "mt6785": "mediatek",
    "mt6833": "mediatek",
    "mt6873": "mediatek",
    "msm8909": "qualcomm",
    "msm8916": "qualcomm",
    "msm8953": "qualcomm",
    "sdm450": "qualcomm",
    "sdm660": "qualcomm",
    "sm6115": "qualcomm",
    "sm7125": "qualcomm",
    "sc7731e": "unisoc",
    "sc9832e": "unisoc",
    "sc9863a": "unisoc",
    "t606": "unisoc",
    "t616": "unisoc",
    "t618": "unisoc",
    "exynos850": "samsung_exynos",
    "exynos9610": "samsung_exynos",
    "exynos9820": "samsung_exynos",
    "kirin659": "kirin",
    "kirin710": "kirin",
    "kirin970": "kirin",
}


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ChipsetFamily(StrEnum):
    """Known chipset families supported by ForensiX hardware acquisition."""

    MEDIATEK = "mediatek"
    QUALCOMM = "qualcomm"
    UNISOC = "unisoc"
    SAMSUNG_EXYNOS = "samsung_exynos"
    KIRIN = "kirin"
    ROCKCHIP = "rockchip"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChipsetProbe:
    """Result of a chipset detection attempt."""

    chipset_family: str
    """One of the :class:`ChipsetFamily` string values."""

    chipset_model: str | None
    """Specific model string if detected (e.g. ``'MT6765'``, ``'MSM8953'``)."""

    detection_method: str
    """How the chipset was identified: ``'usb_vid_pid'``, ``'adb_platform'``,
    ``'adb_hardware'``, ``'adb_fingerprint'``, or ``'unknown'``."""

    usb_mode: str | None
    """Boot mode implied by USB PID (e.g. ``'brom'``, ``'edl'``, ``'fdl'``)."""

    raw_properties: dict[str, str]
    """All ADB properties read during detection (for audit trail)."""

    acquisition_protocol: str
    """Recommended acquisition protocol: ``'mtk_brom'``, ``'qualcomm_edl'``,
    ``'unisoc_fdl'``, ``'samsung_odin'``, or ``'unknown'``."""


# ---------------------------------------------------------------------------
# USB-based detection (bootloader / download mode)
# ---------------------------------------------------------------------------


def detect_chipset_from_usb() -> ChipsetProbe | None:
    """Scan USB bus for a device in a known download / boot-ROM mode.

    Returns a :class:`ChipsetProbe` if a known device is found, or ``None``
    if ``pyusb`` is unavailable or no matching device is connected.
    """
    try:
        import usb.core  # type: ignore[import-untyped]
        import usb.util  # type: ignore[import-untyped]
    except ImportError:
        return None

    all_devices = list(usb.core.find(find_all=True))
    for device in all_devices:
        try:
            vid = device.idVendor
            pid = device.idProduct
        except Exception:  # noqa: BLE001
            continue
        for entry_vid, entry_pid, family, mode in USB_CHIPSET_MAP:
            if vid == entry_vid and pid == entry_pid:
                return ChipsetProbe(
                    chipset_family=family,
                    chipset_model=None,
                    detection_method="usb_vid_pid",
                    usb_mode=mode,
                    raw_properties={"usb_vid": hex(vid), "usb_pid": hex(pid)},
                    acquisition_protocol=_protocol_for_family(family),
                )
    return None


# ---------------------------------------------------------------------------
# ADB-based detection (running Android)
# ---------------------------------------------------------------------------


async def detect_chipset_from_adb(adb: AdbClient, serial: str) -> ChipsetProbe:
    """Read ADB system properties to identify the chipset family.

    Attempts the following properties in order:

    * ``ro.chipname``
    * ``ro.hardware``
    * ``ro.board.platform``
    * ``ro.product.board``
    * ``ro.build.fingerprint`` (fallback \u2014 manufacturer prefix heuristic)

    Parameters
    ----------
    adb:
        Connected :class:`~forensix_forensic.adb.client.AdbClient`.
    serial:
        ADB device serial.

    Returns
    -------
    ChipsetProbe
        Detection result.  ``chipset_family`` is ``'unknown'`` if no
        matching property was found.
    """
    props: dict[str, str] = {}
    prop_keys = [
        "ro.chipname",
        "ro.hardware",
        "ro.board.platform",
        "ro.product.board",
        "ro.build.fingerprint",
        "ro.product.manufacturer",
    ]
    for key in prop_keys:
        try:
            value = await adb.getprop(serial, key)
            if value:
                props[key] = value.strip()
        except Exception:  # noqa: BLE001
            pass

    # Try ro.chipname / ro.hardware exact keyword match
    for prop_key in ("ro.chipname", "ro.hardware"):
        raw = props.get(prop_key, "").lower()
        family, model = _match_hardware_keyword(raw)
        if family != ChipsetFamily.UNKNOWN:
            return ChipsetProbe(
                chipset_family=family,
                chipset_model=model,
                detection_method="adb_hardware",
                usb_mode=None,
                raw_properties=props,
                acquisition_protocol=_protocol_for_family(family),
            )

    # Try ro.board.platform prefix match
    platform = props.get("ro.board.platform", "").lower()
    if platform:
        family = _match_platform_prefix(platform)
        if family != ChipsetFamily.UNKNOWN:
            return ChipsetProbe(
                chipset_family=family,
                chipset_model=platform.upper() or None,
                detection_method="adb_platform",
                usb_mode=None,
                raw_properties=props,
                acquisition_protocol=_protocol_for_family(family),
            )

    # Fingerprint manufacturer heuristic
    fingerprint = props.get("ro.build.fingerprint", "").lower()
    manufacturer = props.get("ro.product.manufacturer", "").lower()
    if "samsung" in manufacturer or "samsung" in fingerprint:
        return ChipsetProbe(
            chipset_family=ChipsetFamily.SAMSUNG_EXYNOS,
            chipset_model=None,
            detection_method="adb_fingerprint",
            usb_mode=None,
            raw_properties=props,
            acquisition_protocol="samsung_odin",
        )
    if "huawei" in manufacturer or "honor" in manufacturer:
        return ChipsetProbe(
            chipset_family=ChipsetFamily.KIRIN,
            chipset_model=None,
            detection_method="adb_fingerprint",
            usb_mode=None,
            raw_properties=props,
            acquisition_protocol="unknown",
        )

    return ChipsetProbe(
        chipset_family=ChipsetFamily.UNKNOWN,
        chipset_model=None,
        detection_method="unknown",
        usb_mode=None,
        raw_properties=props,
        acquisition_protocol="unknown",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _match_hardware_keyword(value: str) -> tuple[str, str | None]:
    """Return ``(family, model)`` if *value* matches a known keyword."""
    clean = re.sub(r"[^a-z0-9]", "", value)
    for keyword, family in _HARDWARE_KEYWORD_MAP.items():
        if clean.startswith(re.sub(r"[^a-z0-9]", "", keyword)):
            return family, value.upper()
    return ChipsetFamily.UNKNOWN, None


def _match_platform_prefix(platform: str) -> str:
    """Return the chipset family for a ``ro.board.platform`` string."""
    clean = platform.lower().strip()
    for prefix, family in _PLATFORM_PREFIX_MAP:
        if clean.startswith(prefix):
            return family
    return ChipsetFamily.UNKNOWN


def _protocol_for_family(family: str) -> str:
    """Map a chipset family to the recommended acquisition protocol."""
    mapping = {
        ChipsetFamily.MEDIATEK: "mtk_brom",
        ChipsetFamily.QUALCOMM: "qualcomm_edl",
        ChipsetFamily.UNISOC: "unisoc_fdl",
        ChipsetFamily.SAMSUNG_EXYNOS: "samsung_odin",
        ChipsetFamily.KIRIN: "kirin_erecovery",
        ChipsetFamily.ROCKCHIP: "rockchip_dfu",
    }
    return mapping.get(family, "unknown")
