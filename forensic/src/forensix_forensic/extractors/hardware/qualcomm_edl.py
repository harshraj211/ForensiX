"""Qualcomm EDL / Sahara / Firehose forensic acquisition protocol handler.

Implements the three-layer Qualcomm Emergency Download Mode (EDL) protocol
stack used for forensic physical acquisition from Qualcomm-chipset Android
devices:

* **Sahara** — Initial ROM-level protocol for image download (Hello/End).
* **Firehose** — XML-over-USB protocol running on the injected programmer
  image; issues ``<program>``, ``<read>``, ``<patch>`` commands to access raw
  UFS / eMMC sectors.
* **Acquisition pipeline** — Streams raw disk sectors to local image files,
  hashing with SHA-256 per chunk.

The module is a *forensic orchestration layer*.  Raw USB bulk transfers are
delegated to ``pyusb``.  The caller must supply a lab-approved Qualcomm
programmer image (e.g. ``prog_emmc_firehose_*.mbn``).
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
import xml.etree.ElementTree as ET
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from uuid import uuid4

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

QCOM_USB_VID = 0x05C6  # Qualcomm
QCOM_USB_PID_EDL = 0x9008  # EDL / 9008 mode
QCOM_USB_PID_ADB = 0x9025  # normal ADB mode (reference only)

# Sahara protocol command IDs
SAHARA_HELLO = 0x01
SAHARA_HELLO_RESP = 0x02
SAHARA_READ_DATA = 0x03
SAHARA_END_IMG_TX = 0x04
SAHARA_DONE = 0x05
SAHARA_DONE_RESP = 0x06
SAHARA_RESET = 0x07
SAHARA_RESET_RESP = 0x08
SAHARA_CMD_READY = 0x0B

# Firehose transfer granularity
FIREHOSE_SECTORS_PER_CMD = 1024
SECTOR_SIZE = 512
CHUNK_BYTES = FIREHOSE_SECTORS_PER_CMD * SECTOR_SIZE  # 512 KiB


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EdlState(IntEnum):
    """EDL acquisition pipeline state machine."""

    IDLE = 0
    USB_DETECTED = 1
    SAHARA_HELLO_RECEIVED = 2
    PROGRAMMER_UPLOADED = 3
    SAHARA_DONE = 4
    FIREHOSE_READY = 5
    READING = 6
    COMPLETE = 7
    ERROR = 8


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SaharaHello:
    """Decoded Sahara Hello packet (48 bytes, little-endian)."""

    version: int
    version_min: int
    max_packet_size: int
    mode: int
    image_tx_status: int


@dataclass(frozen=True, slots=True)
class FirehosePartitionInfo:
    """Partition discovered via Firehose ``<getpartitiontable>`` response."""

    label: str
    start_sector: int
    num_sectors: int
    size_mb: float
    lun: int  # Logical Unit Number for multi-LUN UFS


@dataclass(frozen=True, slots=True)
class ProgrammerEntry:
    """Programmer metadata entry in the Qualcomm SoC registry."""

    soc_model: str
    msm_id: str
    programmer_name: str
    storage_type: str  # 'emmc' | 'ufs'
    default_luns: tuple[int, ...]


class ProgrammerRegistry:
    """Registry mapping Qualcomm SoC models to expected Firehose programmers."""

    _MAPPING: dict[str, ProgrammerEntry] = {
        "MSM8916": ProgrammerEntry(
            "Snapdragon 410", "MSM8916", "prog_emmc_firehose_8916.mbn", "emmc", (0,)
        ),
        "MSM8937": ProgrammerEntry(
            "Snapdragon 430", "MSM8937", "prog_emmc_firehose_8937.mbn", "emmc", (0,)
        ),
        "MSM8953": ProgrammerEntry(
            "Snapdragon 625", "MSM8953", "prog_emmc_firehose_8953.mbn", "emmc", (0,)
        ),
        "SDM660": ProgrammerEntry(
            "Snapdragon 660", "SDM660", "prog_emmc_firehose_sdm660.mbn", "emmc", (0,)
        ),
        "SM6115": ProgrammerEntry(
            "Snapdragon 662", "SM6115", "prog_ufs_firehose_sm6115.elf", "ufs", (0, 1, 2, 3, 4, 5)
        ),
        "SM8250": ProgrammerEntry(
            "Snapdragon 865", "SM8250", "prog_ufs_firehose_sm8250.elf", "ufs", (0, 1, 2, 3, 4, 5)
        ),
        "SM8350": ProgrammerEntry(
            "Snapdragon 888", "SM8350", "prog_ufs_firehose_sm8350.elf", "ufs", (0, 1, 2, 3, 4, 5)
        ),
        "SM8450": ProgrammerEntry(
            "Snapdragon 8 Gen 1",
            "SM8450",
            "prog_ufs_firehose_sm8450.elf",
            "ufs",
            (0, 1, 2, 3, 4, 5),
        ),
        "SM8550": ProgrammerEntry(
            "Snapdragon 8 Gen 2",
            "SM8550",
            "prog_ufs_firehose_sm8550.elf",
            "ufs",
            (0, 1, 2, 3, 4, 5),
        ),
    }

    @classmethod
    def lookup(cls, soc_model: str) -> ProgrammerEntry | None:
        """Lookup programmer metadata by SoC model or MSM identifier string."""
        upper = soc_model.upper().strip()
        for key, entry in cls._MAPPING.items():
            if key in upper or entry.msm_id in upper or entry.soc_model.upper() in upper:
                return entry
        return None

    @classmethod
    def list_supported_socs(cls) -> tuple[str, ...]:
        """Return tuple of all registered SoC models."""
        return tuple(cls._MAPPING.keys())


@dataclass(frozen=True, slots=True)
class QualcommEdlAcquisitionResult:
    """Sealed result of a Qualcomm EDL physical acquisition."""

    acquisition_id: str
    soc_model: str
    storage_type: str  # 'emmc' | 'ufs'
    programmer_sha256: str
    partitions_acquired: tuple[str, ...]
    output_images: tuple[str, ...]
    image_sha256: dict[str, str]
    aggregate_sha256: str
    timeline: list[dict[str, str]]
    started_at: str
    finished_at: str
    duration_seconds: float
    success: bool
    error_message: str | None
    state_reached: str


# ---------------------------------------------------------------------------
# Sahara protocol helpers
# ---------------------------------------------------------------------------


def decode_sahara_hello(data: bytes) -> SaharaHello:
    """Decode a 48-byte Sahara Hello packet (little-endian).

    Layout::

        Offset  Size  Field
        0       4     Command (0x01)
        4       4     Packet length (48)
        8       4     Version
        12      4     Min version
        16      4     Max packet size
        20      4     Mode
        24      4     Image transfer status
        28      20    Reserved
    """
    if len(data) < 28:
        raise ValueError(f"Sahara Hello too short: {len(data)} bytes")
    cmd, _pkt_len, version, version_min, max_pkt, mode, img_status = struct.unpack_from(
        "<IIIIIII", data, 0
    )
    if cmd != SAHARA_HELLO:
        raise ValueError(f"Expected Sahara Hello (0x01), got 0x{cmd:02X}")
    return SaharaHello(
        version=version,
        version_min=version_min,
        max_packet_size=max_pkt,
        mode=mode,
        image_tx_status=img_status,
    )


def build_sahara_hello_response(version: int, mode: int) -> bytes:
    """Build the 48-byte Hello Response packet sent back to the device."""
    return (
        struct.pack(
            "<IIIIIII",
            SAHARA_HELLO_RESP,
            48,
            version,
            2,  # version_min
            0x800,  # max_packet_size = 2 KiB
            mode,
            0,  # image_tx_status
        )
        + b"\x00" * 20
    )


def build_sahara_done() -> bytes:
    """Build the 8-byte Sahara Done packet to transition to Firehose."""
    return struct.pack("<II", SAHARA_DONE, 8)


# ---------------------------------------------------------------------------
# Firehose XML helpers
# ---------------------------------------------------------------------------


def build_firehose_configure(sector_size: int = 512, max_payload: int = 1048576) -> bytes:
    """Build the initial Firehose ``<configure>`` XML command."""
    root = ET.Element("data")
    cfg = ET.SubElement(root, "configure")
    cfg.set("TargetName", "")
    cfg.set("ZLPAwareHost", "1")
    cfg.set("SkipStorageInit", "0")
    cfg.set("SkipWrite", "0")
    cfg.set("MaxPayloadSizeToTargetInBytes", str(max_payload))
    cfg.set("MaxPayloadSizeToTargetInBytesSupported", str(max_payload))
    cfg.set("MaxXMLSizeInBytes", "4096")
    return b'<?xml version="1.0" ?>' + ET.tostring(root)


def build_firehose_getpartitiontable(lun: int = 0) -> bytes:
    """Build a Firehose ``<getpartitiontable>`` XML command."""
    root = ET.Element("data")
    gpt = ET.SubElement(root, "getpartitiontable")
    gpt.set("SECTOR_SIZE_IN_BYTES", "512")
    gpt.set("physical_partition_number", str(lun))
    return b'<?xml version="1.0" ?>' + ET.tostring(root)


def build_firehose_read(start_sector: int, num_sectors: int, lun: int = 0) -> bytes:
    """Build a Firehose ``<read>`` XML command for raw sector access."""
    root = ET.Element("data")
    read = ET.SubElement(root, "read")
    read.set("SECTOR_SIZE_IN_BYTES", "512")
    read.set("num_partition_sectors", str(num_sectors))
    read.set("physical_partition_number", str(lun))
    read.set("start_sector", str(start_sector))
    return b'<?xml version="1.0" ?>' + ET.tostring(root)


def parse_firehose_response(xml_bytes: bytes) -> tuple[bool, str]:
    """Parse a Firehose ``<response>`` or ``<log>`` XML reply.

    Returns ``(success, message)``.
    """
    try:
        root = ET.fromstring(xml_bytes.decode(errors="replace"))  # noqa: S314
    except ET.ParseError:
        return False, f"XML parse error: {xml_bytes[:120]!r}"
    for child in root:
        if child.tag == "response":
            value = child.get("value", "NAK")
            rawmsg = child.get("rawmsg", "")
            return value == "ACK", rawmsg
        if child.tag == "log":
            return True, child.get("value", "")
    return True, ""


# ---------------------------------------------------------------------------
# Core extractor
# ---------------------------------------------------------------------------


class QualcommEdlExtractor:
    """Orchestrate a forensic physical acquisition over the Qualcomm EDL protocol.

    The pipeline:

    1.  Detect USB device in EDL mode (VID 0x05C6 / PID 0x9008).
    2.  Complete the Sahara handshake and upload the programmer image.
    3.  Send Firehose ``<configure>`` and ``<getpartitiontable>``.
    4.  For each requested partition, issue ``<read>`` commands and stream
        raw sector data to a local ``.img`` file.
    5.  Seal with SHA-256 manifest.

    Usage::

        extractor = QualcommEdlExtractor(
            programmer_path=Path('/lab/prog_emmc_firehose_8937.mbn'),
            output_dir=Path('/cases/001/physical'),
        )
        result = await extractor.acquire(
            partitions=['userdata', 'system'],
            luns=[0],
            case_id='CASE-2025-001',
            operator_id='examiner@lab.example',
        )
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        programmer_path: Path,
        output_dir: Path,
        *,
        usb_timeout_ms: int = 10000,
        storage_type: str = "emmc",
    ) -> None:
        self._programmer = programmer_path
        self._output_dir = output_dir
        self._usb_timeout = usb_timeout_ms
        self._storage_type = storage_type
        self._timeline: list[dict[str, str]] = []
        self._state = EdlState.IDLE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def acquire(
        self,
        partitions: list[str],
        case_id: str,
        operator_id: str,
        luns: list[int] | None = None,
    ) -> QualcommEdlAcquisitionResult:
        """Run the full EDL acquisition pipeline."""
        acquisition_id = str(uuid4())
        started_at = datetime.now(UTC).isoformat()
        t0 = asyncio.get_event_loop().time()
        luns = luns or [0]

        self._log(
            "acquisition_start",
            {
                "acquisition_id": acquisition_id,
                "case_id": case_id,
                "operator_id": operator_id,
                "partitions": ", ".join(partitions),
                "luns": ", ".join(str(lun) for lun in luns),
                "programmer": str(self._programmer),
            },
        )

        try:
            return await self._run_pipeline(
                acquisition_id=acquisition_id,
                started_at=started_at,
                t0=t0,
                partitions=partitions,
                luns=luns,
                case_id=case_id,
            )
        except Exception as exc:  # noqa: BLE001
            return self._error_result(acquisition_id, started_at, t0, str(exc))

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------

    async def _run_pipeline(
        self,
        *,
        acquisition_id: str,
        started_at: str,
        t0: float,
        partitions: list[str],
        luns: list[int],
        case_id: str,
    ) -> QualcommEdlAcquisitionResult:
        # Stage 1 — validate programmer
        prog_sha256 = self._validate_programmer()

        # Stage 2 — detect USB device
        device = self._detect_edl_device()
        self._state = EdlState.USB_DETECTED

        # Stage 3 — Sahara handshake + programmer upload
        soc_model = await self._sahara_handshake_and_upload(device, prog_sha256)
        self._state = EdlState.SAHARA_DONE

        # Stage 4 — Firehose configure
        await self._firehose_configure(device)
        self._state = EdlState.FIREHOSE_READY

        # Stage 5 — enumerate partitions across LUNs
        all_parts: list[FirehosePartitionInfo] = []
        for lun in luns:
            all_parts.extend(await self._get_partition_table(device, lun))
        self._log("partitions_discovered", {"count": str(len(all_parts))})

        # Stage 6 — acquire target partitions
        self._state = EdlState.READING
        self._output_dir.mkdir(parents=True, exist_ok=True)
        output_images: list[str] = []
        image_sha256: dict[str, str] = {}

        targets = (
            all_parts
            if partitions == ["__all__"]
            else [p for p in all_parts if p.label in partitions]
        )

        for part in targets:
            img_path = self._output_dir / f"{part.label}.img"
            sha = await self._read_partition(device, part, img_path)
            output_images.append(str(img_path))
            image_sha256[part.label] = sha
            self._log(
                "partition_acquired",
                {
                    "label": part.label,
                    "num_sectors": str(part.num_sectors),
                    "sha256": sha,
                },
            )

        aggregate = self._aggregate_hash(image_sha256)
        self._state = EdlState.COMPLETE
        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0

        self._log(
            "acquisition_complete",
            {
                "aggregate_sha256": aggregate,
                "duration_seconds": f"{duration:.2f}",
            },
        )

        return QualcommEdlAcquisitionResult(
            acquisition_id=acquisition_id,
            soc_model=soc_model,
            storage_type=self._storage_type,
            programmer_sha256=prog_sha256,
            partitions_acquired=tuple(image_sha256.keys()),
            output_images=tuple(output_images),
            image_sha256=image_sha256,
            aggregate_sha256=aggregate,
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            success=True,
            error_message=None,
            state_reached=self._state.name,
        )

    # ------------------------------------------------------------------
    # Stage implementations
    # ------------------------------------------------------------------

    def _validate_programmer(self) -> str:
        """Verify programmer image exists and return its SHA-256."""
        if not self._programmer.exists():
            raise FileNotFoundError(f"Programmer image not found: {self._programmer}")
        h = hashlib.sha256()
        with self._programmer.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        sha = h.hexdigest()
        self._log(
            "programmer_validated",
            {
                "path": str(self._programmer),
                "sha256": sha,
                "size_bytes": str(self._programmer.stat().st_size),
            },
        )
        return sha

    def _detect_edl_device(self) -> object:
        """Locate the Qualcomm EDL USB device and return an open transport.

        Raises
        ------
        RuntimeError
            If no EDL device is found on the USB bus.
        """
        from forensix_forensic.extractors.hardware.usb_transport import (
            UsbBulkTransport,
            UsbDeviceNotFoundError,
        )

        try:
            transport = UsbBulkTransport(
                QCOM_USB_VID,
                QCOM_USB_PID_EDL,
                timeout_ms=self._usb_timeout,
            )
            transport.open()
        except UsbDeviceNotFoundError as exc:
            raise RuntimeError(
                "No Qualcomm EDL device found (VID 0x05C6, PID 0x9008). "
                "Power off device, hold Vol- and connect USB to enter EDL mode."
            ) from exc

        self._log("edl_device_detected", {"vid": "0x05C6", "pid": "0x9008"})
        return transport

    async def _sahara_handshake_and_upload(
        self, device: object, prog_sha256: str
    ) -> str:
        """Complete Sahara Hello/End-of-Image sequence and upload the programmer MBN.

        Protocol:
        1.  Read 48-byte Hello from device; decode and validate with
            :func:`decode_sahara_hello`.
        2.  Write 48-byte Hello Response.
        3.  Loop receiving ``READ_DATA`` (0x03) packets — each 20 bytes:
            ``[cmd:4, pkt_len:4, image_id:4, offset:4, length:4]``.
            For each, read the requested slice from the programmer binary
            and write it to the bulk-OUT endpoint.
        4.  Receive ``END_IMG_TX`` (0x04).
        5.  Write ``DONE`` (0x05, 8 bytes).
        6.  Read ``DONE_RESP`` (0x06) to confirm device is in Firehose mode.
        """
        from forensix_forensic.extractors.hardware.usb_transport import UsbBulkTransport

        transport: UsbBulkTransport = device  # type: ignore[assignment]

        self._log("sahara_handshake_start", {})

        # Step 1 — receive Hello (48 bytes)
        hello_data = await transport.read_exact(48)
        hello = decode_sahara_hello(hello_data)
        self._state = EdlState.SAHARA_HELLO_RECEIVED
        self._log(
            "sahara_hello_received",
            {
                "version": str(hello.version),
                "mode": str(hello.mode),
                "max_packet_size": str(hello.max_packet_size),
            },
        )

        # Step 2 — send Hello Response
        hello_resp = build_sahara_hello_response(hello.version, hello.mode)
        await transport.write(hello_resp)
        self._log("sahara_hello_response_sent", {"size": str(len(hello_resp))})

        # Step 3 — READ_DATA loop
        prog_data = self._programmer.read_bytes()
        bytes_sent = 0

        while True:
            # Every Sahara packet starts with an 8-byte header: cmd (4) + len (4)
            hdr = await transport.read_exact(8)
            cmd, pkt_len = struct.unpack_from("<II", hdr)

            if cmd == SAHARA_END_IMG_TX:
                # Step 4 — End of image transfer: read remaining bytes of packet
                remaining_header = max(0, pkt_len - 8)
                if remaining_header:
                    await transport.read_exact(remaining_header)
                self._log("sahara_end_img_tx_received", {"bytes_sent": str(bytes_sent)})
                break

            if cmd == SAHARA_READ_DATA:
                # READ_DATA body: image_id (4) + offset (4) + length (4) = 12 bytes
                body = await transport.read_exact(pkt_len - 8)
                _image_id, offset, length = struct.unpack_from("<III", body)
                chunk = prog_data[offset : offset + length]
                if len(chunk) < length:
                    # Pad with zeros if programmer is shorter than requested
                    chunk = chunk.ljust(length, b"\x00")
                await transport.write(chunk)
                bytes_sent += len(chunk)
            else:
                # Unexpected command — reset and abort
                self._log("sahara_unexpected_cmd", {"cmd": f"0x{cmd:02X}"})
                with suppress(Exception):
                    await transport.write(struct.pack("<II", SAHARA_RESET, 8))
                raise RuntimeError(
                    f"Unexpected Sahara command 0x{cmd:02X} during upload. "
                    "Device may be locked or in an unexpected state."
                )

        # Step 5 — send Done
        await transport.write(build_sahara_done())
        self._log("sahara_done_sent", {})

        # Step 6 — read Done Response
        done_resp = await transport.read_exact(8)
        done_cmd, _ = struct.unpack_from("<II", done_resp)
        if done_cmd != SAHARA_DONE_RESP:
            self._log(
                "sahara_done_resp_warning",
                {"expected": f"0x{SAHARA_DONE_RESP:02X}", "got": f"0x{done_cmd:02X}"},
            )

        self._state = EdlState.PROGRAMMER_UPLOADED
        prog_size = self._programmer.stat().st_size
        self._log(
            "programmer_uploaded",
            {"sha256": prog_sha256, "size_bytes": str(prog_size), "bytes_sent": str(bytes_sent)},
        )

        # Derive SoC model from programmer filename via ProgrammerRegistry
        prog_stem = self._programmer.stem.upper()
        soc_model = "unknown"
        for key in ProgrammerRegistry.list_supported_socs():
            entry = ProgrammerRegistry.lookup(key)
            if entry and entry.programmer_name.upper() in prog_stem:
                soc_model = entry.msm_id
                break
        if soc_model == "unknown":
            soc_model = prog_stem  # fall back to raw filename stem

        self._state = EdlState.SAHARA_DONE
        self._log("sahara_done", {"soc_model": soc_model})
        return soc_model

    async def _firehose_configure(self, device: object) -> None:
        """Send Firehose ``<configure>`` and wait for ACK.

        Writes the XML configure command over bulk-OUT and reads the
        XML ACK response from bulk-IN.  Raises ``RuntimeError`` if the
        device returns a NAK.
        """
        from forensix_forensic.extractors.hardware.usb_transport import UsbBulkTransport

        transport: UsbBulkTransport = device  # type: ignore[assignment]

        cmd = build_firehose_configure()
        self._log("firehose_configure_sent", {"size": str(len(cmd))})
        await transport.write(cmd)

        # Read response — Firehose XML is variable length; read up to 4 KiB
        resp_raw = await transport.read(4096)
        ok, msg = parse_firehose_response(resp_raw)
        if not ok:
            raise RuntimeError(
                f"Firehose configure NAK: {msg!r}. "
                "Ensure the programmer binary matches the device's SoC and storage type."
            )
        self._log("firehose_ready", {"rawmsg": msg})

    async def _get_partition_table(
        self, device: object, lun: int
    ) -> list[FirehosePartitionInfo]:
        """Query GPT partition table for *lun* via Firehose XML.

        Returns a list of :class:`FirehosePartitionInfo` parsed from the
        ``<getpartitiontable>`` XML response.
        """
        from forensix_forensic.extractors.hardware.usb_transport import UsbBulkTransport

        transport: UsbBulkTransport = device  # type: ignore[assignment]

        cmd = build_firehose_getpartitiontable(lun)
        await transport.write(cmd)

        # Firehose partition table response can be large (many partitions)
        resp_raw = await transport.read(65536)
        partitions = _parse_partition_table_xml(resp_raw, lun)

        self._log(
            "partition_table_queried",
            {"lun": str(lun), "count": str(len(partitions))},
        )
        return partitions

    async def _read_partition(
        self,
        device: object,
        part: FirehosePartitionInfo,
        output_path: Path,
    ) -> str:
        """Stream raw sectors for *part* into *output_path*, returning SHA-256.

        Protocol:
        -  For each batch of up to ``FIREHOSE_SECTORS_PER_CMD`` sectors:
           1.  Write ``<read>`` XML command over bulk-OUT.
           2.  Read XML ACK from bulk-IN.
           3.  Read ``count * SECTOR_SIZE`` raw bytes from bulk-IN.
           4.  Write bytes to file; update running SHA-256.
        """
        from forensix_forensic.extractors.hardware.usb_transport import UsbBulkTransport

        transport: UsbBulkTransport = device  # type: ignore[assignment]

        hasher = hashlib.sha256()
        remaining = part.num_sectors
        current = part.start_sector
        bytes_written = 0

        self._log(
            "partition_read_start",
            {
                "label": part.label,
                "start_sector": str(current),
                "num_sectors": str(remaining),
                "size_mb": f"{part.size_mb:.2f}",
            },
        )

        with output_path.open("wb") as fh:
            while remaining > 0:
                count = min(FIREHOSE_SECTORS_PER_CMD, remaining)
                read_cmd = build_firehose_read(current, count, part.lun)

                # 1. Send read command
                await transport.write(read_cmd)

                # 2. Read XML ACK (variable size, up to 4 KiB)
                ack_raw = await transport.read(4096)
                ok, msg = parse_firehose_response(ack_raw)
                if not ok:
                    raise RuntimeError(
                        f"Firehose read NAK at sector {current} "
                        f"(partition '{part.label}'): {msg!r}"
                    )

                # 3. Read raw sector data
                expected_bytes = count * SECTOR_SIZE
                chunk = await transport.read_exact(expected_bytes)

                # 4. Write and hash
                fh.write(chunk)
                hasher.update(chunk)
                bytes_written += len(chunk)
                current += count
                remaining -= count

                # Progress log every 128 MiB
                if bytes_written % (128 * 1024 * 1024) < expected_bytes:
                    self._log(
                        "partition_read_progress",
                        {
                            "label": part.label,
                            "bytes_written": str(bytes_written),
                            "total_bytes": str(part.num_sectors * SECTOR_SIZE),
                        },
                    )

        sha = hasher.hexdigest()
        self._log(
            "partition_read_complete",
            {
                "label": part.label,
                "bytes_written": str(bytes_written),
                "sha256": sha,
            },
        )
        return sha

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

    @staticmethod
    def _aggregate_hash(image_sha256: dict[str, str]) -> str:
        h = hashlib.sha256()
        for name in sorted(image_sha256):
            h.update(f"{name}:{image_sha256[name]}\n".encode())
        return h.hexdigest()

    def _error_result(
        self, acquisition_id: str, started_at: str, t0: float, message: str
    ) -> QualcommEdlAcquisitionResult:
        self._state = EdlState.ERROR
        self._log("acquisition_error", {"error": message})
        return QualcommEdlAcquisitionResult(
            acquisition_id=acquisition_id,
            soc_model="unknown",
            storage_type=self._storage_type,
            programmer_sha256="",
            partitions_acquired=(),
            output_images=(),
            image_sha256={},
            aggregate_sha256="",
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
            duration_seconds=round(asyncio.get_event_loop().time() - t0, 3),
            success=False,
            error_message=message,
            state_reached=self._state.name,
        )


# ---------------------------------------------------------------------------
# Internal XML parsing helper
# ---------------------------------------------------------------------------


def _parse_partition_table_xml(
    xml_bytes: bytes, lun: int
) -> list[FirehosePartitionInfo]:
    """Parse a Firehose ``<partitiontable>`` XML response into a list of partitions.

    The Firehose programmer returns an XML blob like::

        <data><partitiontable ...>
          <partition name="system" start_sector="2048" num_partition_sectors="4096" .../>
          ...
        </partitiontable></data>

    Entries with ``num_partition_sectors == 0`` are skipped.
    """
    partitions: list[FirehosePartitionInfo] = []
    try:
        root = ET.fromstring(xml_bytes.decode(errors="replace"))  # noqa: S314
    except ET.ParseError:
        return partitions

    for child in root.iter():
        if child.tag not in ("partition", "entry"):
            continue
        try:
            name = (
                child.get("label")
                or child.get("name")
                or child.get("Name")
                or ""
            )
            start = int(child.get("start_sector") or child.get("StartSector") or "0")
            count = int(
                child.get("num_partition_sectors")
                or child.get("NumPartitionSectors")
                or "0"
            )
            if count == 0 or not name:
                continue
            size_mb = round((count * SECTOR_SIZE) / (1024 * 1024), 3)
            partitions.append(
                FirehosePartitionInfo(
                    label=name,
                    start_sector=start,
                    num_sectors=count,
                    size_mb=size_mb,
                    lun=lun,
                )
            )
        except (ValueError, TypeError):
            continue

    return partitions
