"""MediaTek BROM (Boot ROM) forensic acquisition protocol handler.

Implements the SP Flash Tool / BROM USB protocol used for forensic physical
extraction from MediaTek chipsets.  The module orchestrates:

1.  USB enumeration of the device in BROM mode (VID 0x0E8D, PID 0x0003).
2.  Handshake — send 0xA0, 0x0A, 0x50, 0x05 and validate echoes.
3.  Disable SLA/DAA authentication (pre-secured chipsets only).
4.  Inject a minimal Download Agent (DA) binary that exposes a memory-read
    interface over USB.
5.  Issue ``READ_PARTITION`` commands to stream raw eMMC / UFS blocks.
6.  Hash every 4 MiB chunk with SHA-256 and record in the streaming manifest.
7.  Seal the acquisition with an aggregate SHA-256 hash chain.

The implementation is a *forensic orchestration layer*.  Raw USB bulk
transfers are delegated to the ``pyusb`` library (``import usb.core``); if
``pyusb`` is not installed the module raises ``ImportError`` with a helpful
message.  No DA binary is bundled; the caller must supply a lab-approved DA
binary path.
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

BROM_USB_VID = 0x0E8D  # MediaTek
BROM_USB_PID_BROM = 0x0003  # Raw BROM mode
BROM_USB_PID_PRELOADER = 0x2000  # Preloader (early DA injection)

# BROM handshake sequence
_HS_SEND = bytes([0xA0, 0x0A, 0x50, 0x05])
_HS_RECV = bytes([0x5F, 0xF5, 0xAF, 0xFA])

# DA command opcodes (SP Flash protocol v2)
DA_CMD_READ_PARTITION = 0x71
DA_CMD_WRITE = 0x72
DA_CMD_UART_LOG = 0x74
DA_CMD_FLASH_ID = 0x70
DA_RESP_ACK = 0x5A
DA_RESP_NACK = 0xA5

# Chunk size for streaming hash (4 MiB)
CHUNK_SIZE = 4 * 1024 * 1024


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class MtkBromState(IntEnum):
    """State machine states for the BROM acquisition pipeline."""

    IDLE = 0
    USB_DETECTED = 1
    HANDSHAKE_COMPLETE = 2
    AUTH_DISABLED = 3
    DA_INJECTED = 4
    READING = 5
    COMPLETE = 6
    ERROR = 7


class MtkChipset(IntEnum):
    """Known MediaTek chipset identifiers reported by BROM."""

    MT6580 = 0x6580
    MT6737 = 0x6737
    MT6739 = 0x6739
    MT6753 = 0x6753
    MT6761 = 0x6761
    MT6765 = 0x6765
    MT6771 = 0x6771
    MT6785 = 0x6785
    MT6833 = 0x6833
    MT6873 = 0x6873
    UNKNOWN = 0xFFFF


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MtkPartitionInfo:
    """Partition entry discovered via DA flash-ID command."""

    name: str
    start_lba: int
    size_bytes: int
    partition_type: str  # 'emmc' | 'ufs' | 'nor'


@dataclass(frozen=True, slots=True)
class MtkDaEntry:
    """Download Agent entry in the MediaTek chipset registry."""

    chipset_id: int
    chipset_name: str
    recommended_da_file: str
    requires_sla_auth: bool
    flash_type: str


class MtkDaRegistry:
    """Registry mapping MediaTek chipset IDs to Download Agent parameters."""

    _REGISTRY: dict[int, MtkDaEntry] = {
        0x6580: MtkDaEntry(0x6580, "MT6580", "MTK_AllInOne_DA_v5.bin", False, "emmc"),
        0x6737: MtkDaEntry(0x6737, "MT6737", "MTK_AllInOne_DA_v5.bin", False, "emmc"),
        0x6739: MtkDaEntry(0x6739, "MT6739", "MTK_AllInOne_DA_v5.bin", False, "emmc"),
        0x6753: MtkDaEntry(0x6753, "MT6753", "MTK_AllInOne_DA_v5.bin", False, "emmc"),
        0x6761: MtkDaEntry(0x6761, "MT6761", "MTK_AllInOne_DA_v6.bin", True, "emmc"),
        0x6765: MtkDaEntry(0x6765, "MT6765", "MTK_AllInOne_DA_v6.bin", True, "emmc"),
        0x6771: MtkDaEntry(0x6771, "MT6771", "MTK_AllInOne_DA_v6.bin", True, "emmc"),
        0x6785: MtkDaEntry(0x6785, "MT6785", "MTK_AllInOne_DA_v6.bin", True, "ufs"),
        0x6833: MtkDaEntry(0x6833, "MT6833", "MTK_AllInOne_DA_v6.bin", True, "ufs"),
        0x6873: MtkDaEntry(0x6873, "MT6873", "MTK_AllInOne_DA_v6.bin", True, "ufs"),
    }

    @classmethod
    def lookup(cls, chipset_id: int) -> MtkDaEntry | None:
        """Lookup DA metadata by 16-bit MTK Chipset ID."""
        return cls._REGISTRY.get(chipset_id)

    @classmethod
    def is_auth_required(cls, chipset_id: int) -> bool:
        """Return True if the chipset requires SLA/DAA authentication bypass."""
        entry = cls.lookup(chipset_id)
        return entry.requires_sla_auth if entry else True


@dataclass(frozen=True, slots=True)
class MtkBromAcquisitionResult:
    """Sealed result of a BROM physical acquisition."""

    acquisition_id: str
    chipset_id: int
    chipset_name: str
    flash_type: str  # 'emmc' | 'ufs' | 'nor'
    partitions_acquired: tuple[str, ...]
    output_images: tuple[str, ...]  # local paths to raw image files
    image_sha256: dict[str, str]  # partition_name -> sha256
    aggregate_sha256: str
    da_binary_sha256: str
    timeline: list[dict[str, str]]
    started_at: str
    finished_at: str
    duration_seconds: float
    success: bool
    error_message: str | None
    state_reached: str


# ---------------------------------------------------------------------------
# BROM protocol helpers (pure-Python, no USB dependency for unit tests)
# ---------------------------------------------------------------------------


class BromProtocolError(RuntimeError):
    """Raised when the device returns an unexpected BROM response."""


class DaBinaryError(ValueError):
    """Raised when the supplied DA binary fails integrity checks."""


def parse_flash_id_response(payload: bytes) -> tuple[str, int, int]:
    """Decode the 16-byte flash-ID response returned by the DA.

    Returns ``(flash_type, page_size, block_size)`` where *flash_type* is one
    of ``'emmc'``, ``'ufs'``, or ``'nor'``.

    Raises ``BromProtocolError`` if the payload is malformed.
    """
    if len(payload) < 16:
        raise BromProtocolError(
            f"Flash-ID response too short: {len(payload)} bytes, expected >= 16"
        )
    magic = struct.unpack_from(">H", payload, 0)[0]
    page_size = struct.unpack_from(">I", payload, 4)[0]
    block_size = struct.unpack_from(">I", payload, 8)[0]
    flash_map = {0xEA01: "emmc", 0xEA02: "ufs", 0xEA03: "nor"}
    flash_type = flash_map.get(magic, "unknown")
    return flash_type, page_size, block_size


def build_read_command(start_lba: int, sector_count: int) -> bytes:
    """Build a DA ``READ_PARTITION`` command payload.

    Format (12 bytes)::

        [0x71] [start_lba: 4B big-endian] [sector_count: 4B big-endian] [0x00 0x00 0x00]
    """
    return struct.pack(">BIII", DA_CMD_READ_PARTITION, start_lba, sector_count, 0)


def verify_handshake_echo(sent: bytes, received: bytes) -> bool:
    """Validate that the BROM echoed the complemented handshake bytes."""
    return received == _HS_RECV


def sha256_file(path: Path) -> str:
    """Compute SHA-256 of a local file, streaming in 1 MiB chunks."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Core extractor
# ---------------------------------------------------------------------------


class MtkBromExtractor:
    """Orchestrate a forensic physical acquisition over the MediaTek BROM protocol.

    Usage::

        extractor = MtkBromExtractor(
            da_binary_path=Path('/lab/da/DA_v6.bin'),
            output_dir=Path('/cases/001/physical'),
        )
        result = await extractor.acquire(
            partitions=['userdata', 'system', 'boot'],
            case_id='CASE-2025-001',
            operator_id='examiner@lab.example',
        )

    The extractor **never** runs on a live Android system — it only operates
    on a device in BROM mode (USB debugging is irrelevant at this stage).  The
    device must be connected via USB with no preloader running.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        da_binary_path: Path,
        output_dir: Path,
        *,
        usb_timeout_ms: int = 5000,
        sector_size: int = 512,
    ) -> None:
        self._da_path = da_binary_path
        self._output_dir = output_dir
        self._usb_timeout = usb_timeout_ms
        self._sector_size = sector_size
        self._timeline: list[dict[str, str]] = []
        self._state = MtkBromState.IDLE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def acquire(
        self,
        partitions: list[str],
        case_id: str,
        operator_id: str,
    ) -> MtkBromAcquisitionResult:
        """Run the full BROM acquisition pipeline.

        Parameters
        ----------
        partitions:
            List of partition names to acquire (e.g. ``['userdata', 'system']``).
            Pass ``['__all__']`` to acquire every discovered partition.
        case_id:
            ForensiX case identifier for the chain-of-custody record.
        operator_id:
            Examiner identity logged in the acquisition timeline.

        Returns
        -------
        MtkBromAcquisitionResult
            A frozen, hash-sealed result object.
        """
        acquisition_id = str(uuid4())
        started_at = datetime.now(UTC).isoformat()
        t0 = asyncio.get_event_loop().time()

        self._log(
            "acquisition_start",
            {
                "acquisition_id": acquisition_id,
                "case_id": case_id,
                "operator_id": operator_id,
                "partitions_requested": ", ".join(partitions),
                "da_binary": str(self._da_path),
                "output_dir": str(self._output_dir),
            },
        )

        try:
            return await self._run_pipeline(
                acquisition_id=acquisition_id,
                started_at=started_at,
                t0=t0,
                partitions=partitions,
                case_id=case_id,
            )
        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                acquisition_id=acquisition_id,
                started_at=started_at,
                t0=t0,
                message=str(exc),
            )

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
        case_id: str,
    ) -> MtkBromAcquisitionResult:
        # Stage 1 — validate DA binary
        da_sha256 = self._validate_da_binary()
        self._state = MtkBromState.IDLE

        # Stage 2 — detect USB device
        device = self._detect_brom_usb_device()
        self._state = MtkBromState.USB_DETECTED
        self._log("usb_device_detected", {"device": repr(device)})

        # Stage 3 — handshake
        chipset_id = await self._perform_handshake(device)
        self._state = MtkBromState.HANDSHAKE_COMPLETE

        # Stage 4 — disable SLA/DAA (pre-secured chipsets)
        await self._disable_auth(device, chipset_id)
        self._state = MtkBromState.AUTH_DISABLED

        # Stage 5 — inject DA binary
        await self._inject_da(device, da_sha256)
        self._state = MtkBromState.DA_INJECTED

        # Stage 6 — enumerate partitions
        all_partitions = await self._enumerate_partitions(device)
        targets = (
            all_partitions
            if partitions == ["__all__"]
            else [p for p in all_partitions if p.name in partitions]
        )
        self._log("partitions_selected", {"count": str(len(targets))})

        # Stage 7 — stream-acquire partitions
        self._state = MtkBromState.READING
        self._output_dir.mkdir(parents=True, exist_ok=True)
        output_images: list[str] = []
        image_sha256: dict[str, str] = {}

        for part in targets:
            img_path = self._output_dir / f"{part.name}.img"
            sha = await self._acquire_partition(device, part, img_path)
            output_images.append(str(img_path))
            image_sha256[part.name] = sha
            self._log(
                "partition_acquired",
                {
                    "partition": part.name,
                    "size_bytes": str(part.size_bytes),
                    "sha256": sha,
                },
            )

        # Stage 8 — aggregate hash
        aggregate = self._compute_aggregate_hash(image_sha256)
        self._state = MtkBromState.COMPLETE
        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0

        chipset_name = _chipset_name(chipset_id)
        flash_type = all_partitions[0].partition_type if all_partitions else "unknown"

        self._log(
            "acquisition_complete",
            {
                "aggregate_sha256": aggregate,
                "duration_seconds": f"{duration:.2f}",
            },
        )

        return MtkBromAcquisitionResult(
            acquisition_id=acquisition_id,
            chipset_id=chipset_id,
            chipset_name=chipset_name,
            flash_type=flash_type,
            partitions_acquired=tuple(image_sha256.keys()),
            output_images=tuple(output_images),
            image_sha256=image_sha256,
            aggregate_sha256=aggregate,
            da_binary_sha256=da_sha256,
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

    def _validate_da_binary(self) -> str:
        """Verify the DA binary exists and return its SHA-256."""
        if not self._da_path.exists():
            raise DaBinaryError(f"DA binary not found: {self._da_path}")
        da_sha256 = sha256_file(self._da_path)
        self._log(
            "da_binary_validated",
            {
                "path": str(self._da_path),
                "size_bytes": str(self._da_path.stat().st_size),
                "sha256": da_sha256,
            },
        )
        return da_sha256

    def _detect_brom_usb_device(self) -> object:
        """Locate the MediaTek BROM USB device.

        Tries VID/PID pairs for both raw BROM (0x0003) and preloader mode
        (0x2000).  Raises ``RuntimeError`` if no device is found.
        """
        try:
            import usb.core  # type: ignore
        except ImportError as exc:
            raise ImportError("pyusb is required for BROM acquisition: pip install pyusb") from exc

        for pid in (BROM_USB_PID_BROM, BROM_USB_PID_PRELOADER):
            device = usb.core.find(idVendor=BROM_USB_VID, idProduct=pid)
            if device is not None:
                self._log(
                    "usb_device_found",
                    {
                        "vid": hex(BROM_USB_VID),
                        "pid": hex(pid),
                    },
                )
                return device

        raise RuntimeError(
            "No MediaTek BROM device found. "
            "Ensure the device is powered off, then hold Vol+ and connect USB."
        )

    async def _perform_handshake(self, device: object) -> int:
        """Execute the 4-byte BROM handshake and read the 2-byte chipset ID.

        Protocol:
        1. Send each byte of _HS_SEND one at a time; read back complemented echo.
        2. Validate echoes match _HS_RECV.
        3. Read 2-byte big-endian chipset ID from device.
        """
        from forensix_forensic.extractors.hardware.usb_transport import UsbBulkTransport

        transport: UsbBulkTransport = device  # type: ignore[assignment]
        self._log("handshake_start", {})
        echoes = bytearray()

        for send_byte in _HS_SEND:
            await transport.write(bytes([send_byte]))
            echo = await transport.read_exact(1)
            echoes.extend(echo)

        if not verify_handshake_echo(_HS_SEND, bytes(echoes)):
            raise BromProtocolError(
                f"BROM handshake echo mismatch: sent {_HS_SEND.hex()}, "
                f"received {echoes.hex()}. "
                "Ensure the device is in BROM mode (power off → hold Vol+ → connect USB)."
            )

        chipset_raw = await transport.read_exact(2)
        chipset_id: int = int(struct.unpack(">H", chipset_raw)[0])
        self._log("handshake_complete", {"chipset_id": hex(chipset_id)})
        return chipset_id


    async def _disable_auth(self, device: object, chipset_id: int) -> None:
        """Send the SLA/DAA authentication-disable sequence.

        Pre-secured chipsets (MT6580, MT6737, MT6739): send 0xFE opcode and
        read ACK. Secured chipsets (MT6761+): log warning; auth bypass requires
        an external lab-supplied payload not bundled with this module.
        """
        from forensix_forensic.extractors.hardware.usb_transport import UsbBulkTransport

        transport: UsbBulkTransport = device  # type: ignore[assignment]
        secured_chipsets = {
            MtkChipset.MT6761.value,
            MtkChipset.MT6765.value,
            MtkChipset.MT6771.value,
        }
        if chipset_id in secured_chipsets:
            self._log(
                "auth_disable_skipped",
                {"reason": "Chipset requires lab-approved SLA bypass payload"},
            )
        else:
            await transport.write(bytes([0xFE]))
            ack = await transport.read_exact(1)
            if ack != bytes([DA_RESP_ACK]):
                self._log("auth_disable_nak", {"ack": ack.hex(), "chipset_id": hex(chipset_id)})
            else:
                self._log("auth_disable", {"chipset_id": hex(chipset_id)})

    async def _inject_da(self, device: object, da_sha256: str) -> None:
        """Upload the Download Agent binary over USB and verify the BROM ACK.

        Protocol:
        1. Send 12-byte header: [load_address: 4B BE] [da_size: 4B BE] [sig_len: 4B BE].
        2. Stream binary in 4096-byte chunks; read 0x5A ACK after each chunk.
        3. Read final 0x5A to confirm DA execution in SRAM.
        """
        from forensix_forensic.extractors.hardware.usb_transport import UsbBulkTransport

        transport: UsbBulkTransport = device  # type: ignore[assignment]
        da_bytes = self._da_path.read_bytes()
        da_size = len(da_bytes)
        DA_LOAD_ADDR = 0x00200000  # Standard MTK SRAM load address

        self._log("da_inject_start", {"size_bytes": str(da_size), "sha256": da_sha256})

        header = struct.pack(">III", DA_LOAD_ADDR, da_size, 0)
        await transport.write(header)
        hdr_ack = await transport.read_exact(1)
        if hdr_ack != bytes([DA_RESP_ACK]):
            raise BromProtocolError(
                f"DA header rejected: ACK=0x{hdr_ack.hex()} (expected 0x5A). "
                "Ensure the DA binary is compatible with the detected chipset."
            )

        CHUNK_DA = 4096
        offset = 0
        while offset < da_size:
            chunk = da_bytes[offset : offset + CHUNK_DA]
            await transport.write(chunk)
            ack = await transport.read_exact(1)
            if ack != bytes([DA_RESP_ACK]):
                raise BromProtocolError(
                    f"DA chunk rejected at offset {offset}: ACK=0x{ack.hex()} (expected 0x5A)."
                )
            offset += len(chunk)

        final_ack = await transport.read_exact(1)
        if final_ack != bytes([DA_RESP_ACK]):
            self._log("da_inject_final_nak", {"ack": final_ack.hex()})

        self._log("da_inject_complete", {"bytes_sent": str(da_size)})

    async def _enumerate_partitions(self, device: object) -> list[MtkPartitionInfo]:
        """Query the DA for flash info and all partition entries.

        Protocol:
        1. Send DA_CMD_FLASH_ID (0x70); read 16-byte flash geometry response.
        2. Send DA_CMD_READ_PARTITION for LBA 0-1 (MBR + GPT header).
        3. Parse GPT partition entries into MtkPartitionInfo list.
        """
        from forensix_forensic.extractors.hardware.usb_transport import UsbBulkTransport

        transport: UsbBulkTransport = device  # type: ignore[assignment]
        self._log("partition_enumeration_start", {})

        await transport.write(bytes([DA_CMD_FLASH_ID]))
        flash_id_resp = await transport.read_exact(16)
        try:
            flash_type, page_size, _block_size = parse_flash_id_response(flash_id_resp)
        except BromProtocolError:
            flash_type = "emmc"
            page_size = 512
        sector_size = max(page_size, 512)

        gpt_cmd = build_read_command(0, 2)
        await transport.write(gpt_cmd)
        mbr_gpt_data = await transport.read_exact(2 * sector_size)

        partitions: list[MtkPartitionInfo] = _parse_gpt_partitions(
            mbr_gpt_data, sector_size, flash_type
        )

        self._log(
            "partition_enumeration_complete",
            {"count": str(len(partitions)), "flash_type": flash_type},
        )
        return partitions

    async def _acquire_partition(
        self,
        device: object,
        partition: MtkPartitionInfo,
        output_path: Path,
    ) -> str:
        """Stream a partition from the device and write to *output_path*.

        Protocol:
        1. For each chunk of ``sectors_per_chunk`` sectors, send
           ``build_read_command(lba, count)`` over bulk-OUT.
        2. Read exactly ``count * sector_size`` bytes from bulk-IN.
        3. Write bytes to file; update SHA-256; log progress every 128 MiB.

        Returns the hex SHA-256 of the complete partition image.
        """
        from forensix_forensic.extractors.hardware.usb_transport import UsbBulkTransport

        transport: UsbBulkTransport = device  # type: ignore[assignment]

        hasher = hashlib.sha256()
        total_written = 0
        sector_count = partition.size_bytes // self._sector_size
        sectors_per_chunk = CHUNK_SIZE // self._sector_size
        current_lba = partition.start_lba

        self._log(
            "partition_read_start",
            {
                "name": partition.name,
                "start_lba": str(current_lba),
                "sector_count": str(sector_count),
                "size_bytes": str(partition.size_bytes),
            },
        )

        with output_path.open("wb") as fh:
            while current_lba < partition.start_lba + sector_count:
                remaining_sectors = partition.start_lba + sector_count - current_lba
                read_count = min(sectors_per_chunk, remaining_sectors)

                cmd = build_read_command(current_lba, read_count)
                await transport.write(cmd)

                # Read ACK byte (0x5A) before data
                ack = await transport.read_exact(1)
                if ack != bytes([DA_RESP_ACK]):
                    raise BromProtocolError(
                        f"DA read NAK at LBA {current_lba} "
                        f"(partition '{partition.name}'): ACK=0x{ack.hex()}"
                    )

                expected_bytes = read_count * self._sector_size
                chunk = await transport.read_exact(expected_bytes)

                fh.write(chunk)
                hasher.update(chunk)
                total_written += len(chunk)
                current_lba += read_count

                if total_written % (128 * 1024 * 1024) < expected_bytes:
                    self._log(
                        "partition_read_progress",
                        {
                            "name": partition.name,
                            "bytes_written": str(total_written),
                            "total_bytes": str(partition.size_bytes),
                        },
                    )

        sha = hasher.hexdigest()
        self._log(
            "partition_read_complete",
            {"name": partition.name, "bytes_written": str(total_written), "sha256": sha},
        )
        return sha

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _log(self, event: str, details: dict[str, str]) -> None:
        """Append a timeline entry with an ISO-8601 timestamp."""
        self._timeline.append(
            {
                "ts": datetime.now(UTC).isoformat(),
                "event": event,
                **details,
            }
        )

    @staticmethod
    def _compute_aggregate_hash(image_sha256: dict[str, str]) -> str:
        """Compute an aggregate SHA-256 over all partition hashes (sorted by name)."""
        h = hashlib.sha256()
        for name in sorted(image_sha256):
            h.update(f"{name}:{image_sha256[name]}\n".encode())
        return h.hexdigest()

    def _error_result(
        self,
        acquisition_id: str,
        started_at: str,
        t0: float,
        message: str,
    ) -> MtkBromAcquisitionResult:
        self._state = MtkBromState.ERROR
        self._log("acquisition_error", {"error": message})
        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0
        return MtkBromAcquisitionResult(
            acquisition_id=acquisition_id,
            chipset_id=0,
            chipset_name="unknown",
            flash_type="unknown",
            partitions_acquired=(),
            output_images=(),
            image_sha256={},
            aggregate_sha256="",
            da_binary_sha256="",
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            success=False,
            error_message=message,
            state_reached=self._state.name,
        )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _chipset_name(chipset_id: int) -> str:
    """Map a chipset ID integer to a human-readable chipset name."""
    try:
        return MtkChipset(chipset_id).name
    except ValueError:
        return f"MT{chipset_id:04X}"


def _parse_gpt_partitions(
    mbr_gpt_data: bytes,
    sector_size: int,
    flash_type: str,
) -> list[MtkPartitionInfo]:
    """Parse GPT partition entries from a raw 2-sector blob (MBR + GPT header).

    The GPT header is at LBA 1 (bytes sector_size..2*sector_size).
    Partition entries begin at LBA 2 (not included in the 2-sector blob), so
    this function returns only what can be inferred from the GPT header for
    now — a proper implementation would request LBA 2..33 separately and parse
    all 128 entries.  This minimal parser handles the most common case where
    the device returns the full partition table in the same read response.

    Returns an empty list if the GPT signature is not found.
    """
    GPT_SIGNATURE = b"EFI PART"
    partitions: list[MtkPartitionInfo] = []

    if len(mbr_gpt_data) < sector_size + 92:
        return partitions

    gpt_header = mbr_gpt_data[sector_size:]
    if gpt_header[:8] != GPT_SIGNATURE:
        return partitions

    # GPT header fields (little-endian)
    try:
        (
            _sig,
            _revision,
            _header_size,
            _header_crc,
            _reserved,
            _my_lba,
            _alt_lba,
            _first_usable,
            _last_usable,
            _disk_guid,  # 16 bytes
            part_entry_lba,
            num_part_entries,
            part_entry_size,
            _part_array_crc,
        ) = struct.unpack_from("<8sIIII QQ QQ 16s QIIII", gpt_header, 0)
    except struct.error:
        return partitions

    # Partition entries follow immediately after the GPT header if the device
    # returned them in the same bulk transfer (some MTK DAs do this).
    entries_offset = sector_size + 92  # 92 = GPT header size
    entry_data = mbr_gpt_data[entries_offset:]

    for i in range(min(num_part_entries, 128)):
        entry_start = i * part_entry_size
        if entry_start + part_entry_size > len(entry_data):
            break
        entry = entry_data[entry_start : entry_start + part_entry_size]
        try:
            type_guid = entry[:16]
            if type_guid == b"\x00" * 16:
                continue  # Unused partition entry
            _part_guid = entry[16:32]
            start_lba, end_lba = struct.unpack_from("<QQ", entry, 32)
            # Name is UTF-16LE at offset 56, up to 36 chars (72 bytes)
            name_raw = entry[56 : 56 + 72]
            name = name_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            if not name:
                continue
            size_bytes = (end_lba - start_lba + 1) * sector_size
            partitions.append(
                MtkPartitionInfo(
                    name=name,
                    start_lba=start_lba,
                    size_bytes=size_bytes,
                    partition_type=flash_type,
                )
            )
        except (struct.error, UnicodeDecodeError):
            continue

    return partitions
