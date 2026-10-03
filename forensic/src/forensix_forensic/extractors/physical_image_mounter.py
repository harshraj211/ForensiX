"""Read-only physical image metadata inspection.

This module reports only properties observed in a supplied regular image file.
It does not mount an image, modify a device, invent recovered inodes, or claim
deleted-data recovery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import uuid4

_EXT4_SUPERBLOCK_OFFSET = 1024
_F2FS_SUPERBLOCK_OFFSET = 0x400
_EXT4_MAGIC = b"\x53\xef"
_F2FS_MAGIC = b"\x10\x20\xf5\xf2"


@dataclass(frozen=True, slots=True)
class CarvedInodeItem:
    """A verified recovery item, reserved for a later recovery implementation."""

    inode_number: int
    file_name: str
    file_type: str
    size_bytes: int
    unallocated_block_range: str
    sha256_hash: str


@dataclass(frozen=True, slots=True)
class PhysicalImageMountResult:
    """Observed filesystem metadata and any real verified recovery output."""

    mount_id: str
    image_path: str
    case_id: str
    operator_id: str
    timestamp: str
    filesystem_type: str
    block_size_bytes: int
    total_inodes_scanned: int
    carved_inodes: list[CarvedInodeItem] = field(default_factory=list)
    duration_seconds: float = 0.0
    success: bool = True
    error_message: str | None = None


class PhysicalImageMounter:
    """Identify EXT4/F2FS images using superblock bytes without mounting them."""

    def __init__(self, storage_dir: Any = None) -> None:
        self.storage_dir = storage_dir

    async def mount_and_carve_image(
        self,
        case_id: str,
        image_path: str = "data/userdata.img",
        operator_id: str = "operator",
    ) -> PhysicalImageMountResult:
        """Inspect one supplied raw image; no recovery claims are manufactured."""
        mount_id = str(uuid4())
        started = monotonic()
        target = Path(image_path).expanduser()
        try:
            if target.is_symlink() or not target.is_file():
                raise ValueError("Physical image input must be a regular, non-symlink file.")
            if target.stat().st_size < _F2FS_SUPERBLOCK_OFFSET + 4096:
                raise ValueError("Physical image is too small to contain a filesystem superblock.")
            filesystem_type, block_size, inode_count = _inspect_superblock(target)
            if filesystem_type == "UNKNOWN":
                raise ValueError("No supported EXT4 or F2FS superblock was found in the image.")
            return PhysicalImageMountResult(
                mount_id=mount_id,
                image_path=str(target.resolve()),
                case_id=case_id,
                operator_id=operator_id,
                timestamp=datetime.now(UTC).isoformat(),
                filesystem_type=filesystem_type,
                block_size_bytes=block_size,
                total_inodes_scanned=inode_count,
                carved_inodes=[],
                duration_seconds=round(monotonic() - started, 3),
                success=True,
                error_message=(
                    "Filesystem metadata inspection completed. Deleted-inode carving is not "
                    "implemented by this endpoint."
                ),
            )
        except (OSError, ValueError) as exc:
            return PhysicalImageMountResult(
                mount_id=mount_id,
                image_path=str(target),
                case_id=case_id,
                operator_id=operator_id,
                timestamp=datetime.now(UTC).isoformat(),
                filesystem_type="UNKNOWN",
                block_size_bytes=0,
                total_inodes_scanned=0,
                carved_inodes=[],
                duration_seconds=round(monotonic() - started, 3),
                success=False,
                error_message=str(exc),
            )


def _inspect_superblock(path: Path) -> tuple[str, int, int]:
    with path.open("rb") as source:
        source.seek(_EXT4_SUPERBLOCK_OFFSET)
        ext4 = source.read(1024)
        source.seek(_F2FS_SUPERBLOCK_OFFSET)
        f2fs_magic = source.read(4)
    if len(ext4) >= 0x3A and ext4[0x38:0x3A] == _EXT4_MAGIC:
        log_block_size = int.from_bytes(ext4[0x18:0x1C], "little")
        if log_block_size > 6:
            raise ValueError("EXT4 image contains an invalid block-size exponent.")
        return "EXT4", 1024 << log_block_size, int.from_bytes(ext4[0:4], "little")
    if f2fs_magic == _F2FS_MAGIC:
        return "F2FS", 4096, 0
    return "UNKNOWN", 0, 0
