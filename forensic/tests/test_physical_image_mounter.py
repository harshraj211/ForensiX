import asyncio
from pathlib import Path

from forensix_forensic.extractors.physical_image_mounter import PhysicalImageMounter


def test_ext4_superblock_is_observed_without_fake_carving(tmp_path: Path) -> None:
    image = tmp_path / "userdata.img"
    payload = bytearray(8192)
    superblock = 1024
    payload[superblock : superblock + 4] = (12345).to_bytes(4, "little")
    payload[superblock + 0x18 : superblock + 0x1C] = (2).to_bytes(4, "little")
    payload[superblock + 0x38 : superblock + 0x3A] = b"\x53\xef"
    image.write_bytes(payload)

    result = asyncio.run(
        PhysicalImageMounter().mount_and_carve_image("CASE-1", str(image), "operator")
    )

    assert result.success
    assert result.filesystem_type == "EXT4"
    assert result.block_size_bytes == 4096
    assert result.total_inodes_scanned == 12345
    assert result.carved_inodes == []


def test_unknown_image_is_not_reported_as_success(tmp_path: Path) -> None:
    image = tmp_path / "unknown.img"
    image.write_bytes(b"\0" * 8192)
    result = asyncio.run(PhysicalImageMounter().mount_and_carve_image("CASE-1", str(image)))
    assert not result.success
    assert result.carved_inodes == []
