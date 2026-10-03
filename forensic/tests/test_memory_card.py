"""Synthetic FAT32 images with live and deleted directory entries."""

from hashlib import sha256
from pathlib import Path

import pytest

from forensix_forensic.evidence_io import ParserContext
from forensix_forensic.extractors.memory_card import (
    MemoryCardImageParser,
    iter_active_file,
    probe_fat32,
    verified_active_file,
    verified_deleted_candidate,
)


def fat32_image(*, partitioned: bool = False) -> bytes:
    offset = 512 if partitioned else 0
    image = bytearray(offset + 10 * 512)
    if partitioned:
        image[446 + 4] = 0x0C
        image[446 + 8:446 + 12] = (1).to_bytes(4, "little")
        image[446 + 12:446 + 16] = (10).to_bytes(4, "little")
        image[510:512] = b"\x55\xaa"
    boot = memoryview(image)[offset:offset + 512]
    boot[11:13] = (512).to_bytes(2, "little")
    boot[13] = 1
    boot[14:16] = (1).to_bytes(2, "little")
    boot[16] = 1
    boot[32:36] = (10).to_bytes(4, "little")
    boot[36:40] = (1).to_bytes(4, "little")
    boot[44:48] = (2).to_bytes(4, "little")
    boot[82:90] = b"FAT32   "
    boot[510:512] = b"\x55\xaa"
    fat = offset + 512
    for cluster in (0, 1, 2, 3):
        image[fat + cluster * 4:fat + cluster * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    root = offset + 2 * 512
    image[root:root + 11] = b"HELLO   TXT"
    image[root + 11] = 0x20
    image[root + 26:root + 28] = (3).to_bytes(2, "little")
    image[root + 28:root + 32] = (5).to_bytes(4, "little")
    deleted = root + 32
    image[deleted:deleted + 11] = b"\xe5OST    JPG"
    image[deleted + 11] = 0x20
    image[deleted + 26:deleted + 28] = (4).to_bytes(2, "little")
    image[deleted + 28:deleted + 32] = (4).to_bytes(4, "little")
    image[offset + 3 * 512:offset + 3 * 512 + 5] = b"hello"
    image[offset + 4 * 512:offset + 4 * 512 + 4] = b"\xff\xd8\xff\xd9"
    return bytes(image)


def test_fat32_parser_indexes_live_file_and_deleted_contiguous_candidate(tmp_path: Path) -> None:
    image = tmp_path / "card.img"
    image.write_bytes(fat32_image())
    context = ParserContext(
        case_id="CASE", evidence_source_id="SOURCE", working_copy_id="COPY",
        source_sha256="0" * 64, source_label="card.img",
    )

    artifacts = MemoryCardImageParser().parse(image, context)

    live = next(item for item in artifacts if item.subtype == "memory_card_file")
    assert live.title == "HELLO.TXT"
    assert live.metadata["sha256"] == sha256(b"hello").hexdigest()
    deleted = next(item for item in artifacts if item.subtype == "memory_card_deleted_candidate")
    assert deleted.title == "?OST.JPG"
    assert deleted.metadata["candidate_sha256"] == sha256(b"\xff\xd8\xff\xd9").hexdigest()
    assert deleted.metadata["recovery_status"] == "contiguous_unallocated_candidate"
    assert artifacts[0].metadata["record_counts"]["memory_card_deleted_candidate"] == 1


def test_fat32_probe_finds_mbr_partition(tmp_path: Path) -> None:
    image = tmp_path / "partitioned.dd"
    image.write_bytes(fat32_image(partitioned=True))

    volume = probe_fat32(image)

    assert volume is not None and volume.offset == 512
    assert volume.cluster_bytes == 512


def test_deleted_candidate_export_rechecks_hash_and_allocation(tmp_path: Path) -> None:
    image = tmp_path / "card.img"
    image.write_bytes(fat32_image())
    expected = sha256(b"\xff\xd8\xff\xd9").hexdigest()
    assert verified_deleted_candidate(
        image, first_cluster=4, size_bytes=4, expected_sha256=expected
    ) == (2048, 4)
    with pytest.raises(ValueError, match="hash no longer matches"):
        verified_deleted_candidate(
            image, first_cluster=4, size_bytes=4, expected_sha256="0" * 64
        )
    overwritten = bytearray(image.read_bytes())
    overwritten[512 + 4 * 4:512 + 4 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    image.write_bytes(overwritten)
    with pytest.raises(ValueError, match="no longer unallocated"):
        verified_deleted_candidate(
            image, first_cluster=4, size_bytes=4, expected_sha256=expected
        )


def test_active_file_export_follows_fragmented_fat_chain(tmp_path: Path) -> None:
    image = tmp_path / "fragmented.img"
    payload = bytearray(fat32_image())
    payload[1052:1056] = (514).to_bytes(4, "little")
    payload[512 + 3 * 4:512 + 3 * 4 + 4] = (5).to_bytes(4, "little")
    payload[512 + 5 * 4:512 + 5 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    payload[1536:2048] = b"A" * 512
    payload[2560:2562] = b"BC"
    image.write_bytes(payload)
    expected = sha256(b"A" * 512 + b"BC").hexdigest()

    volume = verified_active_file(
        image, first_cluster=3, size_bytes=514, expected_sha256=expected
    )
    assert b"".join(iter_active_file(image, volume, 3, 514)) == b"A" * 512 + b"BC"
    with pytest.raises(ValueError, match="hash no longer matches"):
        verified_active_file(
            image, first_cluster=3, size_bytes=514, expected_sha256="0" * 64
        )
