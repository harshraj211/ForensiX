"""Read-only FAT32 inventory and bounded deleted-entry candidate analysis."""

from __future__ import annotations

import math
from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO, Literal

from forensix_forensic.evidence_io import ParsedArtifact, ParserContext, ParserMetadata

MAX_ENTRIES = 25_000
MAX_DIRECTORY_DEPTH = 16
MAX_HASH_BYTES = 512 * 1024 * 1024
MAX_TOTAL_HASH_BYTES = 2 * 1024 * 1024 * 1024
STREAM_CHUNK_BYTES = 1024 * 1024
_FAT32_PARTITION_TYPES = frozenset({0x0B, 0x0C, 0x1B, 0x1C})


@dataclass(frozen=True, slots=True)
class Fat32Volume:
    offset: int
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    fat_count: int
    sectors_per_fat: int
    total_sectors: int
    root_cluster: int

    @property
    def cluster_bytes(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def fat_offset(self) -> int:
        return self.offset + self.reserved_sectors * self.bytes_per_sector

    @property
    def data_offset(self) -> int:
        return (
            self.offset
            + (self.reserved_sectors + self.fat_count * self.sectors_per_fat)
            * self.bytes_per_sector
        )

    @property
    def cluster_count(self) -> int:
        return (
            self.total_sectors - self.reserved_sectors - self.fat_count * self.sectors_per_fat
        ) // self.sectors_per_cluster

    def cluster_offset(self, cluster: int) -> int:
        return self.data_offset + (cluster - 2) * self.cluster_bytes


def probe_fat32(path: Path) -> Fat32Volume | None:
    """Find one FAT32 superfloppy or primary MBR partition, without mounting."""
    if path.is_symlink() or not path.is_file():
        return None
    size = path.stat().st_size
    with path.open("rb") as source:
        source.seek(0)
        first = source.read(512)
        candidates = [0]
        if len(first) == 512 and first[510:512] == b"\x55\xaa":
            for index in range(4):
                entry = first[446 + 16 * index : 462 + 16 * index]
                if entry[4] in _FAT32_PARTITION_TYPES:
                    lba = int.from_bytes(entry[8:12], "little")
                    if lba:
                        candidates.append(lba * 512)
        for offset in candidates:
            if offset + 512 > size:
                continue
            source.seek(offset)
            boot = source.read(512)
            if boot[510:512] != b"\x55\xaa" or boot[82:87] != b"FAT32":
                continue
            bps = int.from_bytes(boot[11:13], "little")
            spc = boot[13]
            reserved = int.from_bytes(boot[14:16], "little")
            fats = boot[16]
            fat_sectors = int.from_bytes(boot[36:40], "little")
            total_sectors = int.from_bytes(boot[32:36], "little")
            root = int.from_bytes(boot[44:48], "little")
            if bps not in {512, 1024, 2048, 4096} or spc == 0 or spc > 128 or spc & (spc - 1):
                continue
            if not reserved or not 1 <= fats <= 4 or not fat_sectors or not total_sectors:
                continue
            volume = Fat32Volume(offset, bps, spc, reserved, fats, fat_sectors, total_sectors, root)
            if (
                volume.cluster_count < 1
                or not 2 <= root < volume.cluster_count + 2
                or offset + total_sectors * bps > size
                or (volume.cluster_count + 2) * 4 > fat_sectors * bps
            ):
                continue
            return volume
    return None


class MemoryCardImageParser:
    metadata = ParserMetadata(
        parser_id="memory_card.fat32.image",
        name="FAT32 memory-card image",
        version="1.0.0",
        artifact_categories=("system", "file"),
        required_tables=frozenset(),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=(".img", ".dd", ".raw"),
        supported_artifact_types=(
            "memory_card_summary",
            "memory_card_file",
            "memory_card_directory",
            "memory_card_deleted_candidate",
        ),
        description="Inventories FAT32 entries and hashes bounded readable content.",
        input_formats=("img", "dd", "raw"),
    )

    def can_parse(self, source_locator: str) -> bool:
        return Path(source_locator).suffix.casefold() in {".img", ".dd", ".raw"}

    def parse(self, path: Path, context: ParserContext) -> list[ParsedArtifact]:
        volume = probe_fat32(path)
        if volume is None:
            raise ValueError("No supported FAT32 volume found in the card image")
        artifacts: list[ParsedArtifact] = []
        issues: list[str] = []
        with path.open("rb") as source:
            scanner = _Fat32Scanner(source, volume, artifacts, issues)
            scanner.walk(volume.root_cluster, "", depth=0)
        counts = {
            kind: sum(artifact.subtype == kind for artifact in artifacts)
            for kind in (
                "memory_card_file",
                "memory_card_directory",
                "memory_card_deleted_candidate",
            )
        }
        summary = ParsedArtifact(
            category="system",
            subtype="memory_card_summary",
            title="FAT32 card-image examination",
            summary=f"{len(artifacts)} directory entries; {counts['memory_card_deleted_candidate']} deleted candidates",
            event_time=None,
            source_locator="image#fat32-summary",
            status="partial" if issues else "active",
            confidence="high",
            metadata={
                "filesystem_type": "fat32",
                "partition_offset_bytes": volume.offset,
                "bytes_per_sector": volume.bytes_per_sector,
                "cluster_bytes": volume.cluster_bytes,
                "cluster_count": volume.cluster_count,
                "record_counts": counts,
                "issues": issues[:200],
                "source_sha256": context.source_sha256,
            },
        )
        return [summary, *artifacts]


def verified_deleted_candidate(
    image: Path,
    *,
    first_cluster: int,
    size_bytes: int,
    expected_sha256: str,
) -> tuple[int, int]:
    """Revalidate a contiguous deleted candidate before its bytes are exported.

    The first character of a deleted FAT name and its original cluster chain may
    be gone. This verifies that the proposed range is currently unallocated and
    that its bytes still match the parser's recorded digest; it cannot establish
    that they were the file's original contents.
    """
    volume = probe_fat32(image)
    if volume is None or not 2 <= first_cluster < volume.cluster_count + 2:
        raise ValueError("The candidate's FAT32 volume or first cluster is invalid")
    if not 0 < size_bytes <= MAX_HASH_BYTES or len(expected_sha256) != 64:
        raise ValueError("The candidate size or SHA-256 is invalid")
    needed = math.ceil(size_bytes / volume.cluster_bytes)
    if first_cluster + needed > volume.cluster_count + 2:
        raise ValueError("The candidate extends past the cluster heap")
    with image.open("rb") as source:
        scanner = _Fat32Scanner(source, volume, [], [])
        if any(
            scanner.fat(cluster) != 0 for cluster in range(first_cluster, first_cluster + needed)
        ):
            raise ValueError("The candidate clusters are no longer unallocated")
        digest = sha256()
        remaining = size_bytes
        for chunk in iter_deleted_candidate(image, volume, first_cluster, size_bytes):
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining or digest.hexdigest() != expected_sha256.lower():
            raise ValueError("The deleted candidate's content hash no longer matches")
    return volume.cluster_offset(first_cluster), size_bytes


def iter_deleted_candidate(
    image: Path,
    volume: Fat32Volume,
    first_cluster: int,
    size_bytes: int,
) -> Iterator[bytes]:
    """Stream exactly the candidate's bounded content from a read-only image."""
    with image.open("rb") as source:
        source.seek(volume.cluster_offset(first_cluster))
        remaining = size_bytes
        while remaining:
            chunk = source.read(min(remaining, STREAM_CHUNK_BYTES))
            if not chunk:
                raise ValueError("The deleted candidate is truncated")
            remaining -= len(chunk)
            yield chunk


def verified_active_file(
    image: Path,
    *,
    first_cluster: int,
    size_bytes: int,
    expected_sha256: str,
) -> Fat32Volume:
    """Check an active FAT chain and content hash before exporting it."""
    volume = probe_fat32(image)
    if volume is None or not 0 <= size_bytes <= MAX_HASH_BYTES or len(expected_sha256) != 64:
        raise ValueError("The active file volume, size, or hash is invalid")
    digest = sha256()
    for chunk in iter_active_file(image, volume, first_cluster, size_bytes):
        digest.update(chunk)
    if digest.hexdigest() != expected_sha256.lower():
        raise ValueError("The active file content hash no longer matches")
    return volume


def iter_active_file(
    image: Path,
    volume: Fat32Volume,
    first_cluster: int,
    size_bytes: int,
) -> Iterator[bytes]:
    """Read the current FAT chain on demand, including non-contiguous files."""
    if size_bytes == 0:
        return
    remaining = size_bytes
    with image.open("rb") as source:
        scanner = _Fat32Scanner(source, volume, [], [])
        for cluster in scanner.chain(first_cluster):
            source.seek(volume.cluster_offset(cluster))
            chunk = source.read(min(remaining, volume.cluster_bytes))
            if not chunk:
                raise ValueError("The active file is truncated")
            remaining -= len(chunk)
            yield chunk
            if remaining == 0:
                return
    raise ValueError("The active FAT chain is shorter than its file size")


class _Fat32Scanner:
    def __init__(
        self,
        source: BinaryIO,
        volume: Fat32Volume,
        artifacts: list[ParsedArtifact],
        issues: list[str],
    ) -> None:
        self.source = source
        self.volume = volume
        self.artifacts = artifacts
        self.issues = issues
        self.visited_directories: set[int] = set()
        self.hash_bytes_remaining = MAX_TOTAL_HASH_BYTES

    def fat(self, cluster: int) -> int:
        if not 2 <= cluster < self.volume.cluster_count + 2:
            raise ValueError("FAT cluster is outside the volume")
        self.source.seek(self.volume.fat_offset + cluster * 4)
        value = self.source.read(4)
        if len(value) != 4:
            raise ValueError("FAT entry is truncated")
        return int.from_bytes(value, "little") & 0x0FFFFFFF

    def chain(self, start: int) -> Iterator[int]:
        seen: set[int] = set()
        cluster = start
        while 2 <= cluster < self.volume.cluster_count + 2:
            if cluster in seen:
                raise ValueError("FAT cluster chain contains a loop")
            seen.add(cluster)
            yield cluster
            following = self.fat(cluster)
            if following >= 0x0FFFFFF8:
                return
            if following in {0, 1, 0x0FFFFFF7}:
                raise ValueError("FAT cluster chain terminates early")
            cluster = following
        raise ValueError("FAT cluster chain leaves the volume")

    def walk(self, start: int, prefix: str, *, depth: int) -> None:
        if depth > MAX_DIRECTORY_DEPTH or start in self.visited_directories:
            self.issues.append(f"Directory traversal limit or loop at cluster {start}")
            return
        self.visited_directories.add(start)
        lfn: list[tuple[int, str, int]] = []
        try:
            for cluster in self.chain(start):
                self.source.seek(self.volume.cluster_offset(cluster))
                directory = self.source.read(self.volume.cluster_bytes)
                for index in range(0, len(directory), 32):
                    if len(self.artifacts) >= MAX_ENTRIES:
                        self.issues.append("Directory-entry limit reached")
                        return
                    entry = directory[index : index + 32]
                    if len(entry) < 32 or entry[0] == 0:
                        return
                    attr = entry[11]
                    if attr == 0x0F:
                        if entry[0] != 0xE5:
                            lfn.append((entry[0] & 0x1F, _lfn_piece(entry), entry[13]))
                        continue
                    if attr & 0x08:
                        lfn.clear()
                        continue
                    deleted = entry[0] == 0xE5
                    short_name = _short_name(entry[:11], deleted=deleted)
                    long_name = _lfn_name(lfn, entry[:11]) if not deleted else None
                    lfn.clear()
                    name = long_name or short_name
                    if not name or name in {".", ".."}:
                        continue
                    logical_path = f"{prefix}/{name}" if prefix else name
                    first_cluster = (int.from_bytes(entry[20:22], "little") << 16) | int.from_bytes(
                        entry[26:28], "little"
                    )
                    size = int.from_bytes(entry[28:32], "little")
                    is_directory = bool(attr & 0x10)
                    metadata: dict[str, object] = {
                        "path": logical_path,
                        "first_cluster": first_cluster,
                        "size_bytes": size,
                        "directory_entry_offset": self.volume.cluster_offset(cluster) + index,
                        "partition_offset_bytes": self.volume.offset,
                        "fat_attributes": attr,
                        "modified_local_dos_date": int.from_bytes(entry[24:26], "little"),
                        "modified_local_dos_time": int.from_bytes(entry[22:24], "little"),
                    }
                    if deleted:
                        self._deleted(logical_path, first_cluster, size, is_directory, metadata)
                    elif is_directory:
                        self.artifacts.append(
                            _artifact(
                                "memory_card_directory",
                                logical_path,
                                metadata,
                                status="active",
                                confidence="high",
                            )
                        )
                        if first_cluster >= 2:
                            self.walk(first_cluster, logical_path, depth=depth + 1)
                    else:
                        self._file(logical_path, first_cluster, size, metadata)
        except ValueError as error:
            self.issues.append(f"{prefix or '/'}: {error}")

    def _file(self, name: str, cluster: int, size: int, metadata: dict[str, object]) -> None:
        if size == 0:
            metadata["sha256"] = sha256(b"").hexdigest()
            metadata["hash_status"] = "complete"
        elif size > MAX_HASH_BYTES:
            metadata["sha256"] = None
            metadata["hash_status"] = "size_limit"
        elif size > self.hash_bytes_remaining:
            metadata["sha256"] = None
            metadata["hash_status"] = "aggregate_hash_limit"
        else:
            self.hash_bytes_remaining -= size
            try:
                digest = sha256()
                remaining = size
                for item in self.chain(cluster):
                    self.source.seek(self.volume.cluster_offset(item))
                    chunk = self.source.read(min(remaining, self.volume.cluster_bytes))
                    if len(chunk) == 0:
                        raise ValueError("File content is truncated")
                    digest.update(chunk)
                    remaining -= len(chunk)
                    if remaining == 0:
                        break
                if remaining:
                    raise ValueError("File cluster chain is shorter than its size")
                metadata["sha256"] = digest.hexdigest()
                metadata["hash_status"] = "complete"
            except ValueError as error:
                metadata["sha256"] = None
                metadata["hash_status"] = "unreadable"
                self.issues.append(f"{name}: {error}")
        self.artifacts.append(
            _artifact(
                "memory_card_file",
                name,
                metadata,
                status="active" if metadata["hash_status"] == "complete" else "partial",
                confidence="high" if metadata["hash_status"] == "complete" else "medium",
            )
        )

    def _deleted(
        self, name: str, cluster: int, size: int, is_directory: bool, metadata: dict[str, object]
    ) -> None:
        metadata["recovery_status"] = "directory_entry_only"
        metadata["candidate_sha256"] = None
        if (
            not is_directory
            and 0 < size <= MAX_HASH_BYTES
            and size <= self.hash_bytes_remaining
            and cluster >= 2
        ):
            needed = math.ceil(size / self.volume.cluster_bytes)
            if cluster + needed <= self.volume.cluster_count + 2:
                try:
                    if all(self.fat(item) == 0 for item in range(cluster, cluster + needed)):
                        self.hash_bytes_remaining -= size
                        digest = sha256()
                        remaining = size
                        for item in range(cluster, cluster + needed):
                            self.source.seek(self.volume.cluster_offset(item))
                            chunk = self.source.read(min(remaining, self.volume.cluster_bytes))
                            if not chunk:
                                raise ValueError("Candidate content is truncated")
                            digest.update(chunk)
                            remaining -= len(chunk)
                        if remaining == 0:
                            metadata["candidate_sha256"] = digest.hexdigest()
                            metadata["recovery_status"] = "contiguous_unallocated_candidate"
                            metadata["candidate_byte_count"] = size
                except ValueError as error:
                    self.issues.append(f"{name}: {error}")
        self.artifacts.append(
            _artifact(
                "memory_card_deleted_candidate",
                name,
                metadata,
                status="deleted",
                confidence="medium" if metadata["candidate_sha256"] else "low",
            )
        )


def _artifact(
    subtype: str,
    name: str,
    metadata: dict[str, object],
    *,
    status: Literal["active", "deleted", "partial"],
    confidence: Literal["high", "medium", "low"],
) -> ParsedArtifact:
    return ParsedArtifact(
        category="file",
        subtype=subtype,
        title=Path(name).name[:500],
        summary=name[:2000],
        event_time=None,
        source_locator=name[:2000],
        status=status,
        confidence=confidence,
        metadata=metadata,
    )


def _short_name(value: bytes, *, deleted: bool) -> str:
    stem = value[:8].decode("cp437", errors="replace").rstrip()
    extension = value[8:11].decode("cp437", errors="replace").rstrip()
    if deleted:
        stem = "?" + stem[1:]
    elif stem.startswith("\x05"):
        stem = "å" + stem[1:]
    return f"{stem}.{extension}" if extension else stem


def _lfn_piece(entry: bytes) -> str:
    data = entry[1:11] + entry[14:26] + entry[28:32]
    return data.decode("utf-16-le", errors="replace").split("\x00", 1)[0].rstrip("\uffff")


def _lfn_name(parts: list[tuple[int, str, int]], short: bytes) -> str | None:
    if not parts:
        return None
    checksum = 0
    for byte in short:
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) + byte
        checksum &= 0xFF
    indexes = sorted(index for index, _, _ in parts)
    if indexes != list(range(1, len(parts) + 1)) or any(item[2] != checksum for item in parts):
        return None
    name = "".join(piece for _, piece, _ in sorted(parts))
    return name if name and "/" not in name and "\\" not in name else None
