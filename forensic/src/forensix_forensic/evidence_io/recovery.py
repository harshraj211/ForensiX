"""Metadata-only SQLite recovery readiness probes with no row carving claims."""

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGICS = {b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83"}
ROLLBACK_JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"
RECOVERY_PROBE_VERSION = "1.0.0"

RecoveryKind = Literal["sqlite_database", "sqlite_wal", "sqlite_rollback_journal", "unknown"]
RecoveryStatus = Literal[
    "candidate_regions_observed", "no_candidate_regions", "malformed", "unsupported"
]


@dataclass(frozen=True, slots=True)
class RecoveryCandidate:
    source_locator: str
    source_kind: RecoveryKind
    status: RecoveryStatus
    confidence: Literal["medium", "low"]
    page_size_bytes: int | None
    candidate_region_count: int
    source_size_bytes: int
    metadata: dict[str, str | int | bool | None]
    limitations: tuple[str, ...]

    @property
    def canonical_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(asdict(self))).hexdigest()


def assess_sqlite_recovery_file(path: Path, source_locator: str) -> RecoveryCandidate:
    """Read bounded headers only; never mutate, carve rows, or label data recovered."""
    if not source_locator or len(source_locator) > 2048:
        raise ValueError("Source locator is invalid.")
    source = path.expanduser().resolve()
    if source.is_symlink() or not source.is_file():
        raise ValueError("Recovery assessment requires a regular file.")
    size = source.stat().st_size
    with source.open("rb") as stream:
        header = stream.read(100)
    if header.startswith(SQLITE_MAGIC):
        return _assess_database(header, size, source_locator)
    if header[:4] in WAL_MAGICS:
        return _assess_wal(header, size, source_locator)
    if header.startswith(ROLLBACK_JOURNAL_MAGIC):
        return _assess_journal(header, size, source_locator)
    return RecoveryCandidate(
        source_locator=source_locator,
        source_kind="unknown",
        status="unsupported",
        confidence="low",
        page_size_bytes=None,
        candidate_region_count=0,
        source_size_bytes=size,
        metadata={"header_sample_sha256": hashlib.sha256(header).hexdigest()},
        limitations=(
            "No supported SQLite database, WAL, or rollback-journal signature was found.",
        ),
    )


def _assess_database(header: bytes, size: int, locator: str) -> RecoveryCandidate:
    if len(header) < 100:
        return _malformed(locator, "sqlite_database", size, "SQLite header is truncated.")
    page_size = _page_size(int.from_bytes(header[16:18], "big"))
    if page_size is None:
        return _malformed(locator, "sqlite_database", size, "SQLite page size is invalid.")
    database_pages = int.from_bytes(header[28:32], "big")
    first_freelist_trunk = int.from_bytes(header[32:36], "big")
    freelist_pages = int.from_bytes(header[36:40], "big")
    return RecoveryCandidate(
        source_locator=locator,
        source_kind="sqlite_database",
        status=("candidate_regions_observed" if freelist_pages else "no_candidate_regions"),
        confidence="medium",
        page_size_bytes=page_size,
        candidate_region_count=freelist_pages,
        source_size_bytes=size,
        metadata={
            "database_page_count_header": database_pages,
            "first_freelist_trunk_page": first_freelist_trunk,
            "freelist_page_count_header": freelist_pages,
        },
        limitations=(
            "Freelist pages are reuse candidates; they do not prove deleted records exist.",
            "No cell content was carved or interpreted by this metadata-only probe.",
        ),
    )


def _assess_wal(header: bytes, size: int, locator: str) -> RecoveryCandidate:
    if len(header) < 32:
        return _malformed(locator, "sqlite_wal", size, "SQLite WAL header is truncated.")
    page_size = _page_size(int.from_bytes(header[8:12], "big"))
    if page_size is None:
        return _malformed(locator, "sqlite_wal", size, "SQLite WAL page size is invalid.")
    frame_size = 24 + page_size
    payload_size = max(0, size - 32)
    frame_count, trailing = divmod(payload_size, frame_size)
    return RecoveryCandidate(
        source_locator=locator,
        source_kind="sqlite_wal",
        status="candidate_regions_observed" if frame_count else "no_candidate_regions",
        confidence="medium" if trailing == 0 else "low",
        page_size_bytes=page_size,
        candidate_region_count=frame_count,
        source_size_bytes=size,
        metadata={
            "format_version": int.from_bytes(header[4:8], "big"),
            "complete_frame_count": frame_count,
            "trailing_bytes": trailing,
            "checksum_byte_order": (
                "little_endian" if header[:4] == b"\x37\x7f\x06\x82" else "big_endian"
            ),
        },
        limitations=(
            "WAL frames may contain current, superseded, or uncommitted pages; "
            "none are labeled deleted.",
            "Frame and database checksums require a later validated reconstruction stage.",
        ),
    )


def _assess_journal(header: bytes, size: int, locator: str) -> RecoveryCandidate:
    if len(header) < 28:
        return _malformed(
            locator, "sqlite_rollback_journal", size, "SQLite rollback-journal header is truncated."
        )
    page_size = _page_size(int.from_bytes(header[24:28], "big"))
    declared_pages = int.from_bytes(header[8:12], "big")
    valid_page_size = page_size is not None
    return RecoveryCandidate(
        source_locator=locator,
        source_kind="sqlite_rollback_journal",
        status="candidate_regions_observed" if valid_page_size and size > 28 else "malformed",
        confidence="low",
        page_size_bytes=page_size,
        candidate_region_count=(0 if declared_pages == 0xFFFFFFFF else declared_pages),
        source_size_bytes=size,
        metadata={
            "declared_record_count": "unknown" if declared_pages == 0xFFFFFFFF else declared_pages,
            "initial_database_page_count": int.from_bytes(header[16:20], "big"),
            "sector_size_bytes": int.from_bytes(header[20:24], "big"),
        },
        limitations=(
            "A rollback journal is a transaction artifact, not proof of user-deleted records.",
            "Page records and checksums were not reconstructed by this metadata-only probe.",
        ),
    )


def _malformed(
    locator: str,
    kind: RecoveryKind,
    size: int,
    reason: str,
) -> RecoveryCandidate:
    return RecoveryCandidate(
        source_locator=locator,
        source_kind=kind,
        status="malformed",
        confidence="low",
        page_size_bytes=None,
        candidate_region_count=0,
        source_size_bytes=size,
        metadata={},
        limitations=(reason, "Malformed input was not repaired or opened with recovery flags."),
    )


def _page_size(value: int) -> int | None:
    normalized = 65536 if value == 1 else value
    if 512 <= normalized <= 65536 and normalized & (normalized - 1) == 0:
        return normalized
    return None


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
