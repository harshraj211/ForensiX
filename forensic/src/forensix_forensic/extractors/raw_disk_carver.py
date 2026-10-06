"""Read-only signature carving of verified raw image working copies.

This scans the whole image; filesystem allocation state is not inferred. Candidates
are emitted only after image decoding succeeds, with hashes of their exact bytes.
"""

from __future__ import annotations

import io
import time
from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError

from forensix_forensic.evidence_io import ParsedArtifact, ParserContext, ParserMetadata

_CHUNK_BYTES = 1024 * 1024
_MAX_CANDIDATE_BYTES = 32 * 1024 * 1024
_MAX_IMAGE_PIXELS = 64_000_000
_MAX_FINDINGS = 1000
_SIGNATURES = ((b"\xff\xd8\xff", "jpeg"), (b"\x89PNG\r\n\x1a\n", "png"))
RAW_IMAGE_SIGNATURE_PARSER_ID = "raw_image.signature_carve.v1"


@dataclass(frozen=True, slots=True)
class CarvedMediaItem:
    file_type: str
    offset_bytes: int
    size_bytes: int
    sha256_hash: str
    has_gps: bool
    latitude: float | None
    longitude: float | None
    camera_model: str | None


@dataclass(frozen=True, slots=True)
class RawDiskCarveResult:
    carved_media_items: list[CarvedMediaItem]
    total_carved_files: int
    total_bytes_carved: int
    gps_locations_plotted_count: int
    scanned_bytes: int
    truncated: bool
    duration_seconds: float


class RawDiskCarver:
    """Find decodable JPEG and PNG payloads without modifying the source image."""

    def carve_image(self, image_path: Path) -> RawDiskCarveResult:
        started = time.monotonic()
        size = image_path.stat().st_size
        findings: list[CarvedMediaItem] = []
        scanned = 0
        skip_until = 0
        with image_path.open("rb") as image:
            while scanned < size and len(findings) < _MAX_FINDINGS:
                image.seek(scanned)
                block = image.read(min(_CHUNK_BYTES, size - scanned))
                if not block:
                    break
                # Carry seven bytes so a signature split at a chunk boundary is found.
                search = block + image.read(min(7, size - scanned - len(block)))
                candidates = sorted(
                    (scanned + index, kind)
                    for signature, kind in _SIGNATURES
                    for index in _find_all(search, signature, len(block))
                )
                for offset, kind in candidates:
                    if offset < skip_until:
                        continue
                    image.seek(offset)
                    candidate = image.read(min(_MAX_CANDIDATE_BYTES, size - offset))
                    payload = (
                        _jpeg_payload(candidate) if kind == "jpeg" else _png_payload(candidate)
                    )
                    if payload is None:
                        continue
                    metadata = _image_metadata(payload)
                    if metadata is None:
                        continue
                    latitude, longitude, camera = metadata
                    findings.append(
                        CarvedMediaItem(
                            file_type=kind,
                            offset_bytes=offset,
                            size_bytes=len(payload),
                            sha256_hash=sha256(payload).hexdigest(),
                            has_gps=latitude is not None and longitude is not None,
                            latitude=latitude,
                            longitude=longitude,
                            camera_model=camera,
                        )
                    )
                    skip_until = offset + len(payload)
                    if len(findings) >= _MAX_FINDINGS:
                        break
                scanned += len(block)
        return RawDiskCarveResult(
            carved_media_items=findings,
            total_carved_files=len(findings),
            total_bytes_carved=sum(item.size_bytes for item in findings),
            gps_locations_plotted_count=sum(item.has_gps for item in findings),
            scanned_bytes=min(scanned, size),
            truncated=scanned < size or len(findings) >= _MAX_FINDINGS,
            duration_seconds=round(time.monotonic() - started, 3),
        )


class RawImageSignatureParser:
    """Store scanner findings as versioned evidence-source artifacts."""

    metadata = ParserMetadata(
        parser_id=RAW_IMAGE_SIGNATURE_PARSER_ID,
        name="Raw image JPEG/PNG signature scanner",
        version="1.0.0",
        artifact_categories=("system", "file"),
        required_tables=frozenset(),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=(".img", ".dd", ".raw"),
        supported_artifact_types=("raw_image_scan_summary", "raw_image_media_candidate"),
        description="Finds decodable JPEG/PNG byte ranges; allocation and deletion state are unknown.",
        input_formats=("img", "dd", "raw"),
    )

    def can_parse(self, source_locator: str) -> bool:
        return Path(source_locator).suffix.casefold() in {".img", ".dd", ".raw"}

    def parse(self, path: Path, context: ParserContext) -> list[ParsedArtifact]:
        result = RawDiskCarver().carve_image(path)
        summary = ParsedArtifact(
            category="system",
            subtype="raw_image_scan_summary",
            title="Raw image signature scan",
            summary=f"{result.total_carved_files} decodable JPEG/PNG byte ranges found",
            event_time=None,
            source_locator="image#signature-scan",
            status="partial" if result.truncated else "active",
            confidence="high",
            metadata={
                "scanned_bytes": result.scanned_bytes,
                "truncated": result.truncated,
                "duration_seconds": result.duration_seconds,
                "candidate_count": result.total_carved_files,
                "source_sha256": context.source_sha256,
                "allocation_state": "unknown",
            },
        )
        findings = [
            ParsedArtifact(
                category="file",
                subtype="raw_image_media_candidate",
                title=f"{item.file_type.upper()} bytes at offset {item.offset_bytes}",
                summary=f"Decodable {item.file_type.upper()} byte range; allocation and deletion state unknown",
                event_time=None,
                source_locator=f"image@{item.offset_bytes}:{item.size_bytes}",
                status="unverified",
                confidence="medium",
                metadata={
                    "file_type": item.file_type,
                    "offset_bytes": item.offset_bytes,
                    "size_bytes": item.size_bytes,
                    "sha256_hash": item.sha256_hash,
                    "has_gps": item.has_gps,
                    "latitude": item.latitude,
                    "longitude": item.longitude,
                    "camera_model": item.camera_model,
                    "allocation_state": "unknown",
                },
            )
            for item in result.carved_media_items
        ]
        return [summary, *findings]


def _find_all(buffer: bytes, signature: bytes, limit: int) -> Iterator[int]:
    start = 0
    while (index := buffer.find(signature, start)) != -1 and index < limit:
        yield index
        start = index + 1


def _jpeg_payload(candidate: bytes) -> bytes | None:
    if not candidate.startswith(b"\xff\xd8\xff"):
        return None
    # Search for a decodable EOI; Pillow rejects incomplete and malformed candidates.
    end = candidate.find(b"\xff\xd9", 3)
    while end >= 0:
        payload = candidate[: end + 2]
        if _image_metadata(payload) is not None:
            return payload
        end = candidate.find(b"\xff\xd9", end + 2)
    return None


def _png_payload(candidate: bytes) -> bytes | None:
    if not candidate.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    cursor = 8
    while cursor + 12 <= len(candidate):
        length = int.from_bytes(candidate[cursor : cursor + 4], "big")
        end = cursor + 12 + length
        if end > len(candidate):
            return None
        chunk_type = candidate[cursor + 4 : cursor + 8]
        if chunk_type == b"IEND":
            return candidate[:end] if length == 0 else None
        cursor = end
    return None


def _image_metadata(payload: bytes) -> tuple[float | None, float | None, str | None] | None:
    try:
        with Image.open(io.BytesIO(payload)) as image:
            if image.width * image.height > _MAX_IMAGE_PIXELS:
                return None
            image.verify()
        with Image.open(io.BytesIO(payload)) as image:
            image.load()
            exif = image.getexif()
            model = exif.get(272)
            gps = exif.get_ifd(34853)
            latitude = _coordinate(gps, 2, 1)
            longitude = _coordinate(gps, 4, 3)
            return latitude, longitude, str(model)[:255] if model else None
    except (OSError, ValueError, TypeError, UnidentifiedImageError):
        return None


def _coordinate(gps: dict[int, Any], value_key: int, ref_key: int) -> float | None:
    values = gps.get(value_key)
    ref = gps.get(ref_key)
    if not values or len(values) != 3 or ref not in ("N", "S", "E", "W"):
        return None
    try:
        result = float(values[0]) + float(values[1]) / 60 + float(values[2]) / 3600
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    if result < 0 or result > (90 if ref in ("N", "S") else 180):
        return None
    return -result if ref in ("S", "W") else result


def verified_candidate(image_path: Path, *, offset: int, size: int, expected_sha256: str) -> None:
    """Recheck a candidate's exact bytes before a download begins."""
    if offset < 0 or not 0 < size <= _MAX_CANDIDATE_BYTES or len(expected_sha256) != 64:
        raise ValueError("The candidate byte range is invalid")
    if offset + size > image_path.stat().st_size:
        raise ValueError("The candidate extends past the working copy")
    digest = sha256()
    with image_path.open("rb") as image:
        image.seek(offset)
        remaining = size
        while remaining:
            chunk = image.read(min(_CHUNK_BYTES, remaining))
            if not chunk:
                raise ValueError("The candidate byte range is truncated")
            digest.update(chunk)
            remaining -= len(chunk)
    if digest.hexdigest() != expected_sha256:
        raise ValueError("The candidate content hash no longer matches")


def iter_candidate(image_path: Path, *, offset: int, size: int) -> Iterator[bytes]:
    with image_path.open("rb") as image:
        image.seek(offset)
        remaining = size
        while remaining:
            chunk = image.read(min(_CHUNK_BYTES, remaining))
            if not chunk:
                raise ValueError("The candidate byte range is truncated")
            yield chunk
            remaining -= len(chunk)
