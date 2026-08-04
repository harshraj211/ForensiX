"""SQLite Carver for recovering deleted message fragments from WhatsApp databases.

When a message is deleted in WhatsApp, SQLite does not immediately erase the
text bytes from the underlying storage.  Deleted content persists in:

* **Write-Ahead Log (WAL) frames** - Recent changes (including deletions) are
  logged in the ``-wal`` file until a checkpoint occurs.  Fragments often sit
  in uncommitted or superseded WAL frames.

* **Freelists** - After checkpointing, freed pages are marked as reusable but
  their byte content remains until overwritten by new data.

* **Unallocated regions** - Raw byte ranges that SQLite considers available
  for reuse but that have not yet been zeroed or overwritten.

The carver scans the raw binary of ``.db``, ``-wal``, and ``-journal`` files
for SQLite record fragments that look like WhatsApp message payloads.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGICS = {b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83"}

# WhatsApp message types observed in the wild.
MESSAGE_TYPE_TEXT = 0
MESSAGE_TYPE_IMAGE = 1
MESSAGE_TYPE_AUDIO = 2
MESSAGE_TYPE_VIDEO = 3
MESSAGE_TYPE_DOCUMENT = 4
MESSAGE_TYPE_STICKER = 5
MESSAGE_TYPE_LOCATION = 6
MESSAGE_TYPE_CONTACT = 7
MESSAGE_TYPE_SYSTEM = 8

# Patterns commonly found in WhatsApp message payloads.
# These help identify potential message fragments in raw binary data.
_TEXT_UTF8_PATTERN = re.compile(
    rb"(?:(?:\xe2\x80[\x80-\x9f]|[\x20-\x7e\xc0-\xfd]){4,200})"
)
_PHONE_PATTERN = re.compile(rb"\+?\d{7,15}")
_URL_PATTERN = re.compile(rb"https?://[\x20-\x7e]{10,200}")

CARVING_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class CarvedFragment:
    """A single recovered message fragment from unallocated space."""

    source_file: str
    offset_bytes: int
    length_bytes: int
    fragment_type: str
    confidence: Literal["high", "medium", "low"]
    content_preview: str
    content_sha256: str
    metadata: dict[str, str | int | bool | None]


@dataclass(frozen=True, slots=True)
class CarvingResult:
    """Outcome of a SQLite carving pass over one or more database files."""

    carving_id: str
    source_files: list[str]
    source_total_bytes: int
    fragments_found: int
    fragments: tuple[CarvedFragment, ...]
    wal_fragments_found: int
    freelist_fragments_found: int
    unallocated_fragments_found: int
    duration_seconds: float
    limitations: tuple[str, ...]

    @property
    def canonical_sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(
                asdict(self),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()


class SQLiteCarver:
    """Scan raw SQLite database files for recoverable message fragments.

    The carver operates in three phases:

    1. **WAL frame carving** - Scan WAL files for superseded or uncommitted
       frames that may contain deleted message text.
    2. **Freelist page carving** - Parse the database freelist to identify
       pages marked as free but still containing message content.
    3. **Unallocated-region carving** - Scan the raw binary for byte sequences
       that match known WhatsApp message patterns (UTF-8 text runs, phone
       numbers, URLs).
    """

    def carve(
        self,
        source_paths: list[Path],
        *,
        max_fragments: int = 10_000,
    ) -> CarvingResult:
        """Carve deleted message fragments from one or more SQLite files."""
        carving_id = (
            f"carve_{int(time.time())}_"
            f"{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:8]}"
        )
        started = time.monotonic()
        fragments: list[CarvedFragment] = []
        source_total = 0
        wal_count = 0
        freelist_count = 0
        unallocated_count = 0

        for path in source_paths:
            if not path.exists() or not path.is_file():
                continue
            source_total += path.stat().st_size

            # Phase 1: WAL frame carving
            wal_path = Path(str(path) + "-wal")
            if wal_path.exists():
                wal_frags = self._carve_wal(wal_path, max_fragments - len(fragments))
                fragments.extend(wal_frags)
                wal_count += len(wal_frags)

            # Phase 2: Freelist page carving
            if self._is_sqlite_database(path):
                fl_frags = self._carve_freelist(path, max_fragments - len(fragments))
                fragments.extend(fl_frags)
                freelist_count += len(fl_frags)

            # Phase 3: Unallocated-region carving
            unalloc_frags = self._carve_unallocated(path, max_fragments - len(fragments))
            fragments.extend(unalloc_frags)
            unallocated_count += len(unalloc_frags)

        elapsed = time.monotonic() - started

        return CarvingResult(
            carving_id=carving_id,
            source_files=[str(p) for p in source_paths],
            source_total_bytes=source_total,
            fragments_found=len(fragments),
            fragments=tuple(fragments),
            wal_fragments_found=wal_count,
            freelist_fragments_found=freelist_count,
            unallocated_fragments_found=unallocated_count,
            duration_seconds=elapsed,
            limitations=(
                "Carved fragments are raw byte sequences; they do not prove "
                "the bytes were user-authored messages.",
                "UTF-8 text runs may be false positives from other application data.",
                "WAL frames may contain current (non-deleted) data interspersed "
                "with deleted content.",
                "Freelist pages are reuse candidates; content may have been "
                "partially overwritten.",
            ),
        )

    # ------------------------------------------------------------------
    # Phase 1: WAL frame carving
    # ------------------------------------------------------------------

    def _carve_wal(self, wal_path: Path, budget: int) -> list[CarvedFragment]:
        """Scan WAL frames for superseded message content."""
        fragments: list[CarvedFragment] = []
        try:
            data = wal_path.read_bytes()
        except OSError:
            return fragments

        if len(data) < 32:
            return fragments

        page_size = self._wal_page_size(data)
        if page_size is None or page_size < 512:
            return fragments

        frame_size = 24 + page_size
        wal_header_size = 32

        # Parse WAL frames.
        offset = wal_header_size
        frame_index = 0
        while offset + frame_size <= len(data) and len(fragments) < budget:

            page_data = data[offset + 24 : offset + 24 + page_size]

            # Scan the page data for message-like content.
            text_fragments = self._extract_text_fragments(
                page_data, str(wal_path), offset + 24, "wal_frame"
            )
            for frag in text_fragments:
                if len(fragments) < budget:
                    fragments.append(frag)

            offset += frame_size
            frame_index += 1

        return fragments

    # ------------------------------------------------------------------
    # Phase 2: Freelist carving
    # ------------------------------------------------------------------

    def _carve_freelist(self, db_path: Path, budget: int) -> list[CarvedFragment]:
        """Parse the SQLite freelist and scan free pages for message content."""
        fragments: list[CarvedFragment] = []
        try:
            with db_path.open("rb") as fh:
                header = fh.read(100)
        except OSError:
            return fragments

        if not header.startswith(SQLITE_MAGIC) or len(header) < 100:
            return fragments

        page_size = self._sqlite_page_size(header)
        if page_size is None or page_size < 512:
            return fragments

        freelist_pages = struct.unpack(">I", header[36:40])[0]
        if freelist_pages == 0:
            return fragments

        try:
            with db_path.open("rb") as fh:
                for page_idx in range(min(freelist_pages, 1000)):
                    if len(fragments) >= budget:
                        break
                    # Freelist trunk page contains pointers to leaf pages.
                    trunk_offset = 100 + (page_idx * page_size) if page_idx == 0 else None
                    if trunk_offset is None:
                        break
                    fh.seek(trunk_offset)
                    trunk_data = fh.read(page_size)
                    if len(trunk_data) < 8:
                        break

                    leaf_count = struct.unpack(">I", trunk_data[0:4])[0]
                    if leaf_count > 100_000:
                        break  # Sanity check

                    for leaf_idx in range(min(leaf_count, 100)):
                        if len(fragments) >= budget:
                            break
                        if 4 + leaf_idx * 4 + 4 > len(trunk_data):
                            break
                        leaf_page_no = struct.unpack(
                            ">I", trunk_data[4 + leaf_idx * 4 : 8 + leaf_idx * 4]
                        )[0]
                        if leaf_page_no < 1:
                            break

                        leaf_offset = (leaf_page_no - 1) * page_size
                        fh.seek(leaf_offset)
                        leaf_data = fh.read(page_size)
                        if len(leaf_data) < 16:
                            continue

                        text_fragments = self._extract_text_fragments(
                            leaf_data, str(db_path), leaf_offset, "freelist"
                        )
                        for frag in text_fragments:
                            if len(fragments) < budget:
                                fragments.append(frag)

        except OSError:
            pass

        return fragments

    # ------------------------------------------------------------------
    # Phase 3: Unallocated-region carving
    # ------------------------------------------------------------------

    def _carve_unallocated(self, path: Path, budget: int) -> list[CarvedFragment]:
        """Scan raw binary for byte sequences matching WhatsApp message patterns."""
        fragments: list[CarvedFragment] = []
        try:
            data = path.read_bytes()
        except OSError:
            return fragments

        # Scan for UTF-8 text runs.
        for match in _TEXT_UTF8_PATTERN.finditer(data):
            if len(fragments) >= budget:
                break
            text_bytes = match.group()
            try:
                text = text_bytes.decode("utf-8", errors="strict")
            except (UnicodeDecodeError, ValueError):
                continue

            # Filter: only keep text that looks message-like.
            if not self._looks_like_message(text):
                continue

            content_hash = hashlib.sha256(text_bytes).hexdigest()
            confidence = self._classify_confidence(text)

            fragments.append(CarvedFragment(
                source_file=path.name,
                offset_bytes=match.start(),
                length_bytes=len(text_bytes),
                fragment_type="utf8_text_run",
                confidence=confidence,
                content_preview=text[:200],
                content_sha256=content_hash,
                metadata={
                    "encoding": "utf-8",
                    "text_length": len(text),
                },
            ))

        # Scan for phone numbers.
        for match in _PHONE_PATTERN.finditer(data):
            if len(fragments) >= budget:
                break
            phone_bytes = match.group()
            content_hash = hashlib.sha256(phone_bytes).hexdigest()
            fragments.append(CarvedFragment(
                source_file=path.name,
                offset_bytes=match.start(),
                length_bytes=len(phone_bytes),
                fragment_type="phone_number",
                confidence="medium",
                content_preview=phone_bytes.decode("latin-1", errors="replace"),
                content_sha256=content_hash,
                metadata={"pattern": "phone_number"},
            ))

        # Scan for URLs.
        for match in _URL_PATTERN.finditer(data):
            if len(fragments) >= budget:
                break
            url_bytes = match.group()
            content_hash = hashlib.sha256(url_bytes).hexdigest()
            fragments.append(CarvedFragment(
                source_file=path.name,
                offset_bytes=match.start(),
                length_bytes=len(url_bytes),
                fragment_type="url",
                confidence="medium",
                content_preview=url_bytes.decode("ascii", errors="replace"),
                content_sha256=content_hash,
                metadata={"pattern": "url"},
            ))

        return fragments

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_text_fragments(
        self,
        page_data: bytes,
        source_name: str,
        base_offset: int,
        region_type: str,
    ) -> list[CarvedFragment]:
        """Extract message-like text fragments from a raw page."""
        fragments: list[CarvedFragment] = []
        for match in _TEXT_UTF8_PATTERN.finditer(page_data):
            text_bytes = match.group()
            try:
                text = text_bytes.decode("utf-8", errors="strict")
            except (UnicodeDecodeError, ValueError):
                continue

            if not self._looks_like_message(text):
                continue

            content_hash = hashlib.sha256(text_bytes).hexdigest()
            confidence = self._classify_confidence(text)

            fragments.append(CarvedFragment(
                source_file=source_name,
                offset_bytes=base_offset + match.start(),
                length_bytes=len(text_bytes),
                fragment_type=f"{region_type}_text",
                confidence=confidence,
                content_preview=text[:200],
                content_sha256=content_hash,
                metadata={
                    "region_type": region_type,
                    "encoding": "utf-8",
                    "text_length": len(text),
                },
            ))
        return fragments

    @staticmethod
    def _is_sqlite_database(path: Path) -> bool:
        try:
            with path.open("rb") as fh:
                return fh.read(16) == SQLITE_MAGIC
        except OSError:
            return False

    @staticmethod
    def _sqlite_page_size(header: bytes) -> int | None:
        raw = struct.unpack(">H", header[16:18])[0]
        if raw == 1:
            return 65536
        if 512 <= raw <= 65536 and raw & (raw - 1) == 0:
            return int(raw)
        return None

    @staticmethod
    def _wal_page_size(wal_header: bytes) -> int | None:
        if len(wal_header) < 12:
            return None
        raw = struct.unpack(">I", wal_header[8:12])[0]
        if 512 <= raw <= 65536 and raw & (raw - 1) == 0:
            return int(raw)
        return None

    @staticmethod
    def _looks_like_message(text: str) -> bool:
        """Heuristic: does this text fragment look like a chat message?"""
        stripped = text.strip()
        if len(stripped) < 4:
            return False
        if len(stripped) > 5000:
            return False
        # Must contain mostly printable characters.
        printable = sum(1 for c in stripped if c.isprintable() or c in "\n\t")
        if printable / max(len(stripped), 1) < 0.8:
            return False
        lower = stripped.lower()
        return not lower.startswith(
            ("sqlite format 3", "create ", "insert ", "select ", "pragma ", "<?xml")
        )

    @staticmethod
    def _classify_confidence(text: str) -> Literal["high", "medium", "low"]:
        """Classify confidence based on message-like heuristics."""
        stripped = text.strip()
        # Phone numbers and URLs are medium confidence.
        if re.fullmatch(r"\+?\d{7,15}", stripped):
            return "medium"
        if re.fullmatch(r"https?://[\x20-\x7e]{10,200}", stripped):
            return "medium"
        # Messages with common WhatsApp patterns get high confidence.
        if any(marker in stripped for marker in ("@s.whatsapp.net", "WhatsApp",)):
            return "high"
        # Messages with mixed alphanumeric content are medium.
        has_alpha = any(c.isalpha() for c in stripped)
        has_digit = any(c.isdigit() for c in stripped)
        if has_alpha and has_digit:
            return "medium"
        return "low"
