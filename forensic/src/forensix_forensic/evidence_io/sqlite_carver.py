"""Pure-Python SQLite B-Tree Freeblock, Slack Space, and Unallocated Page Carver.

Reconstructs deleted database rows directly from SQLite leaf table pages (0x0D),
following freeblock chains and scanning unallocated page space for intact SQLite
record format headers ([header_len, serial_type_1, serial_type_2, ...]).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SQLITE_MAGIC = b"SQLite format 3\x00"
LEAF_TABLE_PAGE = 0x0D


@dataclass(frozen=True, slots=True)
class CarvedSQLiteRecord:
    page_number: int
    offset_in_page: int
    rowid: int | None
    columns: tuple[Any, ...]
    source_locator: str
    confidence: str


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a variable-length integer (varint) from bytes.

    Returns (value, bytes_consumed).
    """
    result = 0
    bytes_consumed = 0
    for i in range(9):
        if offset + i >= len(data):
            break
        byte = data[offset + i]
        bytes_consumed += 1
        if i == 8:
            result = (result << 8) | byte
            break
        result = (result << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            break
    return result, bytes_consumed


def decode_record_header(data: bytes, offset: int = 0) -> tuple[list[int], int] | None:
    """Decodes a SQLite record header at offset.

    Returns (serial_types, total_header_length) or None if malformed.
    """
    if offset >= len(data):
        return None
    header_len, varint_len = decode_varint(data, offset)
    if header_len < varint_len or header_len > len(data) - offset:
        return None
    if header_len > 1024:  # Reasonable cap for normal row record headers
        return None

    serial_types: list[int] = []
    curr = offset + varint_len
    end_header = offset + header_len

    while curr < end_header:
        st, st_len = decode_varint(data, curr)
        if st_len == 0:
            return None
        serial_types.append(st)
        curr += st_len

    if curr != end_header:
        return None

    return serial_types, header_len


def serial_type_length(serial_type: int) -> int:
    """Returns the payload size in bytes for a given SQLite serial type code."""
    if serial_type == 0:
        return 0  # NULL
    if serial_type == 1:
        return 1  # 8-bit int
    if serial_type == 2:
        return 2  # 16-bit int
    if serial_type == 3:
        return 3  # 24-bit int
    if serial_type == 4:
        return 4  # 32-bit int
    if serial_type == 5:
        return 6  # 48-bit int
    if serial_type == 6:
        return 8  # 64-bit int
    if serial_type == 7:
        return 8  # 64-bit IEEE float
    if serial_type in (8, 9):
        return 0  # 0 or 1 constant
    if serial_type in (10, 11):
        return 0  # Reserved
    if serial_type >= 12:
        if serial_type % 2 == 0:
            return (serial_type - 12) // 2  # BLOB
        return (serial_type - 13) // 2  # String
    return 0


def decode_column_value(data: bytes, offset: int, serial_type: int) -> tuple[Any, int] | None:
    """Decodes one column value based on its serial type.

    Returns (value, bytes_consumed) or None.
    """
    length = serial_type_length(serial_type)
    if offset + length > len(data):
        return None

    chunk = data[offset : offset + length]

    if serial_type == 0:
        return None, 0
    if serial_type == 1:
        return struct.unpack(">b", chunk)[0], 1
    if serial_type == 2:
        return struct.unpack(">h", chunk)[0], 2
    if serial_type == 3:
        # 24-bit big-endian signed int
        val = (chunk[0] << 16) | (chunk[1] << 8) | chunk[2]
        if val & 0x800000:
            val -= 0x1000000
        return val, 3
    if serial_type == 4:
        return struct.unpack(">i", chunk)[0], 4
    if serial_type == 5:
        # 48-bit big-endian signed int
        val = int.from_bytes(chunk, "big", signed=True)
        return val, 6
    if serial_type == 6:
        return struct.unpack(">q", chunk)[0], 8
    if serial_type == 7:
        return struct.unpack(">d", chunk)[0], 8
    if serial_type == 8:
        return 0, 0
    if serial_type == 9:
        return 1, 0
    if serial_type >= 12:
        if serial_type % 2 == 0:
            return chunk, length
        try:
            return chunk.decode("utf-8", errors="replace"), length
        except Exception:
            return chunk.decode("latin-1", errors="replace"), length

    return None, 0


class SQLiteCarver:
    """Carves deleted records from SQLite database B-Tree slack and freeblocks."""

    def __init__(self, page_size: int = 4096) -> None:
        self.page_size = page_size

    def carve_file(self, db_path: Path, *, source_locator: str = "") -> list[CarvedSQLiteRecord]:
        path = db_path.expanduser().resolve()
        if not path.is_file():
            return []

        data = path.read_bytes()
        if len(data) < 100 or not data.startswith(SQLITE_MAGIC):
            return []

        raw_page_size = int.from_bytes(data[16:18], "big")
        page_size = 65536 if raw_page_size == 1 else raw_page_size
        if page_size < 512 or (page_size & (page_size - 1)) != 0:
            page_size = self.page_size

        total_pages = len(data) // page_size
        carved_records: list[CarvedSQLiteRecord] = []

        for page_num in range(1, total_pages + 1):
            page_start = (page_num - 1) * page_size
            page_data = data[page_start : page_start + page_size]
            header_offset = 100 if page_num == 1 else 0

            if len(page_data) < header_offset + 8:
                continue

            flag = page_data[header_offset]
            if flag != LEAF_TABLE_PAGE:
                continue

            first_freeblock = int.from_bytes(
                page_data[header_offset + 1 : header_offset + 3], "big"
            )
            cell_count = int.from_bytes(page_data[header_offset + 3 : header_offset + 5], "big")
            content_start = int.from_bytes(page_data[header_offset + 5 : header_offset + 7], "big")
            if content_start == 0:
                content_start = 65536

            # 1. Carve freeblock chain
            curr_freeblock = first_freeblock
            visited_freeblocks = set()
            while curr_freeblock > 0 and curr_freeblock < len(page_data):
                if curr_freeblock in visited_freeblocks:
                    break
                visited_freeblocks.add(curr_freeblock)
                if curr_freeblock + 4 > len(page_data):
                    break
                next_freeblock = int.from_bytes(
                    page_data[curr_freeblock : curr_freeblock + 2], "big"
                )
                block_size = int.from_bytes(
                    page_data[curr_freeblock + 2 : curr_freeblock + 4], "big"
                )
                if block_size > 4 and curr_freeblock + block_size <= len(page_data):
                    fb_data = page_data[curr_freeblock + 4 : curr_freeblock + block_size]
                    records = self._scan_block_for_records(
                        fb_data,
                        page_num=page_num,
                        base_offset=curr_freeblock + 4,
                        source_locator=source_locator or path.name,
                        confidence="high",
                    )
                    carved_records.extend(records)
                curr_freeblock = next_freeblock

            # 2. Carve unallocated space between cell pointers and content area
            cell_pointers_end = header_offset + 8 + (cell_count * 2)
            if cell_pointers_end < content_start and content_start <= len(page_data):
                unalloc_data = page_data[cell_pointers_end:content_start]
                records = self._scan_block_for_records(
                    unalloc_data,
                    page_num=page_num,
                    base_offset=cell_pointers_end,
                    source_locator=source_locator or path.name,
                    confidence="medium",
                )
                carved_records.extend(records)

            # 3. Scan cell slack spaces across the page
            page_slack = page_data[header_offset + 8 :]
            records = self._scan_block_for_records(
                page_slack,
                page_num=page_num,
                base_offset=header_offset + 8,
                source_locator=source_locator or path.name,
                confidence="low",
            )
            # Avoid exact duplicate carved offsets on this page
            seen_offsets = {r.offset_in_page for r in carved_records if r.page_number == page_num}
            for rec in records:
                if rec.offset_in_page not in seen_offsets:
                    seen_offsets.add(rec.offset_in_page)
                    carved_records.append(rec)

        return carved_records

    def _scan_block_for_records(
        self,
        data: bytes,
        *,
        page_num: int,
        base_offset: int,
        source_locator: str,
        confidence: str,
    ) -> list[CarvedSQLiteRecord]:
        results: list[CarvedSQLiteRecord] = []
        i = 0
        limit = len(data) - 4

        while i < limit:
            # Check cell header: [payload_len, rowid, record_header...]
            payload_len, p_len_bytes = decode_varint(data, i)
            if 0 < payload_len <= len(data) - i:
                rowid, rowid_len = decode_varint(data, i + p_len_bytes)
                rec_offset = i + p_len_bytes + rowid_len
                decoded = self._try_decode_record(data, rec_offset, payload_len)
                if decoded is not None and len(decoded) > 1:
                    results.append(
                        CarvedSQLiteRecord(
                            page_number=page_num,
                            offset_in_page=base_offset + i,
                            rowid=rowid,
                            columns=decoded,
                            source_locator=source_locator,
                            confidence=confidence,
                        )
                    )
                    i += p_len_bytes + rowid_len + payload_len
                    continue

            # Also try decoding directly as a record header without cell wrapper
            decoded_raw = self._try_decode_record(data, i, len(data) - i)
            if decoded_raw is not None and len(decoded_raw) > 1:
                results.append(
                    CarvedSQLiteRecord(
                        page_number=page_num,
                        offset_in_page=base_offset + i,
                        rowid=None,
                        columns=decoded_raw,
                        source_locator=source_locator,
                        confidence=confidence,
                    )
                )
                i += 4
                continue

            i += 1

        return results

    def _try_decode_record(
        self, data: bytes, offset: int, max_payload: int
    ) -> tuple[Any, ...] | None:
        header_info = decode_record_header(data, offset)
        if header_info is None:
            return None

        serial_types, header_len = header_info
        if not serial_types:
            return None

        total_payload_needed = sum(serial_type_length(st) for st in serial_types)
        if header_len + total_payload_needed > max_payload:
            return None
        if offset + header_len + total_payload_needed > len(data):
            return None

        # Ensure at least one text or non-trivial column is present to filter random bytes
        has_meaningful_data = any(
            st >= 13 and (st % 2 != 0) and serial_type_length(st) >= 3 for st in serial_types
        )
        if not has_meaningful_data and total_payload_needed < 8:
            return None

        values: list[Any] = []
        curr_offset = offset + header_len
        for st in serial_types:
            decoded = decode_column_value(data, curr_offset, st)
            if decoded is None:
                return None
            val, consumed = decoded
            values.append(val)
            curr_offset += consumed

        return tuple(values)
