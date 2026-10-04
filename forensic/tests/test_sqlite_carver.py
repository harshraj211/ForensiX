"""Tests for deep SQLite B-Tree deleted cell and freeblock carver."""

import sqlite3
from pathlib import Path

from forensix_forensic.evidence_io.sqlite_carver import (
    SQLiteCarver,
    decode_column_value,
    decode_record_header,
    decode_varint,
    serial_type_length,
)


def test_decode_varint() -> None:
    data = b"\x01\x81\x00\x82\x01\xff\xff\xff\xff\xff\xff\xff\xff\x7f"
    val, consumed = decode_varint(data, 0)
    assert val == 1
    assert consumed == 1

    val, consumed = decode_varint(data, 1)
    assert val == 128
    assert consumed == 2


def test_serial_type_length() -> None:
    assert serial_type_length(0) == 0  # NULL
    assert serial_type_length(1) == 1  # 8-bit int
    assert serial_type_length(4) == 4  # 32-bit int
    assert serial_type_length(6) == 8  # 64-bit int
    assert serial_type_length(7) == 8  # double
    assert serial_type_length(12) == 0  # 0-byte blob
    assert serial_type_length(13) == 0  # 0-byte string
    assert serial_type_length(17) == 2  # (17-13)/2 = 2-byte string
    assert serial_type_length(20) == 4  # (20-12)/2 = 4-byte blob


def test_decode_record_header_and_values() -> None:
    # Record header: length 3, serial type 1 (1 byte int), serial type 19 (3-byte string)
    # Payload: 0x2A (42), b'XYZ'
    raw_header = bytes([3, 1, 19])
    header_info = decode_record_header(raw_header, 0)
    assert header_info is not None
    serial_types, header_len = header_info
    assert serial_types == [1, 19]
    assert header_len == 3

    payload = bytes([42]) + b"XYZ"
    res1 = decode_column_value(payload, 0, 1)
    assert res1 is not None
    v1, c1 = res1
    assert v1 == 42
    assert c1 == 1

    res2 = decode_column_value(payload, c1, 19)
    assert res2 is not None
    v2, c2 = res2
    assert v2 == "XYZ"
    assert c2 == 3


def test_sqlite_carver_on_deleted_records(tmp_path: Path) -> None:
    db_path = tmp_path / "test_carve.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            sender TEXT,
            body TEXT,
            timestamp INTEGER
        )
        """
    )
    conn.execute(
        "INSERT INTO messages VALUES (1, 'Alice', 'Target coordinates 37.77, -122.41', 1700000000)"
    )
    conn.execute(
        "INSERT INTO messages VALUES (2, 'Bob', 'Confidential passphrase AlphaOmega99', 1700000001)"
    )
    conn.execute(
        "INSERT INTO messages VALUES (3, 'Charlie', "
        "'Meeting at safehouse bravo at 2200', 1700000002)"
    )
    conn.commit()

    # Delete records to create freeblocks/slack entries without VACUUM
    conn.execute("DELETE FROM messages WHERE id = 2")
    conn.commit()
    conn.close()

    carver = SQLiteCarver()
    carved = carver.carve_file(db_path, source_locator="test_carve.db")

    assert len(carved) > 0
    # Verify we carved records
    all_texts = [str(col) for r in carved for col in r.columns if isinstance(col, str)]
    # Check that text records are recovered
    assert any("Alice" in t or "AlphaOmega99" in t or "Charlie" in t for t in all_texts)


def test_sqlite_carver_wal_frames(tmp_path: Path) -> None:
    db_path = tmp_path / "wal_evidence.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE chat (
            id INTEGER PRIMARY KEY,
            sender TEXT,
            text TEXT
        )
        """
    )
    conn.execute("INSERT INTO chat VALUES (10, 'Suspect', 'Hidden stash coordinates at 45.12, 9.18')")
    conn.execute("INSERT INTO chat VALUES (20, 'Accomplice', 'Keycode is BravoSierra7788')")
    conn.commit()

    # Delete row 20 in WAL mode
    conn.execute("DELETE FROM chat WHERE id = 20")
    conn.commit()

    wal_path = tmp_path / "wal_evidence.db-wal"
    assert wal_path.is_file()

    carver = SQLiteCarver()
    wal_carved = carver.carve_wal_file(wal_path, source_locator="wal_evidence.db-wal")
    assert len(wal_carved) > 0

    all_texts = [str(col) for r in wal_carved for col in r.columns if isinstance(col, str)]
    assert any("BravoSierra7788" in t or "stash coordinates" in t for t in all_texts)

    # Test carve_file with include_wal=True recovers both
    combined_carved = carver.carve_file(db_path, include_wal=True)
    combined_texts = [str(col) for r in combined_carved for col in r.columns if isinstance(col, str)]
    assert any("BravoSierra7788" in t or "stash coordinates" in t for t in combined_texts)

    conn.close()


def test_extractor_sqlite_carver_freelist_traversal(tmp_path: Path) -> None:
    from forensix_forensic.extractors.sqlite_carver import SQLiteCarver as ExtractorCarver

    db_path = tmp_path / "freelist_test.db"
    page_size = 4096

    # Construct synthetic SQLite DB with freelist trunk (page 2) pointing to leaf (page 3)
    header = bytearray(page_size)
    header[:16] = b"SQLite format 3\x00"
    header[16:18] = page_size.to_bytes(2, "big")
    header[32:36] = (2).to_bytes(4, "big")  # First trunk page = 2
    header[36:40] = (2).to_bytes(4, "big")  # Total freelist pages = 2 (1 trunk + 1 leaf)

    # Page 2: Freelist trunk page
    # [next_trunk_page (4 bytes = 0), leaf_count (4 bytes = 1), leaf_page_no (4 bytes = 3), slack...]
    trunk_page = bytearray(page_size)
    trunk_page[0:4] = (0).to_bytes(4, "big")  # No next trunk
    trunk_page[4:8] = (1).to_bytes(4, "big")  # 1 leaf page
    trunk_page[8:12] = (3).to_bytes(4, "big")  # Leaf page is page 3

    # Page 3: Freelist leaf page containing WhatsApp deleted fragment
    leaf_page = bytearray(page_size)
    msg_bytes = b"Hello from deleted WhatsApp message to user@s.whatsapp.net covert payload"
    leaf_page[128 : 128 + len(msg_bytes)] = msg_bytes

    db_path.write_bytes(bytes(header) + bytes(trunk_page) + bytes(leaf_page))

    extractor = ExtractorCarver()
    result = extractor.carve([db_path])
    assert result.freelist_fragments_found >= 1
    assert any("covert payload" in f.content_preview for f in result.fragments)
