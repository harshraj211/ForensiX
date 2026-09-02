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


def test_decode_varint():
    data = b"\x01\x81\x00\x82\x01\xff\xff\xff\xff\xff\xff\xff\xff\x7f"
    val, consumed = decode_varint(data, 0)
    assert val == 1
    assert consumed == 1

    val, consumed = decode_varint(data, 1)
    assert val == 128
    assert consumed == 2


def test_serial_type_length():
    assert serial_type_length(0) == 0  # NULL
    assert serial_type_length(1) == 1  # 8-bit int
    assert serial_type_length(4) == 4  # 32-bit int
    assert serial_type_length(6) == 8  # 64-bit int
    assert serial_type_length(7) == 8  # double
    assert serial_type_length(12) == 0  # 0-byte blob
    assert serial_type_length(13) == 0  # 0-byte string
    assert serial_type_length(17) == 2  # (17-13)/2 = 2-byte string
    assert serial_type_length(20) == 4  # (20-12)/2 = 4-byte blob


def test_decode_record_header_and_values():
    # Record header: length 3, serial type 1 (1 byte int), serial type 19 (3-byte string)
    # Payload: 0x2A (42), b'XYZ'
    raw_header = bytes([3, 1, 19])
    header_info = decode_record_header(raw_header, 0)
    assert header_info is not None
    serial_types, header_len = header_info
    assert serial_types == [1, 19]
    assert header_len == 3

    payload = bytes([42]) + b"XYZ"
    v1, c1 = decode_column_value(payload, 0, 1)
    assert v1 == 42
    assert c1 == 1

    v2, c2 = decode_column_value(payload, c1, 19)
    assert v2 == "XYZ"
    assert c2 == 3


def test_sqlite_carver_on_deleted_records(tmp_path: Path):
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
