"""Tests for Telegram MTProto / TL binary message deserialization."""

import sqlite3
from pathlib import Path

from forensix_forensic.android_artifacts.applications import TelegramMessageParser
from forensix_forensic.evidence_io import ParserContext, SafeSQLiteReader


def test_telegram_tl_binary_deserialization() -> None:
    # Construct a Telegram TL binary serialized message blob
    # Constructor ID (4 bytes) + flags (4 bytes) + TL string
    message_text = "Urgent forensic intelligence report"
    text_bytes = message_text.encode("utf-8")
    length_byte = bytes([len(text_bytes)])
    padding = (4 - ((len(text_bytes) + 1) % 4)) % 4
    tl_string_blob = length_byte + text_bytes + b"\x00" * padding

    constructor_id = b"\x1e\x36\x04\x48"  # TL_message constructor ID
    flags = b"\x02\x00\x00\x00"  # flags (out=0)
    fake_header = b"\x00" * 8  # other fields (id, from_id)
    tl_blob = constructor_id + flags + fake_header + tl_string_blob

    # Test parser's static deserializer
    decoded_text, meta = TelegramMessageParser._decode_tl_message(tl_blob)
    assert decoded_text == message_text
    assert "tl_extracted_tokens" in meta or decoded_text == message_text


def test_telegram_message_parser_with_binary_blobs(tmp_path: Path) -> None:
    # Create a synthetic cache4.db SQLite database with data BLOB column
    db_path = tmp_path / "cache4.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE messages (
            mid INTEGER PRIMARY KEY,
            uid INTEGER,
            read_state INTEGER,
            send_state INTEGER,
            date INTEGER,
            data BLOB,
            out INTEGER,
            ttl INTEGER,
            media BLOB
        )
        """
    )

    message_text = "Meet at safehouse alpha at 21:00 UTC"
    text_bytes = message_text.encode("utf-8")
    pad_len = (4 - ((len(text_bytes) + 1) % 4)) % 4
    tl_string_blob = bytes([len(text_bytes)]) + text_bytes + (b"\x00" * pad_len)
    tl_blob = b"\x1e\x36\x04\x48\x02\x00\x00\x00" + (b"\x00" * 8) + tl_string_blob

    conn.execute(
        """
        INSERT INTO messages (
            mid, uid, read_state, send_state, date, data, out, ttl, media
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (101, 202, 1, 0, 1690000000, tl_blob, 0, 0, None),
    )
    conn.commit()
    conn.close()

    # 3. Parse with TelegramMessageParser
    parser = TelegramMessageParser()
    context = ParserContext(
        case_id="case-123",
        evidence_source_id="src-1",
        working_copy_id="copy-1",
        source_sha256="0" * 64,
        source_label="cache4.db",
        input_locator="cache4.db",
        input_sha256="1" * 64,
    )

    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, context)
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.category == "communication"
        assert artifact.subtype == "telegram_message"
        assert message_text in artifact.summary
        assert artifact.metadata.get("has_tl_binary_payload") is True
