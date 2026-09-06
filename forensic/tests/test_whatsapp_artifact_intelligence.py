# ruff: noqa: E501
import sqlite3
from pathlib import Path

import pytest

from forensix_forensic.android_artifacts import (
    AndroidArtifactParserError,
    WhatsAppBackupArtifactParser,
    WhatsAppMessageParser,
)
from forensix_forensic.evidence_io import (
    ParserContext,
    SafeSQLiteError,
    SafeSQLiteReader,
)


def _context(locator: str = "data/data/com.whatsapp/databases/msgstore.db") -> ParserContext:
    return ParserContext(
        case_id="whatsapp_case_10",
        evidence_source_id="evidence_source_10",
        working_copy_id="working_copy_10",
        source_sha256="a" * 64,
        source_label="WhatsApp Test Database",
        input_locator=locator,
        input_sha256="b" * 64,
    )


# -----------------------------------------------------------------------------
# Test A: Recognized Database (Modern v14 & Legacy Schemas)
# -----------------------------------------------------------------------------
def test_modern_v14_whatsapp_schema_extraction(tmp_path: Path) -> None:
    db_path = tmp_path / "msgstore.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE jid (
            _id INTEGER PRIMARY KEY,
            raw_string TEXT NOT NULL
        );
        INSERT INTO jid VALUES (1, '15551234567@s.whatsapp.net');
        INSERT INTO jid VALUES (2, '1203630987654@g.us');

        CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            text_data TEXT,
            from_me INTEGER NOT NULL,
            message_type INTEGER,
            chat_row_id INTEGER,
            sender_jid_row_id INTEGER,
            status INTEGER
        );
        INSERT INTO message VALUES (101, 1704067200000, 'Hello from modern WhatsApp', 0, 0, 2, 1, 0);
        INSERT INTO message VALUES (102, 1704067205000, 'Reply sent from self', 1, 0, 2, 1, 0);
        """
    )
    conn.commit()
    conn.close()

    with SafeSQLiteReader(db_path) as reader:
        parser = WhatsAppMessageParser()
        artifacts = parser.parse(reader, _context(str(db_path)))

    assert len(artifacts) >= 2
    msg1 = next(a for a in artifacts if a.metadata.get("message_id") == 101)
    assert msg1.summary == "Hello from modern WhatsApp"
    assert msg1.metadata["direction"] == "incoming"
    assert msg1.metadata["resolved_sender"] == "15551234567@s.whatsapp.net"
    assert msg1.metadata["resolved_chat"] == "1203630987654@g.us"
    assert msg1.metadata["schema_family"] == "whatsapp_v14_message"

    msg2 = next(a for a in artifacts if a.metadata.get("message_id") == 102)
    assert msg2.summary == "Reply sent from self"
    assert msg2.metadata["direction"] == "outgoing"


def test_legacy_whatsapp_schema_extraction(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy_msgstore.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE messages (
            _id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            data TEXT,
            key_from_me INTEGER NOT NULL,
            key_remote_jid TEXT,
            status INTEGER
        );
        INSERT INTO messages VALUES (1, 1704067200000, 'Legacy message body', 0, '15559876543@s.whatsapp.net', 0);
        """
    )
    conn.commit()
    conn.close()

    with SafeSQLiteReader(db_path) as reader:
        parser = WhatsAppMessageParser()
        artifacts = parser.parse(reader, _context(str(db_path)))

    assert len(artifacts) >= 1
    msg = artifacts[0]
    assert msg.summary == "Legacy message body"
    assert msg.metadata["direction"] == "incoming"
    assert msg.metadata["resolved_sender"] == "15559876543@s.whatsapp.net"
    assert msg.metadata["schema_family"] == "whatsapp_legacy_message"


# -----------------------------------------------------------------------------
# Test B: Unknown / Invalid Schema Rejection
# -----------------------------------------------------------------------------
def test_unknown_schema_raises_parser_error(tmp_path: Path) -> None:
    db_path = tmp_path / "unknown_schema.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE message (invalid_column_a TEXT, invalid_column_b INTEGER)")
    conn.commit()
    conn.close()

    with (
        SafeSQLiteReader(db_path) as reader,
        pytest.raises(AndroidArtifactParserError, match="primary key identifier"),
    ):
        WhatsAppMessageParser().parse(reader, _context(str(db_path)))


# -----------------------------------------------------------------------------
# Test C: Encrypted .crypt* Handling
# -----------------------------------------------------------------------------
def test_encrypted_crypt14_backup_returns_encrypted_unparsed_status() -> None:
    parser = WhatsAppBackupArtifactParser()
    assert parser.can_parse_file("msgstore.db.crypt14") is True

    artifact = parser.parse_backup_file(
        file_name="msgstore.db.crypt14",
        size_bytes=5242880,
        context=_context("com.whatsapp/databases/msgstore.db.crypt14"),
        header_bytes=b"CRYPT14_HEADER_DATA_SAMPLE",
    )

    assert artifact.subtype == "whatsapp_backup_artifact"
    assert artifact.metadata["backup_version"] == "crypt14"
    assert artifact.metadata["encrypted"] is True
    assert artifact.metadata["parse_status"] == "encrypted_unparsed"
    assert "encrypted_unparsed" in artifact.summary


# -----------------------------------------------------------------------------
# Test D: Missing Fields / Partial Data Handling
# -----------------------------------------------------------------------------
def test_partial_schema_record_handling(tmp_path: Path) -> None:
    db_path = tmp_path / "partial_msgstore.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            from_me INTEGER NOT NULL
        );
        INSERT INTO message VALUES (50, 1704067200000, 1);
        """
    )
    conn.commit()
    conn.close()

    with SafeSQLiteReader(db_path) as reader:
        artifacts = WhatsAppMessageParser().parse(reader, _context(str(db_path)))

    assert len(artifacts) >= 1
    msg = next(a for a in artifacts if a.metadata.get("message_id") == 50)
    assert msg.summary == "WhatsApp message body unavailable"
    assert msg.metadata["direction"] == "outgoing"
    assert msg.confidence == "medium"


# -----------------------------------------------------------------------------
# Test E: Timestamp Normalization
# -----------------------------------------------------------------------------
def test_timestamp_normalization_millis_and_seconds(tmp_path: Path) -> None:
    db_path = tmp_path / "timestamp_msgstore.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            text_data TEXT,
            from_me INTEGER NOT NULL
        );
        INSERT INTO message VALUES (1, 1704067200000, 'Millisecond timestamp', 1);
        """
    )
    conn.commit()
    conn.close()

    with SafeSQLiteReader(db_path) as reader:
        artifacts = WhatsAppMessageParser().parse(reader, _context(str(db_path)))

    assert len(artifacts) >= 1
    msg = artifacts[0]
    assert msg.event_time is not None
    assert msg.event_time.year == 2024
    assert msg.event_time.month == 1
    assert msg.event_time.day == 1
    ts_details = msg.metadata["timestamp_details"]
    assert ts_details["raw_value"] == "1704067200000"
    assert ts_details["raw_unit"] == "milliseconds"
    assert ts_details["timezone_assumption"] == "UTC"


# -----------------------------------------------------------------------------
# Test F: Contact Resolution
# -----------------------------------------------------------------------------
def test_wa_contacts_parsing_and_resolution(tmp_path: Path) -> None:
    db_path = tmp_path / "wa.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE wa_contacts (
            _id INTEGER PRIMARY KEY,
            jid TEXT NOT NULL,
            display_name TEXT,
            number TEXT,
            status TEXT
        );
        INSERT INTO wa_contacts VALUES (1, '15551234567@s.whatsapp.net', 'Jane Doe', '15551234567', 'Available');
        """
    )
    conn.commit()
    conn.close()

    with SafeSQLiteReader(db_path) as reader:
        parser = WhatsAppMessageParser()
        artifacts = parser.parse(reader, _context(str(db_path)))

    assert len(artifacts) >= 1
    contact = artifacts[0]
    assert contact.category == "contact"
    assert contact.subtype == "whatsapp_contact"
    assert "Jane Doe" in contact.title
    assert contact.metadata["formatted_number"] == "+15551234567"
    assert contact.metadata["raw_jid"] == "15551234567@s.whatsapp.net"


# -----------------------------------------------------------------------------
# Test G: Media Correlation
# -----------------------------------------------------------------------------
def test_media_attachment_correlation(tmp_path: Path) -> None:
    db_path = tmp_path / "media_msgstore.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            media_wa_type INTEGER,
            media_name TEXT,
            media_size INTEGER,
            from_me INTEGER NOT NULL
        );
        CREATE TABLE message_media (
            message_row_id INTEGER PRIMARY KEY,
            file_path TEXT,
            file_size INTEGER,
            mime_type TEXT,
            file_hash TEXT
        );
        INSERT INTO message VALUES (200, 1704067200000, 1, 'photo.jpg', 102400, 0);
        INSERT INTO message_media VALUES (200, '/sdcard/WhatsApp/Media/photo.jpg', 102400, 'image/jpeg', 'abc123hash');
        """
    )
    conn.commit()
    conn.close()

    with SafeSQLiteReader(db_path) as reader:
        artifacts = WhatsAppMessageParser().parse(reader, _context(str(db_path)))

    assert len(artifacts) >= 1
    msg = next(a for a in artifacts if a.metadata.get("message_id") == 200)
    media_meta = msg.metadata.get("media_attachment")
    assert media_meta is not None
    assert media_meta.get("file_path") == "/sdcard/WhatsApp/Media/photo.jpg"
    assert media_meta.get("mime_type") == "image/jpeg"
    assert media_meta.get("file_hash") == "abc123hash"


# -----------------------------------------------------------------------------
# Test H: WAL/SHM Support
# -----------------------------------------------------------------------------
def test_wal_journal_support(tmp_path: Path) -> None:
    db_path = tmp_path / "wal_msgstore.db"
    wal_path = tmp_path / "wal_msgstore.db-wal"
    wal_path.write_bytes(b"\x37\x7f\x06\x82" + b"\x00" * 28)

    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            text_data TEXT,
            from_me INTEGER NOT NULL
        );
        INSERT INTO message VALUES (300, 1704067200000, 'WAL test message', 1);
        """
    )
    conn.commit()
    conn.close()

    with SafeSQLiteReader(db_path) as reader:
        artifacts = WhatsAppMessageParser().parse(reader, _context(str(db_path)))

    assert len(artifacts) >= 1
    msg = artifacts[0]
    assert msg.summary == "WAL test message"


# -----------------------------------------------------------------------------
# Test I: Corrupt Database Handling
# -----------------------------------------------------------------------------
def test_corrupt_database_fails_gracefully(tmp_path: Path) -> None:
    corrupt_path = tmp_path / "corrupt_msgstore.db"
    corrupt_path.write_bytes(b"NOT_A_SQLITE_DATABASE_BLOB_CORRUPT")

    with (
        pytest.raises(SafeSQLiteError, match="SQLite 3 file signature"),
        SafeSQLiteReader(corrupt_path),
    ):
        pass


# -----------------------------------------------------------------------------
# Test J: Provenance Retention
# -----------------------------------------------------------------------------
def test_provenance_retention(tmp_path: Path) -> None:
    db_path = tmp_path / "provenance_msgstore.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            text_data TEXT,
            from_me INTEGER NOT NULL
        );
        INSERT INTO message VALUES (999, 1704067200000, 'Provenance message', 0);
        """
    )
    conn.commit()
    conn.close()

    locator_str = "cases/FX-1001/evidence/provenance_msgstore.db"
    with SafeSQLiteReader(db_path) as reader:
        artifacts = WhatsAppMessageParser().parse(reader, _context(locator_str))

    assert len(artifacts) >= 1
    msg = artifacts[0]
    assert msg.source_locator == f"{locator_str}#message:999"
    assert msg.metadata["source_database"] == "provenance_msgstore.db"
    assert msg.metadata["source_table"] == "message"
    assert msg.metadata["message_id"] == 999
