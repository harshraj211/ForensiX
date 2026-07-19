import sqlite3
from pathlib import Path

import pytest

from forensix_forensic.android_artifacts import (
    AndroidArtifactParserError,
    TelegramMessageParser,
    WhatsAppMessageParser,
    android_parser_registry,
)
from forensix_forensic.evidence_io import ParserContext, SafeSQLiteReader


def _context(locator: str) -> ParserContext:
    return ParserContext(
        case_id="case",
        evidence_source_id="source",
        working_copy_id="copy",
        source_sha256="0" * 64,
        source_label=locator,
        input_locator=locator,
        input_sha256="1" * 64,
    )


def test_whatsapp_plaintext_schema_is_path_gated_and_normalized(tmp_path: Path) -> None:
    path = tmp_path / "msgstore.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY, timestamp INTEGER, text_data TEXT,
            from_me INTEGER, message_type INTEGER, chat_row_id INTEGER,
            sender_jid_row_id INTEGER, status INTEGER, starred INTEGER
        );
        INSERT INTO message VALUES (7, 1704067200000, 'Known WhatsApp message', 1, 0, 3, 4, 5, 1);
        """
    )
    connection.commit()
    connection.close()

    with SafeSQLiteReader(path) as reader:
        tables = reader.table_names()
        without_hint = android_parser_registry().compatible(tables)
        with_hint = android_parser_registry().compatible(
            tables, source_locator="data/data/com.whatsapp/databases/msgstore.db"
        )
        artifacts = WhatsAppMessageParser().parse(
            reader, _context("data/data/com.whatsapp/databases/msgstore.db")
        )

    assert "android.whatsapp.message" not in {
        parser.metadata.parser_id for parser in without_hint
    }
    assert "android.whatsapp.message" in {parser.metadata.parser_id for parser in with_hint}
    assert artifacts[0].summary == "Known WhatsApp message"
    assert artifacts[0].metadata["direction"] == "outgoing"
    assert artifacts[0].event_time is not None and artifacts[0].event_time.year == 2024


def test_telegram_plaintext_schema_and_binary_only_rejection(tmp_path: Path) -> None:
    plaintext = tmp_path / "cache4.db"
    connection = sqlite3.connect(plaintext)
    connection.executescript(
        """
        CREATE TABLE messages (
            _id INTEGER PRIMARY KEY, date INTEGER, message TEXT,
            dialog_id INTEGER, sender_id INTEGER, out INTEGER
        );
        INSERT INTO messages VALUES (9, 1704067200, 'Known Telegram message', 11, 12, 0);
        """
    )
    connection.commit()
    connection.close()
    with SafeSQLiteReader(plaintext) as reader:
        artifacts = TelegramMessageParser().parse(
            reader, _context("data/data/org.telegram.messenger/files/cache4.db")
        )
    assert artifacts[0].summary == "Known Telegram message"
    assert artifacts[0].event_time is not None and artifacts[0].event_time.year == 2024

    binary = tmp_path / "binary-cache4.db"
    connection = sqlite3.connect(binary)
    connection.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, date INTEGER, data BLOB)")
    connection.commit()
    connection.close()
    with SafeSQLiteReader(binary) as reader, pytest.raises(
        AndroidArtifactParserError, match="binary blobs"
    ):
        TelegramMessageParser().parse(
            reader, _context("data/data/org.telegram.messenger/files/cache4.db")
        )


def test_meta_parsers_require_application_path_hint(tmp_path: Path) -> None:
    path = tmp_path / "messages.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, timestamp_ms INTEGER, text TEXT)"
    )
    connection.execute("INSERT INTO messages VALUES (1, 1704067200000, 'Known Meta message')")
    connection.commit()
    connection.close()

    registry = android_parser_registry()
    with SafeSQLiteReader(path) as reader:
        ids = {
            parser.metadata.parser_id
            for parser in registry.compatible(
                reader.table_names(), source_locator="data/data/com.instagram.android/messages.db"
            )
        }
        parser = registry.get("android.instagram.messages")
        artifacts = parser.parse(
            reader, _context("data/data/com.instagram.android/messages.db")
        )
    assert "android.instagram.messages" in ids
    assert "android.facebook.messages" not in ids
    assert artifacts[0].summary == "Known Meta message"
    assert artifacts[0].confidence == "low"
