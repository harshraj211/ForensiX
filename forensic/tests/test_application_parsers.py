import sqlite3
from pathlib import Path

import pytest

from forensix_forensic.android_artifacts import (
    AndroidArtifactParserError,
    InstagramDirectMessageParser,
    SnapchatArroyoMessageParser,
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

    assert "android.whatsapp.message" not in {parser.metadata.parser_id for parser in without_hint}
    assert "android.whatsapp.message" in {parser.metadata.parser_id for parser in with_hint}
    assert artifacts[0].summary == "Known WhatsApp message"
    assert artifacts[0].metadata["direction"] == "outgoing"
    assert artifacts[0].metadata["starred"] is True
    assert artifacts[0].metadata.get("forwarded") is None
    assert artifacts[0].status == "active"
    assert artifacts[0].event_time is not None and artifacts[0].event_time.year == 2024


def test_whatsapp_legacy_optional_forward_and_quote_fields(tmp_path: Path) -> None:
    path = tmp_path / "msgstore.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE messages (
            _id INTEGER PRIMARY KEY, timestamp INTEGER, data TEXT,
            key_from_me INTEGER, key_remote_jid TEXT, status INTEGER,
            forwarded INTEGER, quoted_row_id INTEGER, media_mime_type TEXT
        );
        INSERT INTO messages VALUES (
            10, 1704067200000, 'Forwarded image', 0, '123@s.whatsapp.net',
            5, 1, 7, 'image/jpeg'
        );
        """
    )
    connection.commit()
    connection.close()

    with SafeSQLiteReader(path) as reader:
        artifacts = WhatsAppMessageParser().parse(reader, _context("com.whatsapp/msgstore.db"))

    assert len(artifacts) == 1
    assert artifacts[0].status == "active"
    assert artifacts[0].metadata["forwarded"] is True
    assert artifacts[0].metadata.get("starred") is None
    assert artifacts[0].metadata["quoted_message_id"] == 7
    assert artifacts[0].metadata["media_attachment"]["mime_type"] == "image/jpeg"


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
    with (
        SafeSQLiteReader(binary) as reader,
        pytest.raises(AndroidArtifactParserError, match="binary blobs"),
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
                reader.table_names(), source_locator="data/data/com.facebook.orca/messages.db"
            )
        }
        parser = registry.get("android.messenger.messages")
        artifacts = parser.parse(reader, _context("data/data/com.facebook.orca/messages.db"))
    assert "android.messenger.messages" in ids
    assert "android.facebook.messages" not in ids
    assert artifacts[0].summary == "Known Meta message"
    assert artifacts[0].confidence == "low"


def test_instagram_direct_v2_microsecond_timestamps_and_unsent_flag(tmp_path: Path) -> None:
    path = tmp_path / "direct.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE direct_v2_message_items (
            item_id TEXT PRIMARY KEY, thread_id TEXT, user_id TEXT, timestamp INTEGER,
            item_type TEXT, text TEXT, is_shh_mode INTEGER, media_url TEXT,
            is_sent_by_viewer INTEGER
        );
        INSERT INTO direct_v2_message_items VALUES (
            'ig-1', 'thread-1', 'user-7', 1704067200000000, 'text',
            'Known Direct message', 0, NULL, 1
        );
        INSERT INTO direct_v2_message_items VALUES (
            'ig-2', 'thread-1', 'user-8', 1704067201000000, 'media',
            NULL, 1, 'https://example.invalid/media', 0
        );
        """
    )
    connection.commit()
    connection.close()

    with SafeSQLiteReader(path) as reader:
        parser = InstagramDirectMessageParser()
        artifacts = parser.parse(
            reader, _context("data/data/com.instagram.android/databases/direct.db")
        )
        compatible = android_parser_registry().compatible(
            reader.table_names(),
            source_locator="data/data/com.instagram.android/databases/direct.db",
        )

    assert {parser.metadata.parser_id for parser in compatible} == {"android.instagram.direct"}
    assert artifacts[0].summary == "Known Direct message"
    assert artifacts[0].event_time is not None and artifacts[0].event_time.year == 2024
    assert artifacts[0].metadata["is_outgoing"] is True
    assert artifacts[1].status == "deleted"
    assert artifacts[1].metadata["unsent_flag"] is True


def test_snapchat_arroyo_plaintext_metadata(tmp_path: Path) -> None:
    path = tmp_path / "arroyo.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE messages (
            client_message_id TEXT PRIMARY KEY, conversation_id TEXT, sender_id TEXT,
            sending_timestamp INTEGER, content_type TEXT, message_content TEXT,
            saved_by_sender INTEGER, saved_by_recipient INTEGER
        );
        INSERT INTO messages VALUES (
            'snap-1', 'conversation-1', 'friend-2', 1704067200000, 'CHAT',
            'Known Snapchat message', 1, 0
        );
        """
    )
    connection.commit()
    connection.close()

    with SafeSQLiteReader(path) as reader:
        artifacts = SnapchatArroyoMessageParser().parse(
            reader, _context("data/data/com.snapchat.android/databases/arroyo.db")
        )
        ids = {
            parser.metadata.parser_id
            for parser in android_parser_registry().compatible(
                reader.table_names(),
                source_locator="data/data/com.snapchat.android/databases/arroyo.db",
            )
        }

    assert "android.snapchat.arroyo" in ids
    assert artifacts[0].summary == "Known Snapchat message"
    assert artifacts[0].event_time is not None and artifacts[0].event_time.year == 2024
    assert artifacts[0].metadata["saved_by_sender"] is True
    assert artifacts[0].metadata["saved_by_recipient"] is False
