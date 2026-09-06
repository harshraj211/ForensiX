"""Tests for Iteration 11: Unified Android Application Artifact Framework."""

# ruff: noqa: E501


import sqlite3
import tempfile
from pathlib import Path

import pytest

from forensix_forensic.android_artifacts.adapter import AdapterParseStatus
from forensix_forensic.android_artifacts.applications import (
    SignalAdapter,
    TelegramAdapter,
    WhatsAppAdapter,
)
from forensix_forensic.android_artifacts.common import to_timeline_event
from forensix_forensic.android_artifacts.communications import (
    AndroidCallLogAdapter,
)
from forensix_forensic.android_artifacts.contacts import AndroidContactsAdapter
from forensix_forensic.android_artifacts.discovery import ApplicationArtifactDiscoveryService
from forensix_forensic.android_artifacts.registry import (
    ApplicationAdapterRegistry,
    android_parser_registry,
)
from forensix_forensic.android_artifacts.relationships import (
    ForensicRelationship,
    RelationshipType,
    create_contact_node,
    create_message_node,
)
from forensix_forensic.evidence_io import ParserContext, SafeSQLiteReader


@pytest.fixture
def context() -> ParserContext:
    return ParserContext(
        case_id="case_iter11",
        evidence_source_id="src_iter11",
        working_copy_id="wc_iter11",
        source_sha256="00" * 32,
        source_label="Iteration 11 Test Device",
        input_locator="/data/data/test_app/test.db",
    )


def test_registry_adapter_capabilities() -> None:
    registry = android_parser_registry()
    assert isinstance(registry, ApplicationAdapterRegistry)
    adapters = registry.list_parsers()
    assert len(adapters) > 10

    p_ids = [p.metadata.parser_id for p in adapters]
    assert "android.whatsapp.message" in p_ids
    assert "android.telegram.messages" in p_ids
    assert "android.signal.message" in p_ids
    assert "android.contacts_provider" in p_ids
    assert "android.call_log" in p_ids
    assert "android.telephony.sms" in p_ids


def test_whatsapp_adapter_contract(context: ParserContext) -> None:
    adapter = WhatsAppAdapter()

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = Path(tf.name)

    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);
        INSERT INTO jid VALUES (1, '15551234567@s.whatsapp.net');

        CREATE TABLE wa_contacts (_id INTEGER PRIMARY KEY, jid TEXT, display_name TEXT, number TEXT);
        INSERT INTO wa_contacts VALUES (10, '15551234567@s.whatsapp.net', 'Alice Cooper', '+15551234567');

        CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            chat_row_id INTEGER,
            sender_jid_row_id INTEGER,
            text_data TEXT,
            timestamp INTEGER,
            from_me INTEGER,
            status INTEGER
        );
        INSERT INTO message VALUES (101, 1, 1, 'Framework message hello', 1772712000000, 0, 1);
    """)
    conn.commit()
    conn.close()

    try:
        with SafeSQLiteReader(db_path) as reader:
            result = adapter.parse_adapter(reader, context)

        assert result.status == AdapterParseStatus.SUPPORTED
        assert result.detected_schema == "whatsapp_v14_or_legacy"
        assert len(result.artifacts) >= 2  # contact + message
        assert len(result.relationships) >= 1

        msg_art = next(a for a in result.artifacts if a.subtype == "whatsapp_message")
        assert msg_art.summary == "Framework message hello"
        assert msg_art.metadata["resolved_sender"] == "Alice Cooper"
        assert msg_art.metadata["source_database"] == db_path.name
        assert msg_art.metadata["source_table"] == "message"
        assert msg_art.metadata["message_id"] == 101
    finally:
        db_path.unlink(missing_ok=True)


def test_telegram_userconf_xml_parsing(context: ParserContext) -> None:
    adapter = TelegramAdapter()
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <map>
        <string name="user_id">987654321</string>
        <string name="phone_number">+15559876543</string>
        <string name="first_name">Bob</string>
        <string name="last_name">Builder</string>
    </map>
    """
    artifacts = adapter.parse_userconf_xml(xml_content, context)
    assert len(artifacts) == 1
    acc = artifacts[0]
    assert acc.category == "account"
    assert acc.title == "Telegram Account: Bob Builder"
    assert acc.metadata["user_id"] == "987654321"
    assert acc.metadata["phone_number"] == "+15559876543"


def test_telegram_cache4_db_sqlite(context: ParserContext) -> None:
    adapter = TelegramAdapter()

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = Path(tf.name)

    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE messages (
            mid INTEGER PRIMARY KEY,
            date INTEGER,
            message TEXT,
            out INTEGER
        );
        INSERT INTO messages VALUES (201, 1772712000, 'Telegram test chat', 1);
    """)
    conn.commit()
    conn.close()

    try:
        with SafeSQLiteReader(db_path) as reader:
            result = adapter.parse_adapter(reader, context)

        assert result.status == AdapterParseStatus.SUPPORTED
        assert result.detected_schema == "telegram_messages"
        assert len(result.artifacts) == 1
        assert result.artifacts[0].summary == "Telegram test chat"
        assert result.artifacts[0].metadata["application"] == "telegram"
    finally:
        db_path.unlink(missing_ok=True)


def test_signal_sqlcipher_encrypted_classification(context: ParserContext) -> None:
    adapter = SignalAdapter()

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = Path(tf.name)
        tf.write(b"SQLCipherEncryptedHeaderData1234567890")

    try:
        result = adapter.parse_adapter(None, context, source_path=db_path)
        assert result.status == AdapterParseStatus.ENCRYPTED_UNPARSED
        assert len(result.artifacts) == 1
        art = result.artifacts[0]
        assert art.subtype == "signal_backup_artifact"
        assert art.metadata["encrypted"] is True
        assert art.metadata["parse_status"] == "encrypted_unparsed"
    finally:
        db_path.unlink(missing_ok=True)


def test_signal_plaintext_parsing(context: ParserContext) -> None:
    adapter = SignalAdapter()

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = Path(tf.name)

    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE sms (
            _id INTEGER PRIMARY KEY,
            date INTEGER,
            body TEXT,
            address TEXT
        );
        INSERT INTO sms VALUES (301, 1772712000000, 'Signal unencrypted test', '+15550001111');
    """)
    conn.commit()
    conn.close()

    try:
        with SafeSQLiteReader(db_path) as reader:
            result = adapter.parse_adapter(reader, context)

        assert result.status == AdapterParseStatus.SUPPORTED
        assert len(result.artifacts) == 1
        assert result.artifacts[0].summary == "Signal unencrypted test"
        assert result.artifacts[0].metadata["application"] == "signal"
    finally:
        db_path.unlink(missing_ok=True)


def test_android_system_database_adapters(context: ParserContext) -> None:
    # 1. Contacts
    contacts_adapter = AndroidContactsAdapter()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        c_path = Path(tf.name)

    conn = sqlite3.connect(c_path)
    conn.executescript("""
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/name');
        INSERT INTO mimetypes VALUES (2, 'vnd.android.cursor.item/phone_v2');

        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, deleted INTEGER, account_name TEXT, account_type TEXT);
        INSERT INTO raw_contacts VALUES (1, 0, 'test@gmail.com', 'com.google');

        CREATE TABLE data (
            _id INTEGER PRIMARY KEY,
            raw_contact_id INTEGER,
            mimetype_id INTEGER,
            data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT
        );
        INSERT INTO data VALUES (1, 1, 1, 'Charlie Brown', NULL, NULL, NULL);
        INSERT INTO data VALUES (2, 1, 2, '+15553334444', '2', 'Mobile', NULL);
    """)
    conn.commit()
    conn.close()

    try:
        with SafeSQLiteReader(c_path) as reader:
            res = contacts_adapter.parse_adapter(reader, context)
        assert res.status == AdapterParseStatus.SUPPORTED
        assert len(res.artifacts) == 1
        assert res.artifacts[0].title == "Charlie Brown"
    finally:
        c_path.unlink(missing_ok=True)

    # 2. Call Log
    call_adapter = AndroidCallLogAdapter()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        cl_path = Path(tf.name)

    conn = sqlite3.connect(cl_path)
    conn.executescript("""
        CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER);
        INSERT INTO calls VALUES (1, '+15559998888', 1772712000000, 45, 1);
    """)
    conn.commit()
    conn.close()

    try:
        with SafeSQLiteReader(cl_path) as reader:
            res = call_adapter.parse_adapter(reader, context)
        assert res.status == AdapterParseStatus.SUPPORTED
        assert len(res.artifacts) == 1
        assert res.artifacts[0].summary == "Duration 45 second(s)"
    finally:
        cl_path.unlink(missing_ok=True)


def test_relationships_and_timeline_conversion(context: ParserContext) -> None:
    # Test Relationship models
    contact_node = create_contact_node("cnt_1", "Alice", "+15551234567")
    msg_node = create_message_node("msg_1", "Hello world", "2026-09-05T12:00:00Z")
    rel = ForensicRelationship(
        source_entity=contact_node.entity_id,
        target_entity=msg_node.entity_id,
        relationship_type=RelationshipType.SENDER,
        source_database="msgstore.db",
        source_table="message",
        source_row_id=1,
    )
    assert rel.source_entity == "cnt_1"
    assert rel.target_entity == "msg_1"
    assert rel.relationship_type == RelationshipType.SENDER

    # Test to_timeline_event helper
    adapter = WhatsAppAdapter()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = Path(tf.name)

    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE message (_id INTEGER PRIMARY KEY, text_data TEXT, timestamp INTEGER, from_me INTEGER, status INTEGER);
        INSERT INTO message VALUES (1, 'Timeline test', 1772712000000, 1, 1);
    """)
    conn.commit()
    conn.close()

    try:
        with SafeSQLiteReader(db_path) as reader:
            res = adapter.parse_adapter(reader, context)
        art = res.artifacts[0]
        event = to_timeline_event(art)
        assert event is not None
        assert event["title"].startswith("WhatsApp outgoing message")
        assert event["summary"] == "Timeline test"
        assert "event_time_utc" in event
    finally:
        db_path.unlink(missing_ok=True)


def test_artifact_discovery_service() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        wa_dir = tmp_path / "com.whatsapp"
        wa_dir.mkdir()
        crypt_file = wa_dir / "msgstore.db.crypt14"
        crypt_file.write_bytes(b"CRYPT14HEADERDATA")

        service = ApplicationArtifactDiscoveryService()
        summary = service.discover_directory(tmp_path)

        assert summary.total_applications_found == 1
        assert summary.total_artifacts_found == 1
        assert "com.whatsapp" in summary.applications_by_package
        art_sum = summary.discovered_artifacts[0]
        assert art_sum.package_name == "com.whatsapp"
        assert art_sum.is_encrypted is True
        assert art_sum.parse_status == AdapterParseStatus.ENCRYPTED_UNPARSED
