"""Comprehensive tests for Android core communication, contact, and browser parsers."""

import sqlite3
from pathlib import Path

from forensix_forensic.android_artifacts.communications import (
    AndroidCallLogParser,
    AndroidSmsParser,
)
from forensix_forensic.android_artifacts.contacts import AndroidContactsParser
from forensix_forensic.android_artifacts.system import ChromeHistoryParser
from forensix_forensic.evidence_io import ParserContext, SafeSQLiteReader


def _dummy_context(locator: str = "test.db") -> ParserContext:
    return ParserContext(
        case_id="case-test-101",
        evidence_source_id="src-test-101",
        working_copy_id="copy-test-101",
        source_sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        source_label="test_source",
        input_locator=locator,
        input_sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )


def test_android_sms_parser_lifecycle_and_capability(tmp_path: Path) -> None:
    db_path = tmp_path / "mmssms.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE sms ("
        "_id INTEGER PRIMARY KEY, "
        "date INTEGER, "
        "type INTEGER, "
        "address TEXT, "
        "body TEXT, "
        "read INTEGER)"
    )
    conn.execute(
        "INSERT INTO sms (_id, date, type, address, body, read) "
        "VALUES (1, 1693824000000, 1, '+15551234567', 'Hello from suspect', 1)"
    )
    conn.execute(
        "INSERT INTO sms (_id, date, type, address, body, read) "
        "VALUES (2, 1693824060000, 2, '+15551234567', 'Understood, on my way', 1)"
    )
    conn.commit()
    conn.close()

    parser = AndroidSmsParser()
    assert parser.metadata.parser_id == "android.telephony.sms"

    # Test capability evaluation
    cap = parser.detect_capability(
        frozenset({"sms", "threads"}),
        source_locator="/data/data/com.android.providers.telephony/databases/mmssms.db",
    )
    assert cap.supported is True
    assert cap.confidence >= 0.8

    # Test parsing
    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _dummy_context("mmssms.db"))
        assert len(artifacts) == 2

        msg1 = artifacts[0]
        assert msg1.category == "communication"
        assert msg1.subtype == "sms"
        assert "+15551234567" in msg1.title
        assert "Hello from suspect" in msg1.summary
        assert msg1.metadata["direction"] == "inbox"

        msg2 = artifacts[1]
        assert msg2.metadata["direction"] == "sent"
        assert "Understood" in msg2.summary


def test_android_call_log_parser_lifecycle_and_capability(tmp_path: Path) -> None:
    db_path = tmp_path / "calllog.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE calls ("
        "_id INTEGER PRIMARY KEY, "
        "number TEXT, "
        "date INTEGER, "
        "duration INTEGER, "
        "type INTEGER, "
        "name TEXT, "
        "geocoded_location TEXT)"
    )
    conn.execute(
        "INSERT INTO calls (_id, number, date, duration, type, name, geocoded_location) "
        "VALUES (1, '+15559876543', 1693825000000, 142, 1, 'Jane Doe', 'New York, NY')"
    )
    conn.execute(
        "INSERT INTO calls (_id, number, date, duration, type, name, geocoded_location) "
        "VALUES (2, '+15559876543', 1693825500000, 0, 3, 'Jane Doe', 'New York, NY')"
    )
    conn.commit()
    conn.close()

    parser = AndroidCallLogParser()
    assert parser.metadata.parser_id == "android.call_log"

    cap = parser.detect_capability(frozenset({"calls"}), source_locator="data/system/calllog.db")
    assert cap.supported is True
    assert cap.confidence >= 0.8

    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _dummy_context("calllog.db"))
        assert len(artifacts) == 2

        call1 = artifacts[0]
        assert call1.category == "communication"
        assert call1.subtype == "call"
        assert "incoming" in call1.title.lower()
        assert "+15559876543" in call1.title
        assert call1.metadata["name"] == "Jane Doe"
        assert call1.metadata["duration"] == 142

        call2 = artifacts[1]
        assert "missed" in call2.title.lower()


def test_android_contacts_parser_lifecycle_and_capability(tmp_path: Path) -> None:
    db_path = tmp_path / "contacts2.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE raw_contacts ("
        "_id INTEGER PRIMARY KEY, account_name TEXT, account_type TEXT, deleted INTEGER)"
    )
    conn.execute("CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT)")
    conn.execute(
        "CREATE TABLE data ("
        "_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER, "
        "data1 TEXT, data2 TEXT, data3 TEXT)"
    )

    conn.execute(
        "INSERT INTO raw_contacts (_id, account_name, account_type, deleted) "
        "VALUES (1, 'user@gmail.com', 'com.google', 0)"
    )
    conn.execute("INSERT INTO mimetypes (_id, mimetype) VALUES (1, 'vnd.android.cursor.item/name')")
    conn.execute(
        "INSERT INTO mimetypes (_id, mimetype) VALUES (2, 'vnd.android.cursor.item/phone_v2')"
    )
    conn.execute(
        "INSERT INTO mimetypes (_id, mimetype) VALUES (3, 'vnd.android.cursor.item/email_v2')"
    )

    conn.execute(
        "INSERT INTO data (_id, raw_contact_id, mimetype_id, data1, data2, data3) "
        "VALUES (1, 1, 1, 'Alice Smith', 'Alice', 'Smith')"
    )
    conn.execute(
        "INSERT INTO data (_id, raw_contact_id, mimetype_id, data1, data2, data3) "
        "VALUES (2, 1, 2, '+15554443322', '2', NULL)"
    )
    conn.execute(
        "INSERT INTO data (_id, raw_contact_id, mimetype_id, data1, data2, data3) "
        "VALUES (3, 1, 3, 'alice@example.com', '1', NULL)"
    )
    conn.commit()
    conn.close()

    parser = AndroidContactsParser()
    assert parser.metadata.parser_id == "android.contacts_provider"

    cap = parser.detect_capability(
        frozenset({"data", "mimetypes", "raw_contacts"}), source_locator="contacts2.db"
    )
    assert cap.supported is True

    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _dummy_context("contacts2.db"))
        assert len(artifacts) == 1
        contact = artifacts[0]
        assert contact.category == "contact"
        assert contact.title == "Alice Smith"
        assert any(p["number"] == "+15554443322" for p in contact.metadata["phones"])
        assert any(e["address"] == "alice@example.com" for e in contact.metadata["emails"])


def test_chrome_history_parser_lifecycle_and_capability(tmp_path: Path) -> None:
    db_path = tmp_path / "History"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)"
    )
    conn.execute(
        "CREATE TABLE visits ("
        "id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)"
    )

    conn.execute(
        "INSERT INTO urls (id, url, title, visit_count) "
        "VALUES (1, 'https://github.com/forensics', 'Forensics Hub', 5)"
    )
    conn.execute(
        "INSERT INTO visits (id, url, visit_time, transition) VALUES (10, 1, 13338240000000000, 0)"
    )
    conn.commit()
    conn.close()

    parser = ChromeHistoryParser()
    assert parser.metadata.parser_id == "android.chrome.history"

    cap = parser.detect_capability(
        frozenset({"urls", "visits"}),
        source_locator="/data/data/com.android.chrome/app_chrome/Default/History",
    )
    assert cap.supported is True
    assert cap.confidence >= 0.8

    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _dummy_context("History"))
        assert len(artifacts) == 1
        visit = artifacts[0]
        assert visit.category == "application"
        assert visit.subtype == "browser_visit"
        assert "Forensics Hub" in visit.title
        assert "https://github.com/forensics" in visit.summary


def test_sqlite_carver_parser_integration(tmp_path: Path) -> None:
    from forensix_forensic.android_artifacts.carver_parser import SQLiteCarverParser

    db_path = tmp_path / "chat_store.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, body TEXT)")
    conn.execute(
        "INSERT INTO messages (id, sender, body) "
        "VALUES (1, '+15550001111', 'Active WhatsApp message payload')"
    )
    conn.execute(
        "INSERT INTO messages (id, sender, body) "
        "VALUES (2, '+15550002222', 'Secret transaction details at midnight')"
    )
    conn.commit()
    # Now delete row 2 so it sits in freeblocks/freelist
    conn.execute("DELETE FROM messages WHERE id = 2")
    conn.commit()
    conn.close()

    parser = SQLiteCarverParser()
    assert parser.metadata.parser_id == "android.sqlite.carver"
    assert parser.can_parse(frozenset()) is True

    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _dummy_context("chat_store.db"))
        assert len(artifacts) >= 1
        carved = artifacts[0]
        assert carved.status == "recovered"
        assert carved.category == "communication"
        assert "Secret transaction" in carved.summary or "Active WhatsApp" in carved.summary
