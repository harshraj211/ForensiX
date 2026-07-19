import sqlite3
from pathlib import Path

from forensix_forensic.android_artifacts import (
    AndroidCallLogParser,
    AndroidContactsParser,
    AndroidMmsParser,
    AndroidSmsParser,
    android_parser_registry,
)
from forensix_forensic.evidence_io import ParserContext, SafeSQLiteReader


def _context() -> ParserContext:
    return ParserContext(
        case_id="case",
        evidence_source_id="source",
        working_copy_id="copy",
        source_sha256="0" * 64,
        source_label="known-answer.db",
    )


def test_contacts_provider_known_answer(tmp_path: Path) -> None:
    path = tmp_path / "contacts2.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE raw_contacts (
            _id INTEGER PRIMARY KEY, deleted INTEGER, account_name TEXT, account_type TEXT
        );
        CREATE TABLE data (
            _id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER,
            data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT
        );
        INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/name');
        INSERT INTO mimetypes VALUES (2, 'vnd.android.cursor.item/phone_v2');
        INSERT INTO mimetypes VALUES (3, 'vnd.android.cursor.item/email_v2');
        INSERT INTO raw_contacts VALUES (10, 0, 'local', 'com.android.local');
        INSERT INTO data VALUES (1, 10, 1, 'Alice Example', NULL, NULL, NULL);
        INSERT INTO data VALUES (2, 10, 2, '+15551234567', '2', 'Mobile', NULL);
        INSERT INTO data VALUES (3, 10, 3, 'alice@example.test', '1', 'Home', NULL);
        """
    )
    connection.commit()
    connection.close()

    with SafeSQLiteReader(path) as reader:
        artifacts = AndroidContactsParser().parse(reader, _context())

    assert len(artifacts) == 1
    assert artifacts[0].title == "Alice Example"
    assert artifacts[0].metadata["phones"][0]["number"] == "+15551234567"
    assert artifacts[0].metadata["emails"][0]["address"] == "alice@example.test"


def test_sms_and_mms_known_answers(tmp_path: Path) -> None:
    path = tmp_path / "mmssms.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE sms (
            _id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER,
            date_sent INTEGER, read INTEGER, seen INTEGER, type INTEGER, body TEXT,
            service_center TEXT, sub_id INTEGER, creator TEXT
        );
        INSERT INTO sms VALUES (
            1, 7, '+15550000001', 1704067200000, 1704067200000, 1, 1, 1,
            'Known SMS', NULL, 1, 'fixture'
        );
        CREATE TABLE pdu (
            _id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, date_sent INTEGER,
            msg_box INTEGER, read INTEGER, seen INTEGER, sub TEXT, ct_t TEXT
        );
        CREATE TABLE part (
            _id INTEGER PRIMARY KEY, mid INTEGER, ct TEXT, text TEXT, _data TEXT,
            name TEXT, fn TEXT, cid TEXT, cl TEXT
        );
        CREATE TABLE addr (msg_id INTEGER, address TEXT, type INTEGER, charset INTEGER);
        INSERT INTO pdu VALUES (
            2, 8, 1704067200, 1704067200, 1, 1, 1, 'Subject',
            'application/vnd.wap.multipart.related'
        );
        INSERT INTO part VALUES (20, 2, 'text/plain', 'Known MMS', NULL, NULL, NULL, NULL, NULL);
        INSERT INTO addr VALUES (2, '+15550000002', 137, 106);
        """
    )
    connection.commit()
    connection.close()

    with SafeSQLiteReader(path) as reader:
        sms = AndroidSmsParser().parse(reader, _context())
        mms = AndroidMmsParser().parse(reader, _context())

    assert sms[0].summary == "Known SMS"
    assert sms[0].metadata["direction"] == "inbox"
    assert sms[0].event_time is not None and sms[0].event_time.year == 2024
    assert mms[0].summary == "Known MMS"
    assert "+15550000002" in mms[0].title
    assert mms[0].event_time is not None and mms[0].event_time.year == 2024


def test_call_log_known_answer_and_registry(tmp_path: Path) -> None:
    path = tmp_path / "calllog.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE calls (
            _id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER,
            type INTEGER, name TEXT, geocoded_location TEXT
        );
        INSERT INTO calls VALUES (1, '+15550000003', 1704067200000, 42, 2, 'Bob', 'Test City');
        """
    )
    connection.commit()
    connection.close()

    with SafeSQLiteReader(path) as reader:
        artifacts = AndroidCallLogParser().parse(reader, _context())
        compatible = android_parser_registry().compatible(reader.table_names())

    assert artifacts[0].title == "Outgoing call: +15550000003"
    assert artifacts[0].summary == "Duration 42 second(s)"
    assert [parser.metadata.parser_id for parser in compatible] == ["android.call_log"]
