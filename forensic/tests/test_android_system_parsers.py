import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from forensix_forensic.android_artifacts import (
    AndroidCalendarEventParser,
    AndroidDownloadsParser,
    AndroidLocationParser,
    AndroidNotesParser,
    AndroidNotificationParser,
    ChromeHistoryParser,
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


def test_calendar_and_download_provider_known_answers(tmp_path: Path) -> None:
    calendar_path = tmp_path / "calendar.db"
    connection = sqlite3.connect(calendar_path)
    connection.execute(
        "CREATE TABLE Events (_id INTEGER PRIMARY KEY, dtstart INTEGER, dtend INTEGER, "
        "title TEXT, description TEXT, eventLocation TEXT, eventTimezone TEXT, deleted INTEGER)"
    )
    connection.execute(
        "INSERT INTO Events VALUES (1, 1704067200000, 1704070800000, "
        "'Known meeting', 'Validation event', 'Lab', 'UTC', 0)"
    )
    connection.commit()
    connection.close()
    with SafeSQLiteReader(calendar_path) as reader:
        event = AndroidCalendarEventParser().parse(
            reader, _context("com.android.providers.calendar/databases/calendar.db")
        )[0]
    assert event.title == "Known meeting"
    assert event.event_time is not None and event.event_time.year == 2024

    downloads_path = tmp_path / "downloads.db"
    connection = sqlite3.connect(downloads_path)
    connection.execute(
        "CREATE TABLE downloads (_id INTEGER PRIMARY KEY, lastmod INTEGER, uri TEXT, "
        "_data TEXT, title TEXT, mimetype TEXT, total_bytes INTEGER, status INTEGER)"
    )
    connection.execute(
        "INSERT INTO downloads VALUES (2, 1704067200000, 'https://example.test/a.pdf', "
        "'/storage/emulated/0/Download/a.pdf', 'a.pdf', 'application/pdf', 1234, 200)"
    )
    connection.commit()
    connection.close()
    with SafeSQLiteReader(downloads_path) as reader:
        download = AndroidDownloadsParser().parse(
            reader, _context("com.android.providers.downloads/databases/downloads.db")
        )[0]
    assert download.title == "a.pdf"
    assert download.summary == "https://example.test/a.pdf"


def test_chrome_history_converts_webkit_timestamp(tmp_path: Path) -> None:
    path = tmp_path / "History"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT);
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER
        );
        INSERT INTO urls VALUES (1, 'https://example.test/', 'Known page');
        INSERT INTO visits VALUES (3, 1, 13348540800000000, 805306368);
        """
    )
    connection.commit()
    connection.close()
    with SafeSQLiteReader(path) as reader:
        visit = ChromeHistoryParser().parse(
            reader, _context("data/data/com.android.chrome/app_chrome/Default/History")
        )[0]
    assert visit.title == "Known page"
    assert visit.summary == "https://example.test/"
    assert visit.event_time == datetime(2024, 1, 1, tzinfo=UTC)


def test_oem_notification_notes_and_location_interchange(tmp_path: Path) -> None:
    path = tmp_path / "oem-artifacts.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE notifications (
            _id INTEGER PRIMARY KEY, post_time INTEGER, package_name TEXT, title TEXT, text TEXT
        );
        INSERT INTO notifications VALUES (
            1, 1704067200000, 'com.example', 'Alert', 'Known notification'
        );
        CREATE TABLE notes (
            _id INTEGER PRIMARY KEY, modified_time INTEGER, title TEXT,
            content TEXT, deleted INTEGER
        );
        INSERT INTO notes VALUES (2, 1704067200000, 'Known note', 'Known body', 0);
        CREATE TABLE locations (
            _id INTEGER PRIMARY KEY, timestamp INTEGER, latitude REAL, longitude REAL,
            accuracy REAL, provider TEXT
        );
        INSERT INTO locations VALUES (3, 1704067200000, 28.6139, 77.2090, 5.5, 'gps');
        """
    )
    connection.commit()
    connection.close()
    with SafeSQLiteReader(path) as reader:
        notification = AndroidNotificationParser().parse(
            reader, _context("oem/notification/history.db")
        )[0]
        note = AndroidNotesParser().parse(reader, _context("oem/notes/notes.db"))[0]
        location = AndroidLocationParser().parse(reader, _context("oem/location/locations.db"))[0]
    assert notification.summary == "Known notification"
    assert note.summary == "Known body"
    assert "28.6139" in location.title and location.metadata["provider"] == "gps"


def test_system_parsers_are_path_gated(tmp_path: Path) -> None:
    path = tmp_path / "ambiguous.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE notes (_id INTEGER, modified_time INTEGER)")
    connection.commit()
    connection.close()
    with SafeSQLiteReader(path) as reader:
        without_hint = android_parser_registry().compatible(reader.table_names())
        with_hint = android_parser_registry().compatible(
            reader.table_names(), source_locator="vendor/notes/notes.db"
        )
    assert "android.notes" not in {item.metadata.parser_id for item in without_hint}
    assert "android.notes" in {item.metadata.parser_id for item in with_hint}
