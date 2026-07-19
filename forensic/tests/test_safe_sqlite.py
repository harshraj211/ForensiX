import sqlite3
from pathlib import Path

import pytest

from forensix_forensic.evidence_io import SafeSQLiteError, SafeSQLiteReader


def _database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    connection.executemany("INSERT INTO messages(body) VALUES (?)", [("one",), ("two",)])
    connection.commit()
    connection.close()


def test_reader_lists_tables_and_executes_bounded_select(tmp_path: Path) -> None:
    source = tmp_path / "messages.db"
    _database(source)

    with SafeSQLiteReader(source, max_rows=10) as reader:
        assert reader.table_names() == frozenset({"messages"})
        assert reader.execute_select("SELECT id, body FROM messages ORDER BY id") == [
            {"id": 1, "body": "one"},
            {"id": 2, "body": "two"},
        ]


def test_reader_denies_writes_and_multiple_statements(tmp_path: Path) -> None:
    source = tmp_path / "messages.db"
    _database(source)

    with SafeSQLiteReader(source) as reader:
        with pytest.raises(SafeSQLiteError, match="Only bounded"):
            reader.execute_select("DELETE FROM messages")
        with pytest.raises(SafeSQLiteError, match="failed"):
            reader.execute_select("SELECT * FROM messages; DELETE FROM messages")

    connection = sqlite3.connect(source)
    assert connection.execute("SELECT count(*) FROM messages").fetchone()[0] == 2
    connection.close()


def test_reader_enforces_row_limit(tmp_path: Path) -> None:
    source = tmp_path / "messages.db"
    _database(source)

    with (
        SafeSQLiteReader(source, max_rows=1) as reader,
        pytest.raises(SafeSQLiteError, match="row limit"),
    ):
        reader.execute_select("SELECT * FROM messages ORDER BY id")


def test_reader_rejects_non_sqlite_input(tmp_path: Path) -> None:
    source = tmp_path / "not-sqlite.bin"
    source.write_bytes(b"not a database")

    with pytest.raises(SafeSQLiteError, match="signature"):
        SafeSQLiteReader(source)
