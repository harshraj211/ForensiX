"""Read-only, immutable SQLite access for allowlisted parser code."""

import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import TracebackType
from urllib.parse import quote

type SQLiteValue = None | int | float | str | bytes
type SQLiteRow = dict[str, SQLiteValue]


class SafeSQLiteError(ValueError):
    """Raised when a database or parser query violates read-only policy."""


_DENIED_ACTIONS = frozenset(
    action
    for action in (
        getattr(sqlite3, name, -1)
        for name in (
            "SQLITE_ALTER_TABLE",
            "SQLITE_ATTACH",
            "SQLITE_CREATE_INDEX",
            "SQLITE_CREATE_TABLE",
            "SQLITE_CREATE_TEMP_INDEX",
            "SQLITE_CREATE_TEMP_TABLE",
            "SQLITE_CREATE_TEMP_TRIGGER",
            "SQLITE_CREATE_TEMP_VIEW",
            "SQLITE_CREATE_TRIGGER",
            "SQLITE_CREATE_VIEW",
            "SQLITE_DELETE",
            "SQLITE_DETACH",
            "SQLITE_DROP_INDEX",
            "SQLITE_DROP_TABLE",
            "SQLITE_DROP_TEMP_INDEX",
            "SQLITE_DROP_TEMP_TABLE",
            "SQLITE_DROP_TEMP_TRIGGER",
            "SQLITE_DROP_TEMP_VIEW",
            "SQLITE_DROP_TRIGGER",
            "SQLITE_DROP_VIEW",
            "SQLITE_INSERT",
            "SQLITE_PRAGMA",
            "SQLITE_REINDEX",
            "SQLITE_SAVEPOINT",
            "SQLITE_TRANSACTION",
            "SQLITE_UPDATE",
        )
    )
    if action >= 0
)
_DENIED_FUNCTIONS = frozenset({"load_extension", "readfile", "writefile"})


class SafeSQLiteReader:
    """Opens one verified regular SQLite file without journals or write access."""

    def __init__(
        self,
        path: Path,
        *,
        max_rows: int = 100_000,
        max_query_characters: int = 20_000,
        progress_opcodes: int = 1_000_000,
    ) -> None:
        if min(max_rows, max_query_characters, progress_opcodes) < 1:
            raise ValueError("SQLite reader limits must be positive integers.")
        if path.is_symlink() or not path.is_file():
            raise SafeSQLiteError("The SQLite source must be a regular non-link file.")
        with path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                raise SafeSQLiteError("The source does not have a SQLite 3 file signature.")
        self.path = path.resolve(strict=True)
        self.max_rows = max_rows
        self.max_query_characters = max_query_characters
        self.progress_opcodes = progress_opcodes
        self._connection: sqlite3.Connection | None = None

    def __enter__(self) -> "SafeSQLiteReader":
        uri = f"file:{quote(self.path.as_posix(), safe='/:')}?mode=ro&immutable=1"
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=1.0)
            connection.row_factory = sqlite3.Row
            connection.enable_load_extension(False)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.set_authorizer(_authorizer)
            self._connection = connection
            return self
        except sqlite3.Error as error:
            raise SafeSQLiteError("The SQLite working copy could not be opened safely.") from error

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def execute_select(
        self,
        sql: str,
        parameters: Sequence[SQLiteValue] | Mapping[str, SQLiteValue] = (),
        *,
        max_rows: int | None = None,
    ) -> list[SQLiteRow]:
        connection = self._require_connection()
        normalized = sql.strip()
        if (
            not normalized
            or len(normalized) > self.max_query_characters
            or "\x00" in normalized
            or not normalized.casefold().startswith(("select", "with"))
        ):
            raise SafeSQLiteError("Only bounded SELECT or WITH parser queries are allowed.")
        row_limit = max_rows if max_rows is not None else self.max_rows
        if row_limit < 1 or row_limit > self.max_rows:
            raise SafeSQLiteError("The requested row limit exceeds parser policy.")
        budget = self.progress_opcodes

        def progress() -> int:
            nonlocal budget
            budget -= 1000
            return int(budget <= 0)

        connection.set_progress_handler(progress, 1000)
        try:
            cursor = connection.execute(normalized, parameters)
            rows = cursor.fetchmany(row_limit + 1)
            columns = tuple(str(description[0]) for description in (cursor.description or ()))
        except sqlite3.Error as error:
            raise SafeSQLiteError("The approved SQLite parser query failed.") from error
        finally:
            connection.set_progress_handler(None, 0)
        if len(rows) > row_limit:
            raise SafeSQLiteError("The SQLite parser query exceeded its row limit.")
        return [
            {column: _sqlite_value(row[index]) for index, column in enumerate(columns)}
            for row in rows
        ]

    def table_names(self) -> frozenset[str]:
        rows = self.execute_select(
            "SELECT name FROM sqlite_schema WHERE type = ? AND name NOT LIKE ? ORDER BY name",
            ("table", "sqlite_%"),
        )
        return frozenset(str(row["name"]) for row in rows)

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise SafeSQLiteError("The SQLite reader is not open.")
        return self._connection


def _authorizer(
    action: int,
    argument_one: str | None,
    argument_two: str | None,
    database_name: str | None,
    trigger_name: str | None,
) -> int:
    del argument_one, database_name, trigger_name
    if action in _DENIED_ACTIONS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and (argument_two or "").casefold() in _DENIED_FUNCTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _sqlite_value(value: object) -> SQLiteValue:
    if value is None or isinstance(value, (int, float, str, bytes)):
        return value
    raise SafeSQLiteError("The SQLite parser returned an unsupported value type.")
