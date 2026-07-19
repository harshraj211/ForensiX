"""Shared normalization helpers for Android artifact parsers."""

from datetime import UTC, datetime
from typing import Any

from forensix_forensic.evidence_io import SafeSQLiteError, SafeSQLiteReader


class AndroidArtifactParserError(ValueError):
    """Raised when an Android database does not match a supported schema."""


def require_columns(reader: SafeSQLiteReader, table: str, required: set[str]) -> frozenset[str]:
    columns = reader.column_names(table)
    missing = required - columns
    if missing:
        raise AndroidArtifactParserError(
            f"Android table '{table}' is missing required columns: {', '.join(sorted(missing))}."
        )
    return columns


def optional_column(columns: frozenset[str], name: str, alias: str | None = None) -> str:
    output = alias or name
    if name in columns:
        return f'"{name}" AS "{output}"'
    return f'NULL AS "{output}"'


def android_timestamp(value: object, *, seconds: bool = False) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, (int, float, str, bytes)):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if not seconds:
        numeric /= 1000
    try:
        parsed = datetime.fromtimestamp(numeric, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    if not 1990 <= parsed.year <= 2200:
        return None
    return parsed


def text(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def integer(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, (int, float, str, bytes)):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def compact_metadata(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None and item != []}


def parser_error(error: SafeSQLiteError) -> AndroidArtifactParserError:
    return AndroidArtifactParserError(str(error))
