"""Shared normalization helpers for Android artifact parsers."""

from datetime import UTC, datetime
from typing import Any

from forensix_forensic.evidence_io import ParsedArtifact, SafeSQLiteError, SafeSQLiteReader


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


def normalize_timestamp_detailed(value: object, *, seconds: bool = False) -> dict[str, Any]:
    parsed = android_timestamp(value, seconds=seconds)
    return {
        "raw_value": str(value) if value is not None else None,
        "raw_unit": "seconds" if seconds else "milliseconds",
        "normalized_utc": parsed.isoformat() if parsed else None,
        "timezone_assumption": "UTC",
        "timestamp_confidence": "high" if parsed else "none",
    }


def normalize_phone_number(raw: object) -> str | None:
    val = text(raw)
    if not val:
        return None
    # Strip spaces, hyphens, parentheses
    cleaned = "".join(c for c in val if c.isdigit() or c == "+")
    if not cleaned:
        return None
    if not cleaned.startswith("+") and len(cleaned) >= 10:
        cleaned = f"+{cleaned}"
    return cleaned


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
    return int(numeric) if (numeric := integer_or_none(value)) is not None else None


def integer_or_none(value: object) -> int | None:
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


def to_timeline_event(artifact: ParsedArtifact) -> dict[str, Any] | None:
    """Convert ParsedArtifact to normalized timeline event payload if timestamp is present."""
    if not artifact.event_time:
        return None
    return {
        "event_time_utc": artifact.event_time.isoformat(),
        "category": artifact.category,
        "subtype": artifact.subtype,
        "title": artifact.title,
        "summary": artifact.summary,
        "source_locator": artifact.source_locator,
        "status": artifact.status,
        "confidence": artifact.confidence,
        "application": artifact.metadata.get("application", "unknown"),
        "metadata": artifact.metadata,
    }
