"""Schema-gated Android system, browser, and OEM artifact parsers."""

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from forensix_forensic.evidence_io import (
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    SafeSQLiteError,
    SafeSQLiteReader,
)

from .common import (
    android_timestamp,
    compact_metadata,
    integer,
    optional_column,
    parser_error,
    require_columns,
    text,
)


def _query(
    reader: SafeSQLiteReader,
    table: str,
    required: set[str],
    optional: tuple[str, ...],
    order_by: str,
) -> tuple[Mapping[str, object], ...]:
    columns = require_columns(reader, table, required)
    selected = [
        *(f'"{name}"' for name in sorted(required)),
        *(optional_column(columns, name) for name in optional),
    ]
    try:
        return tuple(
            reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table}" ORDER BY "{order_by}"'  # noqa: S608
            )
        )
    except SafeSQLiteError as error:
        raise parser_error(error) from error


class AndroidCalendarEventParser:
    metadata = ParserMetadata(
        parser_id="android.calendar.events",
        name="Android Calendar events",
        version="1.0.0",
        artifact_categories=("calendar",),
        required_tables=frozenset({"Events"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.android.providers.calendar", "calendar.db"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "Events" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        rows = _query(
            reader,
            "Events",
            {"_id", "dtstart"},
            (
                "dtend",
                "title",
                "description",
                "eventLocation",
                "eventTimezone",
                "calendar_id",
                "allDay",
                "deleted",
                "lastDate",
            ),
            "dtstart",
        )
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        deleted = integer(row.get("deleted")) == 1
        return ParsedArtifact(
            category="application",
            subtype="calendar_event",
            title=text(row.get("title")) or "Untitled calendar event",
            summary=(
                text(row.get("description"))
                or text(row.get("eventLocation"))
                or "No event description"
            ),
            event_time=android_timestamp(row.get("dtstart")),
            source_locator=f"{context.input_locator}#Events:{identifier}",
            status="deleted" if deleted else "active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "android_calendar"}),
        )


class AndroidDownloadsParser:
    metadata = ParserMetadata(
        parser_id="android.downloads.provider",
        name="Android Downloads provider",
        version="1.0.0",
        artifact_categories=("download",),
        required_tables=frozenset({"downloads"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.android.providers.downloads", "downloads.db"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "downloads" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        rows = _query(
            reader,
            "downloads",
            {"_id", "lastmod"},
            (
                "uri",
                "_data",
                "title",
                "description",
                "mimetype",
                "total_bytes",
                "status",
                "deleted",
            ),
            "lastmod",
        )
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        deleted = integer(row.get("deleted")) == 1
        title = text(row.get("title")) or text(row.get("_data")) or "Downloaded item"
        return ParsedArtifact(
            category="file",
            subtype="download_record",
            title=title,
            summary=(
                text(row.get("uri"))
                or text(row.get("description"))
                or "Download source unavailable"
            ),
            event_time=android_timestamp(row.get("lastmod")),
            source_locator=f"{context.input_locator}#downloads:{identifier}",
            status="deleted" if deleted else "active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "android_downloads"}),
        )


class ChromeHistoryParser:
    metadata = ParserMetadata(
        parser_id="android.chrome.history",
        name="Chrome visit history",
        version="1.0.0",
        artifact_categories=("browser",),
        required_tables=frozenset({"urls", "visits"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.android.chrome", "app_chrome", "chrome/history"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return self.metadata.required_tables.issubset(tables)

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        require_columns(reader, "urls", {"id", "url"})
        visit_columns = require_columns(reader, "visits", {"id", "url", "visit_time"})
        title = "u.title" if "title" in reader.column_names("urls") else "NULL"
        transition = "v.transition" if "transition" in visit_columns else "NULL"
        try:
            rows = reader.execute_select(  # noqa: S608
                "SELECT v.id AS visit_id, v.url AS url_id, v.visit_time, "  # noqa: S608
                f"{transition} AS transition, u.url, {title} AS title "  # noqa: S608
                "FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time, v.id"
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("visit_id"))
        url = text(row.get("url"))
        return ParsedArtifact(
            category="application",
            subtype="browser_visit",
            title=text(row.get("title")) or url or "Browser visit",
            summary=url or "URL unavailable",
            event_time=_chrome_timestamp(row.get("visit_time")),
            source_locator=f"{context.input_locator}#visits:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "chrome"}),
        )


class AndroidNotificationParser:
    metadata = ParserMetadata(
        parser_id="android.notifications",
        name="Android notification history",
        version="1.0.0",
        artifact_categories=("notification",),
        required_tables=frozenset({"notifications"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("notification",),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "notifications" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        rows = _query(
            reader,
            "notifications",
            {"_id", "post_time"},
            ("package_name", "title", "text", "channel_id", "category", "dismissed"),
            "post_time",
        )
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        package = text(row.get("package_name"))
        return ParsedArtifact(
            category="system",
            subtype="notification",
            title=text(row.get("title")) or f"Notification from {package or 'unknown app'}",
            summary=text(row.get("text")) or "Notification text unavailable",
            event_time=android_timestamp(row.get("post_time")),
            source_locator=f"{context.input_locator}#notifications:{identifier}",
            status="active",
            confidence="medium",
            metadata=compact_metadata({**row, "application": package}),
        )


class AndroidNotesParser:
    metadata = ParserMetadata(
        parser_id="android.notes",
        name="OEM notes interchange",
        version="1.0.0",
        artifact_categories=("note",),
        required_tables=frozenset({"notes"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("notes", "memo"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "notes" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        rows = _query(
            reader,
            "notes",
            {"_id", "modified_time"},
            ("title", "content", "created_time", "deleted"),
            "modified_time",
        )
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        return ParsedArtifact(
            category="application",
            subtype="note",
            title=text(row.get("title")) or "Untitled note",
            summary=text(row.get("content")) or "Note content unavailable",
            event_time=android_timestamp(row.get("modified_time")),
            source_locator=f"{context.input_locator}#notes:{identifier}",
            status="deleted" if integer(row.get("deleted")) == 1 else "active",
            confidence="medium",
            metadata=compact_metadata({**row, "application": "oem_notes"}),
        )


class AndroidLocationParser:
    metadata = ParserMetadata(
        parser_id="android.location.records",
        name="Android location interchange",
        version="1.0.0",
        artifact_categories=("location",),
        required_tables=frozenset({"locations"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("location",),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "locations" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        rows = _query(
            reader,
            "locations",
            {"_id", "timestamp", "latitude", "longitude"},
            ("accuracy", "altitude", "provider"),
            "timestamp",
        )
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        latitude = row.get("latitude")
        longitude = row.get("longitude")
        return ParsedArtifact(
            category="location",
            subtype="location_observation",
            title=f"Location {latitude}, {longitude}",
            summary=f"Provider {text(row.get('provider')) or 'unknown'}",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#locations:{identifier}",
            status="active",
            confidence="medium",
            metadata=compact_metadata(dict(row)),
        )


def _chrome_timestamp(value: object) -> datetime | None:
    numeric = integer(value)
    if numeric is None:
        return None
    try:
        parsed = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=numeric)
    except (OverflowError, ValueError):
        return None
    return parsed if 1990 <= parsed.year <= 2200 else None
