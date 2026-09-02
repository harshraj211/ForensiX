"""Schema-gated Android system, browser, and OEM artifact parsers."""

# ruff: noqa: E501, S608

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


class FirefoxHistoryParser:
    """Parse Firefox for Android visit history from places.sqlite."""

    metadata = ParserMetadata(
        parser_id="android.firefox.history",
        name="Firefox visit history",
        version="1.0.0",
        artifact_categories=("browser",),
        required_tables=frozenset({"moz_places", "moz_historyvisits"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("org.mozilla.firefox", "places.sqlite", "firefox"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return self.metadata.required_tables.issubset(tables)

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        require_columns(reader, "moz_places", {"id", "url"})
        visit_columns = require_columns(
            reader, "moz_historyvisits", {"id", "place_id", "visit_date"}
        )
        title_expr = "p.title" if "title" in reader.column_names("moz_places") else "NULL"
        visit_type = "v.visit_type" if "visit_type" in visit_columns else "NULL"
        try:
            rows = reader.execute_select(  # noqa: S608
                f"SELECT v.id AS visit_id, v.place_id, v.visit_date, "
                f"{visit_type} AS visit_type, p.url, {title_expr} AS title "
                "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id "
                "ORDER BY v.visit_date, v.id"
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("visit_id"))
        url = text(row.get("url"))
        # Firefox stores visit_date in microseconds since epoch
        visit_us = integer(row.get("visit_date"))
        event_time: datetime | None = None
        if visit_us is not None:
            try:
                event_time = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=visit_us)
                if not (1990 <= event_time.year <= 2200):
                    event_time = None
            except (OverflowError, ValueError):
                event_time = None
        return ParsedArtifact(
            category="application",
            subtype="browser_visit",
            title=text(row.get("title")) or url or "Firefox browser visit",
            summary=url or "URL unavailable",
            event_time=event_time,
            source_locator=f"{context.input_locator}#moz_historyvisits:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "firefox"}),
        )


class SamsungBrowserHistoryParser:
    """Parse Samsung Internet browser history from BrowserProvider.db."""

    metadata = ParserMetadata(
        parser_id="android.samsung.browser.history",
        name="Samsung Internet visit history",
        version="1.0.0",
        artifact_categories=("browser",),
        required_tables=frozenset({"history"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.sec.android.app.sbrowser", "BrowserProvider.db", "samsung"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "history" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        rows = _query(
            reader,
            "history",
            {"_id", "date"},
            ("url", "title", "visits", "favicon_id"),
            "date",
        )
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        url = text(row.get("url"))
        return ParsedArtifact(
            category="application",
            subtype="browser_visit",
            title=text(row.get("title")) or url or "Samsung browser visit",
            summary=url or "URL unavailable",
            event_time=android_timestamp(row.get("date")),
            source_locator=f"{context.input_locator}#history:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "samsung_browser"}),
        )


class EdgeHistoryParser:
    """Parse Microsoft Edge for Android visit history (Chrome-compatible schema)."""

    metadata = ParserMetadata(
        parser_id="android.edge.history",
        name="Edge visit history",
        version="1.0.0",
        artifact_categories=("browser",),
        required_tables=frozenset({"urls", "visits"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.microsoft.emmx", "edge", "History"),
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
                "SELECT v.id AS visit_id, v.url AS url_id, v.visit_time, "
                f"{transition} AS transition, u.url, {title} AS title "
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
            title=text(row.get("title")) or url or "Edge browser visit",
            summary=url or "URL unavailable",
            event_time=_chrome_timestamp(row.get("visit_time")),
            source_locator=f"{context.input_locator}#visits:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "edge"}),
        )


class GoogleMapsSearchParser:
    """Parse Google Maps recent searches from gmm_storage.db → search_queries table."""

    metadata = ParserMetadata(
        parser_id="android.google_maps.searches",
        name="Google Maps search queries",
        version="1.0.0",
        artifact_categories=("location",),
        required_tables=frozenset({"search_queries"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.google.android.apps.maps", "gmm_storage.db", "maps"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "search_queries" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        rows = _query(
            reader,
            "search_queries",
            {"_id", "timestamp"},
            ("query", "result_title", "result_lat", "result_lng", "provider"),
            "timestamp",
        )
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        query = text(row.get("query"))
        result = text(row.get("result_title"))
        lat = row.get("result_lat")
        lng = row.get("result_lng")
        coords = f" ({lat}, {lng})" if lat is not None and lng is not None else ""
        return ParsedArtifact(
            category="location",
            subtype="maps_search",
            title=f"Maps search: {query or 'unknown'}",
            summary=(result or query or "Search query unavailable") + coords,
            event_time=android_timestamp(row.get("timestamp"), seconds=True),
            source_locator=f"{context.input_locator}#search_queries:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "google_maps"}),
        )


class AppUsageStatsParser:
    """Parse per-application usage events from the app_ops or usage_events SQLite interchange.

    This parser targets the SQLite format produced by ALEAPP or exported directly from
    the UsageStatsManager content provider. It expects a table named ``app_events`` or
    ``usage_events`` with at least a package name, timestamp, and event type column.
    """

    metadata = ParserMetadata(
        parser_id="android.app_usage_stats",
        name="App usage events",
        version="1.0.0",
        artifact_categories=("application",),
        required_tables=frozenset({"app_events"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("usagestats", "app_events", "usage"),
    )

    # Android UsageEvents event type codes
    _EVENT_TYPES: dict[int, str] = {
        1: "moved_to_foreground",
        2: "moved_to_background",
        5: "configuration_change",
        7: "user_interaction",
        8: "shortcut_invocation",
        15: "standby_bucket_changed",
        16: "foreground_service_start",
        17: "foreground_service_stop",
        23: "activity_stopped",
        26: "activity_resumed",
    }

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "app_events" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        rows = _query(
            reader,
            "app_events",
            {"_id", "timestamp"},
            ("package_name", "class_name", "event_type", "instance_id", "shortcut_id"),
            "timestamp",
        )
        return [self._artifact(row, context) for row in rows]

    def _artifact(self, row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        package = text(row.get("package_name"))
        event_code = integer(row.get("event_type")) or 0
        event_label = self._EVENT_TYPES.get(event_code, f"event_{event_code}")
        return ParsedArtifact(
            category="application",
            subtype="app_usage_event",
            title=f"{package or 'Unknown app'}: {event_label.replace('_', ' ')}",
            summary=f"Package {package or 'unknown'} — {event_label}",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#app_events:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "event_label": event_label}),
        )


class AndroidWifiProfilesParser:
    """Parse configured and historical Wi-Fi network profiles."""

    metadata = ParserMetadata(
        parser_id="android.wifi.profiles",
        name="Wi-Fi network profiles and known hotspots",
        version="1.0.0",
        artifact_categories=("location", "system"),
        required_tables=frozenset({"wifi_profiles"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("wifi", "wpa_supplicant", "WifiConfigStore"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "wifi_profiles" in tables or "wifi_configurations" in tables or "wifi_networks" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        tables = reader.table_names()
        table_name = "wifi_profiles" if "wifi_profiles" in tables else (
            "wifi_configurations" if "wifi_configurations" in tables else "wifi_networks"
        )
        columns = reader.column_names(table_name)
        id_col = '"_id"' if "_id" in columns else '"id"'
        time_col = '"last_connected"' if "last_connected" in columns else (
            '"timestamp"' if "timestamp" in columns else id_col
        )
        selected = [
            f"{id_col} AS _id",
            f"{time_col} AS timestamp",
            *(
                optional_column(columns, name)
                for name in (
                    "ssid",
                    "bssid",
                    "psk",
                    "pre_shared_key",
                    "key_mgmt",
                    "hidden",
                    "latitude",
                    "longitude",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table_name}" ORDER BY {time_col}, {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        ssid = text(row.get("ssid")) or "Hidden SSID"
        bssid = text(row.get("bssid")) or ""
        key_mgmt = text(row.get("key_mgmt")) or "WPA/WPA2"
        lat = row.get("latitude")
        lng = row.get("longitude")
        coords = f" @ ({lat}, {lng})" if lat is not None and lng is not None else ""

        return ParsedArtifact(
            category="location",
            subtype="wifi_profile",
            title=f"Wi-Fi Network: {ssid}",
            summary=f"BSSID: {bssid or 'unknown'}, Security: {key_mgmt}{coords}",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#wifi_profiles:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "wifi"}),
        )


class AndroidBluetoothDevicesParser:
    """Parse paired and discovered Bluetooth devices and connection logs."""

    metadata = ParserMetadata(
        parser_id="android.bluetooth.devices",
        name="Bluetooth paired devices and history",
        version="1.0.0",
        artifact_categories=("system",),
        required_tables=frozenset({"bluetooth_devices"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("bluetooth", "bluetooth_manager"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "bluetooth_devices" in tables or "paired_devices" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        tables = reader.table_names()
        table_name = "bluetooth_devices" if "bluetooth_devices" in tables else "paired_devices"
        columns = reader.column_names(table_name)
        id_col = '"_id"' if "_id" in columns else '"id"'
        time_col = '"last_connected"' if "last_connected" in columns else (
            '"paired_time"' if "paired_time" in columns else (
                '"timestamp"' if "timestamp" in columns else id_col
            )
        )
        selected = [
            f"{id_col} AS _id",
            f"{time_col} AS timestamp",
            *(
                optional_column(columns, name)
                for name in (
                    "name",
                    "address",
                    "mac_address",
                    "device_class",
                    "link_key",
                    "paired_time",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table_name}" ORDER BY {time_col}, {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        name = text(row.get("name")) or "Unknown Bluetooth Device"
        address = text(row.get("address")) or text(row.get("mac_address")) or "00:00:00:00:00:00"
        dev_class = text(row.get("device_class")) or "unknown"

        return ParsedArtifact(
            category="system",
            subtype="bluetooth_device",
            title=f"Bluetooth: {name}",
            summary=f"MAC: {address}, Class: {dev_class}",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#bluetooth_devices:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "bluetooth"}),
        )


class AndroidCellTowerParser:
    """Parse cellular network observations and cell tower tower IDs."""

    metadata = ParserMetadata(
        parser_id="android.telephony.cell_towers",
        name="Cell tower and cellular network observations",
        version="1.0.0",
        artifact_categories=("location", "system"),
        required_tables=frozenset({"cell_towers"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("telephony", "cell_towers", "radio"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "cell_towers" in tables or "telephony_registry" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        tables = reader.table_names()
        table_name = "cell_towers" if "cell_towers" in tables else "telephony_registry"
        columns = reader.column_names(table_name)
        id_col = '"_id"' if "_id" in columns else '"id"'
        time_col = '"timestamp"' if "timestamp" in columns else id_col
        selected = [
            f"{id_col} AS _id",
            f"{time_col} AS timestamp",
            *(
                optional_column(columns, name)
                for name in (
                    "cid",
                    "lac",
                    "mcc",
                    "mnc",
                    "network_type",
                    "signal_strength",
                    "latitude",
                    "longitude",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table_name}" ORDER BY {time_col}, {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        cid = row.get("cid")
        lac = row.get("lac")
        mcc = row.get("mcc")
        mnc = row.get("mnc")
        net_type = text(row.get("network_type")) or "Cellular"
        lat = row.get("latitude")
        lng = row.get("longitude")
        coords = f" @ ({lat}, {lng})" if lat is not None and lng is not None else ""

        return ParsedArtifact(
            category="location",
            subtype="cell_tower_observation",
            title=f"Cell Tower: CID {cid}, LAC {lac}",
            summary=f"MCC {mcc} MNC {mnc} — {net_type}{coords}",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#cell_towers:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "telephony"}),
        )


class AndroidUsersParser:
    """Parse Android system users, multi-user profiles, and Dual App sandboxes."""

    metadata = ParserMetadata(
        parser_id="android.system.users",
        name="Android system users and work profiles",
        version="1.0.0",
        artifact_categories=("system",),
        required_tables=frozenset({"users"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("system/users", "userlist", "users.db", "users"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "users" in tables or "user_profiles" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        tables = reader.table_names()
        table_name = "users" if "users" in tables else "user_profiles"
        columns = reader.column_names(table_name)
        id_col = '"id"' if "id" in columns else ('"_id"' if "_id" in columns else '"user_id"')
        time_col = '"created_at"' if "created_at" in columns else (
            '"creation_time"' if "creation_time" in columns else (
                '"last_logged_in"' if "last_logged_in" in columns else id_col
            )
        )
        selected = [
            f"{id_col} AS id",
            f"{time_col} AS timestamp",
            *(
                optional_column(columns, name)
                for name in (
                    "name",
                    "flags",
                    "serial_number",
                    "user_type",
                    "profile_group_id",
                    "restricted",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table_name}" ORDER BY {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        user_id = integer(row.get("id"))
        name = text(row.get("name")) or (
            "Primary Owner" if user_id == 0 else (
                "Work Profile" if user_id == 10 else (
                    "Dual App Clone Profile" if user_id in (11, 999) else f"User {user_id}"
                )
            )
        )
        u_type = text(row.get("user_type")) or (
            "android.os.usertype.full.SYSTEM" if user_id == 0 else "android.os.usertype.profile.MANAGED"
        )
        sandbox_path = f"/data/user/{user_id}/"

        return ParsedArtifact(
            category="system",
            subtype="user_profile",
            title=f"Android User {user_id}: {name}",
            summary=f"Type: {u_type}, Sandbox: {sandbox_path}",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#users:{user_id}",
            status="active",
            confidence="high",
            metadata=compact_metadata(
                {**row, "user_id": user_id, "sandbox_path": sandbox_path, "application": "system"}
            ),
        )
