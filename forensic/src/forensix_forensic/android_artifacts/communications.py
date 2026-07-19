"""Android TelephonyProvider SMS/MMS and CallLogProvider parsers."""

from collections import defaultdict
from collections.abc import Mapping

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

_SMS_TYPES = {1: "inbox", 2: "sent", 3: "draft", 4: "outbox", 5: "failed", 6: "queued"}
_CALL_TYPES = {
    1: "incoming",
    2: "outgoing",
    3: "missed",
    4: "voicemail",
    5: "rejected",
    6: "blocked",
    7: "answered_externally",
}


class AndroidSmsParser:
    metadata = ParserMetadata(
        parser_id="android.telephony.sms",
        name="Android SMS",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"sms"}),
        access_level="filesystem",
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "sms" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        del context
        columns = require_columns(reader, "sms", {"_id", "date", "type"})
        selected = [
            '"_id"',
            '"date"',
            '"type"',
            *(
                optional_column(columns, name)
                for name in (
                    "thread_id",
                    "address",
                    "body",
                    "read",
                    "seen",
                    "date_sent",
                    "service_center",
                    "sub_id",
                    "creator",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "sms" ORDER BY "date", "_id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object]) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        sms_type = _SMS_TYPES.get(integer(row.get("type")) or 0, "unknown")
        address = text(row.get("address"))
        body = text(row.get("body"))
        return ParsedArtifact(
            category="communication",
            subtype="sms",
            title=f"SMS {sms_type}: {address or 'unknown party'}",
            summary=body or "SMS body unavailable",
            event_time=android_timestamp(row.get("date")),
            source_locator=f"sms:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "direction": sms_type}),
        )


class AndroidMmsParser:
    metadata = ParserMetadata(
        parser_id="android.telephony.mms",
        name="Android MMS",
        version="1.0.0",
        artifact_categories=("message", "attachment"),
        required_tables=frozenset({"pdu", "part", "addr"}),
        access_level="filesystem",
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return self.metadata.required_tables.issubset(tables)

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        del context
        pdu_columns = require_columns(reader, "pdu", {"_id", "date", "msg_box"})
        part_columns = require_columns(reader, "part", {"mid", "ct"})
        addr_columns = require_columns(reader, "addr", {"msg_id", "address", "type"})
        pdu_select = [
            '"_id"',
            '"date"',
            '"msg_box"',
            *(
                optional_column(pdu_columns, name)
                for name in ("thread_id", "date_sent", "read", "seen", "sub", "ct_t")
            ),
        ]
        part_select = [
            '"mid"',
            '"ct"',
            *(
                optional_column(part_columns, name)
                for name in ("_id", "text", "_data", "name", "fn", "cid", "cl")
            ),
        ]
        addr_select = [
            '"msg_id"',
            '"address"',
            '"type"',
            optional_column(addr_columns, "charset"),
        ]
        try:
            pdus = reader.execute_select(
                f'SELECT {", ".join(pdu_select)} FROM "pdu" ORDER BY "date", "_id"'  # noqa: S608
            )
            parts = reader.execute_select(
                f'SELECT {", ".join(part_select)} FROM "part" ORDER BY "mid"'  # noqa: S608
            )
            addresses = reader.execute_select(
                f'SELECT {", ".join(addr_select)} FROM "addr" ORDER BY "msg_id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        parts_by_message: dict[int, list[Mapping[str, object]]] = defaultdict(list)
        addresses_by_message: dict[int, list[Mapping[str, object]]] = defaultdict(list)
        for item in parts:
            message_id = integer(item.get("mid"))
            if message_id is not None:
                parts_by_message[message_id].append(item)
        for item in addresses:
            message_id = integer(item.get("msg_id"))
            if message_id is not None:
                addresses_by_message[message_id].append(item)
        return [self._artifact(row, parts_by_message, addresses_by_message) for row in pdus]

    @staticmethod
    def _artifact(
        row: Mapping[str, object],
        parts: dict[int, list[Mapping[str, object]]],
        addresses: dict[int, list[Mapping[str, object]]],
    ) -> ParsedArtifact:
        identifier = integer(row.get("_id")) or 0
        message_parts = parts.get(identifier, [])
        text_parts = [value for item in message_parts if (value := text(item.get("text")))]
        attachment_count = sum(1 for item in message_parts if text(item.get("_data")))
        parties = [
            value for item in addresses.get(identifier, []) if (value := text(item.get("address")))
        ]
        return ParsedArtifact(
            category="communication",
            subtype="mms",
            title=f"MMS with {', '.join(parties[:3]) or 'unknown party'}",
            summary=" ".join(text_parts) or f"{attachment_count} attachment(s)",
            event_time=android_timestamp(row.get("date"), seconds=True),
            source_locator=f"pdu:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata(
                {**row, "addresses": addresses.get(identifier, []), "parts": message_parts}
            ),
        )


class AndroidCallLogParser:
    metadata = ParserMetadata(
        parser_id="android.call_log",
        name="Android Call Log",
        version="1.0.0",
        artifact_categories=("call",),
        required_tables=frozenset({"calls"}),
        access_level="filesystem",
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "calls" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        del context
        columns = require_columns(reader, "calls", {"_id", "number", "date", "duration", "type"})
        selected = [
            '"_id"',
            '"number"',
            '"date"',
            '"duration"',
            '"type"',
            *(
                optional_column(columns, name)
                for name in (
                    "name",
                    "geocoded_location",
                    "phone_account_address",
                    "features",
                    "data_usage",
                    "via_number",
                    "transcription",
                    "is_read",
                    "block_reason",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "calls" ORDER BY "date", "_id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object]) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        call_type = _CALL_TYPES.get(integer(row.get("type")) or 0, "unknown")
        number = text(row.get("number"))
        duration = integer(row.get("duration")) or 0
        return ParsedArtifact(
            category="communication",
            subtype="call",
            title=f"{call_type.replace('_', ' ').title()} call: {number or 'unknown party'}",
            summary=f"Duration {duration} second(s)",
            event_time=android_timestamp(row.get("date")),
            source_locator=f"calls:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "call_type": call_type}),
        )
