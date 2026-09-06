"""Android TelephonyProvider SMS/MMS and CallLogProvider adapters."""

# ruff: noqa: E501

from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

from forensix_forensic.evidence_io import (
    ParsedArtifact,
    ParserContext,
    SafeSQLiteError,
    SafeSQLiteReader,
)

from .adapter import AdapterMetadata, AdapterParseResult, AdapterParseStatus, BaseApplicationAdapter
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


class AndroidSmsParser(BaseApplicationAdapter):
    """Android TelephonyProvider SMS adapter."""

    metadata = AdapterMetadata(
        parser_id="android.telephony.sms",
        name="Android SMS",
        version="1.1.0",
        package_name="com.android.providers.telephony",
        application_name="Android Telephony Provider (SMS)",
        artifact_categories=("message",),
        required_tables=frozenset({"sms"}),
        access_level="filesystem",
        maturity="validated",
        source_path_hints=(),
        supported_schema_families=("android_sms_db",),
        supported_formats=("sqlite",),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "sms" in tables

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        if reader is None:
            return AdapterParseResult(
                status=AdapterParseStatus.UNSUPPORTED, reason="Reader required"
            )

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

        artifacts = [self._artifact(row) for row in rows]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema="android_sms_db",
        )

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
            metadata=compact_metadata(
                {**row, "direction": sms_type, "application": "android.telephony"}
            ),
        )


class AndroidMmsParser(BaseApplicationAdapter):
    """Android TelephonyProvider MMS adapter."""

    metadata = AdapterMetadata(
        parser_id="android.telephony.mms",
        name="Android MMS",
        version="1.1.0",
        package_name="com.android.providers.telephony",
        application_name="Android Telephony Provider (MMS)",
        artifact_categories=("message", "attachment"),
        required_tables=frozenset({"pdu", "part", "addr"}),
        access_level="filesystem",
        maturity="validated",
        source_path_hints=(),
        supported_schema_families=("android_mms_db",),
        supported_formats=("sqlite",),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return self.metadata.required_tables.issubset(tables)

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        if reader is None:
            return AdapterParseResult(
                status=AdapterParseStatus.UNSUPPORTED, reason="Reader required"
            )

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
            m_id = integer(item.get("mid"))
            if m_id is not None:
                parts_by_message[m_id].append(item)
        for item in addresses:
            m_id = integer(item.get("msg_id"))
            if m_id is not None:
                addresses_by_message[m_id].append(item)

        artifacts = [self._artifact(row, parts_by_message, addresses_by_message) for row in pdus]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema="android_mms_db",
        )

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
                {
                    **row,
                    "addresses": addresses.get(identifier, []),
                    "parts": message_parts,
                    "application": "android.telephony",
                }
            ),
        )


class AndroidTelephonyAdapter(BaseApplicationAdapter):
    """Combined Android TelephonyProvider SMS/MMS adapter."""

    metadata = AdapterMetadata(
        parser_id="android.telephony.provider",
        name="Android Telephony Provider Adapter",
        version="1.1.0",
        package_name="com.android.providers.telephony",
        application_name="Android Telephony Provider",
        artifact_categories=("message", "attachment"),
        required_tables=frozenset({"sms"}),
        access_level="filesystem",
        maturity="validated",
        source_path_hints=(),
        supported_schema_families=("android_mmssms_db",),
        supported_formats=("sqlite",),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "sms" in tables or "pdu" in tables

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        if reader is None:
            return AdapterParseResult(
                status=AdapterParseStatus.UNSUPPORTED, reason="Reader required"
            )

        artifacts: list[ParsedArtifact] = []
        sms_adapter = AndroidSmsParser()
        mms_adapter = AndroidMmsParser()

        if reader.has_table("sms"):
            res_sms = sms_adapter.parse_adapter(reader, context, source_path=source_path)
            artifacts.extend(res_sms.artifacts)
        if reader.has_table("pdu") and reader.has_table("part") and reader.has_table("addr"):
            res_mms = mms_adapter.parse_adapter(reader, context, source_path=source_path)
            artifacts.extend(res_mms.artifacts)

        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED if artifacts else AdapterParseStatus.UNSUPPORTED,
            artifacts=artifacts,
            detected_schema="android_mmssms_db",
        )


class AndroidCallLogAdapter(BaseApplicationAdapter):
    """Android CallLogProvider calllog.db adapter."""

    metadata = AdapterMetadata(
        parser_id="android.call_log",
        name="Android Call Log Adapter",
        version="1.1.0",
        package_name="com.android.providers.calllog",
        application_name="Android Call Log Provider",
        artifact_categories=("call",),
        required_tables=frozenset({"calls"}),
        access_level="filesystem",
        maturity="validated",
        source_path_hints=(),
        supported_schema_families=("android_calllog_db",),
        supported_formats=("sqlite",),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "calls" in tables

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        if reader is None:
            return AdapterParseResult(
                status=AdapterParseStatus.UNSUPPORTED, reason="Reader required"
            )

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

        artifacts = [self._artifact(row) for row in rows]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema="android_calllog_db",
        )

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
            metadata=compact_metadata(
                {**row, "call_type": call_type, "application": "android.calllog"}
            ),
        )


AndroidCallLogParser = AndroidCallLogAdapter
