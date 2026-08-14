"""Conservative parsers for recognized plaintext social-application schemas.

These adapters never acquire private data and never decrypt databases. They run only
against a verified working copy whose archive path identifies the expected application.
"""

# ruff: noqa: E501, SIM103

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


class WhatsAppMessageParser:
    """Parse the modern plaintext WhatsApp ``message`` table when lawfully obtained."""

    metadata = ParserMetadata(
        parser_id="android.whatsapp.message",
        name="WhatsApp plaintext messages",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"message"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.whatsapp", "msgstore"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "message" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        columns = require_columns(reader, "message", {"_id", "timestamp"})
        selected = [
            '"_id"',
            '"timestamp"',
            *(
                optional_column(columns, name)
                for name in (
                    "text_data",
                    "from_me",
                    "message_type",
                    "chat_row_id",
                    "sender_jid_row_id",
                    "status",
                    "starred",
                    "remote_resource",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "message" ORDER BY "timestamp", "_id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        outgoing = integer(row.get("from_me")) == 1
        body = text(row.get("text_data"))
        direction = "outgoing" if outgoing else "incoming_or_system"
        return ParsedArtifact(
            category="communication",
            subtype="whatsapp_message",
            title=f"WhatsApp {direction.replace('_', ' ')} message",
            summary=body or "WhatsApp message body unavailable or non-text",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#message:{identifier}",
            status="active",
            confidence="medium",
            metadata=compact_metadata({**row, "application": "whatsapp", "direction": direction}),
        )


class TelegramMessageParser:
    """Parse a deliberately narrow plaintext Telegram fixture-compatible schema."""

    metadata = ParserMetadata(
        parser_id="android.telegram.messages",
        name="Telegram plaintext message rows",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"messages"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("org.telegram", "cache4.db", "telegram"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "messages" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        columns = require_columns(reader, "messages", {"_id", "date"})
        if not {"message", "text"}.intersection(columns):
            from .common import AndroidArtifactParserError

            raise AndroidArtifactParserError(
                "Telegram message rows are encoded as unsupported binary blobs in this schema."
            )
        selected = [
            '"_id"',
            '"date"',
            optional_column(columns, "message"),
            optional_column(columns, "text"),
            *(optional_column(columns, name) for name in ("dialog_id", "sender_id", "out")),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "messages" ORDER BY "date", "_id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        body = text(row.get("message")) or text(row.get("text"))
        outgoing = integer(row.get("out")) == 1
        return ParsedArtifact(
            category="communication",
            subtype="telegram_message",
            title=f"Telegram {'outgoing' if outgoing else 'incoming or system'} message",
            summary=body or "Telegram text unavailable",
            event_time=android_timestamp(row.get("date"), seconds=True),
            source_locator=f"{context.input_locator}#messages:{identifier}",
            status="active",
            confidence="medium",
            metadata=compact_metadata({**row, "application": "telegram"}),
        )


class MetaMessageParser:
    """Parse only the documented ForensiX interchange schema for a Meta application."""

    def __init__(self, app_id: str, name: str, path_hints: tuple[str, ...]) -> None:
        self.app_id = app_id
        self.metadata = ParserMetadata(
            parser_id=f"android.{app_id}.messages",
            name=f"{name} plaintext message interchange",
            version="1.0.0",
            artifact_categories=("message",),
            required_tables=frozenset({"messages"}),
            access_level="filesystem",
            maturity="experimental",
            source_path_hints=path_hints,
        )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "messages" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        columns = require_columns(reader, "messages", {"_id", "timestamp_ms", "text"})
        selected = [
            '"_id"',
            '"timestamp_ms"',
            '"text"',
            *(
                optional_column(columns, name)
                for name in ("thread_id", "sender_id", "sender_name", "is_outgoing", "message_type")
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "messages" ORDER BY "timestamp_ms", "_id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    def _artifact(self, row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        return ParsedArtifact(
            category="communication",
            subtype=f"{self.app_id}_message",
            title=f"{self.metadata.name.split(' plaintext', 1)[0]} message",
            summary=text(row.get("text")) or "Message text unavailable",
            event_time=android_timestamp(row.get("timestamp_ms")),
            source_locator=f"{context.input_locator}#messages:{identifier}",
            status="active",
            confidence="low",
            metadata=compact_metadata({**row, "application": self.app_id}),
        )


def meta_message_parsers() -> tuple[MetaMessageParser, ...]:
    return (
        MetaMessageParser("messenger", "Messenger", ("com.facebook.orca", "messenger")),
        MetaMessageParser("facebook", "Facebook", ("com.facebook.katana", "facebook")),
        MetaMessageParser("instagram", "Instagram", ("com.instagram.android", "instagram")),
    )


class SnapchatMessageParser:
    """Parse Snapchat chat messages from the Chat table in main.db."""

    metadata = ParserMetadata(
        parser_id="android.snapchat.messages",
        name="Snapchat chat messages",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"Chat"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.snapchat.android", "main.db", "snapchat"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "Chat" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        columns = require_columns(reader, "Chat", {"_id", "createdAt"})
        selected = [
            '"_id"',
            '"createdAt"',
            *(
                optional_column(columns, name)
                for name in ("conversationId", "senderId", "type", "text", "status", "mediaType")
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "Chat" ORDER BY "createdAt", "_id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        body = text(row.get("text"))
        media = text(row.get("mediaType"))
        return ParsedArtifact(
            category="communication",
            subtype="snapchat_message",
            title="Snapchat chat message",
            summary=body
            or (f"Snapchat media: {media}" if media else "Snapchat message unavailable"),
            event_time=android_timestamp(row.get("createdAt")),
            source_locator=f"{context.input_locator}#Chat:{identifier}",
            status="active",
            confidence="medium",
            metadata=compact_metadata({**row, "application": "snapchat"}),
        )


class DiscordMessageParser:
    """Parse Discord messages from the messages table in the SQLite cache database."""

    metadata = ParserMetadata(
        parser_id="android.discord.messages",
        name="Discord messages",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"messages"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.discord", "cache_v9", "discord"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "messages" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        columns = require_columns(reader, "messages", {"id", "timestamp"})
        if "channel_id" not in columns and "author_id" not in columns:
            from .common import AndroidArtifactParserError

            raise AndroidArtifactParserError(
                "Discord messages table missing channel_id and author_id; schema unrecognised."
            )
        selected = [
            '"id"',
            '"timestamp"',
            *(
                optional_column(columns, name)
                for name in ("channel_id", "author_id", "content", "type", "edited_timestamp")
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "messages" ORDER BY "timestamp", "id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        msg_id = text(row.get("id")) or str(integer(row.get("id")))
        body = text(row.get("content"))
        channel = text(row.get("channel_id"))
        return ParsedArtifact(
            category="communication",
            subtype="discord_message",
            title=f"Discord message{f' in channel {channel}' if channel else ''}",
            summary=body or "Discord message content unavailable",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#messages:{msg_id}",
            status="active",
            confidence="medium",
            metadata=compact_metadata({**row, "application": "discord"}),
        )


class TikTokMessageParser:
    """Parse TikTok direct messages from msg_table in AwemeIM.db."""

    metadata = ParserMetadata(
        parser_id="android.tiktok.messages",
        name="TikTok direct messages",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"msg_table"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.zhiliaoapp.musically", "com.ss.android.ugc.trill", "AwemeIM.db"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "msg_table" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        columns = require_columns(reader, "msg_table", {"msg_id", "create_time"})
        selected = [
            '"msg_id"',
            '"create_time"',
            *(
                optional_column(columns, name)
                for name in (
                    "content",
                    "sender_uid",
                    "receiver_uid",
                    "conversation_id",
                    "read_status",
                    "msg_type",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "msg_table" ORDER BY "create_time", "msg_id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = text(row.get("msg_id")) or str(integer(row.get("msg_id")))
        body = text(row.get("content"))
        return ParsedArtifact(
            category="communication",
            subtype="tiktok_message",
            title="TikTok direct message",
            summary=body or "TikTok message content unavailable or media",
            event_time=android_timestamp(row.get("create_time"), seconds=True),
            source_locator=f"{context.input_locator}#msg_table:{identifier}",
            status="active",
            confidence="medium",
            metadata=compact_metadata({**row, "application": "tiktok"}),
        )


class GmailMessageParser:
    """Parse Gmail message summaries from mailstore.*.db."""

    metadata = ParserMetadata(
        parser_id="android.gmail.messages",
        name="Gmail message summaries",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"messages"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.google.android.gm", "mailstore", "gmail"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        if "messages" not in tables:
            return False
        return True

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        columns = require_columns(reader, "messages", {"_id", "dateSentMs"})
        if not {"fromAddress", "subject", "snippet", "toAddresses"}.intersection(columns):
            from .common import AndroidArtifactParserError

            raise AndroidArtifactParserError(
                "Gmail messages table missing expected email columns; schema unrecognised."
            )
        selected = [
            '"_id"',
            '"dateSentMs"',
            *(
                optional_column(columns, name)
                for name in (
                    "fromAddress",
                    "toAddresses",
                    "subject",
                    "snippet",
                    "read",
                    "starred",
                    "deleted",
                    "labelIds",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "messages" ORDER BY "dateSentMs", "_id"'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error
        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        subject = text(row.get("subject"))
        sender = text(row.get("fromAddress"))
        snippet = text(row.get("snippet"))
        deleted = integer(row.get("deleted")) == 1
        return ParsedArtifact(
            category="communication",
            subtype="gmail_message",
            title=subject or f"Email from {sender or 'unknown'}",
            summary=snippet or sender or "Email snippet unavailable",
            event_time=android_timestamp(row.get("dateSentMs")),
            source_locator=f"{context.input_locator}#messages:{identifier}",
            status="deleted" if deleted else "active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "gmail"}),
        )
