"""Conservative parsers for recognized plaintext social-application schemas.

These adapters never acquire private data and never decrypt databases. They run only
against a verified working copy whose archive path identifies the expected application.
"""

# ruff: noqa: E501, SIM102, SIM103, S110

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
    """Parse modern or legacy plaintext WhatsApp database schemas when lawfully obtained."""

    metadata = ParserMetadata(
        parser_id="android.whatsapp.message",
        name="WhatsApp plaintext messages",
        version="1.1.0",
        artifact_categories=("message", "attachment"),
        required_tables=frozenset({"message"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.whatsapp", "msgstore"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "message" in tables or "messages" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        tables = reader.table_names()
        table_name = "message" if "message" in tables else "messages"
        columns = reader.column_names(table_name)
        if "_id" not in columns and "key_id" not in columns:
            from .common import AndroidArtifactParserError

            raise AndroidArtifactParserError("WhatsApp table missing primary key identifier.")

        id_col = '"_id"' if "_id" in columns else '"key_id"'
        time_col = (
            '"timestamp"'
            if "timestamp" in columns
            else ('"received_timestamp"' if "received_timestamp" in columns else id_col)
        )

        selected = [
            f"{id_col} AS _id",
            f"{time_col} AS timestamp",
            *(
                optional_column(columns, name)
                for name in (
                    "text_data",
                    "data",
                    "from_me",
                    "key_from_me",
                    "message_type",
                    "chat_row_id",
                    "sender_jid_row_id",
                    "key_remote_jid",
                    "status",
                    "starred",
                    "remote_resource",
                    "media_caption",
                    "media_wa_type",
                    "media_name",
                    "media_size",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table_name}" ORDER BY {time_col}, {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error

        # Resolve JIDs if jid table is present
        jid_map: dict[int, str] = {}
        if "jid" in tables:
            try:
                jid_cols = reader.column_names("jid")
                if "_id" in jid_cols and "raw_string" in jid_cols:
                    jid_rows = reader.execute_select('SELECT "_id", "raw_string" FROM "jid"')
                    for r in jid_rows:
                        jid_id = integer(r.get("_id"))
                        raw_jid = text(r.get("raw_string"))
                        if jid_id is not None and raw_jid:
                            jid_map[jid_id] = raw_jid
            except Exception:
                pass

        return [self._artifact(row, context, jid_map) for row in rows]

    @staticmethod
    def _artifact(
        row: Mapping[str, object], context: ParserContext, jid_map: dict[int, str]
    ) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        from_me_val = (
            row.get("from_me") if row.get("from_me") is not None else row.get("key_from_me")
        )
        outgoing = integer(from_me_val) == 1
        body = (
            text(row.get("text_data"))
            or text(row.get("data"))
            or text(row.get("media_caption"))
            or text(row.get("media_name"))
        )
        sender_jid_id = integer(row.get("sender_jid_row_id"))
        chat_jid_id = integer(row.get("chat_row_id"))
        sender_jid = (
            jid_map.get(sender_jid_id, "") if sender_jid_id else text(row.get("key_remote_jid"))
        )
        chat_jid = jid_map.get(chat_jid_id, "") if chat_jid_id else ""

        direction = "outgoing" if outgoing else "incoming_or_system"
        title = f"WhatsApp {direction.replace('_', ' ')} message"
        if sender_jid:
            title += f": {sender_jid}"

        return ParsedArtifact(
            category="communication",
            subtype="whatsapp_message",
            title=title,
            summary=body or "WhatsApp message body unavailable or non-text",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#message:{identifier}",
            status="active",
            confidence="high" if body else "medium",
            metadata=compact_metadata(
                {
                    **row,
                    "application": "whatsapp",
                    "direction": direction,
                    "resolved_sender": sender_jid,
                    "resolved_chat": chat_jid,
                }
            ),
        )


class TelegramMessageParser:
    """Parse Telegram SQLite databases (cache4.db) with MTProto TL binary blob decoding."""

    metadata = ParserMetadata(
        parser_id="android.telegram.messages",
        name="Telegram messages and binary TL payloads",
        version="1.1.0",
        artifact_categories=("message", "attachment"),
        required_tables=frozenset({"messages"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("org.telegram", "cache4.db", "telegram"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "messages" in tables or "messages_v2" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        tables = reader.table_names()
        table_name = "messages" if "messages" in tables else "messages_v2"
        columns = reader.column_names(table_name)
        id_col = '"mid"' if "mid" in columns else ('"_id"' if "_id" in columns else '"id"')
        date_col = '"date"' if "date" in columns else id_col

        selected = [
            f"{id_col} AS _id",
            f"{date_col} AS date",
            *(
                optional_column(columns, name)
                for name in (
                    "message",
                    "text",
                    "data",
                    "media",
                    "dialog_id",
                    "uid",
                    "sender_id",
                    "out",
                    "read_state",
                    "send_state",
                    "ttl",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table_name}" ORDER BY {date_col}, {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error

        if not {"message", "text"}.intersection(columns):
            if not rows or "data" not in columns:
                from .common import AndroidArtifactParserError

                raise AndroidArtifactParserError(
                    "Telegram message rows are encoded as unsupported binary blobs in this schema."
                )

        artifacts = [self._artifact(row, context) for row in rows]
        # If no plaintext columns exist and none of the binary blobs yielded readable text, reject
        if not {"message", "text"}.intersection(columns):
            if not any(a.summary and a.summary != "Telegram text unavailable" for a in artifacts):
                from .common import AndroidArtifactParserError

                raise AndroidArtifactParserError(
                    "Telegram message rows are encoded as unsupported binary blobs in this schema."
                )

        return artifacts

    @classmethod
    def _artifact(cls, row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        body = text(row.get("message")) or text(row.get("text"))
        data_blob = row.get("data")
        media_blob = row.get("media")

        # Decode binary MTProto / Type Language (TL) serialized message object if text not in plain column
        tl_meta: dict[str, object] = {}
        if not body and isinstance(data_blob, (bytes, bytearray)):
            decoded_text, tl_meta = cls._decode_tl_message(bytes(data_blob))
            if decoded_text:
                body = decoded_text

        if not body and isinstance(media_blob, (bytes, bytearray)):
            media_desc = cls._extract_tl_string(bytes(media_blob))
            if media_desc:
                body = f"[Telegram Media: {media_desc}]"

        outgoing = integer(row.get("out")) == 1
        return ParsedArtifact(
            category="communication",
            subtype="telegram_message",
            title=f"Telegram {'outgoing' if outgoing else 'incoming or system'} message",
            summary=body or "Telegram text unavailable",
            event_time=android_timestamp(row.get("date"), seconds=True),
            source_locator=f"{context.input_locator}#messages:{identifier}",
            status="active",
            confidence="high" if body else "medium",
            metadata=compact_metadata(
                {
                    **row,
                    **tl_meta,
                    "application": "telegram",
                    "has_tl_binary_payload": isinstance(data_blob, (bytes, bytearray)),
                }
            ),
        )

    @classmethod
    def _decode_tl_message(cls, data: bytes) -> tuple[str | None, dict[str, object]]:
        """Lightweight pure-Python TL-object deserializer for Telegram message blobs."""
        if len(data) < 8:
            return None, {}

        meta: dict[str, object] = {}
        extracted_strings: list[str] = []

        # Scan for TL strings (skipping initial 8 bytes for constructor ID + flags)
        pos = 8
        while pos < len(data):
            b = data[pos]
            if b == 0xFE and pos + 4 <= len(data):
                str_len = data[pos + 1] | (data[pos + 2] << 8) | (data[pos + 3] << 16)
                str_start = pos + 4
                padding = (4 - ((str_len + 4) % 4)) % 4
                if 0 < str_len <= 65536 and str_start + str_len + padding <= len(data):
                    pad_bytes = data[str_start + str_len : str_start + str_len + padding]
                    if pad_bytes == b"\x00" * padding:
                        try:
                            val = data[str_start : str_start + str_len].decode("utf-8").strip()
                            if val and any(c.isalnum() for c in val):
                                extracted_strings.append(val)
                                pos = str_start + str_len + padding
                                continue
                        except UnicodeDecodeError:
                            pass
            elif 0 < b < 254:
                str_len = b
                str_start = pos + 1
                padding = (4 - ((str_len + 1) % 4)) % 4
                if str_start + str_len + padding <= len(data):
                    pad_bytes = data[str_start + str_len : str_start + str_len + padding]
                    if pad_bytes == b"\x00" * padding:
                        try:
                            val = data[str_start : str_start + str_len].decode("utf-8").strip()
                            if val and any(c.isalnum() for c in val):
                                extracted_strings.append(val)
                                pos = str_start + str_len + padding
                                continue
                        except UnicodeDecodeError:
                            pass
            pos += 1

        body: str | None = None
        if extracted_strings:
            filtered = [s for s in extracted_strings if not s.startswith("TL_") and len(s) > 1]
            if filtered:
                body = filtered[0]
                meta["tl_extracted_tokens"] = filtered[:5]
            else:
                body = extracted_strings[0]

        return body, meta

    @staticmethod
    def _extract_tl_string(blob: bytes) -> str | None:
        """Extract first printable string from binary TL media blob."""
        if len(blob) < 4:
            return None
        try:
            # Look for printable ASCII/UTF-8 run
            chars: list[str] = []
            for b in blob:
                if 32 <= b <= 126:
                    chars.append(chr(b))
                elif chars and len(chars) > 3:
                    break
                else:
                    chars.clear()
            if len(chars) > 3:
                return "".join(chars)
        except Exception:
            pass
        return None


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
    """Parse cached Discord messages and direct messages."""

    metadata = ParserMetadata(
        parser_id="android.discord.messages",
        name="Discord messages and chat channels",
        version="1.0.0",
        artifact_categories=("message", "attachment"),
        required_tables=frozenset({"discord_messages"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.discord", "cache_v9", "discord"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "discord_messages" in tables or "messages" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        tables = reader.table_names()
        table_name = "discord_messages" if "discord_messages" in tables else "messages"
        columns = reader.column_names(table_name)
        id_col = '"_id"' if "_id" in columns else ('"id"' if "id" in columns else '"mid"')
        time_col = (
            '"timestamp_ms"'
            if "timestamp_ms" in columns
            else (
                '"timestamp"'
                if "timestamp" in columns
                else ('"date"' if "date" in columns else id_col)
            )
        )
        selected = [
            f"{id_col} AS _id",
            f"{time_col} AS timestamp",
            *(
                optional_column(columns, name)
                for name in (
                    "content",
                    "text",
                    "author_name",
                    "author_id",
                    "channel_name",
                    "channel_id",
                    "attachments",
                    "out",
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
        body = text(row.get("content")) or text(row.get("text")) or text(row.get("attachments"))
        author = text(row.get("author_name")) or text(row.get("author_id")) or "Unknown author"
        channel = text(row.get("channel_name")) or text(row.get("channel_id"))
        title = f"Discord message from {author}"
        if channel:
            title += f" in #{channel}"

        return ParsedArtifact(
            category="communication",
            subtype="discord_message",
            title=title,
            summary=body or "Discord message content unavailable",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#discord_messages:{identifier}",
            status="active",
            confidence="high",
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


class WeChatMessageParser:
    """Parse decrypted WeChat message database (EnMicroMsg.db / message table)."""

    metadata = ParserMetadata(
        parser_id="android.wechat.messages",
        name="WeChat messages and conversations",
        version="1.0.0",
        artifact_categories=("message", "attachment"),
        required_tables=frozenset({"wechat_message"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.tencent.mm", "MicroMsg", "EnMicroMsg", "wechat"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "wechat_message" in tables or "message" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        tables = reader.table_names()
        table_name = "wechat_message" if "wechat_message" in tables else "message"
        columns = reader.column_names(table_name)
        id_col = '"msgId"' if "msgId" in columns else ('"_id"' if "_id" in columns else '"id"')
        time_col = (
            '"createTime"'
            if "createTime" in columns
            else ('"timestamp"' if "timestamp" in columns else id_col)
        )
        selected = [
            f"{id_col} AS _id",
            f"{time_col} AS timestamp",
            *(
                optional_column(columns, name)
                for name in (
                    "content",
                    "talker",
                    "isSend",
                    "type",
                    "status",
                    "imgPath",
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
        content = text(row.get("content")) or text(row.get("imgPath"))
        talker = text(row.get("talker")) or "Unknown contact"
        outgoing = integer(row.get("isSend")) == 1
        direction = "outgoing" if outgoing else "incoming"

        return ParsedArtifact(
            category="communication",
            subtype="wechat_message",
            title=f"WeChat {direction} message: {talker}",
            summary=content or "WeChat message body unavailable",
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#wechat_message:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata({**row, "application": "wechat", "direction": direction}),
        )
