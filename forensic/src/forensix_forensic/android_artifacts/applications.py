"""Unified Application Adapters for Recognized Android Applications.

Implements contract-driven adapters for WhatsApp, Telegram, Signal, Snapchat, Discord,
TikTok, Gmail, WeChat, Meta apps, and accessible Agent artifacts.
"""

# ruff: noqa: E501, SIM102, SIM103, S110, S314

import xml.etree.ElementTree as ET
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from forensix_forensic.evidence_io import (
    ParsedArtifact,
    ParserContext,
    SafeSQLiteError,
    SafeSQLiteReader,
)
from forensix_forensic.evidence_io.sqlite_carver import SQLiteCarver

from .adapter import AdapterMetadata, AdapterParseResult, AdapterParseStatus, BaseApplicationAdapter
from .common import (
    AndroidArtifactParserError,
    android_timestamp,
    compact_metadata,
    integer,
    normalize_phone_number,
    normalize_timestamp_detailed,
    optional_column,
    parser_error,
    require_columns,
    text,
)
from .relationships import ForensicRelationship, RelationshipType


class WhatsAppAdapter(BaseApplicationAdapter):
    """WhatsApp Reference Adapter supporting v14+, legacy, wa.db, and encrypted backups."""

    metadata = AdapterMetadata(
        parser_id="android.whatsapp.message",
        name="WhatsApp Application Forensic Adapter",
        version="2.1.0",
        package_name="com.whatsapp",
        application_name="WhatsApp",
        artifact_categories=("message", "attachment", "contact"),
        required_tables=frozenset({"message"}),
        access_level="filesystem",
        maturity="validated",
        source_path_hints=("com.whatsapp", "msgstore", "wa.db"),
        supported_schema_families=(
            "whatsapp_v14_message",
            "whatsapp_legacy_message",
            "whatsapp_wa_contacts",
        ),
        supported_formats=("sqlite", "crypt12", "crypt14", "crypt15"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "message" in tables or "messages" in tables or "wa_contacts" in tables

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        if reader is None:
            return AdapterParseResult(
                status=AdapterParseStatus.UNSUPPORTED,
                reason="SafeSQLiteReader is required for WhatsApp database parsing",
            )

        tables = reader.table_names()
        artifacts: list[ParsedArtifact] = []
        relationships: list[ForensicRelationship] = []

        # 1. Check for wa_contacts table
        if "wa_contacts" in tables:
            artifacts.extend(self._parse_wa_contacts(reader, context))

        # 2. Check for message/messages table
        if "message" in tables or "messages" in tables:
            msg_artifacts, msg_rels = self._parse_messages(reader, context, tables)
            artifacts.extend(msg_artifacts)
            relationships.extend(msg_rels)

        if not artifacts:
            return AdapterParseResult(
                status=AdapterParseStatus.UNKNOWN_SCHEMA,
                reason="WhatsApp database missing recognized message or contact schemas",
            )

        # 3. Deleted record carving from B-Tree leaf pages
        carved = self._carve_deleted_records(reader, context)
        artifacts.extend(carved)

        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            relationships=relationships,
            detected_schema="whatsapp_v14_or_legacy",
            confidence=1.0,
            reason="Successfully parsed WhatsApp database schema and relationships",
        )

    def _parse_wa_contacts(
        self, reader: SafeSQLiteReader, context: ParserContext
    ) -> list[ParsedArtifact]:
        columns = reader.column_names("wa_contacts")
        if "_id" not in columns:
            return []

        id_col = '"_id"'
        selected = [
            f"{id_col} AS _id",
            *(
                optional_column(columns, name)
                for name in (
                    "jid",
                    "display_name",
                    "wa_name",
                    "number",
                    "given_name",
                    "family_name",
                    "status",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "wa_contacts" ORDER BY {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error

        db_name = getattr(reader, "path", Path(context.input_locator)).name
        contacts: list[ParsedArtifact] = []
        for row in rows:
            identifier = integer(row.get("_id"))
            display_name = (
                text(row.get("display_name"))
                or text(row.get("wa_name"))
                or text(row.get("given_name"))
            )
            raw_number = text(row.get("number"))
            formatted_number = normalize_phone_number(raw_number) or raw_number
            raw_jid = text(row.get("jid"))
            title = display_name or formatted_number or raw_jid or f"WhatsApp Contact {identifier}"

            contacts.append(
                ParsedArtifact(
                    category="contact",
                    subtype="whatsapp_contact",
                    title=f"WhatsApp Contact: {title}",
                    summary=f"Phone: {formatted_number or 'N/A'}, JID: {raw_jid or 'N/A'}",
                    event_time=None,
                    source_locator=f"{context.input_locator}#wa_contacts:{identifier}",
                    status="active",
                    confidence="high",
                    metadata=compact_metadata(
                        {
                            "raw_contact_id": identifier,
                            "display_name": display_name,
                            "formatted_number": formatted_number,
                            "raw_jid": raw_jid,
                            "status_text": text(row.get("status")),
                            "application": "whatsapp",
                            "schema_family": "whatsapp_wa_contacts",
                            "source_database": db_name,
                            "source_table": "wa_contacts",
                        }
                    ),
                )
            )
        return contacts

    def _parse_messages(
        self, reader: SafeSQLiteReader, context: ParserContext, tables: frozenset[str]
    ) -> tuple[list[ParsedArtifact], list[ForensicRelationship]]:
        table_name = "message" if "message" in tables else "messages"
        columns = reader.column_names(table_name)
        if "_id" not in columns and "key_id" not in columns:
            raise AndroidArtifactParserError("WhatsApp table missing primary key identifier.")

        id_col = '"_id"' if "_id" in columns else '"key_id"'
        time_col = (
            '"timestamp"'
            if "timestamp" in columns
            else ('"received_timestamp"' if "received_timestamp" in columns else id_col)
        )
        is_seconds = time_col == '"received_timestamp"' and "timestamp" not in columns

        schema_family = (
            "whatsapp_v14_message"
            if any(c in columns for c in ("chat_row_id", "sender_jid_row_id", "text_data"))
            else "whatsapp_legacy_message"
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
                    "media_url",
                    "file_path",
                )
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table_name}" ORDER BY {time_col}, {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error

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

        contact_map: dict[str, str] = {}
        if "wa_contacts" in tables:
            try:
                c_cols = reader.column_names("wa_contacts")
                if "jid" in c_cols and ("display_name" in c_cols or "wa_name" in c_cols):
                    c_rows = reader.execute_select(
                        'SELECT "jid", "display_name", "wa_name", "number" FROM "wa_contacts"'
                    )
                    for cr in c_rows:
                        cj = text(cr.get("jid"))
                        cn = (
                            text(cr.get("display_name"))
                            or text(cr.get("wa_name"))
                            or normalize_phone_number(cr.get("number"))
                        )
                        if cj and cn:
                            contact_map[cj] = cn
            except Exception:
                pass

        media_map: dict[int, dict[str, object]] = {}
        if "message_media" in tables:
            try:
                m_cols = reader.column_names("message_media")
                if "message_row_id" in m_cols:
                    m_select = [
                        '"message_row_id"',
                        *(
                            optional_column(m_cols, name)
                            for name in (
                                "file_path",
                                "file_size",
                                "mime_type",
                                "file_hash",
                                "width",
                                "height",
                            )
                        ),
                    ]
                    m_rows = reader.execute_select(
                        f'SELECT {", ".join(m_select)} FROM "message_media"'  # noqa: S608
                    )
                    for mr in m_rows:
                        m_id = integer(mr.get("message_row_id"))
                        if m_id is not None:
                            media_map[m_id] = compact_metadata(mr)
            except Exception:
                pass

        quoted_map: dict[int, dict[str, object]] = {}
        if "message_quoted" in tables:
            try:
                q_cols = reader.column_names("message_quoted")
                if "message_row_id" in q_cols:
                    q_select = [
                        '"message_row_id"',
                        *(
                            optional_column(q_cols, name)
                            for name in ("quoted_row_id", "text_data", "parent_message_row_id")
                        ),
                    ]
                    q_rows = reader.execute_select(
                        f'SELECT {", ".join(q_select)} FROM "message_quoted"'  # noqa: S608
                    )
                    for qr in q_rows:
                        q_id = integer(qr.get("message_row_id"))
                        if q_id is not None:
                            quoted_map[q_id] = compact_metadata(qr)
            except Exception:
                pass

        db_name = getattr(reader, "path", Path(context.input_locator)).name

        artifacts: list[ParsedArtifact] = []
        relationships: list[ForensicRelationship] = []

        for row in rows:
            art = self._artifact(
                row,
                context,
                jid_map,
                contact_map,
                media_map,
                quoted_map,
                table_name,
                schema_family,
                is_seconds,
                db_name,
            )
            artifacts.append(art)

            # Build relationships
            msg_id_str = f"whatsapp_msg_{art.metadata.get('message_id')}"
            sender = art.metadata.get("resolved_sender")
            if sender and sender != "unresolved":
                relationships.append(
                    ForensicRelationship(
                        source_entity=sender,
                        target_entity=msg_id_str,
                        relationship_type=RelationshipType.SENDER,
                        source_database=db_name,
                        source_table=table_name,
                        source_row_id=art.metadata.get("message_id"),
                    )
                )

            media_info = art.metadata.get("media_attachment")
            if isinstance(media_info, dict) and media_info.get("file_path"):
                relationships.append(
                    ForensicRelationship(
                        source_entity=msg_id_str,
                        target_entity=str(media_info["file_path"]),
                        relationship_type=RelationshipType.ATTACHED_TO,
                        source_database=db_name,
                        source_table="message_media",
                        source_row_id=art.metadata.get("message_id"),
                    )
                )

        return artifacts, relationships

    @staticmethod
    def _artifact(
        row: Mapping[str, object],
        context: ParserContext,
        jid_map: dict[int, str],
        contact_map: dict[str, str],
        media_map: dict[int, dict[str, object]],
        quoted_map: dict[int, dict[str, object]],
        table_name: str,
        schema_family: str,
        is_seconds: bool,
        db_name: str,
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
        if not sender_jid and not outgoing:
            sender_jid = text(row.get("remote_resource")) or text(row.get("key_remote_jid"))
        chat_jid = jid_map.get(chat_jid_id, "") if chat_jid_id else text(row.get("key_remote_jid"))

        sender_contact = contact_map.get(sender_jid or "", "")
        chat_contact = contact_map.get(chat_jid or "", "")

        resolved_sender = (
            sender_contact or sender_jid or ("User (Self)" if outgoing else "unresolved")
        )
        resolved_chat = chat_contact or chat_jid or "unresolved"
        contact_resolution = (
            "resolved" if (sender_contact or chat_contact or sender_jid) else "unresolved"
        )

        direction = "outgoing" if outgoing else "incoming"
        title = f"WhatsApp {direction} message"
        if resolved_sender and resolved_sender != "unresolved":
            title += f": {resolved_sender}"

        raw_status = integer(row.get("status"))
        is_deleted = raw_status == -1
        artifact_status: Literal["deleted", "active"] = "deleted" if is_deleted else "active"

        raw_timestamp = row.get("timestamp")
        timestamp_details = normalize_timestamp_detailed(raw_timestamp, seconds=is_seconds)
        event_dt = android_timestamp(raw_timestamp, seconds=is_seconds)

        msg_id_int = identifier or 0
        media_info = media_map.get(msg_id_int, {})
        if not media_info and (row.get("media_wa_type") or row.get("media_name")):
            media_info = compact_metadata(
                {
                    "file_name": text(row.get("media_name")),
                    "file_size": integer(row.get("media_size")),
                    "media_type": text(row.get("media_wa_type")),
                    "file_path": text(row.get("file_path")),
                    "media_url": text(row.get("media_url")),
                    "caption": text(row.get("media_caption")),
                }
            )

        quoted_info = quoted_map.get(msg_id_int)

        return ParsedArtifact(
            category="communication",
            subtype="whatsapp_message",
            title=title,
            summary=body
            or (
                f"WhatsApp media ({media_info.get('media_type', 'attachment')})"
                if media_info
                else "WhatsApp message body unavailable"
            ),
            event_time=event_dt,
            source_locator=f"{context.input_locator}#{table_name}:{identifier}",
            status=artifact_status,
            confidence="high" if body else "medium",
            metadata=compact_metadata(
                {
                    **row,
                    "application": "whatsapp",
                    "direction": direction,
                    "resolved_sender": resolved_sender,
                    "resolved_chat": resolved_chat,
                    "contact_resolution": contact_resolution,
                    "timestamp_details": timestamp_details,
                    "media_attachment": media_info,
                    "quoted_message": quoted_info,
                    "schema_family": schema_family,
                    "source_database": db_name,
                    "source_table": table_name,
                    "message_id": identifier,
                }
            ),
        )

    def _carve_deleted_records(
        self, reader: SafeSQLiteReader, context: ParserContext
    ) -> list[ParsedArtifact]:
        if not hasattr(reader, "path") or not reader.path.is_file():
            return []
        try:
            carver = SQLiteCarver()
            carved_records = carver.carve_file(reader.path, source_locator=context.input_locator)
        except Exception:
            return []

        db_name = getattr(reader, "path", Path(context.input_locator)).name
        carved_artifacts: list[ParsedArtifact] = []
        for rec in carved_records:
            text_candidates = [c for c in rec.columns if isinstance(c, str) and len(c.strip()) > 3]
            if not text_candidates:
                continue

            summary_text = text_candidates[0].strip()
            carved_artifacts.append(
                ParsedArtifact(
                    category="communication",
                    subtype="whatsapp_message",
                    title="WhatsApp carved deleted message",
                    summary=summary_text,
                    event_time=None,
                    source_locator=f"{context.input_locator}#carved_page_{rec.page_number}:{rec.offset_in_page}",
                    status="recovered",
                    confidence="medium",
                    metadata=compact_metadata(
                        {
                            "application": "whatsapp",
                            "record_status": "recovered",
                            "page_number": rec.page_number,
                            "offset_in_page": rec.offset_in_page,
                            "rowid": rec.rowid,
                            "carved_columns_count": len(rec.columns),
                            "source_database": db_name,
                        }
                    ),
                )
            )
        return carved_artifacts


WhatsAppMessageParser = WhatsAppAdapter


class TelegramAdapter(BaseApplicationAdapter):
    """Telegram Adapter for userconf.xml, cache4.db SQLite, and TL binary payloads."""

    metadata = AdapterMetadata(
        parser_id="android.telegram.messages",
        name="Telegram Application Forensic Adapter",
        version="1.2.0",
        package_name="org.telegram.messenger",
        application_name="Telegram",
        artifact_categories=("message", "attachment", "account", "contact"),
        required_tables=frozenset({"messages"}),
        access_level="filesystem",
        maturity="validated",
        source_path_hints=("org.telegram", "cache4.db", "telegram", "userconf.xml"),
        supported_schema_families=("telegram_messages", "telegram_userconf_xml"),
        supported_formats=("sqlite", "xml"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "messages" in tables or "messages_v2" in tables or "userconf" in tables

    def parse_userconf_xml(self, xml_content: str, context: ParserContext) -> list[ParsedArtifact]:
        """Parse Telegram userconf.xml configuration payload."""
        artifacts: list[ParsedArtifact] = []
        try:
            root = ET.fromstring(xml_content)
            user_id = None
            phone = None
            first_name = None
            last_name = None

            for elem in root.findall("string"):
                name_attr = elem.get("name")
                if name_attr in ("user_id", "id"):
                    user_id = elem.text
                elif name_attr in ("phone_number", "phone"):
                    phone = elem.text
                elif name_attr == "first_name":
                    first_name = elem.text
                elif name_attr == "last_name":
                    last_name = elem.text

            if not user_id:
                user_id = root.findtext("user_id") or root.findtext("id") or root.get("user_id")
            if not phone:
                phone = root.findtext("phone") or root.findtext("phone_number")
            if not first_name:
                first_name = root.findtext("first_name")
            if not last_name:
                last_name = root.findtext("last_name")

            if user_id or phone or first_name:
                display_name = f"{first_name or ''} {last_name or ''}".strip() or "Telegram User"
                artifacts.append(
                    ParsedArtifact(
                        category="account",
                        subtype="telegram_account",
                        title=f"Telegram Account: {display_name}",
                        summary=f"User ID: {user_id or 'N/A'}, Phone: {phone or 'N/A'}",
                        event_time=None,
                        source_locator=f"{context.input_locator}#userconf.xml",
                        status="active",
                        confidence="high",
                        metadata=compact_metadata(
                            {
                                "user_id": user_id,
                                "phone_number": phone,
                                "first_name": first_name,
                                "last_name": last_name,
                                "application": "telegram",
                                "artifact_source": "userconf.xml",
                            }
                        ),
                    )
                )
        except Exception:
            pass
        return artifacts

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        if reader is None:
            if source_path and source_path.name == "userconf.xml" and source_path.is_file():
                content = source_path.read_text(encoding="utf-8", errors="replace")
                arts = self.parse_userconf_xml(content, context)
                return AdapterParseResult(
                    status=AdapterParseStatus.SUPPORTED if arts else AdapterParseStatus.UNSUPPORTED,
                    artifacts=arts,
                    detected_schema="telegram_userconf_xml",
                )
            return AdapterParseResult(
                status=AdapterParseStatus.UNSUPPORTED,
                reason="SafeSQLiteReader or userconf.xml path required for Telegram parsing",
            )

        tables = reader.table_names()
        table_name = (
            "messages"
            if "messages" in tables
            else ("messages_v2" if "messages_v2" in tables else "")
        )
        if not table_name:
            return AdapterParseResult(
                status=AdapterParseStatus.UNKNOWN_SCHEMA,
                reason="Telegram database missing messages or messages_v2 table",
            )

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

        if not {"message", "text"}.intersection(columns) and not (
            "data" in columns or "media" in columns
        ):
            return AdapterParseResult(
                status=AdapterParseStatus.UNKNOWN_SCHEMA,
                reason="Telegram table missing message, text, data, or media columns",
            )

        artifacts = [self._artifact(row, context) for row in rows]
        if not {"message", "text"}.intersection(columns):
            if not any(a.summary and a.summary != "Telegram text unavailable" for a in artifacts):
                return AdapterParseResult(
                    status=AdapterParseStatus.UNSUPPORTED,
                    reason="Telegram rows encoded as unsupported binary blobs",
                )

        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema=f"telegram_{table_name}",
            confidence=0.9,
            reason="Successfully parsed Telegram messages",
        )

    @classmethod
    def _artifact(cls, row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        body = text(row.get("message")) or text(row.get("text"))
        data_blob = row.get("data")
        media_blob = row.get("media")

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
        if len(data) < 8:
            return None, {}

        meta: dict[str, object] = {}
        extracted_strings: list[str] = []

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
        if len(blob) < 4:
            return None
        try:
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


TelegramMessageParser = TelegramAdapter


class SignalAdapter(BaseApplicationAdapter):
    """Signal Adapter detecting SQLCipher database encryption vs accessible exports."""

    metadata = AdapterMetadata(
        parser_id="android.signal.message",
        name="Signal Application Forensic Adapter",
        version="1.0.0",
        package_name="org.thoughtcrime.securesms",
        application_name="Signal",
        artifact_categories=("message", "attachment", "contact"),
        required_tables=frozenset({"sms"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("org.thoughtcrime.securesms", "signal", "securesms"),
        supported_schema_families=("signal_sqlcipher_encrypted", "signal_plaintext_export"),
        supported_formats=("sqlite", "sqlcipher"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "sms" in tables or "mms" in tables or "recipient" in tables or "thread" in tables

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        # 1. Check if database is encrypted (SQLCipher header check)
        is_encrypted = False
        if source_path and source_path.is_file():
            try:
                with source_path.open("rb") as f:
                    header = f.read(16)
                    if header and not header.startswith(b"SQLite format 3\x00"):
                        is_encrypted = True
            except Exception:
                pass

        if is_encrypted or (reader is not None and getattr(reader, "is_encrypted", False)):
            filename = source_path.name if source_path else "signal.db"
            encrypted_artifact = ParsedArtifact(
                category="communication",
                subtype="signal_backup_artifact",
                title="Signal Encrypted Database Artifact (SQLCipher)",
                summary=f"Signal database file '{filename}' is encrypted with SQLCipher. Master key required.",
                event_time=None,
                source_locator=f"{context.input_locator}#{filename}",
                status="active",
                confidence="high",
                metadata=compact_metadata(
                    {
                        "file_name": filename,
                        "encrypted": True,
                        "parse_status": "encrypted_unparsed",
                        "encryption_type": "sqlcipher",
                        "application": "signal",
                        "package_name": "org.thoughtcrime.securesms",
                    }
                ),
            )
            return AdapterParseResult(
                status=AdapterParseStatus.ENCRYPTED_UNPARSED,
                artifacts=[encrypted_artifact],
                detected_schema="signal_sqlcipher_encrypted",
                confidence=1.0,
                reason="Signal database is encrypted with SQLCipher. 0 false message records extracted.",
            )

        if reader is None:
            return AdapterParseResult(
                status=AdapterParseStatus.UNSUPPORTED,
                reason="SafeSQLiteReader is required for Signal database parsing",
            )

        # Plaintext or decrypted Signal schema parsing
        tables = reader.table_names()
        table_name = "sms" if "sms" in tables else ("mms" if "mms" in tables else "")
        if not table_name:
            return AdapterParseResult(
                status=AdapterParseStatus.UNKNOWN_SCHEMA,
                reason="Unencrypted Signal database missing sms or mms tables",
            )

        columns = reader.column_names(table_name)
        id_col = '"_id"' if "_id" in columns else '"id"'
        date_col = (
            '"date"' if "date" in columns else ('"date_sent"' if "date_sent" in columns else id_col)
        )

        selected = [
            f"{id_col} AS _id",
            f"{date_col} AS date",
            *(
                optional_column(columns, name)
                for name in ("body", "address", "thread_id", "type", "read")
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table_name}" ORDER BY {date_col}, {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error

        artifacts: list[ParsedArtifact] = []
        for row in rows:
            identifier = integer(row.get("_id"))
            body = text(row.get("body"))
            address = text(row.get("address"))
            artifacts.append(
                ParsedArtifact(
                    category="communication",
                    subtype="signal_message",
                    title=f"Signal message: {address or 'unknown'}",
                    summary=body or "Signal message body unavailable",
                    event_time=android_timestamp(row.get("date")),
                    source_locator=f"{context.input_locator}#{table_name}:{identifier}",
                    status="active",
                    confidence="high" if body else "medium",
                    metadata=compact_metadata({**row, "application": "signal"}),
                )
            )

        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema=f"signal_plaintext_{table_name}",
            confidence=0.9,
            reason="Successfully parsed unencrypted Signal database",
        )


class MetaMessageParser(BaseApplicationAdapter):
    """Parse Meta application interchange schemas (Messenger, Facebook, Instagram)."""

    def __init__(self, app_id: str, name: str, path_hints: tuple[str, ...]) -> None:
        self.app_id = app_id
        self.metadata = AdapterMetadata(
            parser_id=f"android.{app_id}.messages",
            name=f"{name} Plaintext Message Adapter",
            version="1.0.0",
            package_name=f"com.{app_id}.android",
            application_name=name,
            artifact_categories=("message",),
            required_tables=frozenset({"messages"}),
            access_level="filesystem",
            maturity="experimental",
            source_path_hints=path_hints,
        )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "messages" in tables

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        if reader is None:
            return AdapterParseResult(
                status=AdapterParseStatus.UNSUPPORTED,
                reason="SafeSQLiteReader required",
            )
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

        artifacts = [self._artifact(row, context) for row in rows]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema="meta_messages_interchange",
        )

    def _artifact(self, row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        return ParsedArtifact(
            category="communication",
            subtype=f"{self.app_id}_message",
            title=f"{self.metadata.application_name} message",
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


class SnapchatMessageParser(BaseApplicationAdapter):
    """Snapchat Chat table parser."""

    metadata = AdapterMetadata(
        parser_id="android.snapchat.messages",
        name="Snapchat chat messages",
        version="1.0.0",
        package_name="com.snapchat.android",
        application_name="Snapchat",
        artifact_categories=("message",),
        required_tables=frozenset({"Chat"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.snapchat.android", "main.db", "snapchat"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "Chat" in tables

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

        artifacts = [self._artifact(row, context) for row in rows]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema="snapchat_chat",
        )

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


class DiscordMessageParser(BaseApplicationAdapter):
    """Discord messages parser."""

    metadata = AdapterMetadata(
        parser_id="android.discord.messages",
        name="Discord messages and chat channels",
        version="1.0.0",
        package_name="com.discord",
        application_name="Discord",
        artifact_categories=("message", "attachment"),
        required_tables=frozenset({"discord_messages"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.discord", "cache_v9", "discord"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "discord_messages" in tables or "messages" in tables

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

        artifacts = [self._artifact(row, context) for row in rows]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema=f"discord_{table_name}",
        )

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


class TikTokMessageParser(BaseApplicationAdapter):
    """TikTok direct messages parser."""

    metadata = AdapterMetadata(
        parser_id="android.tiktok.messages",
        name="TikTok direct messages",
        version="1.0.0",
        package_name="com.zhiliaoapp.musically",
        application_name="TikTok",
        artifact_categories=("message",),
        required_tables=frozenset({"msg_table"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.zhiliaoapp.musically", "com.ss.android.ugc.trill", "AwemeIM.db"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "msg_table" in tables

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

        artifacts = [self._artifact(row, context) for row in rows]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema="tiktok_msg_table",
        )

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


class GmailMessageParser(BaseApplicationAdapter):
    """Gmail mailstore parser."""

    metadata = AdapterMetadata(
        parser_id="android.gmail.messages",
        name="Gmail message summaries",
        version="1.0.0",
        package_name="com.google.android.gm",
        application_name="Gmail",
        artifact_categories=("message",),
        required_tables=frozenset({"messages"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.google.android.gm", "mailstore", "gmail"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "messages" in tables

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
        columns = require_columns(reader, "messages", {"_id", "dateSentMs"})
        if not {"fromAddress", "subject", "snippet", "toAddresses"}.intersection(columns):
            return AdapterParseResult(
                status=AdapterParseStatus.UNKNOWN_SCHEMA,
                reason="Gmail messages table missing expected email columns",
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

        artifacts = [self._artifact(row, context) for row in rows]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema="gmail_messages",
        )

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


class WeChatMessageParser(BaseApplicationAdapter):
    """WeChat EnMicroMsg parser."""

    metadata = AdapterMetadata(
        parser_id="android.wechat.messages",
        name="WeChat messages and conversations",
        version="1.0.0",
        package_name="com.tencent.mm",
        application_name="WeChat",
        artifact_categories=("message", "attachment"),
        required_tables=frozenset({"wechat_message"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("com.tencent.mm", "MicroMsg", "EnMicroMsg", "wechat"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "wechat_message" in tables or "message" in tables

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
                for name in ("content", "talker", "isSend", "type", "status", "imgPath")
            ),
        ]
        try:
            rows = reader.execute_select(
                f'SELECT {", ".join(selected)} FROM "{table_name}" ORDER BY {time_col}, {id_col}'  # noqa: S608
            )
        except SafeSQLiteError as error:
            raise parser_error(error) from error

        artifacts = [self._artifact(row, context) for row in rows]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema=f"wechat_{table_name}",
        )

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


class WhatsAppBackupArtifactParser(BaseApplicationAdapter):
    """WhatsApp backup database artifact parser."""

    metadata = AdapterMetadata(
        parser_id="android.whatsapp.backup_artifact",
        name="WhatsApp backup database artifact parser",
        version="2.0.0",
        package_name="com.whatsapp",
        application_name="WhatsApp Backup",
        artifact_categories=("message", "backup"),
        required_tables=frozenset(),
        access_level="filesystem",
        maturity="validated",
        source_path_hints=("msgstore", "wa.db", "com.whatsapp"),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return False

    def can_parse_file(self, file_name: str) -> bool:
        name = file_name.lower()
        return "msgstore" in name or "wa.db" in name

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        if source_path:
            art = self.parse_backup_file(
                source_path.name, source_path.stat().st_size if source_path.exists() else 0, context
            )
            return AdapterParseResult(
                status=AdapterParseStatus.ENCRYPTED_UNPARSED
                if art.metadata.get("encrypted")
                else AdapterParseStatus.SUPPORTED,
                artifacts=[art],
            )
        return AdapterParseResult(
            status=AdapterParseStatus.UNSUPPORTED, reason="File path required"
        )

    def parse_backup_file(
        self, file_name: str, size_bytes: int, context: ParserContext, header_bytes: bytes = b""
    ) -> ParsedArtifact:
        name = file_name.lower()
        version = "unknown"
        is_encrypted = False
        if "crypt14" in name:
            version = "crypt14"
            is_encrypted = True
        elif "crypt12" in name:
            version = "crypt12"
            is_encrypted = True
        elif "crypt15" in name:
            version = "crypt15"
            is_encrypted = True
        elif name.endswith(".db"):
            version = "plaintext_db"

        parse_status = "encrypted_unparsed" if is_encrypted else "active"

        return ParsedArtifact(
            category="communication",
            subtype="whatsapp_backup_artifact",
            title=f"WhatsApp Backup Artifact ({version})",
            summary=f"WhatsApp database backup file: {file_name} ({size_bytes} bytes, status: {parse_status})",
            event_time=None,
            source_locator=f"{context.input_locator}#{file_name}",
            status="active",
            confidence="high",
            metadata=compact_metadata(
                {
                    "file_name": file_name,
                    "size_bytes": size_bytes,
                    "backup_version": version,
                    "has_header_bytes": len(header_bytes) > 0,
                    "parse_status": parse_status,
                    "encrypted": is_encrypted,
                    "application": "whatsapp",
                }
            ),
        )


class AccessibleAppArtifactJSONParser(BaseApplicationAdapter):
    """Agent accessible app artifacts inventory parser."""

    metadata = AdapterMetadata(
        parser_id="android.agent.app_artifacts",
        name="Agent accessible app artifacts inventory",
        version="1.0.0",
        package_name="android.agent",
        application_name="Agent Artifact Inventory",
        artifact_categories=("application", "media", "backup"),
        required_tables=frozenset(),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("app_artifacts.json",),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return False

    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        return AdapterParseResult(
            status=AdapterParseStatus.UNSUPPORTED,
            reason="JSON payload parsing requires parse_json_data",
        )

    def parse_json_data(
        self, data: list[dict[str, object]], context: ParserContext
    ) -> list[ParsedArtifact]:
        artifacts: list[ParsedArtifact] = []
        for idx, item in enumerate(data):
            pkg = str(item.get("package_name") or "unknown_package")
            category = str(item.get("artifact_category") or "other")
            rel_path = str(item.get("relative_path") or f"artifact_{idx}")
            size_bytes = integer(item.get("size_bytes")) or 0
            mime_type = str(item.get("mime_type") or "application/octet-stream")

            artifacts.append(
                ParsedArtifact(
                    category="communication"
                    if ("whatsapp" in pkg or "telegram" in pkg)
                    else "application",
                    subtype="accessible_app_artifact",
                    title=f"Accessible App Artifact: {pkg} ({category})",
                    summary=f"File: {rel_path} ({size_bytes} bytes, MIME: {mime_type})",
                    event_time=None,
                    source_locator=f"{context.input_locator}#artifact:{idx}:{pkg}",
                    status="active",
                    confidence="high",
                    metadata=compact_metadata(
                        {
                            "package_name": pkg,
                            "artifact_category": category,
                            "relative_path": rel_path,
                            "size_bytes": size_bytes,
                            "mime_type": mime_type,
                            "accessibility_status": item.get("accessibility_status", "accessible"),
                        }
                    ),
                )
            )
        return artifacts
