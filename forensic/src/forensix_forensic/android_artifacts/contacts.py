"""Android ContactsProvider contacts2.db adapter."""

# ruff: noqa: E501, S608 -- query fragments below are selected only from code-defined columns.

from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime
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
    parser_error,
    require_columns,
    text,
)

_NAME = "vnd.android.cursor.item/name"
_PHONE = "vnd.android.cursor.item/phone_v2"
_EMAIL = "vnd.android.cursor.item/email_v2"
_ORGANIZATION = "vnd.android.cursor.item/organization"
_ADDRESS = "vnd.android.cursor.item/postal-address_v2"


class AndroidContactsAdapter(BaseApplicationAdapter):
    """Android ContactsProvider contacts2.db forensic adapter."""

    metadata = AdapterMetadata(
        parser_id="android.contacts_provider",
        name="Android Contacts Provider Adapter",
        version="1.1.0",
        package_name="com.android.providers.contacts",
        application_name="Android Contacts Provider",
        artifact_categories=("contact",),
        required_tables=frozenset({"data", "mimetypes", "raw_contacts"}),
        access_level="filesystem",
        maturity="validated",
        source_path_hints=(),
        supported_schema_families=("android_contacts2_db",),
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

        data_columns = require_columns(
            reader, "data", {"raw_contact_id", "mimetype_id", "data1", "data2", "data3"}
        )
        require_columns(reader, "mimetypes", {"_id", "mimetype"})
        raw_columns = require_columns(reader, "raw_contacts", {"_id"})
        tables = reader.table_names()
        deleted = 'r."deleted" AS "deleted"' if "deleted" in raw_columns else '0 AS "deleted"'
        account_name = (
            'r."account_name" AS "account_name"'
            if "account_name" in raw_columns
            else 'NULL AS "account_name"'
        )
        account_type = (
            'r."account_type" AS "account_type"'
            if "account_type" in raw_columns
            else 'NULL AS "account_type"'
        )
        data4 = 'd."data4" AS "data4"' if "data4" in data_columns else 'NULL AS "data4"'
        aggregate_contact_id = (
            'r."contact_id" AS "contact_id"'
            if "contact_id" in raw_columns
            else 'r."_id" AS "contact_id"'
        )
        has_contacts = "contacts" in tables and "contact_id" in raw_columns
        contact_join = 'LEFT JOIN contacts AS c ON c."_id" = r."contact_id"' if has_contacts else ""
        contact_fields = (
            'c."times_contacted" AS "times_contacted", '
            'c."last_time_contacted" AS "last_time_contacted", '
            'c."starred" AS "starred", c."photo_id" AS "photo_id"'
            if has_contacts
            else 'NULL AS "times_contacted", NULL AS "last_time_contacted", '
            'NULL AS "starred", NULL AS "photo_id"'
        )
        query = f"""
            SELECT d.raw_contact_id, {aggregate_contact_id}, m.mimetype, d.data1, d.data2, d.data3,
                   {data4}, {deleted}, {account_name}, {account_type}, {contact_fields}
            FROM data AS d
            JOIN mimetypes AS m ON m._id = d.mimetype_id
            JOIN raw_contacts AS r ON r._id = d.raw_contact_id
            {contact_join}
            ORDER BY d.raw_contact_id, d._id
        """
        try:
            rows = reader.execute_select(query)
        except SafeSQLiteError as error:
            raise parser_error(error) from error

        grouped: dict[int, list[Mapping[str, object]]] = defaultdict(list)
        for row in rows:
            identifier = integer(row.get("contact_id"))
            if identifier is not None:
                grouped[identifier].append(row)

        artifacts = [self._artifact(identifier, values) for identifier, values in grouped.items()]
        return AdapterParseResult(
            status=AdapterParseStatus.SUPPORTED,
            artifacts=artifacts,
            detected_schema="android_contacts2_db",
        )

    @staticmethod
    def _artifact(identifier: int, rows: list[Mapping[str, object]]) -> ParsedArtifact:
        name: str | None = None
        phones: list[dict[str, str | None]] = []
        emails: list[dict[str, str | None]] = []
        organizations: list[str] = []
        addresses: list[str] = []
        deleted = False
        account_name: str | None = None
        account_type: str | None = None
        raw_contact_ids: set[int] = set()
        times_contacted: int | None = None
        last_time_contacted: datetime | None = None
        starred = False
        has_photo = False
        for row in rows:
            mimetype = text(row.get("mimetype"))
            value = text(row.get("data1"))
            deleted = deleted or integer(row.get("deleted")) == 1
            account_name = account_name or text(row.get("account_name"))
            account_type = account_type or text(row.get("account_type"))
            raw_identifier = integer(row.get("raw_contact_id"))
            if raw_identifier is not None:
                raw_contact_ids.add(raw_identifier)
            times_contacted = (
                times_contacted
                if times_contacted is not None
                else integer(row.get("times_contacted"))
            )
            last_time_contacted = last_time_contacted or android_timestamp(
                row.get("last_time_contacted")
            )
            starred = starred or bool(integer(row.get("starred")) or 0)
            has_photo = has_photo or row.get("photo_id") is not None
            if mimetype == _NAME and value:
                name = value
            elif mimetype == _PHONE and value:
                phones.append(
                    {
                        "number": value,
                        "type": text(row.get("data2")),
                        "label": text(row.get("data3")),
                    }
                )
            elif mimetype == _EMAIL and value:
                emails.append(
                    {
                        "address": value,
                        "type": text(row.get("data2")),
                        "label": text(row.get("data3")),
                    }
                )
            elif mimetype == _ORGANIZATION and value:
                organizations.append(value)
            elif mimetype == _ADDRESS and value:
                addresses.append(value)
        title = name or (phones[0]["number"] if phones else None) or f"Contact {identifier}"
        return ParsedArtifact(
            category="contact",
            subtype="android_contact",
            title=title,
            summary=f"{len(phones)} phone number(s), {len(emails)} email address(es)",
            event_time=None,
            source_locator=f"raw_contacts:{identifier}",
            status="deleted" if deleted else "active",
            confidence="high",
            metadata=compact_metadata(
                {
                    "contact_id": identifier,
                    "raw_contact_ids": sorted(raw_contact_ids),
                    "display_name": name,
                    "phones": phones,
                    "emails": emails,
                    "organizations": organizations,
                    "addresses": addresses,
                    "account_name": account_name,
                    "account_type": account_type,
                    "times_contacted": times_contacted,
                    "last_time_contacted": last_time_contacted.isoformat()
                    if last_time_contacted
                    else None,
                    "starred": starred,
                    "has_photo": has_photo,
                    "application": "android.contacts",
                }
            ),
        )


AndroidContactsParser = AndroidContactsAdapter
