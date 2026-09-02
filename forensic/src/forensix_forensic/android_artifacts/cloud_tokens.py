"""Cloud account tokens, OAuth sessions, and synchronized account parser."""

from __future__ import annotations

from collections.abc import Mapping

from forensix_forensic.android_artifacts.common import (
    android_timestamp,
    compact_metadata,
    integer,
    optional_column,
    parser_error,
    text,
)
from forensix_forensic.evidence_io import (
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    SafeSQLiteError,
    SafeSQLiteReader,
)


class AndroidCloudTokensParser:
    """Parse Android system account records, Google tokens, and cloud credentials."""

    metadata = ParserMetadata(
        parser_id="android.cloud.tokens",
        name="Android system account tokens and cloud credentials",
        version="1.0.0",
        artifact_categories=("system", "credential"),
        required_tables=frozenset({"accounts"}),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=(
            "system_ce",
            "system_de",
            "accounts_ce.db",
            "accounts_de.db",
            "accounts.db",
        ),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "accounts" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        tables = reader.table_names()
        columns = reader.column_names("accounts")
        id_col = '"_id"' if "_id" in columns else '"id"'
        time_col = (
            '"last_password_entry_time_millis_epoch"'
            if "last_password_entry_time_millis_epoch" in columns
            else id_col
        )

        has_authtokens = "authtokens" in tables
        if has_authtokens:
            auth_cols = reader.column_names("authtokens")
            token_col = '"authtoken"' if "authtoken" in auth_cols else '"token"'
            auth_type_col = '"type"' if "type" in auth_cols else '"auth_type"'
            query = f"""
            SELECT
                a.{id_col} AS _id,
                a.{time_col} AS timestamp,
                a.name AS account_name,
                a.type AS account_type,
                a.password AS password,
                t.{auth_type_col} AS token_type,
                t.{token_col} AS token_value
            FROM accounts a
            LEFT JOIN authtokens t ON a.{id_col} = t.accounts_id
            ORDER BY a.{id_col}
            """  # noqa: S608
        else:
            selected = [
                f"{id_col} AS _id",
                f"{time_col} AS timestamp",
                *(
                    optional_column(columns, name)
                    for name in (
                        "name",
                        "type",
                        "password",
                        "previous_name",
                        "last_password_entry_time_millis_epoch",
                    )
                ),
            ]
            query = f'SELECT {", ".join(selected)} FROM "accounts" ORDER BY {id_col}'  # noqa: S608

        try:
            rows = reader.execute_select(query)
        except SafeSQLiteError as error:
            raise parser_error(error) from error

        return [self._artifact(row, context) for row in rows]

    @staticmethod
    def _artifact(row: Mapping[str, object], context: ParserContext) -> ParsedArtifact:
        identifier = integer(row.get("_id"))
        account_name = text(row.get("account_name")) or text(row.get("name")) or "Unknown Account"
        account_type = text(row.get("account_type")) or text(row.get("type")) or "unknown.service"
        token_type = text(row.get("token_type")) or "OAuth2/Master"
        has_token = bool(row.get("token_value"))

        # Map common Android account types to human-readable services
        service_label = account_type
        if "google" in account_type.lower():
            service_label = "Google Account / Drive"
        elif "whatsapp" in account_type.lower():
            service_label = "WhatsApp Sync"
        elif "telegram" in account_type.lower():
            service_label = "Telegram Session"
        elif "facebook" in account_type.lower():
            service_label = "Facebook / Messenger"
        elif "microsoft" in account_type.lower():
            service_label = "Microsoft 365 / Outlook"
        elif "samsung" in account_type.lower():
            service_label = "Samsung Cloud"

        summary_parts = [f"Service: {service_label}"]
        if has_token:
            summary_parts.append(f"Token: {token_type} [PRESENT]")
        if row.get("password"):
            summary_parts.append("Stored Password [PRESENT]")

        return ParsedArtifact(
            category="system",
            subtype="cloud_account_token",
            title=f"Cloud Account: {account_name} ({service_label})",
            summary=", ".join(summary_parts),
            event_time=android_timestamp(row.get("timestamp")),
            source_locator=f"{context.input_locator}#accounts:{identifier}",
            status="active",
            confidence="high",
            metadata=compact_metadata(
                {
                    **row,
                    "service_label": service_label,
                    "application": "cloud_accounts",
                }
            ),
        )
