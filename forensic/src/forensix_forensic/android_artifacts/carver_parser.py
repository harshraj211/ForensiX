"""Parser wrapping SQLiteCarver to extract recovered records into artifacts."""

from forensix_forensic.evidence_io import (
    BaseEvidenceParser,
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    SafeSQLiteReader,
)
from forensix_forensic.extractors.sqlite_carver import SQLiteCarver


class SQLiteCarverParser(BaseEvidenceParser):
    metadata = ParserMetadata(
        parser_id="android.sqlite.carver",
        name="SQLite Deleted Record & Freelist Carver",
        version="1.0.0",
        artifact_categories=("recovered", "communication"),
        required_tables=frozenset(),
        access_level="filesystem",
        maturity="validated",
        source_path_hints=("msgstore.db", "mmssms.db", "sms.db", "calllog.db", "calls.db", "chat"),
        description=(
            "Carves deleted messages, freeblock gaps, and WAL "
            "historical frames from SQLite databases"
        ),
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        if not tables:
            return True
        lowered = {t.casefold() for t in tables}
        return any(
            t in lowered
            for t in (
                "message",
                "messages",
                "sms",
                "mms",
                "chat",
                "chats",
                "parts",
                "part",
                "call",
                "calls",
                "call_log",
            )
        )

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        db_path = reader.path
        carver = SQLiteCarver()
        result = carver.carve([db_path], max_fragments=1000)
        artifacts: list[ParsedArtifact] = []
        for frag in result.fragments:
            title = f"Recovered ({frag.fragment_type}): {frag.content_preview[:40]}"
            artifacts.append(
                ParsedArtifact(
                    category="communication",
                    subtype=f"carved_{frag.fragment_type}",
                    title=title,
                    summary=frag.content_preview,
                    event_time=None,
                    source_locator=f"{context.input_locator}@{frag.offset_bytes}",
                    status="recovered",
                    confidence=frag.confidence,
                    metadata={
                        "carved_from": frag.source_file,
                        "offset_bytes": frag.offset_bytes,
                        "length_bytes": frag.length_bytes,
                        "fragment_type": frag.fragment_type,
                        "content_sha256": frag.content_sha256,
                        **frag.metadata,
                    },
                    content=frag.content_preview,
                )
            )
        return artifacts
