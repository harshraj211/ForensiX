"""Explicit registry for versioned forensic parsers."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from .sqlite import SafeSQLiteReader


class ParserRegistryError(ValueError):
    """Raised when parser registration or selection is invalid."""


@dataclass(frozen=True, slots=True)
class ParserMetadata:
    parser_id: str
    name: str
    version: str
    artifact_categories: tuple[str, ...]
    required_tables: frozenset[str]
    access_level: Literal["logical", "filesystem", "physical"]
    maturity: Literal["experimental", "validated"] = "experimental"
    source_path_hints: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ParserContext:
    case_id: str
    evidence_source_id: str
    working_copy_id: str
    source_sha256: str
    source_label: str
    input_locator: str = "working_copy"
    input_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedArtifact:
    category: str
    subtype: str
    title: str
    summary: str
    event_time: datetime | None
    source_locator: str
    status: Literal["active", "deleted", "recovered", "partial", "corrupted", "unverified"]
    confidence: Literal["high", "medium", "low"]
    metadata: dict[str, Any]


class EvidenceParser(Protocol):
    metadata: ParserMetadata

    def can_parse(self, tables: frozenset[str]) -> bool: ...

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]: ...


class DocumentEvidenceParser(Protocol):
    metadata: ParserMetadata

    def can_parse(self, source_locator: str) -> bool: ...

    def parse(self, path: Path, context: ParserContext) -> list[ParsedArtifact]: ...


class ParserRegistry:
    """Allows only parser objects registered by trusted application code."""

    def __init__(self) -> None:
        self._parsers: dict[str, EvidenceParser] = {}

    def register(self, parser: EvidenceParser) -> None:
        metadata = parser.metadata
        if not metadata.parser_id or not metadata.version:
            raise ParserRegistryError("Parser ID and version are required.")
        if metadata.parser_id in self._parsers:
            raise ParserRegistryError(f"Parser '{metadata.parser_id}' is already registered.")
        self._parsers[metadata.parser_id] = parser

    def get(self, parser_id: str) -> EvidenceParser:
        try:
            return self._parsers[parser_id]
        except KeyError as error:
            raise ParserRegistryError(f"Parser '{parser_id}' is not registered.") from error

    def compatible(
        self, tables: frozenset[str], *, source_locator: str = ""
    ) -> tuple[EvidenceParser, ...]:
        locator = source_locator.casefold()
        return tuple(
            parser
            for parser in self._parsers.values()
            if parser.metadata.required_tables.issubset(tables)
            and parser.can_parse(tables)
            and (
                not parser.metadata.source_path_hints
                or any(hint.casefold() in locator for hint in parser.metadata.source_path_hints)
            )
        )

    def metadata(self) -> tuple[ParserMetadata, ...]:
        return tuple(parser.metadata for parser in self._parsers.values())


class DocumentParserRegistry:
    """Closed registry for bounded non-SQLite evidence document parsers."""

    def __init__(self) -> None:
        self._parsers: dict[str, DocumentEvidenceParser] = {}

    def register(self, parser: DocumentEvidenceParser) -> None:
        parser_id = parser.metadata.parser_id
        if not parser_id or not parser.metadata.version:
            raise ParserRegistryError("Parser ID and version are required.")
        if parser_id in self._parsers:
            raise ParserRegistryError(f"Parser '{parser_id}' is already registered.")
        self._parsers[parser_id] = parser

    def get(self, parser_id: str) -> DocumentEvidenceParser:
        try:
            return self._parsers[parser_id]
        except KeyError as error:
            raise ParserRegistryError(f"Parser '{parser_id}' is not registered.") from error

    def compatible(self, source_locator: str) -> tuple[DocumentEvidenceParser, ...]:
        return tuple(
            parser for parser in self._parsers.values() if parser.can_parse(source_locator)
        )

    def metadata(self) -> tuple[ParserMetadata, ...]:
        return tuple(parser.metadata for parser in self._parsers.values())
