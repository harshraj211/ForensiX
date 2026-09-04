"""Explicit registry for versioned forensic parsers."""

import abc
import importlib
import inspect
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Literal, Protocol

from .sqlite import SafeSQLiteReader


class ParserRegistryError(ValueError):
    """Raised when parser registration or selection is invalid."""


@dataclass(frozen=True, slots=True)
class ParserCapability:
    """Quantitative evaluation of a parser's compatibility with an evidence target."""

    supported: bool
    confidence: float = 1.0  # 0.0 to 1.0
    reason: str = ""
    matched_tables: frozenset[str] = frozenset()
    matched_hints: tuple[str, ...] = ()


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
    supported_artifact_types: tuple[str, ...] = ()
    description: str = ""
    input_formats: tuple[str, ...] = ("sqlite",)


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
    content: str | None = None

    def searchable_text(self) -> str:
        """Extract clean normalized text for full-text search indexing."""
        parts: list[str] = [self.title, self.summary]
        if self.content:
            parts.append(self.content)
        for val in self.metadata.values():
            if isinstance(val, str) and val.strip():
                parts.append(val.strip())
            elif isinstance(val, (list, tuple)):
                for item in val:
                    if isinstance(item, str) and item.strip():
                        parts.append(item.strip())
        return " ".join(parts)


class EvidenceParser(Protocol):
    metadata: ParserMetadata

    def can_parse(self, tables: frozenset[str]) -> bool: ...

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]: ...


class BaseEvidenceParser(abc.ABC):
    """Abstract base class for structured forensic SQLite evidence parsers."""

    metadata: ParserMetadata

    def can_parse(self, tables: frozenset[str]) -> bool:
        return self.metadata.required_tables.issubset(tables)

    def detect_capability(
        self,
        tables: frozenset[str] | None = None,
        *,
        source_locator: str = "",
    ) -> ParserCapability:
        if tables is None:
            return ParserCapability(supported=False, confidence=0.0, reason="No tables provided")
        if not self.metadata.required_tables.issubset(tables):
            missing = sorted(self.metadata.required_tables - tables)
            return ParserCapability(
                supported=False,
                confidence=0.0,
                reason=f"Missing required tables: {', '.join(missing)}",
            )
        matched_hints: tuple[str, ...] = ()
        hint_boost = 0.0
        reason = "Schema matched"
        if self.metadata.source_path_hints:
            locator = source_locator.casefold()
            matched = tuple(h for h in self.metadata.source_path_hints if h.casefold() in locator)
            if matched:
                matched_hints = matched
                hint_boost = 0.2
                reason = "Schema and path hints matched"
            elif source_locator:
                hint_boost = -0.15
                reason = "Schema matched but source path did not match hints"
        confidence = max(0.1, min(1.0, 0.8 + hint_boost))
        return ParserCapability(
            supported=True,
            confidence=round(confidence, 2),
            reason=reason,
            matched_tables=self.metadata.required_tables & tables,
            matched_hints=matched_hints,
        )

    @abc.abstractmethod
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

    def register_all(self, parsers: Iterable[EvidenceParser]) -> None:
        for parser in parsers:
            self.register(parser)

    def unregister(self, parser_id: str) -> bool:
        if parser_id in self._parsers:
            del self._parsers[parser_id]
            return True
        return False

    def get(self, parser_id: str) -> EvidenceParser:
        try:
            return self._parsers[parser_id]
        except KeyError as error:
            raise ParserRegistryError(f"Parser '{parser_id}' is not registered.") from error

    def get_optional(self, parser_id: str) -> EvidenceParser | None:
        return self._parsers.get(parser_id)

    def list_parsers(self) -> tuple[EvidenceParser, ...]:
        return tuple(self._parsers.values())

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

    def select_best_match(
        self, tables: frozenset[str], *, source_locator: str = ""
    ) -> EvidenceParser | None:
        """Automatically select the highest-confidence compatible parser for an evidence target."""
        candidates = self.compatible(tables, source_locator=source_locator)
        if not candidates:
            return None

        def rank_key(p: EvidenceParser) -> tuple[int, int, int]:
            maturity_score = 2 if p.metadata.maturity == "validated" else 1
            has_matching_hint = any(
                h.casefold() in source_locator.casefold() for h in p.metadata.source_path_hints
            )
            hint_score = 2 if has_matching_hint else 1
            table_count = len(p.metadata.required_tables)
            return (hint_score, maturity_score, table_count)

        return max(candidates, key=rank_key)

    def discover(self, modules_or_packages: Sequence[str | ModuleType] | None = None) -> int:
        """Discover and register EvidenceParser instances or factory functions.

        Scans target modules for classes subclassing BaseEvidenceParser, instances implementing
        EvidenceParser, or functions named ending with '_parser' or '_parsers'.
        """
        registered_count = 0
        targets: list[ModuleType] = []
        if modules_or_packages is None:
            default_pkg = "forensix_forensic.android_artifacts"
            try:
                targets.append(importlib.import_module(default_pkg))
            except ImportError:
                return 0
        else:
            for item in modules_or_packages:
                if isinstance(item, str):
                    targets.append(importlib.import_module(item))
                elif isinstance(item, ModuleType):
                    targets.append(item)

        for mod in targets:
            for _, obj in inspect.getmembers(mod):
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BaseEvidenceParser)
                    and obj is not BaseEvidenceParser
                ):
                    try:
                        instance = obj()
                        if instance.metadata.parser_id not in self._parsers:
                            self.register(instance)
                            registered_count += 1
                    except Exception:  # noqa: BLE001, S112
                        continue
        return registered_count

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

    def register_all(self, parsers: Iterable[DocumentEvidenceParser]) -> None:
        for parser in parsers:
            self.register(parser)

    def unregister(self, parser_id: str) -> bool:
        if parser_id in self._parsers:
            del self._parsers[parser_id]
            return True
        return False

    def get(self, parser_id: str) -> DocumentEvidenceParser:
        try:
            return self._parsers[parser_id]
        except KeyError as error:
            raise ParserRegistryError(f"Parser '{parser_id}' is not registered.") from error

    def get_optional(self, parser_id: str) -> DocumentEvidenceParser | None:
        return self._parsers.get(parser_id)

    def list_parsers(self) -> tuple[DocumentEvidenceParser, ...]:
        return tuple(self._parsers.values())

    def compatible(self, source_locator: str) -> tuple[DocumentEvidenceParser, ...]:
        return tuple(
            parser for parser in self._parsers.values() if parser.can_parse(source_locator)
        )

    def metadata(self) -> tuple[ParserMetadata, ...]:
        return tuple(parser.metadata for parser in self._parsers.values())
