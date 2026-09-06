"""Unified Android Application Artifact Adapter Contract.

Defines the core contract, capability enumeration, parse status lifecycle,
and abstract base class for version-resilient application forensic adapters.
"""

# ruff: noqa: E501

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from forensix_forensic.evidence_io import (
    BaseEvidenceParser,
    ParsedArtifact,
    ParserCapability,
    ParserContext,
    ParserMetadata,
    SafeSQLiteReader,
)

from .common import AndroidArtifactParserError
from .relationships import ForensicRelationship


class AdapterParseStatus(StrEnum):
    """Explicit status classification for application artifact parsing attempts."""

    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    ENCRYPTED_UNPARSED = "encrypted_unparsed"
    CORRUPTED = "corrupted"
    UNKNOWN_SCHEMA = "unknown_schema"


@dataclass(frozen=True, slots=True)
class AdapterMetadata(ParserMetadata):
    """Extended metadata for application forensic adapters."""

    package_name: str = ""
    application_name: str = ""
    supported_formats: tuple[str, ...] = ("sqlite",)
    supported_schema_families: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(slots=True)
class AdapterParseResult:
    """Structured output returned by an ApplicationAdapter parse operation."""

    status: AdapterParseStatus
    artifacts: list[ParsedArtifact] = field(default_factory=list)
    relationships: list[ForensicRelationship] = field(default_factory=list)
    detected_schema: str = "unknown"
    confidence: float = 1.0
    reason: str = ""
    limitations: list[str] = field(default_factory=list)

    def is_successful(self) -> bool:
        return self.status in (AdapterParseStatus.SUPPORTED, AdapterParseStatus.PARTIAL)


class ApplicationAdapter(abc.ABC):
    """Abstract base class for all Android Application Artifact Adapters."""

    metadata: AdapterMetadata

    @abc.abstractmethod
    def detect_capability(
        self,
        tables: frozenset[str] | None = None,
        *,
        source_locator: str = "",
    ) -> ParserCapability:
        """Evaluate capability and confidence against target tables and locator."""
        ...

    @abc.abstractmethod
    def parse_adapter(
        self,
        reader: SafeSQLiteReader | None,
        context: ParserContext,
        *,
        source_path: Path | None = None,
    ) -> AdapterParseResult:
        """Parse target evidence using the adapter contract and return structured result."""
        ...


class BaseApplicationAdapter(BaseEvidenceParser, ApplicationAdapter, abc.ABC):
    """Base implementation integrating EvidenceParser protocol with ApplicationAdapter contract."""

    metadata: AdapterMetadata

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        """Bridge standard EvidenceParser.parse call to parse_adapter."""
        result = self.parse_adapter(reader, context)
        if (
            result.status
            in (
                AdapterParseStatus.UNSUPPORTED,
                AdapterParseStatus.UNKNOWN_SCHEMA,
                AdapterParseStatus.CORRUPTED,
            )
            and not result.artifacts
        ):
            raise AndroidArtifactParserError(
                result.reason
                or f"Application database schema '{result.detected_schema}' is unsupported or unrecognised."
            )
        return result.artifacts

    def detect_capability(
        self,
        tables: frozenset[str] | None = None,
        *,
        source_locator: str = "",
    ) -> ParserCapability:
        if tables is None:
            return ParserCapability(supported=False, confidence=0.0, reason="No tables provided")
        if self.metadata.required_tables and not self.metadata.required_tables.issubset(tables):
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
