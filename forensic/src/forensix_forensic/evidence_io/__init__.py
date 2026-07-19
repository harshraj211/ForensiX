"""Hostile-evidence intake primitives used by approved forensic parsers."""

from .archive import (
    ArchiveExtractionError,
    ArchivePolicy,
    ExtractedArchiveMember,
    SafeArchiveExtractor,
)
from .parser import (
    DocumentEvidenceParser,
    DocumentParserRegistry,
    EvidenceParser,
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    ParserRegistry,
    ParserRegistryError,
)
from .sqlite import SafeSQLiteError, SafeSQLiteReader

__all__ = [
    "ArchiveExtractionError",
    "ArchivePolicy",
    "DocumentEvidenceParser",
    "DocumentParserRegistry",
    "EvidenceParser",
    "ExtractedArchiveMember",
    "ParsedArtifact",
    "ParserContext",
    "ParserMetadata",
    "ParserRegistry",
    "ParserRegistryError",
    "SafeArchiveExtractor",
    "SafeSQLiteError",
    "SafeSQLiteReader",
]
