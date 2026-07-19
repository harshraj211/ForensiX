from dataclasses import dataclass
from datetime import datetime

import pytest

from forensix_forensic.evidence_io import (
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    ParserRegistry,
    ParserRegistryError,
    SafeSQLiteReader,
)


@dataclass(frozen=True)
class FixtureParser:
    metadata = ParserMetadata(
        parser_id="android.fixture",
        name="Fixture",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"messages"}),
        access_level="filesystem",
    )

    def can_parse(self, tables: frozenset[str]) -> bool:
        return "messages" in tables

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        del reader, context
        return [
            ParsedArtifact(
                category="communication",
                subtype="fixture",
                title="Fixture",
                summary="Fixture",
                event_time=datetime.fromisoformat("2026-01-01T00:00:00+00:00"),
                source_locator="messages:1",
                status="active",
                confidence="high",
                metadata={},
            )
        ]


def test_registry_matches_required_tables() -> None:
    registry = ParserRegistry()
    parser = FixtureParser()
    registry.register(parser)

    assert registry.get("android.fixture") is parser
    assert registry.compatible(frozenset({"messages"})) == (parser,)
    assert registry.compatible(frozenset({"contacts"})) == ()


def test_registry_rejects_duplicates_and_unknown_ids() -> None:
    registry = ParserRegistry()
    registry.register(FixtureParser())

    with pytest.raises(ParserRegistryError, match="already registered"):
        registry.register(FixtureParser())
    with pytest.raises(ParserRegistryError, match="not registered"):
        registry.get("missing")
