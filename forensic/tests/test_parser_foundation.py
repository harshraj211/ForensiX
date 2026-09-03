"""Tests for Phase 0 Forensic Parser Foundation primitives."""

from dataclasses import dataclass
from datetime import UTC, datetime
from types import ModuleType

from forensix_forensic.evidence_io import (
    BaseEvidenceParser,
    DocumentParserRegistry,
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    ParserRegistry,
    SafeSQLiteReader,
)


class SampleBaseParser(BaseEvidenceParser):
    metadata = ParserMetadata(
        parser_id="test.sample",
        name="Sample Parser",
        version="1.0.0",
        artifact_categories=("message",),
        required_tables=frozenset({"messages", "chats"}),
        source_path_hints=("data/data/com.sample.app/databases/main.db",),
        maturity="validated",
        access_level="filesystem",
        supported_artifact_types=("chat_message", "reaction"),
        description="Sample test parser for foundation verification",
    )

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        del reader, context
        return []


class SecondaryParser(BaseEvidenceParser):
    metadata = ParserMetadata(
        parser_id="test.secondary",
        name="Secondary Parser",
        version="1.0.0",
        artifact_categories=("contact",),
        required_tables=frozenset({"contacts"}),
        source_path_hints=("com.sample.contacts",),
        maturity="experimental",
        access_level="filesystem",
    )

    def parse(self, reader: SafeSQLiteReader, context: ParserContext) -> list[ParsedArtifact]:
        del reader, context
        return []


@dataclass(frozen=True)
class SampleDocumentParser:
    metadata = ParserMetadata(
        parser_id="test.document",
        name="Sample Doc Parser",
        version="1.0.0",
        artifact_categories=("system",),
        required_tables=frozenset(),
        source_path_hints=("shared_prefs/app_config.xml",),
        access_level="filesystem",
    )

    def can_parse(self, source_locator: str) -> bool:
        return "app_config.xml" in source_locator

    def parse(self, path: object, context: ParserContext) -> list[ParsedArtifact]:
        del path, context
        return []


def test_base_evidence_parser_capability_detection() -> None:
    parser = SampleBaseParser()
    assert parser.metadata.description == "Sample test parser for foundation verification"
    assert parser.metadata.supported_artifact_types == ("chat_message", "reaction")

    # 1. Matching tables and matching hint
    cap = parser.detect_capability(
        frozenset({"messages", "chats", "extra_table"}),
        source_locator="/data/data/com.sample.app/databases/main.db",
    )
    assert cap.supported is True
    assert cap.confidence == 1.0
    assert "matched" in cap.reason
    assert cap.matched_tables == frozenset({"messages", "chats"})
    assert "data/data/com.sample.app/databases/main.db" in cap.matched_hints

    # 2. Matching tables without matching hint
    cap_no_hint = parser.detect_capability(
        frozenset({"messages", "chats"}),
        source_locator="/unknown/path/other.db",
    )
    assert cap_no_hint.supported is True
    assert cap_no_hint.confidence == 0.65
    assert len(cap_no_hint.matched_hints) == 0

    # 3. Missing tables
    cap_missing = parser.detect_capability(
        frozenset({"messages"}),
        source_locator="/data/data/com.sample.app/databases/main.db",
    )
    assert cap_missing.supported is False
    assert cap_missing.confidence == 0.0


def test_parser_registry_management_and_selection() -> None:
    registry = ParserRegistry()
    p1 = SampleBaseParser()
    p2 = SecondaryParser()

    registry.register_all([p1, p2])
    assert len(registry.list_parsers()) == 2
    assert registry.get_optional("test.sample") is p1
    assert registry.get_optional("unknown.parser") is None

    # select_best_match prefers hint and maturity
    best = registry.select_best_match(
        frozenset({"messages", "chats"}),
        source_locator="/data/data/com.sample.app/databases/main.db",
    )
    assert best is p1

    # Unregister
    assert registry.unregister("test.sample") is True
    assert registry.unregister("test.sample") is False
    assert len(registry.list_parsers()) == 1
    assert registry.get_optional("test.sample") is None


def test_parser_registry_discovery() -> None:
    registry = ParserRegistry()
    dummy_mod = ModuleType("dummy_forensic_module")
    dummy_mod.DiscoveredParser = SampleBaseParser

    count = registry.discover(modules_or_packages=[dummy_mod])
    assert count == 1
    assert registry.get_optional("test.sample") is not None


def test_document_parser_registry_management() -> None:
    doc_registry = DocumentParserRegistry()
    doc_parser = SampleDocumentParser()

    doc_registry.register(doc_parser)
    assert doc_registry.get_optional("test.document") is doc_parser
    assert doc_registry.get_optional("nonexistent") is None
    assert len(doc_registry.list_parsers()) == 1
    assert doc_registry.compatible("com.sample/shared_prefs/app_config.xml") == (doc_parser,)
    assert doc_registry.compatible("other.txt") == ()

    assert doc_registry.unregister("test.document") is True
    assert doc_registry.unregister("test.document") is False
    assert len(doc_registry.list_parsers()) == 0


def test_parsed_artifact_searchable_text() -> None:
    artifact = ParsedArtifact(
        category="communication",
        subtype="whatsapp_message",
        title="Message from Alice",
        summary="Discussion about project kickoff",
        event_time=datetime.now(UTC),
        source_locator="msgstore.db:messages:42",
        status="active",
        confidence="high",
        content="Hey Bob, are we meeting at 10am tomorrow? Let me know.",
        metadata={
            "sender": "alice@example.com",
            "recipient": "+15551234567",
            "app": "WhatsApp",
            "ocr_text": "Whiteboard notes from team session",
        },
    )

    searchable = artifact.searchable_text()
    assert "Message from Alice" in searchable
    assert "Discussion about project kickoff" in searchable
    assert "meeting at 10am" in searchable
    assert "alice@example.com" in searchable
    assert "+15551234567" in searchable
    assert "Whiteboard notes" in searchable
