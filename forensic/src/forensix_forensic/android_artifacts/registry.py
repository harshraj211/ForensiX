"""Default registry of native Android artifact parsers."""

from forensix_forensic.evidence_io import ParserRegistry

from .communications import AndroidCallLogParser, AndroidMmsParser, AndroidSmsParser
from .contacts import AndroidContactsParser


def android_parser_registry() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register(AndroidContactsParser())
    registry.register(AndroidSmsParser())
    registry.register(AndroidMmsParser())
    registry.register(AndroidCallLogParser())
    return registry
