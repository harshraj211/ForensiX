"""Default registry of native Android artifact parsers."""

from forensix_forensic.evidence_io import ParserRegistry

from .applications import TelegramMessageParser, WhatsAppMessageParser, meta_message_parsers
from .communications import AndroidCallLogParser, AndroidMmsParser, AndroidSmsParser
from .contacts import AndroidContactsParser


def android_parser_registry() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register(AndroidContactsParser())
    registry.register(AndroidSmsParser())
    registry.register(AndroidMmsParser())
    registry.register(AndroidCallLogParser())
    registry.register(WhatsAppMessageParser())
    registry.register(TelegramMessageParser())
    for parser in meta_message_parsers():
        registry.register(parser)
    return registry
