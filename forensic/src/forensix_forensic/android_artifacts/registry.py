"""Default registry of native Android artifact parsers."""

from forensix_forensic.evidence_io import ParserRegistry

from .applications import (
    DiscordMessageParser,
    GmailMessageParser,
    SnapchatMessageParser,
    TelegramMessageParser,
    TikTokMessageParser,
    WhatsAppMessageParser,
    meta_message_parsers,
)
from .communications import AndroidCallLogParser, AndroidMmsParser, AndroidSmsParser
from .contacts import AndroidContactsParser
from .system import (
    AndroidCalendarEventParser,
    AndroidDownloadsParser,
    AndroidLocationParser,
    AndroidNotesParser,
    AndroidNotificationParser,
    AppUsageStatsParser,
    ChromeHistoryParser,
    EdgeHistoryParser,
    FirefoxHistoryParser,
    GoogleMapsSearchParser,
    SamsungBrowserHistoryParser,
)


def android_parser_registry() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register(AndroidContactsParser())
    registry.register(AndroidSmsParser())
    registry.register(AndroidMmsParser())
    registry.register(AndroidCallLogParser())
    registry.register(WhatsAppMessageParser())
    registry.register(TelegramMessageParser())
    registry.register(SnapchatMessageParser())
    registry.register(DiscordMessageParser())
    registry.register(TikTokMessageParser())
    registry.register(GmailMessageParser())
    for parser in meta_message_parsers():
        registry.register(parser)
    registry.register(AndroidCalendarEventParser())
    registry.register(AndroidDownloadsParser())
    registry.register(ChromeHistoryParser())
    registry.register(FirefoxHistoryParser())
    registry.register(SamsungBrowserHistoryParser())
    registry.register(EdgeHistoryParser())
    registry.register(AndroidNotificationParser())
    registry.register(AndroidNotesParser())
    registry.register(AndroidLocationParser())
    registry.register(GoogleMapsSearchParser())
    registry.register(AppUsageStatsParser())
    return registry
