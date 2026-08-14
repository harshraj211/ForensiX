"""Versioned parsers for Android databases obtained through lawful elevated access."""

from .applications import (
    DiscordMessageParser,
    GmailMessageParser,
    MetaMessageParser,
    SnapchatMessageParser,
    TelegramMessageParser,
    TikTokMessageParser,
    WhatsAppMessageParser,
)
from .common import AndroidArtifactParserError
from .communications import AndroidCallLogParser, AndroidMmsParser, AndroidSmsParser
from .contacts import AndroidContactsParser
from .documents import (
    AndroidBluetoothConfigParser,
    AndroidDocumentParserError,
    AndroidWifiConfigParser,
    android_document_parser_registry,
)
from .registry import android_parser_registry
from .support import ApplicationArtifactSupport, application_artifact_support
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

__all__ = [
    "AndroidArtifactParserError",
    "AndroidCallLogParser",
    "AndroidContactsParser",
    "AndroidBluetoothConfigParser",
    "AndroidDocumentParserError",
    "AndroidWifiConfigParser",
    "AndroidMmsParser",
    "AndroidSmsParser",
    "AppUsageStatsParser",
    "DiscordMessageParser",
    "EdgeHistoryParser",
    "FirefoxHistoryParser",
    "GmailMessageParser",
    "GoogleMapsSearchParser",
    "MetaMessageParser",
    "SamsungBrowserHistoryParser",
    "SnapchatMessageParser",
    "TelegramMessageParser",
    "TikTokMessageParser",
    "WhatsAppMessageParser",
    "ApplicationArtifactSupport",
    "application_artifact_support",
    "AndroidCalendarEventParser",
    "AndroidDownloadsParser",
    "AndroidLocationParser",
    "AndroidNotesParser",
    "AndroidNotificationParser",
    "ChromeHistoryParser",
    "android_parser_registry",
    "android_document_parser_registry",
]
