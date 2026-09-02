"""Versioned parsers for Android databases obtained through lawful elevated access."""

from .applications import (
    DiscordMessageParser,
    GmailMessageParser,
    MetaMessageParser,
    SnapchatMessageParser,
    TelegramMessageParser,
    TikTokMessageParser,
    WeChatMessageParser,
    WhatsAppMessageParser,
)
from .cloud_tokens import AndroidCloudTokensParser
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
    AndroidBluetoothDevicesParser,
    AndroidCalendarEventParser,
    AndroidCellTowerParser,
    AndroidDownloadsParser,
    AndroidLocationParser,
    AndroidNotesParser,
    AndroidNotificationParser,
    AndroidUsersParser,
    AndroidWifiProfilesParser,
    AppUsageStatsParser,
    ChromeHistoryParser,
    EdgeHistoryParser,
    FirefoxHistoryParser,
    GoogleMapsSearchParser,
    SamsungBrowserHistoryParser,
)

__all__ = [
    "AndroidArtifactParserError",
    "AndroidBluetoothConfigParser",
    "AndroidBluetoothDevicesParser",
    "AndroidCalendarEventParser",
    "AndroidCallLogParser",
    "AndroidCellTowerParser",
    "AndroidCloudTokensParser",
    "AndroidContactsParser",
    "AndroidDocumentParserError",
    "AndroidDownloadsParser",
    "AndroidLocationParser",
    "AndroidMmsParser",
    "AndroidNotesParser",
    "AndroidNotificationParser",
    "AndroidSmsParser",
    "AndroidUsersParser",
    "AndroidWifiConfigParser",
    "AndroidWifiProfilesParser",
    "AppUsageStatsParser",
    "ApplicationArtifactSupport",
    "ChromeHistoryParser",
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
    "WeChatMessageParser",
    "WhatsAppMessageParser",
    "android_document_parser_registry",
    "android_parser_registry",
    "application_artifact_support",
]
