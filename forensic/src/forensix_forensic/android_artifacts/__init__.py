"""Versioned parsers for Android databases obtained through lawful elevated access."""

from .applications import (
    AccessibleAppArtifactJSONParser,
    DiscordMessageParser,
    GmailMessageParser,
    MetaMessageParser,
    SnapchatMessageParser,
    TelegramMessageParser,
    TikTokMessageParser,
    WeChatMessageParser,
    WhatsAppBackupArtifactParser,
    WhatsAppMessageParser,
)
from .carver_parser import SQLiteCarverParser
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
from .dumpsys_parser import AndroidDumpsysUsageStatsParser
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
    ChromiumBookmarksParser,
    ChromiumDownloadsParser,
    EdgeHistoryParser,
    FirefoxHistoryParser,
    GoogleMapsSearchParser,
    SamsungBrowserHistoryParser,
)

__all__ = [
    "AccessibleAppArtifactJSONParser",
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
    "AndroidDumpsysUsageStatsParser",
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
    "ChromiumBookmarksParser",
    "ChromiumDownloadsParser",
    "DiscordMessageParser",
    "EdgeHistoryParser",
    "FirefoxHistoryParser",
    "GmailMessageParser",
    "GoogleMapsSearchParser",
    "MetaMessageParser",
    "SamsungBrowserHistoryParser",
    "SnapchatMessageParser",
    "SQLiteCarverParser",
    "TelegramMessageParser",
    "TikTokMessageParser",
    "WeChatMessageParser",
    "WhatsAppBackupArtifactParser",
    "WhatsAppMessageParser",
    "android_document_parser_registry",
    "android_parser_registry",
    "application_artifact_support",
]
