"""Default registry of native Android application artifact adapters and parsers."""

from forensix_forensic.evidence_io import ParserRegistry

from .applications import (
    AccessibleAppArtifactJSONParser,
    DiscordMessageParser,
    GmailMessageParser,
    SignalAdapter,
    SnapchatMessageParser,
    TelegramAdapter,
    TikTokMessageParser,
    WeChatMessageParser,
    WhatsAppAdapter,
    WhatsAppBackupArtifactParser,
    meta_message_parsers,
)
from .cloud_tokens import AndroidCloudTokensParser
from .communications import (
    AndroidCallLogAdapter,
    AndroidMmsParser,
    AndroidSmsParser,
    AndroidTelephonyAdapter,
)
from .contacts import AndroidContactsAdapter
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


class ApplicationAdapterRegistry(ParserRegistry):
    """Extended registry for version-resilient Android application adapters."""

    def list_adapters(self) -> tuple[object, ...]:
        return self.list_parsers()


def android_parser_registry() -> ApplicationAdapterRegistry:
    registry = ApplicationAdapterRegistry()
    registry.register(AndroidContactsAdapter())
    registry.register(AndroidSmsParser())
    registry.register(AndroidMmsParser())
    registry.register(AndroidTelephonyAdapter())
    registry.register(AndroidCallLogAdapter())
    registry.register(WhatsAppAdapter())
    registry.register(WhatsAppBackupArtifactParser())
    registry.register(AccessibleAppArtifactJSONParser())
    registry.register(TelegramAdapter())
    registry.register(SignalAdapter())
    registry.register(SnapchatMessageParser())
    registry.register(DiscordMessageParser())
    registry.register(TikTokMessageParser())
    registry.register(GmailMessageParser())
    registry.register(WeChatMessageParser())
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
    registry.register(AndroidWifiProfilesParser())
    registry.register(AndroidBluetoothDevicesParser())
    registry.register(AndroidCellTowerParser())
    registry.register(AndroidUsersParser())
    registry.register(AndroidCloudTokensParser())
    return registry
