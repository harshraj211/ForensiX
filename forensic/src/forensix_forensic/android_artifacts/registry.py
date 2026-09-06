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
    registry.register(AndroidContactsAdapter())  # type: ignore[arg-type]
    registry.register(AndroidSmsParser())  # type: ignore[arg-type]
    registry.register(AndroidMmsParser())  # type: ignore[arg-type]
    registry.register(AndroidTelephonyAdapter())  # type: ignore[arg-type]
    registry.register(AndroidCallLogAdapter())  # type: ignore[arg-type]
    registry.register(WhatsAppAdapter())  # type: ignore[arg-type]
    registry.register(WhatsAppBackupArtifactParser())  # type: ignore[arg-type]
    registry.register(AccessibleAppArtifactJSONParser())  # type: ignore[arg-type]
    registry.register(TelegramAdapter())  # type: ignore[arg-type]
    registry.register(SignalAdapter())  # type: ignore[arg-type]
    registry.register(SnapchatMessageParser())  # type: ignore[arg-type]
    registry.register(DiscordMessageParser())  # type: ignore[arg-type]
    registry.register(TikTokMessageParser())  # type: ignore[arg-type]
    registry.register(GmailMessageParser())  # type: ignore[arg-type]
    registry.register(WeChatMessageParser())  # type: ignore[arg-type]
    for parser in meta_message_parsers():
        registry.register(parser)  # type: ignore[arg-type]
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
