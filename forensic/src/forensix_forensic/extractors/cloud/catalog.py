"""Cloud service coverage catalog for connector planning and UI disclosure."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal, cast

CloudDepth = Literal["deep_target", "connector_planned", "import_only"]
CloudBlocker = Literal["oauth", "user_export", "api_cost", "vendor_policy", "encryption", "not_started"]


@dataclass(frozen=True, slots=True)
class CloudServiceCapability:
    service_id: str
    display_name: str
    category: str
    depth: CloudDepth
    auth_methods: tuple[str, ...]
    artifact_types: tuple[str, ...]
    blocker_class: CloudBlocker
    implementation_note: str


DEEP_TARGET_SERVICES = frozenset({"google", "whatsapp", "icloud", "microsoft", "telegram"})


def cloud_service_catalog() -> tuple[CloudServiceCapability, ...]:
    """Return the commercial cloud breadth target without claiming implemented downloads."""
    notes = {
        "google": "Implemented offline Takeout: Chrome history, location/semantic history, My Activity, photo metadata, Gmail MBOX/EML, contact CSV/VCF and calendar ICS. Live OAuth/backup downloads remain planned.",
        "whatsapp": "Implemented offline Android/iOS chat TXT/ZIP and supported plaintext msgstore/wa SQLite schemas. Encrypted crypt backups and live cloud-backup retrieval are not decoded.",
        "microsoft": "Implemented offline Graph JSON mail/contact/calendar/drive-item records, EML/MBOX, contact CSV/VCF and ICS. No live Graph connector or PST decoding.",
        "telegram": "Implemented Desktop result.json/single-chat JSON and ZIP media inventory with sender, reply, service-event and location records. HTML exports and live API acquisition remain unsupported.",
        "icloud": "Implemented exported VCF contacts, ICS calendars, EML/MBOX mail and supported contact/photo CSV with ZIP inventory. No live iCloud account or device-backup download.",
    }
    return tuple(replace(service, implementation_note=notes[service.service_id]) if service.service_id in notes else service for service in _SERVICES)


def _catalog_service(
    service_id: str,
    display_name: str,
    category: str,
    depth: str,
    auth_methods: tuple[str, ...] | str,
    artifact_types: tuple[str, ...] | str,
    blocker: str,
    note: str,
) -> CloudServiceCapability:
    return CloudServiceCapability(
        service_id=service_id,
        display_name=display_name,
        category=category,
        depth=cast(CloudDepth, depth),
        auth_methods=(auth_methods,) if isinstance(auth_methods, str) else auth_methods,
        artifact_types=(artifact_types,) if isinstance(artifact_types, str) else artifact_types,
        blocker_class=cast(CloudBlocker, blocker),
        implementation_note=note,
    )


_SERVICES: tuple[CloudServiceCapability, ...] = (
    CloudServiceCapability(
        "google",
        "Google Account",
        "account",
        "deep_target",
        ("OAuth", "Google Takeout import", "user supplied token"),
        ("Drive files", "Photos", "Gmail", "Maps Timeline", "Android backup metadata"),
        "oauth",
        "Build official OAuth and Takeout import first; Android backup depth depends on Google API exposure.",
    ),
    CloudServiceCapability(
        "whatsapp",
        "WhatsApp Cloud Backup",
        "messaging_backup",
        "deep_target",
        ("Google Drive app data authorization", "local exported backup", "rooted key import"),
        ("msgstore backups", "media manifest", "chat databases"),
        "encryption",
        "Download/discovery is separate from database decryption; key material must come from lawful backup, root, or user export.",
    ),
    CloudServiceCapability(
        "icloud",
        "Apple iCloud",
        "account",
        "deep_target",
        ("OAuth/web session", "user export"),
        ("Photos", "Drive files", "contacts", "calendar", "device backup metadata"),
        "vendor_policy",
        "Prefer user-authorized export/import and documented APIs; device backup depth is policy and session dependent.",
    ),
    CloudServiceCapability(
        "microsoft",
        "Microsoft Account",
        "account",
        "deep_target",
        ("OAuth", "Graph API export"),
        ("OneDrive", "Outlook mail", "calendar", "contacts", "Teams export"),
        "oauth",
        "Microsoft Graph can provide broad account artifacts when scopes and tenant policy allow it.",
    ),
    CloudServiceCapability(
        "telegram",
        "Telegram",
        "messaging",
        "deep_target",
        ("Telegram API authorization", "desktop export import"),
        ("messages", "contacts", "media", "sessions"),
        "vendor_policy",
        "Start with official export parsing, then add API collection with user-present authorization.",
    ),
    *tuple(
        _catalog_service(
            service_id,
            display_name,
            category,
            depth,
            auth_methods,
            artifact_types,
            blocker,
            note,
        )
        for service_id, display_name, category, depth, auth_methods, artifact_types, blocker, note in (
            ("dropbox", "Dropbox", "cloud_storage", "connector_planned", ("OAuth", "user export"), ("files", "sharing metadata", "deleted file metadata"), "oauth", "Use official API for owner-authorized file and metadata collection."),
            ("box", "Box", "cloud_storage", "connector_planned", ("OAuth", "enterprise export"), ("files", "collaboration metadata", "retention metadata"), "oauth", "Enterprise tenants may expose richer audit and retention artifacts."),
            ("facebook", "Facebook", "social", "import_only", ("Download Your Information import",), ("posts", "messages export", "photos", "friends"), "user_export", "Build robust export parser before live API work."),
            ("instagram", "Instagram", "social", "import_only", ("Download Your Information import",), ("messages", "posts", "media", "followers"), "user_export", "Use account export parser for dependable hackathon coverage."),
            ("x_twitter", "X/Twitter", "social", "import_only", ("archive import", "paid API"), ("posts", "messages archive", "media"), "api_cost", "Live API breadth depends on paid tiers; archive parser is cheaper."),
            ("snapchat", "Snapchat", "social", "import_only", ("My Data export",), ("chat history", "memories metadata", "friends"), "user_export", "Parse user export packages and preserve provider manifest hashes."),
            ("signal", "Signal Backup", "messaging_backup", "import_only", ("local backup import",), ("messages", "attachments"), "encryption", "Requires user backup passphrase or already decrypted database."),
            ("discord", "Discord", "messaging", "connector_planned", ("data package import", "OAuth"), ("messages package", "servers", "attachments metadata"), "user_export", "Start with Discord data package parser."),
            ("slack", "Slack", "collaboration", "connector_planned", ("workspace export", "OAuth"), ("channels", "DM export where available", "files"), "vendor_policy", "Workspace export permissions define practical depth."),
            ("linkedin", "LinkedIn", "social", "import_only", ("data export",), ("connections", "messages", "posts"), "user_export", "Parser-first target."),
            ("tiktok", "TikTok", "social", "import_only", ("data export",), ("messages", "posts", "watch history"), "user_export", "Parser-first target."),
            ("reddit", "Reddit", "social", "connector_planned", ("OAuth", "GDPR export"), ("posts", "comments", "messages"), "oauth", "OAuth works for user-owned account data within API limits."),
            ("github", "GitHub", "developer", "connector_planned", ("OAuth", "personal access token", "archive import"), ("repositories", "issues", "pull requests", "events"), "oauth", "Useful for account activity timelines and file provenance."),
            ("gmail_takeout", "Gmail Takeout", "email", "import_only", ("Takeout MBOX import",), ("mail", "labels", "attachments"), "user_export", "MBOX parser and attachment hashing provide high value."),
            ("imap", "Generic IMAP", "email", "connector_planned", ("IMAP app password", "OAuth where supported"), ("mail", "attachments", "folders"), "oauth", "Provider-specific OAuth improves Gmail/Outlook/Yahoo coverage."),
            ("yahoo_mail", "Yahoo Mail", "email", "connector_planned", ("OAuth", "IMAP app password"), ("mail", "attachments", "contacts export"), "oauth", "Use IMAP plus provider metadata where available."),
            ("proton_mail", "Proton Mail", "email", "import_only", ("export import",), ("mail export", "attachments"), "vendor_policy", "Bridge/API availability limits live collection."),
            ("amazon", "Amazon", "commerce", "import_only", ("data export",), ("orders", "addresses", "devices", "Prime activity"), "user_export", "Parser-first target for account activity."),
            ("paypal", "PayPal", "finance", "import_only", ("CSV export", "statement import"), ("transactions", "counterparties", "timestamps"), "user_export", "Normalize statements into timeline and graph entities."),
            ("venmo", "Venmo", "finance", "import_only", ("CSV export",), ("transactions", "notes", "counterparties"), "user_export", "Normalize CSV exports."),
            ("cash_app", "Cash App", "finance", "import_only", ("CSV export",), ("transactions", "bitcoin activity", "counterparties"), "user_export", "Normalize CSV exports."),
            ("uber", "Uber", "mobility", "import_only", ("privacy export",), ("trips", "receipts", "locations"), "user_export", "Trip exports map directly to location timeline."),
            ("lyft", "Lyft", "mobility", "import_only", ("privacy export",), ("trips", "receipts", "locations"), "user_export", "Trip exports map directly to location timeline."),
            ("airbnb", "Airbnb", "travel", "import_only", ("privacy export",), ("reservations", "messages", "payments"), "user_export", "Parser-first travel timeline target."),
            ("booking", "Booking.com", "travel", "import_only", ("email/import", "privacy export"), ("reservations", "messages"), "user_export", "Use export and email receipt parsing."),
            ("google_photos_takeout", "Google Photos Takeout", "media", "import_only", ("Takeout import",), ("photos", "albums", "metadata JSON"), "user_export", "Dedicated parser can pair media and sidecar JSON."),
            ("google_maps_timeline", "Google Maps Timeline", "location", "import_only", ("Takeout import",), ("semantic locations", "raw location points"), "user_export", "Existing Takeout importer can be extended for richer location artifacts."),
            ("fitbit", "Fitbit", "health", "connector_planned", ("OAuth", "export import"), ("activity", "sleep", "heart rate summaries"), "oauth", "Health data requires explicit scoped authorization."),
            ("strava", "Strava", "fitness", "connector_planned", ("OAuth", "export import"), ("activities", "routes", "GPS tracks"), "oauth", "Good location and timeline source."),
            ("spotify", "Spotify", "media_activity", "connector_planned", ("privacy export", "OAuth"), ("play history", "playlists", "devices"), "oauth", "Export parser first, OAuth later."),
            ("netflix", "Netflix", "media_activity", "import_only", ("viewing activity export",), ("viewing history", "profiles"), "user_export", "Simple CSV normalization."),
            ("youtube", "YouTube", "media_activity", "import_only", ("Takeout import",), ("watch history", "search history", "subscriptions"), "user_export", "Part of broader Google Takeout module."),
            ("chrome_sync", "Chrome Sync", "browser", "import_only", ("Takeout import", "local profile import"), ("history", "bookmarks", "tabs"), "user_export", "Tie into browser history parser."),
            ("firefox_sync", "Firefox Sync", "browser", "import_only", ("profile import", "export import"), ("history", "bookmarks", "logins metadata"), "user_export", "Local profile parser first."),
            ("samsung_cloud", "Samsung Cloud", "device_cloud", "connector_planned", ("Samsung account export", "Smart Switch import"), ("gallery", "notes", "backup metadata"), "vendor_policy", "Smart Switch import is the practical first path."),
            ("samsung_smart_switch", "Samsung Smart Switch", "device_backup", "import_only", ("local backup import",), ("contacts", "messages", "media", "settings"), "user_export", "Implement local backup parser and manifest hashing."),
            ("huawei_cloud", "Huawei Cloud", "device_cloud", "import_only", ("export import",), ("gallery", "contacts", "backup metadata"), "vendor_policy", "Parser-first unless documented API access is available."),
            ("xiaomi_cloud", "Xiaomi Cloud", "device_cloud", "import_only", ("export import",), ("gallery", "contacts", "backup metadata"), "vendor_policy", "Parser-first unless documented API access is available."),
            ("onedrive", "OneDrive", "cloud_storage", "connector_planned", ("Microsoft Graph OAuth",), ("files", "sharing metadata", "versions"), "oauth", "Covered by Microsoft deep target but exposed for service-level tracking."),
            ("google_drive", "Google Drive", "cloud_storage", "connector_planned", ("Google OAuth", "Takeout import"), ("files", "comments metadata", "revisions"), "oauth", "Covered by Google deep target but exposed for service-level tracking."),
            ("icloud_drive", "iCloud Drive", "cloud_storage", "import_only", ("user export", "session-based collection"), ("files", "folder metadata"), "vendor_policy", "Covered by iCloud deep target but exposed for service-level tracking."),
            ("mega", "MEGA", "cloud_storage", "connector_planned", ("user credentials", "export import"), ("files", "sharing metadata"), "encryption", "Client-side encryption requires user credentials/session."),
            ("pcloud", "pCloud", "cloud_storage", "connector_planned", ("OAuth", "export import"), ("files", "sharing metadata"), "oauth", "Official API target."),
            ("icloud_keychain_export", "iCloud Keychain Export", "credentials", "import_only", ("user export",), ("password export CSV",), "vendor_policy", "Treat as sensitive imported document, not live keychain extraction."),
            ("bitwarden", "Bitwarden", "credentials", "import_only", ("vault export",), ("logins", "notes", "attachments metadata"), "encryption", "Requires user-exported decrypted vault file."),
            ("lastpass", "LastPass", "credentials", "import_only", ("vault export",), ("logins", "notes"), "encryption", "Requires user-exported vault data."),
            ("authy", "Authy", "authenticator", "import_only", ("device export where available",), ("token metadata"), "vendor_policy", "Usually limited by vendor policy and encryption."),
            ("google_calendar", "Google Calendar", "calendar", "connector_planned", ("Google OAuth", "Takeout import"), ("events", "attendees", "attachments metadata"), "oauth", "Covered by Google deep target."),
            ("outlook_calendar", "Outlook Calendar", "calendar", "connector_planned", ("Microsoft Graph OAuth",), ("events", "attendees"), "oauth", "Covered by Microsoft deep target."),
            ("apple_calendar", "Apple Calendar", "calendar", "import_only", ("iCloud export", "ICS import"), ("events", "attendees"), "user_export", "ICS import provides broad baseline."),
        )
    ),
)
