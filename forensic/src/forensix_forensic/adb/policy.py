"""Closed ADB command policy for approved ForensiX operations."""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath


class AdbOperation(StrEnum):
    SERVER_INFO = "server_info"
    LIST_TRANSPORTS = "list_transports"
    GET_PROPERTIES = "get_properties"
    LIST_PACKAGES = "list_packages"
    STORAGE_ROOT_EXISTS = "storage_root_exists"
    STORAGE_ROOT_READABLE = "storage_root_readable"
    INVENTORY_STORAGE_PATHS = "inventory_storage_paths"
    PULL_INVENTORY_FILE = "pull_inventory_file"
    PROBE_ROOT_ACCESS = "probe_root_access"
    CAPTURE_ROOTED_BUNDLE = "capture_rooted_bundle"
    PROBE_PHYSICAL_BLOCK = "probe_physical_block"
    CAPTURE_PHYSICAL_BLOCK = "capture_physical_block"
    PROBE_CONTENT_PROVIDER = "probe_content_provider"
    QUERY_CONTENT_PROVIDER = "query_content_provider"
    CAPTURE_SCREENSHOT = "capture_screenshot"


class SharedStorageRoot(StrEnum):
    PRIMARY_ALIAS = "primary_alias"
    EMULATED_PRIMARY = "emulated_primary"


class RootedCollectionProfile(StrEnum):
    ANDROID_PROVIDERS = "android_providers"
    ANDROID_SYSTEM = "android_system"
    ANDROID_APPS = "android_apps"


class PhysicalBlockProfile(StrEnum):
    USERDATA_BY_NAME = "userdata_by_name"


class ContentProviderProfile(StrEnum):
    CONTACTS = "contacts"
    SMS = "sms"
    CALL_LOG = "call_log"


_STORAGE_PATHS: dict[SharedStorageRoot, str] = {
    SharedStorageRoot.PRIMARY_ALIAS: "/sdcard",
    SharedStorageRoot.EMULATED_PRIMARY: "/storage/emulated/0",
}

INVENTORY_MAX_DEPTH = 6
INVENTORY_MAX_ITEMS = 250
MAX_ACQUIRED_FILE_BYTES = 100 * 1024 * 1024
MAX_ROOTED_BUNDLE_BYTES = 1024 * 1024 * 1024
MAX_PHYSICAL_BLOCK_BYTES = 512 * 1024 * 1024 * 1024
CONTENT_PROVIDER_MAX_RECORDS = 500
MAX_SCREENSHOT_BYTES = 50 * 1024 * 1024

_ROOTED_PROFILE_PATHS: dict[RootedCollectionProfile, tuple[str, ...]] = {
    RootedCollectionProfile.ANDROID_PROVIDERS: (
        "/data/user_de/0/com.android.providers.contacts/databases",
        "/data/user/0/com.android.providers.contacts/databases",
        "/data/user_de/0/com.android.providers.telephony/databases",
        "/data/user/0/com.android.providers.telephony/databases",
        "/data/user_de/0/com.android.providers.calendar/databases",
        "/data/user/0/com.android.providers.calendar/databases",
    ),
    RootedCollectionProfile.ANDROID_SYSTEM: (
        "/data/user_de/0/com.android.providers.downloads/databases",
        "/data/user/0/com.android.providers.downloads/databases",
        "/data/user/0/com.android.chrome/app_chrome/Default/History",
        "/data/system/notification_policy.xml",
        "/data/system/users/0/settings_secure.xml",
        "/data/misc/apexdata/com.android.wifi",
        "/data/misc/wifi",
        "/data/misc/bluedroid",
        "/data/misc/location",
    ),
    RootedCollectionProfile.ANDROID_APPS: (
        "/data/user/0/com.whatsapp/databases",
        "/data/user/0/com.whatsapp/files/key",
        "/data/user/0/com.whatsapp/shared_prefs",
        "/data/user/0/org.telegram.messenger.web/files/cache4.db",
        "/data/user/0/org.telegram.messenger.web/files/cache4.db-shm",
        "/data/user/0/org.telegram.messenger.web/files/cache4.db-wal",
        "/data/user/0/org.telegram.messenger.web/shared_prefs",
        "/data/user/0/org.telegram.messenger/files/cache4.db",
        "/data/user/0/org.telegram.messenger/files/cache4.db-shm",
        "/data/user/0/org.telegram.messenger/files/cache4.db-wal",
        "/data/user/0/org.telegram.messenger/shared_prefs",
        "/data/user/0/org.thoughtcrime.securesms/databases",
        "/data/user/0/org.thoughtcrime.securesms/shared_prefs",
        "/data/user/0/com.facebook.orca/databases",
        "/data/user/0/com.facebook.katana/databases",
        "/data/user/0/com.instagram.android/databases",
        "/data/user/0/com.snapchat.android/databases",
    ),
}

_PHYSICAL_BLOCK_PATHS: dict[PhysicalBlockProfile, str] = {
    PhysicalBlockProfile.USERDATA_BY_NAME: "/dev/block/by-name/userdata"
}

_CONTENT_PROVIDER_URIS: dict[ContentProviderProfile, str] = {
    ContentProviderProfile.CONTACTS: "content://com.android.contacts/data/phones",
    ContentProviderProfile.SMS: "content://sms",
    ContentProviderProfile.CALL_LOG: "content://call_log/calls",
}

_CONTENT_PROVIDER_PROJECTIONS: dict[ContentProviderProfile, tuple[str, ...]] = {
    ContentProviderProfile.CONTACTS: (
        "_id",
        "contact_id",
        "display_name",
        "data1",
        "data2",
        "data4",
    ),
    ContentProviderProfile.SMS: (
        "_id",
        "thread_id",
        "address",
        "date",
        "date_sent",
        "type",
        "read",
        "body",
    ),
    ContentProviderProfile.CALL_LOG: (
        "_id",
        "number",
        "date",
        "duration",
        "type",
        "name",
    ),
}


@dataclass(frozen=True, slots=True)
class ApprovedAdbCommand:
    operation: AdbOperation
    arguments: tuple[str, ...]
    timeout_seconds: float


class AdbCommandPolicy:
    """Builds argument vectors from typed operations; no caller supplies shell text or paths."""

    @staticmethod
    def server_info() -> ApprovedAdbCommand:
        return ApprovedAdbCommand(AdbOperation.SERVER_INFO, ("version",), 10.0)

    @staticmethod
    def list_transports() -> ApprovedAdbCommand:
        return ApprovedAdbCommand(AdbOperation.LIST_TRANSPORTS, ("devices", "-l"), 5.0)

    @staticmethod
    def get_properties(serial: str) -> ApprovedAdbCommand:
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.GET_PROPERTIES,
            ("-s", serial, "shell", "getprop"),
            8.0,
        )

    @staticmethod
    def list_packages(serial: str) -> ApprovedAdbCommand:
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.LIST_PACKAGES,
            ("-s", serial, "shell", "cmd", "package", "list", "packages"),
            12.0,
        )

    @staticmethod
    def probe_content_provider(serial: str, profile: ContentProviderProfile) -> ApprovedAdbCommand:
        """Check provider permission without returning a user record."""
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.PROBE_CONTENT_PROVIDER,
            (
                "-s",
                serial,
                "shell",
                "content",
                "query",
                "--uri",
                _CONTENT_PROVIDER_URIS[profile],
                "--projection",
                "_id",
                "--where",
                "0=1",
            ),
            10.0,
        )

    @staticmethod
    def query_content_provider(serial: str, profile: ContentProviderProfile) -> ApprovedAdbCommand:
        """Collect a fixed projection after a successful capability probe."""
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.QUERY_CONTENT_PROVIDER,
            (
                "-s",
                serial,
                "shell",
                "content",
                "query",
                "--uri",
                _CONTENT_PROVIDER_URIS[profile],
                "--projection",
                ":".join(_CONTENT_PROVIDER_PROJECTIONS[profile]),
            ),
            60.0,
        )

    @staticmethod
    def content_provider_projection(profile: ContentProviderProfile) -> tuple[str, ...]:
        return _CONTENT_PROVIDER_PROJECTIONS[profile]

    @staticmethod
    def capture_screenshot(serial: str) -> ApprovedAdbCommand:
        """Stream a PNG to the workstation without creating a device-side file."""
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.CAPTURE_SCREENSHOT,
            ("-s", serial, "exec-out", "screencap", "-p"),
            20.0,
        )

    @staticmethod
    def probe_root_access(serial: str) -> ApprovedAdbCommand:
        """Return the one fixed elevated identity probe; no caller supplies shell text."""
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.PROBE_ROOT_ACCESS,
            ("-s", serial, "shell", "su", "-c", "id"),
            8.0,
        )

    @staticmethod
    def capture_rooted_bundle(serial: str, profile: RootedCollectionProfile) -> ApprovedAdbCommand:
        """Build one literal provider-bundle command from a closed profile enum."""
        _validate_serial(serial)
        quoted_paths = " ".join(f"'{path}'" for path in _ROOTED_PROFILE_PATHS[profile])
        command = (
            f"set --; for p in {quoted_paths}; do "
            'if [ -e "$p" ]; then set -- "$@" "$p"; fi; done; '
            '[ "$#" -gt 0 ] || exit 44; exec tar -cf - "$@"'
        )
        return ApprovedAdbCommand(
            AdbOperation.CAPTURE_ROOTED_BUNDLE,
            ("-s", serial, "exec-out", "su", "-c", command),
            600.0,
        )

    @staticmethod
    def rooted_profile_paths(profile: RootedCollectionProfile) -> tuple[str, ...]:
        return _ROOTED_PROFILE_PATHS[profile]

    @staticmethod
    def probe_physical_block(serial: str, profile: PhysicalBlockProfile) -> ApprovedAdbCommand:
        _validate_serial(serial)
        path = _PHYSICAL_BLOCK_PATHS[profile]
        command = f"blockdev --getsize64 '{path}'"
        return ApprovedAdbCommand(
            AdbOperation.PROBE_PHYSICAL_BLOCK,
            ("-s", serial, "exec-out", "su", "-c", command),
            10.0,
        )

    @staticmethod
    def capture_physical_block(serial: str, profile: PhysicalBlockProfile) -> ApprovedAdbCommand:
        _validate_serial(serial)
        path = _PHYSICAL_BLOCK_PATHS[profile]
        command = f"exec dd if='{path}' bs=1048576"
        return ApprovedAdbCommand(
            AdbOperation.CAPTURE_PHYSICAL_BLOCK,
            ("-s", serial, "exec-out", "su", "-c", command),
            24 * 60 * 60.0,
        )

    @staticmethod
    def physical_block_path(profile: PhysicalBlockProfile) -> str:
        return _PHYSICAL_BLOCK_PATHS[profile]

    @staticmethod
    def storage_root_exists(serial: str, root: SharedStorageRoot) -> ApprovedAdbCommand:
        return AdbCommandPolicy._storage_test(serial, root, "-d", AdbOperation.STORAGE_ROOT_EXISTS)

    @staticmethod
    def storage_root_readable(serial: str, root: SharedStorageRoot) -> ApprovedAdbCommand:
        return AdbCommandPolicy._storage_test(
            serial, root, "-r", AdbOperation.STORAGE_ROOT_READABLE
        )

    @staticmethod
    def inventory_storage_paths(serial: str, root: SharedStorageRoot) -> ApprovedAdbCommand:
        _validate_serial(serial)
        # This is intentionally a closed, literal command.  `head` terminates
        # the producer after the approved record cap, preventing a full-device
        # traversal before the workstation can apply its own parser limits.
        command = (
            f"find {_STORAGE_PATHS[root]} -xdev -maxdepth {INVENTORY_MAX_DEPTH} "
            "-type f -exec stat -c '%n:%s:%Y' {} + "
            f"| head -n {INVENTORY_MAX_ITEMS}"
        )
        return ApprovedAdbCommand(
            AdbOperation.INVENTORY_STORAGE_PATHS,
            (
                "-s",
                serial,
                "shell",
                command,
            ),
            30.0,
        )

    @staticmethod
    def pull_inventory_file(
        serial: str,
        root: SharedStorageRoot,
        relative_path: str,
        destination: Path,
    ) -> ApprovedAdbCommand:
        _validate_serial(serial)
        _validate_inventory_relative_path(relative_path)
        destination = destination.absolute()
        if any(character in str(destination) for character in ("\x00", "\r", "\n")):
            raise ValueError("ADB pull destination must be a safe absolute local path")
        remote_path = f"{_STORAGE_PATHS[root].rstrip('/')}/{relative_path}"
        return ApprovedAdbCommand(
            AdbOperation.PULL_INVENTORY_FILE,
            ("-s", serial, "pull", remote_path, str(destination)),
            120.0,
        )

    @staticmethod
    def display_path(root: SharedStorageRoot) -> str:
        return _STORAGE_PATHS[root]

    @staticmethod
    def _storage_test(
        serial: str,
        root: SharedStorageRoot,
        predicate: str,
        operation: AdbOperation,
    ) -> ApprovedAdbCommand:
        _validate_serial(serial)
        return ApprovedAdbCommand(
            operation,
            ("-s", serial, "shell", "test", predicate, _STORAGE_PATHS[root]),
            5.0,
        )


def _validate_serial(serial: str) -> None:
    if not serial or len(serial) > 255:
        raise ValueError("ADB serial must contain between 1 and 255 characters")
    if any(character.isspace() or ord(character) < 32 for character in serial):
        raise ValueError("ADB serial contains a prohibited control character")


def _validate_inventory_relative_path(relative_path: str) -> None:
    if not relative_path or len(relative_path) > 1024:
        raise ValueError("Inventory relative path must contain between 1 and 1024 characters")
    path = PurePosixPath(relative_path)
    parts = relative_path.split("/")
    if (
        path.is_absolute()
        or len(parts) > INVENTORY_MAX_DEPTH
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in relative_path)
    ):
        raise ValueError("Inventory relative path is outside the approved path policy")
