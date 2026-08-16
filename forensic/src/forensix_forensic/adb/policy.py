"""Closed ADB command policy for approved ForensiX operations."""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath


class AdbOperation(StrEnum):
    SERVER_INFO = "server_info"
    LIST_TRANSPORTS = "list_transports"
    GET_PROPERTIES = "get_properties"
    GET_KERNEL_VERSION = "get_kernel_version"
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
    GET_BATTERY = "get_battery"
    INSTALL_PACKAGE = "install_package"
    INSTALL_PACKAGES = "install_packages"
    LIST_PACKAGE_APKS = "list_package_apks"
    PULL_PACKAGE_APK = "pull_package_apk"
    UNINSTALL_PACKAGE = "uninstall_package"
    PUSH_FILE = "push_file"
    BACKUP_PACKAGE = "backup_package"
    DUMP_PACKAGE = "dump_package"
    ROOT_EXEC = "root_exec"


class SharedStorageRoot(StrEnum):
    PRIMARY_ALIAS = "primary_alias"
    EMULATED_PRIMARY = "emulated_primary"


class RootedCollectionProfile(StrEnum):
    ANDROID_CONTACTS = "android_contacts"
    ANDROID_MESSAGES = "android_messages"
    ANDROID_CALL_LOG = "android_call_log"
    WHATSAPP = "whatsapp"
    TELEGRAM = "telegram"
    SIGNAL = "signal"
    MESSENGER = "messenger"
    INSTAGRAM = "instagram"
    SNAPCHAT = "snapchat"
    ANDROID_PROVIDERS = "android_providers"
    ANDROID_SYSTEM = "android_system"
    ANDROID_APPS = "android_apps"
    ANDROID_USERDATA = "android_userdata"
    BFU_CREDENTIALS = "bfu_credentials"


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

INVENTORY_MAX_DEPTH = 10
INVENTORY_MAX_ITEMS = 5_000
MAX_ACQUIRED_FILE_BYTES = 100 * 1024 * 1024
MAX_ROOTED_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024
MAX_PHYSICAL_BLOCK_BYTES = 512 * 1024 * 1024 * 1024
CONTENT_PROVIDER_MAX_RECORDS = 500
MAX_SCREENSHOT_BYTES = 50 * 1024 * 1024
MAX_PUSH_FILE_BYTES = 200 * 1024 * 1024
MAX_BACKUP_FILE_BYTES = 256 * 1024 * 1024
MAX_PACKAGE_APK_BYTES = 1024 * 1024 * 1024
ADB_BACKUP_TIMEOUT_SECONDS = 300.0
ADB_INSTALL_TIMEOUT_SECONDS = 120.0

_ROOTED_PROFILE_PATHS: dict[RootedCollectionProfile, tuple[str, ...]] = {
    RootedCollectionProfile.ANDROID_CONTACTS: (
        "/data/user_de/0/com.android.providers.contacts/databases",
        "/data/user/0/com.android.providers.contacts/databases",
    ),
    RootedCollectionProfile.ANDROID_MESSAGES: (
        "/data/user_de/0/com.android.providers.telephony/databases",
        "/data/user/0/com.android.providers.telephony/databases",
    ),
    RootedCollectionProfile.ANDROID_CALL_LOG: (
        "/data/user_de/0/com.android.providers.contacts/databases/calllog.db",
        "/data/user/0/com.android.providers.contacts/databases/calllog.db",
    ),
    RootedCollectionProfile.WHATSAPP: (
        "/data/user/0/com.whatsapp/databases",
        "/data/user/0/com.whatsapp/files/key",
        "/data/user/0/com.whatsapp/shared_prefs",
    ),
    RootedCollectionProfile.TELEGRAM: (
        "/data/user/0/org.telegram.messenger.web/files/cache4.db",
        "/data/user/0/org.telegram.messenger.web/files/cache4.db-shm",
        "/data/user/0/org.telegram.messenger.web/files/cache4.db-wal",
        "/data/user/0/org.telegram.messenger.web/shared_prefs",
        "/data/user/0/org.telegram.messenger/files/cache4.db",
        "/data/user/0/org.telegram.messenger/files/cache4.db-shm",
        "/data/user/0/org.telegram.messenger/files/cache4.db-wal",
        "/data/user/0/org.telegram.messenger/shared_prefs",
    ),
    RootedCollectionProfile.SIGNAL: (
        "/data/user/0/org.thoughtcrime.securesms/databases",
        "/data/user/0/org.thoughtcrime.securesms/shared_prefs",
    ),
    RootedCollectionProfile.MESSENGER: ("/data/user/0/com.facebook.orca/databases",),
    RootedCollectionProfile.INSTAGRAM: ("/data/user/0/com.instagram.android/databases",),
    RootedCollectionProfile.SNAPCHAT: ("/data/user/0/com.snapchat.android/databases",),
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
    RootedCollectionProfile.ANDROID_USERDATA: (
        "/data/user/0",
        "/data/user_de/0",
        "/data/system",
        "/data/misc",
        "/data/media/0",
    ),
    RootedCollectionProfile.BFU_CREDENTIALS: (
        "/data/system/gatekeeper.password.key",
        "/data/system/gatekeeper.pattern.key",
        "/data/system/gatekeeper/0/gatekeeper.password.key",
        "/data/system/gatekeeper/0/gatekeeper.pattern.key",
        "/data/system/locksettings.db",
        "/data/system/locksettings.db-shm",
        "/data/system/locksettings.db-wal",
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
        return ApprovedAdbCommand(AdbOperation.LIST_TRANSPORTS, ("devices", "-l"), 15.0)

    @staticmethod
    def get_properties(serial: str) -> ApprovedAdbCommand:
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.GET_PROPERTIES,
            ("-s", serial, "shell", "getprop"),
            8.0,
        )

    @staticmethod
    def get_kernel_version(serial: str) -> ApprovedAdbCommand:
        """Return the live kernel version string for provider-profile revalidation."""
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.GET_KERNEL_VERSION,
            ("-s", serial, "shell", "uname", "-r"),
            8.0,
        )

    @staticmethod
    def get_battery(serial: str) -> ApprovedAdbCommand:
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.GET_BATTERY,
            ("-s", serial, "shell", "dumpsys", "battery"),
            5.0,
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
    def probe_root_access_android_su(serial: str) -> ApprovedAdbCommand:
        """Use the fixed UID form accepted by Android Studio's userdebug su binary."""
        _validate_serial(serial)
        return ApprovedAdbCommand(
            AdbOperation.PROBE_ROOT_ACCESS,
            ("-s", serial, "shell", "su", "0", "id"),
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
            3600.0 if profile is RootedCollectionProfile.ANDROID_USERDATA else 600.0,
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
    def install_package(serial: str, apk_path: str) -> ApprovedAdbCommand:
        """Push and install an APK to the device."""
        _validate_serial(serial)
        _validate_apk_path(apk_path)
        return ApprovedAdbCommand(
            AdbOperation.INSTALL_PACKAGE,
            ("-s", serial, "install", "-r", "-d", apk_path),
            ADB_INSTALL_TIMEOUT_SECONDS,
        )

    @staticmethod
    def install_packages(serial: str, apk_paths: tuple[str, ...]) -> ApprovedAdbCommand:
        """Restore a base APK and its split APKs in one package-manager transaction."""
        _validate_serial(serial)
        if not apk_paths or len(apk_paths) > 64:
            raise ValueError("APK restore must contain between 1 and 64 files")
        for apk_path in apk_paths:
            _validate_apk_path(apk_path)
        return ApprovedAdbCommand(
            AdbOperation.INSTALL_PACKAGES,
            ("-s", serial, "install-multiple", "-r", "-d", *apk_paths),
            ADB_INSTALL_TIMEOUT_SECONDS,
        )

    @staticmethod
    def list_package_apks(serial: str, package_name: str) -> ApprovedAdbCommand:
        """List installed base and split APK paths for one validated package."""
        _validate_serial(serial)
        _validate_package_name(package_name)
        return ApprovedAdbCommand(
            AdbOperation.LIST_PACKAGE_APKS,
            ("-s", serial, "shell", "pm", "path", package_name),
            15.0,
        )

    @staticmethod
    def pull_package_apk(serial: str, remote_path: str, destination: Path) -> ApprovedAdbCommand:
        """Copy one package-manager-reported APK to the workstation."""
        _validate_serial(serial)
        _validate_installed_apk_path(remote_path)
        destination = destination.absolute()
        if any(character in str(destination) for character in ("\x00", "\r", "\n")):
            raise ValueError("APK pull destination must be a safe absolute local path")
        return ApprovedAdbCommand(
            AdbOperation.PULL_PACKAGE_APK,
            ("-s", serial, "pull", remote_path, str(destination)),
            180.0,
        )

    @staticmethod
    def uninstall_package(serial: str, package_name: str) -> ApprovedAdbCommand:
        """Uninstall a package, keeping data."""
        _validate_serial(serial)
        _validate_package_name(package_name)
        return ApprovedAdbCommand(
            AdbOperation.UNINSTALL_PACKAGE,
            ("-s", serial, "uninstall", "-k", package_name),
            ADB_INSTALL_TIMEOUT_SECONDS,
        )

    @staticmethod
    def push_file(serial: str, local_path: Path, remote_path: str) -> ApprovedAdbCommand:
        """Push a single file to the device via ADB."""
        _validate_serial(serial)
        local = local_path.absolute()
        if any(character in str(local) for character in ("\x00", "\r", "\n")):
            raise ValueError("ADB push source must be a safe absolute local path")
        _validate_remote_path(remote_path)
        return ApprovedAdbCommand(
            AdbOperation.PUSH_FILE,
            ("-s", serial, "push", str(local), remote_path),
            120.0,
        )

    @staticmethod
    def backup_package(serial: str, package_name: str, destination: Path) -> ApprovedAdbCommand:
        """Run ``adb backup -f <dest> -noapk <pkg>`` for the downgrade-attack workflow."""
        _validate_serial(serial)
        _validate_package_name(package_name)
        dest = destination.absolute()
        if any(character in str(dest) for character in ("\x00", "\r", "\n")):
            raise ValueError("ADB backup destination must be a safe absolute local path")
        return ApprovedAdbCommand(
            AdbOperation.BACKUP_PACKAGE,
            (
                "-s",
                serial,
                "backup",
                "-f",
                str(dest),
                "-noapk",
                package_name,
            ),
            ADB_BACKUP_TIMEOUT_SECONDS,
        )

    @staticmethod
    def dump_package(serial: str, package_name: str) -> ApprovedAdbCommand:
        """Dump package metadata (version, codePath, etc.)."""
        _validate_serial(serial)
        _validate_package_name(package_name)
        return ApprovedAdbCommand(
            AdbOperation.DUMP_PACKAGE,
            ("-s", serial, "shell", "dumpsys", "package", package_name),
            10.0,
        )

    @staticmethod
    def root_exec(serial: str, command: str) -> ApprovedAdbCommand:
        """Execute a single approved command via ``su -c`` on a rooted device."""
        _validate_serial(serial)
        _validate_root_command(command)
        return ApprovedAdbCommand(
            AdbOperation.ROOT_EXEC,
            ("-s", serial, "shell", "su", "-c", command),
            60.0,
        )

    @staticmethod
    def storage_root_readable(serial: str, root: SharedStorageRoot) -> ApprovedAdbCommand:
        return AdbCommandPolicy._storage_test(
            serial, root, "-r", AdbOperation.STORAGE_ROOT_READABLE
        )

    @staticmethod
    def inventory_storage_paths(serial: str, root: SharedStorageRoot) -> ApprovedAdbCommand:
        _validate_serial(serial)
        # Prioritize standard user-content directories so the bounded result
        # cannot be consumed entirely by app caches under Android/.
        root_path = _STORAGE_PATHS[root]
        priority_directories = (
            ("DCIM", 800),
            ("Pictures", 400),
            ("Movies", 400),
            ("Music", 400),
            ("Download", 400),
            ("Downloads", 100),
            ("Documents", 400),
            ("Recordings", 200),
            ("Audiobooks", 100),
            ("Podcasts", 100),
        )
        priority_commands = "; ".join(
            f"[ ! -d {root_path}/{directory} ] || "
            f"find {root_path}/{directory} -xdev -maxdepth {INVENTORY_MAX_DEPTH - 1} "
            f"-type f -exec stat -c '%n:%s:%Y' {{}} + | head -n {item_limit}"
            for directory, item_limit in priority_directories
        )
        prune_expression = " -o ".join(
            f"-path {root_path}/{directory}" for directory, _ in priority_directories
        )
        command = (
            f"{{ {priority_commands}; find {root_path} -xdev "
            f"-maxdepth {INVENTORY_MAX_DEPTH} \\( {prune_expression} \\) -prune -o "
            "-type f -exec stat -c '%n:%s:%Y' {} +; "
            f"}} | head -n {INVENTORY_MAX_ITEMS}"
        )
        return ApprovedAdbCommand(
            AdbOperation.INVENTORY_STORAGE_PATHS,
            (
                "-s",
                serial,
                "shell",
                command,
            ),
            90.0,
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


# ---------------------------------------------------------------------------
# Validation helpers for new extraction operations
# ---------------------------------------------------------------------------

_APK_PATH_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/\\: "
)


def _validate_apk_path(apk_path: str) -> None:
    """Validate an APK file path for the install-package operation."""
    if not apk_path or len(apk_path) > 1024:
        raise ValueError("APK path must contain between 1 and 1024 characters")
    if "\x00" in apk_path or "\r" in apk_path or "\n" in apk_path:
        raise ValueError("APK path contains a prohibited control character")
    if not apk_path.lower().endswith(".apk"):
        raise ValueError("APK path must end with .apk")


def _validate_installed_apk_path(remote_path: str) -> None:
    """Accept only APK locations returned by Android's package manager."""
    if not remote_path or len(remote_path) > 2048:
        raise ValueError("Installed APK path must contain between 1 and 2048 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in remote_path):
        raise ValueError("Installed APK path contains a prohibited control character")
    path = PurePosixPath(remote_path)
    allowed = remote_path.startswith("/data/app/") or (
        remote_path.startswith("/mnt/expand/") and "/app/" in remote_path
    )
    if not allowed or not remote_path.lower().endswith(".apk") or ".." in path.parts:
        raise ValueError("Installed APK path is outside package-manager storage")


def _validate_package_name(package_name: str) -> None:
    """Validate an Android package name (e.g. com.whatsapp)."""
    import re

    if not package_name or len(package_name) > 255:
        raise ValueError("Package name must contain between 1 and 255 characters")
    if not re.fullmatch(r"[a-zA-Z0-9._]+", package_name):
        raise ValueError("Package name contains invalid characters")


def _validate_remote_path(remote_path: str) -> None:
    """Validate a remote ADB push destination path."""
    if not remote_path or len(remote_path) > 1024:
        raise ValueError("Remote path must contain between 1 and 1024 characters")
    if "\x00" in remote_path or "\r" in remote_path or "\n" in remote_path:
        raise ValueError("Remote path contains a prohibited control character")


def _validate_root_command(command: str) -> None:
    """Validate a command string for root_exec (closed set of allowed prefixes)."""
    if not command or len(command) > 2048:
        raise ValueError("Root command must contain between 1 and 2048 characters")
    if "\x00" in command or "\r" in command or "\n" in command:
        raise ValueError("Root command contains a prohibited control character")
    allowed_prefixes = (
        "cat ",
        "cp ",
        "chmod ",
        "chown ",
        "ls ",
        "stat ",
        "dd ",
        "tar ",
        "dbtool ",
        "sqlite3 ",
        "sha256sum ",
        "md5sum ",
        "am ",
        "pm ",
        "input ",
        "getprop ",
        "setprop ",
        "id ",
    )
    normalized = command.strip()
    if not any(normalized.startswith(prefix) for prefix in allowed_prefixes):
        raise ValueError(
            "Root command must start with an approved forensic prefix: "
            + ", ".join(allowed_prefixes)
        )
