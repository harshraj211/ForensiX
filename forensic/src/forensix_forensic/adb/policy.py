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


class SharedStorageRoot(StrEnum):
    PRIMARY_ALIAS = "primary_alias"
    EMULATED_PRIMARY = "emulated_primary"


_STORAGE_PATHS: dict[SharedStorageRoot, str] = {
    SharedStorageRoot.PRIMARY_ALIAS: "/sdcard",
    SharedStorageRoot.EMULATED_PRIMARY: "/storage/emulated/0",
}

INVENTORY_MAX_DEPTH = 6
INVENTORY_MAX_ITEMS = 250
MAX_ACQUIRED_FILE_BYTES = 100 * 1024 * 1024


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
