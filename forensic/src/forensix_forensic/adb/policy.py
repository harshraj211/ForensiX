"""Closed ADB command policy for approved ForensiX operations."""

from dataclasses import dataclass
from enum import StrEnum


class AdbOperation(StrEnum):
    SERVER_INFO = "server_info"
    LIST_TRANSPORTS = "list_transports"
    GET_PROPERTIES = "get_properties"
    LIST_PACKAGES = "list_packages"
    STORAGE_ROOT_EXISTS = "storage_root_exists"
    STORAGE_ROOT_READABLE = "storage_root_readable"


class SharedStorageRoot(StrEnum):
    PRIMARY_ALIAS = "primary_alias"
    EMULATED_PRIMARY = "emulated_primary"


_STORAGE_PATHS: dict[SharedStorageRoot, str] = {
    SharedStorageRoot.PRIMARY_ALIAS: "/sdcard",
    SharedStorageRoot.EMULATED_PRIMARY: "/storage/emulated/0",
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
    def storage_root_exists(serial: str, root: SharedStorageRoot) -> ApprovedAdbCommand:
        return AdbCommandPolicy._storage_test(serial, root, "-d", AdbOperation.STORAGE_ROOT_EXISTS)

    @staticmethod
    def storage_root_readable(serial: str, root: SharedStorageRoot) -> ApprovedAdbCommand:
        return AdbCommandPolicy._storage_test(
            serial, root, "-r", AdbOperation.STORAGE_ROOT_READABLE
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
