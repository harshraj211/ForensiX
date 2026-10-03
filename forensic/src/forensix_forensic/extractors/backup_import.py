"""Bounded inspection of user-supplied Android backup containers.

This module classifies a backup before the original bytes are sealed. It does
not decrypt, modify, restore, or extract data from a device.
"""

from __future__ import annotations

import tarfile
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from forensix_forensic.extractors.memory_card import probe_fat32

MAX_BACKUP_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024


class InvalidBackupImport(ValueError):
    """Raised when a backup does not meet the bounded import contract."""


@dataclass(frozen=True, slots=True)
class BackupImportInspection:
    backup_kind: str
    format_version: str | None
    compression: str | None
    encrypted: bool
    member_count: int | None
    member_bytes: int | None
    package_hints: tuple[str, ...]
    warnings: tuple[str, ...]
    filesystem_type: str | None = None
    filesystem_block_size: int | None = None


def inspect_backup_import(path: Path, *, source_name: str | None = None) -> BackupImportInspection:
    """Inspect a legacy Android Backup or Smart Switch archive without extraction."""
    if not path.is_file() or path.is_symlink():
        raise InvalidBackupImport("Backup input must be a regular file.")
    if not 0 < path.stat().st_size <= MAX_BACKUP_BYTES:
        raise InvalidBackupImport("Backup input violates the 2 GiB size limit.")
    suffix = path.suffix.casefold()
    if suffix == ".ab":
        return _inspect_android_backup(path)
    if suffix in {".zip", ".sbu"}:
        return _inspect_vendor_archive(path, source_name=source_name)
    if suffix in {".img", ".dd", ".raw"}:
        return _inspect_memory_card_image(path)
    raise InvalidBackupImport("Supported inputs are .ab, .zip, .sbu, .img, .dd, and .raw files.")


def _inspect_android_backup(path: Path) -> BackupImportInspection:
    with path.open("rb") as source:
        fields = [_read_header_line(source) for _ in range(4)]
    magic, version, compression, encryption = fields
    if magic != "ANDROID BACKUP":
        raise InvalidBackupImport("The .ab file does not have an Android Backup header.")
    if version not in {"1", "2", "3", "4", "5"}:
        raise InvalidBackupImport("The Android Backup format version is unsupported.")
    if compression not in {"0", "1"}:
        raise InvalidBackupImport("The Android Backup compression field is invalid.")
    if not encryption:
        raise InvalidBackupImport("The Android Backup encryption field is missing.")
    encrypted = encryption.casefold() != "none"
    warnings: tuple[str, ...] = (
        (
            "Encrypted Android Backup payload; a user-supplied passphrase is required before parsing.",
        )
        if encrypted
        else (
            "Legacy Android Backup TAR inventory is structural; application payloads are not restored or modified.",
        )
    )
    member_count: int | None = None
    member_bytes: int | None = None
    package_hints: tuple[str, ...] = ()
    if not encrypted:
        member_count, member_bytes, package_hints = _inspect_unencrypted_ab_payload(
            path, compressed=compression == "1"
        )
    return BackupImportInspection(
        backup_kind="legacy_android_backup",
        format_version=version,
        compression="zlib" if compression == "1" else "none",
        encrypted=encrypted,
        member_count=member_count,
        member_bytes=member_bytes,
        package_hints=package_hints,
        warnings=warnings,
    )


def _inspect_unencrypted_ab_payload(
    path: Path, *, compressed: bool
) -> tuple[int, int, tuple[str, ...]]:
    """Boundedly decompress and inventory an unencrypted Android Backup TAR stream."""
    with path.open("rb") as source:
        for _ in range(4):
            _read_header_line(source)
        with tempfile.TemporaryFile() as payload:
            if compressed:
                decompressor = zlib.decompressobj()
                total = 0
                while chunk := source.read(1024 * 1024):
                    data = decompressor.decompress(
                        chunk, MAX_ARCHIVE_UNCOMPRESSED_BYTES - total + 1
                    )
                    total += len(data)
                    if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        raise InvalidBackupImport(
                            "Android Backup payload exceeds the uncompressed size limit."
                        )
                    payload.write(data)
                tail = decompressor.flush(MAX_ARCHIVE_UNCOMPRESSED_BYTES - total + 1)
                total += len(tail)
                if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES or not decompressor.eof:
                    raise InvalidBackupImport(
                        "Android Backup payload is malformed or exceeds the size limit."
                    )
                payload.write(tail)
            else:
                total = 0
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        raise InvalidBackupImport(
                            "Android Backup payload exceeds the uncompressed size limit."
                        )
                    payload.write(chunk)
            payload.seek(0)
            try:
                with tarfile.open(fileobj=payload, mode="r:") as archive:
                    members = archive.getmembers()
            except tarfile.TarError as error:
                raise InvalidBackupImport(
                    "Unencrypted Android Backup payload is not a valid TAR archive."
                ) from error
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise InvalidBackupImport("Android Backup contains too many archive members.")
    names = [member.name for member in members]
    if any(not _safe_archive_member(name) for name in names):
        raise InvalidBackupImport("Android Backup contains an unsafe member path.")
    member_bytes = sum(member.size for member in members)
    if member_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
        raise InvalidBackupImport(
            "Android Backup archive members exceed the uncompressed size limit."
        )
    packages = sorted(
        {
            parts[1]
            for name in names
            if (parts := name.split("/"))[:1] == ["apps"] and len(parts) > 1
        }
    )
    return len(members), member_bytes, tuple(packages[:200])


def _inspect_vendor_archive(
    path: Path, *, source_name: str | None = None
) -> BackupImportInspection:
    try:
        with ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise InvalidBackupImport("Backup archive has too many members.")
            names = [member.filename for member in members]
            if any(not _safe_archive_member(name) for name in names):
                raise InvalidBackupImport("Backup archive contains an unsafe member path.")
            total = sum(member.file_size for member in members)
            if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise InvalidBackupImport("Backup archive exceeds the uncompressed size limit.")
    except BadZipFile as error:
        raise InvalidBackupImport(
            "Vendor backup must be a readable ZIP-compatible archive."
        ) from error
    lower = "\n".join(names).casefold()
    hints = tuple(
        name
        for name, marker in (
            ("contacts", "contact"),
            ("messages", "message"),
            ("call_logs", "call"),
            ("media", "media"),
            ("settings", "setting"),
        )
        if marker in lower
    )
    declared_stem = Path((source_name or path.name).replace("\\", "/")).stem
    smart_switch_marker = (
        path.suffix.casefold() == ".sbu"
        or "smartswitch" in declared_stem.casefold().replace(" ", "")
        or any("smartswitch" in name.casefold().replace(" ", "") for name in names)
    )
    backup_kind = (
        "samsung_smart_switch_archive" if smart_switch_marker else "generic_backup_archive"
    )
    warnings = (
        (
            "Archive inventory is structural only; source application versions and encrypted members require parser review.",
        )
        if smart_switch_marker
        else (
            "ZIP format alone does not establish a Smart Switch origin; no Samsung parser was run.",
        )
    )
    return BackupImportInspection(
        backup_kind=backup_kind,
        format_version=None,
        compression="zip",
        encrypted=any(member.flag_bits & 0x1 for member in members),
        member_count=len(members),
        member_bytes=total,
        package_hints=hints,
        warnings=warnings,
    )


def _inspect_memory_card_image(path: Path) -> BackupImportInspection:
    """Identify supported card filesystems without mounting the image."""
    fat32 = probe_fat32(path)
    if fat32 is not None:
        return BackupImportInspection(
            backup_kind="memory_card_image",
            format_version=None,
            compression="none",
            encrypted=False,
            member_count=None,
            member_bytes=path.stat().st_size,
            package_hints=(),
            warnings=(
                "FAT32 image detected; read-only file and deleted-entry examination requires a verified working copy.",
            ),
            filesystem_type="fat32",
            filesystem_block_size=fat32.cluster_bytes,
        )
    with path.open("rb") as source:
        source.seek(0x400)
        f2fs_magic = source.read(4)
        source.seek(1024)
        ext4 = source.read(1024)
    filesystem_type = "unknown"
    block_size: int | None = None
    if len(ext4) >= 0x3A and ext4[0x38:0x3A] == b"\x53\xef":
        exponent = int.from_bytes(ext4[0x18:0x1C], "little")
        if exponent <= 6:
            filesystem_type = "ext4"
            block_size = 1024 << exponent
    elif f2fs_magic == b"\x10\x20\xf5\xf2":
        filesystem_type = "f2fs"
        block_size = 4096
    return BackupImportInspection(
        backup_kind="memory_card_image",
        format_version=None,
        compression="none",
        encrypted=False,
        member_count=None,
        member_bytes=path.stat().st_size,
        package_hints=(),
        warnings=(
            "Read-only image identification only; filesystem traversal and carved files require a verified working-copy examination.",
        ),
        filesystem_type=filesystem_type,
        filesystem_block_size=block_size,
    )


def _read_header_line(source: object) -> str:
    value = source.readline(257)  # type: ignore[attr-defined]
    if not isinstance(value, bytes) or not value.endswith(b"\n") or len(value) > 256:
        raise InvalidBackupImport("The Android Backup header is malformed.")
    try:
        return value[:-1].decode("ascii")
    except UnicodeDecodeError as error:
        raise InvalidBackupImport("The Android Backup header is not ASCII.") from error


def _safe_archive_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return bool(normalized) and not normalized.startswith("/") and ".." not in normalized.split("/")
