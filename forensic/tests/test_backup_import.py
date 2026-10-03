from __future__ import annotations

import io
import tarfile
import zlib
from pathlib import Path
from zipfile import ZipFile

import pytest

from forensix_forensic.extractors.backup_import import (
    InvalidBackupImport,
    inspect_backup_import,
)


def test_inspects_unencrypted_legacy_android_backup(tmp_path: Path) -> None:
    backup = tmp_path / "legacy.ab"
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode="w") as archive:
        info = tarfile.TarInfo("apps/com.example.app/db/data.db")
        info.size = 3
        archive.addfile(info, io.BytesIO(b"db!"))
    backup.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(tar_data.getvalue()))

    inspection = inspect_backup_import(backup)

    assert inspection.backup_kind == "legacy_android_backup"
    assert inspection.format_version == "5"
    assert inspection.compression == "zlib"
    assert inspection.encrypted is False
    assert inspection.member_count == 1
    assert inspection.package_hints == ("com.example.app",)


def test_marks_encrypted_legacy_android_backup_without_decrypting(tmp_path: Path) -> None:
    backup = tmp_path / "encrypted.ab"
    backup.write_bytes(b"ANDROID BACKUP\n5\n0\nAES-256\nencrypted-payload")

    inspection = inspect_backup_import(backup)

    assert inspection.encrypted is True
    assert "passphrase" in inspection.warnings[0]


def test_inspects_smart_switch_style_zip_structure(tmp_path: Path) -> None:
    backup = tmp_path / "SmartSwitch.sbu"
    with ZipFile(backup, "w") as archive:
        archive.writestr("contacts/contacts.db", b"SQLite format 3\x00")
        archive.writestr("messages/messages.db", b"SQLite format 3\x00")
        archive.writestr("media/image.jpg", b"image")

    inspection = inspect_backup_import(backup)

    assert inspection.backup_kind == "samsung_smart_switch_archive"
    assert inspection.member_count == 3
    assert {"contacts", "messages", "media"}.issubset(inspection.package_hints)


def test_generic_zip_is_not_labeled_smart_switch(tmp_path: Path) -> None:
    backup = tmp_path / "unrelated.zip"
    with ZipFile(backup, "w") as archive:
        archive.writestr("contacts.csv", b"name,phone\nExample,123\n")

    inspection = inspect_backup_import(backup)

    assert inspection.backup_kind == "generic_backup_archive"
    assert "no Samsung parser" in inspection.warnings[0]


def test_declared_smart_switch_zip_name_survives_temporary_upload_path(tmp_path: Path) -> None:
    backup = tmp_path / "upload.zip"
    with ZipFile(backup, "w") as archive:
        archive.writestr("contacts.csv", b"name,phone\nExample,123\n")

    inspection = inspect_backup_import(backup, source_name="SmartSwitch.zip")

    assert inspection.backup_kind == "samsung_smart_switch_archive"


def test_rejects_unsafe_vendor_archive_member(tmp_path: Path) -> None:
    backup = tmp_path / "unsafe.zip"
    with ZipFile(backup, "w") as archive:
        archive.writestr("../outside.db", b"not allowed")

    with pytest.raises(InvalidBackupImport, match="unsafe member path"):
        inspect_backup_import(backup)


def test_inspects_ext4_memory_card_image_without_mounting(tmp_path: Path) -> None:
    image = tmp_path / "card.img"
    data = bytearray(8192)
    data[1024 + 0x18 : 1024 + 0x1C] = (2).to_bytes(4, "little")
    data[1024 + 0x38 : 1024 + 0x3A] = b"\x53\xef"
    image.write_bytes(data)

    inspection = inspect_backup_import(image)

    assert inspection.backup_kind == "memory_card_image"
    assert inspection.filesystem_type == "ext4"
    assert inspection.filesystem_block_size == 4096
