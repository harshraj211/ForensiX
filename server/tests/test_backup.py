from pathlib import Path

import pytest

from forensix_server.backup import BackupError, create_backup, restore_backup, verify_backup
from forensix_server.db import Database

PASSPHRASE = "Known-answer backup passphrase 2026!"


def _database(tmp_path: Path) -> Database:
    data_dir = tmp_path / "data"
    database = Database(f"sqlite:///{(data_dir / 'forensix.db').as_posix()}", data_dir)
    database.initialize()
    evidence = data_dir / "evidence" / "cases" / "case-1"
    evidence.mkdir(parents=True)
    (evidence / "known.bin").write_bytes(b"known forensic evidence\x00\x01")
    return database


def test_encrypted_backup_round_trip_and_manifest_verification(tmp_path: Path) -> None:
    database = _database(tmp_path)
    backup = tmp_path / "backup.fxb"
    restored = tmp_path / "restored"
    try:
        created = create_backup(database, backup, PASSPHRASE)
        verified = verify_backup(backup, PASSPHRASE)
        restoration = restore_backup(backup, restored, PASSPHRASE)
    finally:
        database.dispose()

    assert backup.read_bytes().startswith(b"FXBACK01")
    assert b"known forensic evidence" not in backup.read_bytes()
    assert created.file_count == 2
    assert verified.valid is True
    assert verified.plaintext_sha256 == created.plaintext_sha256
    assert restoration.file_count == created.file_count
    assert (restored / "evidence" / "cases" / "case-1" / "known.bin").read_bytes() == (
        b"known forensic evidence\x00\x01"
    )
    assert (restored / "database" / "forensix.db").is_file()


def test_backup_rejects_wrong_passphrase_and_tampering(tmp_path: Path) -> None:
    database = _database(tmp_path)
    backup = tmp_path / "backup.fxb"
    try:
        create_backup(database, backup, PASSPHRASE)
    finally:
        database.dispose()

    with pytest.raises(BackupError, match="wrong passphrase or modified"):
        verify_backup(backup, "A different long passphrase!")

    payload = bytearray(backup.read_bytes())
    payload[-1] ^= 1
    backup.write_bytes(payload)
    with pytest.raises(BackupError, match="wrong passphrase or modified"):
        verify_backup(backup, PASSPHRASE)


def test_restore_requires_empty_destination(tmp_path: Path) -> None:
    database = _database(tmp_path)
    backup = tmp_path / "backup.fxb"
    try:
        create_backup(database, backup, PASSPHRASE)
    finally:
        database.dispose()
    destination = tmp_path / "occupied"
    destination.mkdir()
    (destination / "keep.txt").write_text("do not overwrite", encoding="utf-8")

    with pytest.raises(BackupError, match="must be empty"):
        restore_backup(backup, destination, PASSPHRASE)

    assert (destination / "keep.txt").read_text(encoding="utf-8") == "do not overwrite"
