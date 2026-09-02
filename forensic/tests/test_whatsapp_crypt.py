"""Tests for enterprise WhatsApp Crypt12/14/15 decryption and backup unpacking."""

import io
import tarfile
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from forensix_forensic.extractors.whatsapp_downgrade import WhatsAppDowngradeExtractor


def test_decrypt_whatsapp_crypt15_gcm(tmp_path: Path) -> None:
    # 1. Create a dummy SQLite database
    sqlite_content = b"SQLite format 3\x00" + b"\x00" * 500 + b"test message content"
    compressed_sqlite = zlib.compress(sqlite_content)

    # 2. Generate 32-byte AES key inside a 158-byte key file
    master_key = b"K" * 32
    key_file_bytes = b"\x00" * 30 + master_key + b"\x00" * 96
    key_path = tmp_path / "whatsapp.key"
    key_path.write_bytes(key_file_bytes)

    # 3. Create Crypt15 encrypted file
    # 67-byte header, IV at bytes 51..67
    iv = b"I" * 16
    header = b"W" * 51 + iv
    aesgcm = AESGCM(master_key)
    ciphertext_with_tag = aesgcm.encrypt(iv, compressed_sqlite, None)

    crypt_path = tmp_path / "msgstore.db.crypt15"
    crypt_path.write_bytes(header + ciphertext_with_tag)

    # 4. Decrypt
    decrypted_path = WhatsAppDowngradeExtractor._decrypt_database(key_path, crypt_path, tmp_path)
    assert decrypted_path is not None
    assert decrypted_path.exists()
    assert decrypted_path.read_bytes().startswith(b"SQLite format 3\x00")
    assert b"test message content" in decrypted_path.read_bytes()


def test_unpack_ab_archive(tmp_path: Path) -> None:
    # 1. Create a tar archive with a key and msgstore file
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        key_data = b"KEY_CONTENT_BYTES_32_BYTES_1234567"
        key_info = tarfile.TarInfo(name="apps/com.whatsapp/files/key")
        key_info.size = len(key_data)
        tar.addfile(key_info, io.BytesIO(key_data))

        db_data = b"SQLite format 3\x00" + b"TEST_DB"
        db_info = tarfile.TarInfo(name="apps/com.whatsapp/databases/msgstore.db")
        db_info.size = len(db_data)
        tar.addfile(db_info, io.BytesIO(db_data))

    compressed_tar = zlib.compress(tar_buf.getvalue())

    # 2. Prepend standard Android Backup header
    header = b"ANDROID BACKUP\n5\n1\nnone\n"
    ab_path = tmp_path / "test.ab"
    ab_path.write_bytes(header + compressed_tar)

    # 3. Unpack
    dest_dir = tmp_path / "unpacked"
    dest_dir.mkdir()
    extracted = WhatsAppDowngradeExtractor._unpack_ab_archive(ab_path, dest_dir)
    assert len(extracted) == 2

    # 4. Find key and db files
    found_key = WhatsAppDowngradeExtractor._find_key_file(extracted)
    found_db = WhatsAppDowngradeExtractor._find_database_file(extracted)
    assert found_key is not None
    assert found_key.name == "key"
    assert found_db is not None
    assert found_db.name == "msgstore.db"
