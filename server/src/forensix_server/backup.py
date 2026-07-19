"""Versioned, chunk-authenticated workstation backup and safe restore."""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from forensix_forensic.storage import sha256_file

from .db import Database

MAGIC = b"FXBACK01"
FORMAT_VERSION = "1.0.0"
CHUNK_SIZE = 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 1


class BackupError(RuntimeError):
    """Safe backup or restore failure."""


@dataclass(frozen=True, slots=True)
class BackupResult:
    path: Path
    size_bytes: int
    sha256: str
    plaintext_sha256: str
    file_count: int
    created_at: datetime


@dataclass(frozen=True, slots=True)
class BackupVerification:
    valid: bool
    plaintext_sha256: str
    file_count: int
    created_at: datetime


def create_backup(
    database: Database, output: Path, passphrase: str, *, overwrite: bool = False
) -> BackupResult:
    _validate_passphrase(passphrase)
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not overwrite:
        raise BackupError("The backup destination already exists.")
    created_at = datetime.now(UTC)
    with tempfile.TemporaryDirectory(prefix="forensix-backup-") as temporary:
        workspace = Path(temporary)
        snapshot = workspace / "forensix.db"
        archive = workspace / "payload.zip"
        _snapshot_database(database, snapshot)
        entries = _build_archive(database.data_dir, snapshot, archive, created_at)
        plaintext_hash = sha256_file(archive)
        partial = output.with_name(f".{output.name}.{os.getpid()}.partial")
        partial.unlink(missing_ok=True)
        try:
            _encrypt_file(
                archive,
                partial,
                passphrase,
                plaintext_sha256=plaintext_hash.hexdigest,
                created_at=created_at,
            )
            verification = verify_backup(partial, passphrase)
            if (
                not verification.valid
                or verification.plaintext_sha256 != plaintext_hash.hexdigest
                or verification.file_count != len(entries)
            ):
                raise BackupError("The encrypted backup failed post-write verification.")
            if overwrite:
                os.replace(partial, output)
            else:
                partial.replace(output)
        except Exception:
            partial.unlink(missing_ok=True)
            raise
    sealed = sha256_file(output)
    return BackupResult(
        path=output,
        size_bytes=sealed.size_bytes,
        sha256=sealed.hexdigest,
        plaintext_sha256=plaintext_hash.hexdigest,
        file_count=len(entries),
        created_at=created_at,
    )


def verify_backup(path: Path, passphrase: str) -> BackupVerification:
    _validate_passphrase(passphrase)
    path = path.expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix="forensix-verify-") as temporary:
        archive = Path(temporary) / "payload.zip"
        header = _decrypt_file(path, archive, passphrase)
        observed = sha256_file(archive)
        expected = _header_text(header, "plaintext_sha256")
        if observed.hexdigest != expected:
            raise BackupError("The decrypted backup payload hash does not match its header.")
        entries = _verify_archive(archive)
        return BackupVerification(
            valid=True,
            plaintext_sha256=observed.hexdigest,
            file_count=len(entries),
            created_at=datetime.fromisoformat(_header_text(header, "created_at")),
        )


def restore_backup(path: Path, destination: Path, passphrase: str) -> BackupVerification:
    _validate_passphrase(passphrase)
    destination = destination.expanduser().resolve()
    if destination.exists() and any(destination.iterdir()):
        raise BackupError("Restore destination must be empty.")
    with tempfile.TemporaryDirectory(prefix="forensix-restore-") as temporary:
        archive = Path(temporary) / "payload.zip"
        header = _decrypt_file(path.expanduser().resolve(), archive, passphrase)
        observed = sha256_file(archive)
        if observed.hexdigest != _header_text(header, "plaintext_sha256"):
            raise BackupError("The decrypted backup payload hash does not match its header.")
        entries = _verify_archive(archive)
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".forensix-restore-", dir=destination.parent))
        try:
            with zipfile.ZipFile(archive, "r") as bundle:
                for entry in entries:
                    relative = _safe_relative_path(cast(str, entry["path"]))
                    target = (staging / Path(*relative.parts)).resolve()
                    if staging not in target.parents:
                        raise BackupError("A backup member escapes the restore destination.")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    partial = target.with_name(f".{target.name}.partial")
                    digest = hashlib.sha256()
                    size = 0
                    with bundle.open(relative.as_posix(), "r") as source, partial.open("xb") as out:
                        while chunk := source.read(CHUNK_SIZE):
                            size += len(chunk)
                            digest.update(chunk)
                            out.write(chunk)
                        out.flush()
                        os.fsync(out.fileno())
                    if size != entry["size_bytes"] or digest.hexdigest() != entry["sha256"]:
                        raise BackupError("A restored file failed manifest verification.")
                    partial.replace(target)
            if destination.exists():
                destination.rmdir()
            os.replace(staging, destination)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return BackupVerification(
            valid=True,
            plaintext_sha256=observed.hexdigest,
            file_count=len(entries),
            created_at=datetime.fromisoformat(_header_text(header, "created_at")),
        )


def _snapshot_database(database: Database, destination: Path) -> None:
    if database.engine.url.get_backend_name() != "sqlite":
        raise BackupError("The workstation backup utility currently supports SQLite only.")
    source_path = database.engine.url.database
    if not source_path:
        raise BackupError("The SQLite database path is unavailable.")
    source = sqlite3.connect(source_path)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
        result = target.execute("PRAGMA integrity_check").fetchone()
        if result != ("ok",):
            raise BackupError("The SQLite backup did not pass integrity_check.")
    finally:
        target.close()
        source.close()


def _build_archive(
    data_dir: Path, database_snapshot: Path, archive: Path, created_at: datetime
) -> list[dict[str, object]]:
    sources: list[tuple[Path, PurePosixPath]] = [
        (database_snapshot, PurePosixPath("database/forensix.db"))
    ]
    evidence_root = data_dir / "evidence"
    if evidence_root.exists():
        for source in sorted(evidence_root.rglob("*")):
            if source.is_symlink():
                raise BackupError("Evidence storage contains a symlink; backup was blocked.")
            if source.is_file():
                relative = PurePosixPath("evidence") / PurePosixPath(
                    source.relative_to(evidence_root).as_posix()
                )
                sources.append((source, relative))
    entries: list[dict[str, object]] = []
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_STORED, allowZip64=True) as bundle:
        for source, relative in sources:
            digest = hashlib.sha256()
            size = 0
            with source.open("rb") as input_stream, bundle.open(relative.as_posix(), "w") as out:
                while chunk := input_stream.read(CHUNK_SIZE):
                    size += len(chunk)
                    digest.update(chunk)
                    out.write(chunk)
            entries.append(
                {"path": relative.as_posix(), "sha256": digest.hexdigest(), "size_bytes": size}
            )
        manifest = json.dumps(
            {
                "created_at": created_at.isoformat(),
                "files": entries,
                "format": "ForensiX workstation backup payload",
                "version": FORMAT_VERSION,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(manifest) > MAX_MANIFEST_BYTES:
            raise BackupError("The backup manifest exceeds its safety limit.")
        bundle.writestr("manifest.json", manifest)
    return entries


def _encrypt_file(
    source: Path,
    destination: Path,
    passphrase: str,
    *,
    plaintext_sha256: str,
    created_at: datetime,
) -> None:
    salt = os.urandom(16)
    nonce_prefix = os.urandom(4)
    header = {
        "cipher": "AES-256-GCM",
        "chunk_size": CHUNK_SIZE,
        "created_at": created_at.isoformat(),
        "format_version": FORMAT_VERSION,
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "p": SCRYPT_P, "r": SCRYPT_R},
        "nonce_prefix": base64.b64encode(nonce_prefix).decode("ascii"),
        "plaintext_sha256": plaintext_sha256,
        "plaintext_size": source.stat().st_size,
        "salt": base64.b64encode(salt).decode("ascii"),
    }
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    key = _derive_key(passphrase, salt)
    cipher = AESGCM(key)
    with source.open("rb") as plain, destination.open("xb") as encrypted:
        encrypted.write(MAGIC)
        encrypted.write(struct.pack(">I", len(header_bytes)))
        encrypted.write(header_bytes)
        index = 0
        while chunk := plain.read(CHUNK_SIZE):
            length = len(chunk)
            length_bytes = struct.pack(">I", length)
            nonce = nonce_prefix + index.to_bytes(8, "big")
            aad = MAGIC + header_bytes + index.to_bytes(8, "big") + length_bytes
            encrypted.write(length_bytes)
            encrypted.write(cipher.encrypt(nonce, chunk, aad))
            index += 1
        encrypted.flush()
        os.fsync(encrypted.fileno())


def _decrypt_file(source: Path, destination: Path, passphrase: str) -> dict[str, object]:
    try:
        with source.open("rb") as encrypted:
            if encrypted.read(len(MAGIC)) != MAGIC:
                raise BackupError("The file is not a supported ForensiX backup.")
            header_length = struct.unpack(">I", _read_exact(encrypted, 4))[0]
            if not 1 <= header_length <= MAX_HEADER_BYTES:
                raise BackupError("The encrypted backup header is invalid.")
            header_bytes = _read_exact(encrypted, header_length)
            header = json.loads(header_bytes)
            if not isinstance(header, dict) or header.get("format_version") != FORMAT_VERSION:
                raise BackupError("The encrypted backup version is unsupported.")
            if (
                header.get("cipher") != "AES-256-GCM"
                or header.get("chunk_size") != CHUNK_SIZE
                or header.get("kdf")
                != {"name": "scrypt", "n": SCRYPT_N, "p": SCRYPT_P, "r": SCRYPT_R}
            ):
                raise BackupError("The encrypted backup cryptographic parameters are invalid.")
            salt = base64.b64decode(_header_text(header, "salt"), validate=True)
            nonce_prefix = base64.b64decode(_header_text(header, "nonce_prefix"), validate=True)
            if len(salt) != 16 or len(nonce_prefix) != 4:
                raise BackupError("The encrypted backup parameters are invalid.")
            plaintext_size = _header_int(header, "plaintext_size")
            if plaintext_size < 1:
                raise BackupError("The encrypted backup payload size is invalid.")
            key = _derive_key(passphrase, salt)
            cipher = AESGCM(key)
            written = 0
            index = 0
            with destination.open("xb") as plain:
                while written < plaintext_size:
                    length_bytes = _read_exact(encrypted, 4)
                    length = struct.unpack(">I", length_bytes)[0]
                    if not 1 <= length <= CHUNK_SIZE or written + length > plaintext_size:
                        raise BackupError("The encrypted backup chunk framing is invalid.")
                    ciphertext = _read_exact(encrypted, length + 16)
                    nonce = nonce_prefix + index.to_bytes(8, "big")
                    aad = MAGIC + header_bytes + index.to_bytes(8, "big") + length_bytes
                    try:
                        chunk = cipher.decrypt(nonce, ciphertext, aad)
                    except InvalidTag as error:
                        raise BackupError(
                            "Backup authentication failed: wrong passphrase or modified data."
                        ) from error
                    plain.write(chunk)
                    written += len(chunk)
                    index += 1
                if encrypted.read(1):
                    raise BackupError("The encrypted backup has unexpected trailing data.")
                plain.flush()
                os.fsync(plain.fileno())
    except (OSError, ValueError, json.JSONDecodeError, struct.error) as error:
        destination.unlink(missing_ok=True)
        if isinstance(error, BackupError):
            raise
        raise BackupError("The encrypted backup is corrupt or unreadable.") from error
    return cast(dict[str, object], header)


def _verify_archive(archive: Path) -> list[dict[str, object]]:
    try:
        with zipfile.ZipFile(archive, "r") as bundle:
            names = bundle.namelist()
            if len(names) != len(set(names)) or "manifest.json" not in names:
                raise BackupError("The backup archive member list is invalid.")
            manifest_bytes = bundle.read("manifest.json")
            if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                raise BackupError("The backup manifest exceeds its safety limit.")
            manifest = json.loads(manifest_bytes)
            entries = manifest.get("files") if isinstance(manifest, dict) else None
            if not isinstance(entries, list) or len(entries) + 1 != len(names):
                raise BackupError("The backup manifest does not match the archive.")
            verified: list[dict[str, object]] = []
            for raw in entries:
                if not isinstance(raw, dict):
                    raise BackupError("The backup manifest contains an invalid file record.")
                path = _safe_relative_path(_manifest_text(raw, "path"))
                expected_size = _manifest_int(raw, "size_bytes")
                expected_hash = _manifest_text(raw, "sha256")
                if path.as_posix() not in names or len(expected_hash) != 64:
                    raise BackupError("The backup manifest references an invalid member.")
                member = bundle.getinfo(path.as_posix())
                if member.compress_type != zipfile.ZIP_STORED or member.file_size != expected_size:
                    raise BackupError("The backup member encoding or size is invalid.")
                digest = hashlib.sha256()
                size = 0
                with bundle.open(path.as_posix(), "r") as source:
                    while chunk := source.read(CHUNK_SIZE):
                        size += len(chunk)
                        digest.update(chunk)
                if size != expected_size or digest.hexdigest() != expected_hash:
                    raise BackupError("A backup archive member failed manifest verification.")
                verified.append(cast(dict[str, object], raw))
            return verified
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        if isinstance(error, BackupError):
            raise
        raise BackupError("The backup payload archive is invalid.") from error


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        passphrase.encode("utf-8")
    )


def _safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or "\\" in value
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
    ):
        raise BackupError("The backup contains an unsafe member path.")
    if path.as_posix() == "manifest.json":
        raise BackupError("The manifest cannot list itself as payload data.")
    return path


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    value = stream.read(length)
    if len(value) != length:
        raise BackupError("The encrypted backup ended unexpectedly.")
    return value


def _header_text(header: dict[str, object], key: str) -> str:
    value = header.get(key)
    if not isinstance(value, str):
        raise BackupError(f"The encrypted backup header field '{key}' is invalid.")
    return value


def _header_int(header: dict[str, object], key: str) -> int:
    value = header.get(key)
    if type(value) is not int:
        raise BackupError(f"The encrypted backup header field '{key}' is invalid.")
    return value


def _manifest_text(record: dict[str, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str):
        raise BackupError("The backup manifest contains an invalid value.")
    return value


def _manifest_int(record: dict[str, object], key: str) -> int:
    value = record.get(key)
    if type(value) is not int or value < 0:
        raise BackupError("The backup manifest contains an invalid size.")
    return value


def _validate_passphrase(passphrase: str) -> None:
    if not 16 <= len(passphrase) <= 1024:
        raise BackupError("Backup passphrase must contain between 16 and 1024 characters.")


def prompt_passphrase(*, confirmation: bool) -> str:
    passphrase = getpass.getpass("Backup passphrase: ")
    _validate_passphrase(passphrase)
    if confirmation and getpass.getpass("Confirm passphrase: ") != passphrase:
        raise BackupError("Passphrase confirmation did not match.")
    return passphrase
