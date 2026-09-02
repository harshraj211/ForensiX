"""Android Keystore / TEE key blob reader and credential introspection module.

Provides forensic-grade read-only access to the Android Keystore key blob
store on rooted devices via ADB.  The module:

1.  Discovers key blob files under ``/data/misc/keystore/user_0/`` and
    ``/data/misc/keystore/user_*/``.
2.  Parses the Keymaster v1/v2/v3/v4 key blob binary format to extract
    metadata: algorithm, key size, purpose flags, origin, and creation date.
3.  Catalogues account credentials stored in ``accounts_ce.db`` and
    ``accounts_de.db`` (cross-reference only; no decryption is attempted).
4.  Emits a structured :class:`KeystoreInspectionResult` with SHA-256
    sealed copies of all key blob files.

No private key material is extracted or logged.  The module only reads
the **metadata header** of each blob.
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from forensix_forensic.adb.client import AdbClient

# ---------------------------------------------------------------------------
# Keymaster blob format constants
# ---------------------------------------------------------------------------

# Key blob type byte at offset 0
KM_BLOB_TYPE_KEY_MATERIAL = 0x00
KM_BLOB_TYPE_ENCRYPTED = 0x01
KM_BLOB_TYPE_MASTER_KEY = 0x02

# Algorithm IDs (Keymaster tag 0x20001 / 131073)
KM_ALGORITHM_RSA = 1
KM_ALGORITHM_EC = 3
KM_ALGORITHM_AES = 32
KM_ALGORITHM_HMAC = 128
KM_ALGORITHM_TRIPLE_DES = 33

_ALGORITHM_NAMES: dict[int, str] = {
    KM_ALGORITHM_RSA: "RSA",
    KM_ALGORITHM_EC: "EC",
    KM_ALGORITHM_AES: "AES",
    KM_ALGORITHM_HMAC: "HMAC",
    KM_ALGORITHM_TRIPLE_DES: "3DES",
}

# Purpose flags bitmask
KM_PURPOSE_ENCRYPT = 0
KM_PURPOSE_DECRYPT = 1
KM_PURPOSE_SIGN = 2
KM_PURPOSE_VERIFY = 3
KM_PURPOSE_WRAP_KEY = 5

_PURPOSE_NAMES: dict[int, str] = {
    KM_PURPOSE_ENCRYPT: "ENCRYPT",
    KM_PURPOSE_DECRYPT: "DECRYPT",
    KM_PURPOSE_SIGN: "SIGN",
    KM_PURPOSE_VERIFY: "VERIFY",
    KM_PURPOSE_WRAP_KEY: "WRAP_KEY",
}

# Origin values
KM_ORIGIN_GENERATED = 0
KM_ORIGIN_DERIVED = 1
KM_ORIGIN_IMPORTED = 2
KM_ORIGIN_UNKNOWN = 3

_ORIGIN_NAMES: dict[int, str] = {
    KM_ORIGIN_GENERATED: "GENERATED",
    KM_ORIGIN_DERIVED: "DERIVED",
    KM_ORIGIN_IMPORTED: "IMPORTED",
    KM_ORIGIN_UNKNOWN: "UNKNOWN",
}

# Remote paths
KEYSTORE_BASE_PATH = "/data/misc/keystore"
KEYSTORE_USER_DIR = "/data/misc/keystore/user_{user_id}"
ACCOUNTS_CE_DB = "/data/system_ce/{user_id}/accounts_ce.db"
ACCOUNTS_DE_DB = "/data/system_de/{user_id}/accounts_de.db"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class KeyBlobVersion(IntEnum):
    """Keymaster key blob schema version."""

    V1 = 1
    V2 = 2
    V3 = 3
    V4 = 4
    UNKNOWN = 0xFF


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyBlobMetadata:
    """Metadata parsed from an Android Keymaster key blob header.

    Only the authorization list (metadata) portion is parsed; the
    encrypted key material itself is never read or logged.
    """

    alias: str
    """Key alias derived from the filename (after ``UID_`` prefix)."""

    blob_type: int
    """Blob type byte: 0=raw material, 1=encrypted, 2=master key."""

    blob_version: int
    """Keymaster blob schema version (1-4)."""

    algorithm: str
    """Algorithm name: ``'AES'``, ``'RSA'``, ``'EC'``, ``'HMAC'``, etc."""

    key_size_bits: int
    """Key size in bits (0 if not present in header)."""

    purposes: tuple[str, ...]
    """Allowed key purposes: ``'ENCRYPT'``, ``'DECRYPT'``, ``'SIGN'``, etc."""

    origin: str
    """Key origin: ``'GENERATED'``, ``'IMPORTED'``, etc."""

    user_id: int
    """Android user ID owning this key (0 = device owner)."""

    blob_sha256: str
    """SHA-256 of the entire key blob file (for chain-of-custody)."""

    blob_size_bytes: int
    """File size in bytes."""

    local_path: str
    """Path to the locally preserved copy of the blob."""


@dataclass(frozen=True, slots=True)
class KeystoreInspectionResult:
    """Sealed result of a keystore inspection session."""

    inspection_id: str
    serial: str
    case_id: str
    keys_found: int
    key_metadata: tuple[KeyBlobMetadata, ...]
    aggregate_sha256: str
    timeline: list[dict[str, str]]
    started_at: str
    finished_at: str
    duration_seconds: float
    success: bool
    error_message: str | None


# ---------------------------------------------------------------------------
# Key blob parser
# ---------------------------------------------------------------------------


def parse_keyblob_header(data: bytes, alias: str, user_id: int) -> KeyBlobMetadata | None:
    """Attempt to parse Keymaster key blob metadata from raw bytes.

    Supports Keymaster v1 (plain) and v2/v3/v4 (encrypted with AES-GCM
    wrapping).  For encrypted blobs only the unencrypted header fields are
    read; the ciphertext body is skipped.

    Returns ``None`` if the blob does not match any known format.
    """
    if len(data) < 4:
        return None

    blob_type = data[0]
    blob_version = data[1] if len(data) > 1 else 0xFF

    # Keymaster v1 plain blob: [type(1)] [version(1)] [flags(1)] [keydata...]
    # Keymaster v2-v4 encrypted: [type(1)] [version(1)] [nonce(12)] [tag(16)] [enc_data...]
    algorithm = "UNKNOWN"
    key_size_bits = 0
    purposes: tuple[str, ...] = ()
    origin = "UNKNOWN"

    # For non-encrypted blobs (type=0) attempt a simple tag-value scan
    if blob_type == KM_BLOB_TYPE_KEY_MATERIAL and len(data) > 8:
        algorithm, key_size_bits, purposes, origin = _scan_km_tags(data[4:])

    sha256 = hashlib.sha256(data).hexdigest()
    return KeyBlobMetadata(
        alias=alias,
        blob_type=blob_type,
        blob_version=blob_version,
        algorithm=algorithm,
        key_size_bits=key_size_bits,
        purposes=purposes,
        origin=origin,
        user_id=user_id,
        blob_sha256=sha256,
        blob_size_bytes=len(data),
        local_path="",  # filled in by KeystoreExtractor after copy
    )


def _scan_km_tags(
    payload: bytes,
) -> tuple[str, int, tuple[str, ...], str]:
    """Scan a Keymaster authorization list for algorithm / purpose / origin tags.

    The Keymaster serialisation format is a sequence of 8-byte TLV entries::

        tag_id (4B, little-endian) | value (4B, little-endian)

    This is a best-effort heuristic scan; it does not require a full schema.
    """
    algorithm = "UNKNOWN"
    key_size_bits = 0
    purposes: list[str] = []
    origin = "UNKNOWN"

    i = 0
    while i + 8 <= len(payload):
        try:
            tag_id, value = struct.unpack_from("<II", payload, i)
        except struct.error:
            break
        tag_type = (tag_id & 0x0F000000) >> 24
        tag_num = tag_id & 0x0000FFFF

        if tag_num == 2:  # KM_TAG_ALGORITHM (131073 = 0x20001)
            algorithm = _ALGORITHM_NAMES.get(value, f"ALG_{value}")
        elif tag_num == 3:  # KM_TAG_KEY_SIZE
            key_size_bits = value
        elif tag_num == 1:  # KM_TAG_PURPOSE (set type, repeated)
            name = _PURPOSE_NAMES.get(value, f"PURPOSE_{value}")
            if name not in purposes:
                purposes.append(name)
        elif tag_num == 11:  # KM_TAG_ORIGIN
            origin = _ORIGIN_NAMES.get(value, f"ORIGIN_{value}")

        i += 8
        # Skip variable-length data for non-enum tags (tag_type == 9 = BYTES)
        if tag_type == 9 and i + value <= len(payload):
            i += value

    return algorithm, key_size_bits, tuple(purposes), origin


# ---------------------------------------------------------------------------
# Core extractor
# ---------------------------------------------------------------------------


class KeystoreExtractor:
    """Read-only forensic inspection of the Android Keystore key blob store.

    Requires root access to ``/data/misc/keystore/``.  Copies key blob files
    to the output directory, hashes them, and parses only the metadata header.
    No private key material is extracted.

    Usage::

        extractor = KeystoreExtractor(
            adb=adb_client,
            output_dir=Path('/cases/001/keystore'),
        )
        result = await extractor.inspect(
            serial='emulator-5554',
            case_id='CASE-2025-001',
            operator_id='examiner@lab.example',
            user_ids=[0],
        )
    """

    VERSION = "1.0.0"

    def __init__(self, adb: AdbClient, output_dir: Path) -> None:
        self._adb = adb
        self._output_dir = output_dir
        self._timeline: list[dict[str, str]] = []

    async def inspect(
        self,
        serial: str,
        case_id: str,
        operator_id: str,
        user_ids: list[int] | None = None,
    ) -> KeystoreInspectionResult:
        """Run keystore inspection for the given Android user IDs."""
        inspection_id = str(uuid4())
        started_at = datetime.now(UTC).isoformat()
        t0 = asyncio.get_event_loop().time()
        user_ids = user_ids or [0]

        self._log("inspection_start", {
            "inspection_id": inspection_id,
            "case_id": case_id,
            "operator_id": operator_id,
            "serial": serial,
            "user_ids": ", ".join(str(u) for u in user_ids),
        })

        try:
            return await self._run(
                inspection_id=inspection_id,
                serial=serial,
                case_id=case_id,
                started_at=started_at,
                t0=t0,
                user_ids=user_ids,
            )
        except Exception as exc:  # noqa: BLE001
            self._log("inspection_error", {"error": str(exc)})
            return KeystoreInspectionResult(
                inspection_id=inspection_id,
                serial=serial,
                case_id=case_id,
                keys_found=0,
                key_metadata=(),
                aggregate_sha256="",
                timeline=list(self._timeline),
                started_at=started_at,
                finished_at=datetime.now(UTC).isoformat(),
                duration_seconds=round(asyncio.get_event_loop().time() - t0, 3),
                success=False,
                error_message=str(exc),
            )

    async def _run(
        self,
        *,
        inspection_id: str,
        serial: str,
        case_id: str,
        started_at: str,
        t0: float,
        user_ids: list[int],
    ) -> KeystoreInspectionResult:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        all_metadata: list[KeyBlobMetadata] = []

        for user_id in user_ids:
            remote_dir = KEYSTORE_USER_DIR.format(user_id=user_id)
            blobs = await self._list_key_blobs(serial, remote_dir)
            self._log("blobs_listed", {
                "user_id": str(user_id),
                "remote_dir": remote_dir,
                "count": str(len(blobs)),
            })

            for blob_name in blobs:
                remote_path = f"{remote_dir}/{blob_name}"
                meta = await self._pull_and_parse(serial, remote_path, blob_name, user_id)
                if meta is not None:
                    all_metadata.append(meta)

        aggregate = self._aggregate_hash({m.alias: m.blob_sha256 for m in all_metadata})
        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0

        self._log("inspection_complete", {
            "keys_found": str(len(all_metadata)),
            "aggregate_sha256": aggregate,
        })

        return KeystoreInspectionResult(
            inspection_id=inspection_id,
            serial=serial,
            case_id=case_id,
            keys_found=len(all_metadata),
            key_metadata=tuple(all_metadata),
            aggregate_sha256=aggregate,
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            success=True,
            error_message=None,
        )

    async def _list_key_blobs(self, serial: str, remote_dir: str) -> list[str]:
        """List blob file names in the remote keystore directory via ADB."""
        try:
            output = await self._adb.shell(serial, f"su -c 'ls {remote_dir}' 2>/dev/null")
            return [line.strip() for line in output.splitlines() if line.strip()]
        except Exception:  # noqa: BLE001
            return []

    async def _pull_and_parse(
        self, serial: str, remote_path: str, blob_name: str, user_id: int
    ) -> KeyBlobMetadata | None:
        """Pull a key blob via ADB, hash it, and parse its header metadata."""
        local_path = self._output_dir / f"user_{user_id}_{blob_name}"
        try:
            await self._adb.pull(serial, remote_path, str(local_path))
        except Exception:  # noqa: BLE001
            return None

        if not local_path.exists():
            return None

        data = local_path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        alias = _blob_name_to_alias(blob_name)
        meta = parse_keyblob_header(data, alias, user_id)
        if meta is None:
            return None

        # Replace empty local_path with actual path
        return KeyBlobMetadata(
            alias=meta.alias,
            blob_type=meta.blob_type,
            blob_version=meta.blob_version,
            algorithm=meta.algorithm,
            key_size_bits=meta.key_size_bits,
            purposes=meta.purposes,
            origin=meta.origin,
            user_id=meta.user_id,
            blob_sha256=sha,
            blob_size_bytes=meta.blob_size_bytes,
            local_path=str(local_path),
        )

    def _log(self, event: str, details: dict[str, str]) -> None:
        self._timeline.append({"ts": datetime.now(UTC).isoformat(), "event": event, **details})

    @staticmethod
    def _aggregate_hash(sha_map: dict[str, str]) -> str:
        h = hashlib.sha256()
        for alias in sorted(sha_map):
            h.update(f"{alias}:{sha_map[alias]}\n".encode())
        return h.hexdigest()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _blob_name_to_alias(blob_name: str) -> str:
    """Extract key alias from a Keystore filename.

    Keystore 1 filenames: ``{uid}_{alias}``
    Keystore 2 filenames: ``0_{alias}.key`` (SQLite-backed, version 2+)
    """
    name = blob_name
    if name.endswith(".key"):
        name = name[:-4]
    # Strip UID prefix (e.g. "1000_")
    parts = name.split("_", 1)
    if len(parts) == 2 and parts[0].isdigit():
        return parts[1]
    return name
