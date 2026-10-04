"""Contained evidence storage and integrity primitives."""

from .errors import (
    EvidenceAlreadyExistsError,
    EvidenceNotFoundError,
    InvalidStorageKeyError,
    StorageBoundaryError,
    StorageError,
)
from .hashing import (
    DualHashResult,
    HashResult,
    StreamHasher,
    dual_hash_bytes,
    dual_hash_file,
    sha256_file,
)
from .store import (
    AtomicEvidenceWriter,
    EvidenceStore,
    ExternalEvidenceReservation,
    StoredEvidence,
)

__all__ = [
    "AtomicEvidenceWriter",
    "DualHashResult",
    "EvidenceAlreadyExistsError",
    "EvidenceNotFoundError",
    "EvidenceStore",
    "ExternalEvidenceReservation",
    "HashResult",
    "InvalidStorageKeyError",
    "StorageBoundaryError",
    "StorageError",
    "StoredEvidence",
    "StreamHasher",
    "dual_hash_bytes",
    "dual_hash_file",
    "sha256_file",
]
