"""Contained evidence storage and integrity primitives."""

from .errors import (
    EvidenceAlreadyExistsError,
    EvidenceNotFoundError,
    InvalidStorageKeyError,
    StorageBoundaryError,
    StorageError,
)
from .hashing import HashResult, sha256_file
from .store import AtomicEvidenceWriter, EvidenceStore, StoredEvidence

__all__ = [
    "AtomicEvidenceWriter",
    "EvidenceAlreadyExistsError",
    "EvidenceNotFoundError",
    "EvidenceStore",
    "HashResult",
    "InvalidStorageKeyError",
    "StorageBoundaryError",
    "StorageError",
    "StoredEvidence",
    "sha256_file",
]
