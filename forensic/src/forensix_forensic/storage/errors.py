"""Stable failures for evidence storage operations."""


class StorageError(RuntimeError):
    """Base class for evidence storage failures."""

    code = "STORAGE_ERROR"


class InvalidStorageKeyError(StorageError):
    code = "INVALID_STORAGE_KEY"

    def __init__(self, reason: str) -> None:
        super().__init__(f"The evidence storage key is invalid: {reason}.")
        self.reason = reason


class StorageBoundaryError(StorageError):
    code = "STORAGE_BOUNDARY_VIOLATION"

    def __init__(self, reason: str) -> None:
        super().__init__(f"The evidence storage boundary was rejected: {reason}.")
        self.reason = reason


class EvidenceAlreadyExistsError(StorageError):
    code = "EVIDENCE_ALREADY_EXISTS"

    def __init__(self, storage_key: str) -> None:
        super().__init__(f"Evidence already exists at storage key {storage_key!r}.")
        self.storage_key = storage_key


class EvidenceNotFoundError(StorageError):
    code = "EVIDENCE_NOT_FOUND"

    def __init__(self, storage_key: str) -> None:
        super().__init__(f"Evidence was not found at storage key {storage_key!r}.")
        self.storage_key = storage_key
