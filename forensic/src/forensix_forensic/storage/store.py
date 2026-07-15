"""Contained, append-oriented storage for acquired evidence."""

import os
import re
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import TracebackType

from .errors import (
    EvidenceAlreadyExistsError,
    EvidenceNotFoundError,
    InvalidStorageKeyError,
    StorageBoundaryError,
)
from .hashing import HashResult, sha256_file

_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WINDOWS_RESERVED_NAMES = {
    "AUX",
    "CON",
    "NUL",
    "PRN",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


@dataclass(frozen=True, slots=True)
class StoredEvidence:
    storage_key: str
    size_bytes: int
    sha256: str


class EvidenceStore:
    """Maps strict portable keys to files contained by one evidence root."""

    def __init__(self, root: Path) -> None:
        requested_root = root.expanduser().absolute()
        if requested_root.exists() and _is_link_or_reparse_point(requested_root):
            raise StorageBoundaryError("the configured evidence root is a link or reparse point")
        requested_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not requested_root.is_dir():
            raise StorageBoundaryError("the configured evidence root is not a directory")

        self._root = requested_root.resolve(strict=True)
        _restrict_permissions(self._root, directory=True)

    @property
    def root(self) -> Path:
        return self._root

    def resolve(self, storage_key: str, *, require_file: bool = False) -> Path:
        parts = _validate_storage_key(storage_key)
        candidate = self._root.joinpath(*parts)
        self._assert_contained(candidate)
        self._assert_safe_existing_chain(candidate)

        if require_file:
            if not candidate.exists():
                raise EvidenceNotFoundError(storage_key)
            if candidate.is_symlink() or not candidate.is_file():
                raise StorageBoundaryError("the evidence object is not a regular file")
        return candidate

    def open_writer(self, storage_key: str) -> "AtomicEvidenceWriter":
        target = self.resolve(storage_key)
        self._create_safe_directories(target.parent)
        if target.exists():
            raise EvidenceAlreadyExistsError(storage_key)
        return AtomicEvidenceWriter(self, storage_key, target)

    def hash(self, storage_key: str) -> HashResult:
        path = self.resolve(storage_key, require_file=True)
        return sha256_file(path)

    def verify(self, storage_key: str, expected_sha256: str) -> bool:
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("expected_sha256 must be 64 lowercase hexadecimal characters")
        return self.hash(storage_key).hexdigest == expected_sha256

    def _create_safe_directories(self, directory: Path) -> None:
        relative = directory.relative_to(self._root)
        current = self._root
        for part in relative.parts:
            current /= part
            if current.exists():
                if _is_link_or_reparse_point(current) or not current.is_dir():
                    raise StorageBoundaryError("an evidence path ancestor is unsafe")
                continue
            current.mkdir(mode=0o700)
            _restrict_permissions(current, directory=True)

    def _assert_contained(self, candidate: Path) -> None:
        try:
            if os.path.commonpath((self._root, candidate)) != str(self._root):
                raise StorageBoundaryError("the resolved key escaped the evidence root")
        except ValueError as error:
            raise StorageBoundaryError("the resolved key is on another filesystem root") from error

    def _assert_safe_existing_chain(self, candidate: Path) -> None:
        current = self._root
        for part in candidate.relative_to(self._root).parts:
            current /= part
            if not current.exists() and not current.is_symlink():
                break
            if _is_link_or_reparse_point(current):
                raise StorageBoundaryError("an evidence path component is a link or reparse point")


class AtomicEvidenceWriter:
    """Streams bytes to a partial file and seals them into a unique final key."""

    def __init__(self, store: EvidenceStore, storage_key: str, target: Path) -> None:
        self._store = store
        self.storage_key = storage_key
        self._target = target
        token = sha256(storage_key.encode("utf-8")).hexdigest()[:20]
        self._partial = target.parent / f".forensix-{token}-{os.urandom(8).hex()}.partial"
        self._lock = target.parent / f".forensix-{token}.lock"
        self._stream = self._partial.open("xb")
        _restrict_permissions(self._partial, directory=False)
        self._digest = sha256()
        self._size_bytes = 0
        self._sealed = False
        self._closed = False

    @property
    def partial_path(self) -> Path:
        return self._partial

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("cannot write to a closed evidence writer")
        written = self._stream.write(data)
        if written != len(data):
            raise OSError("evidence write was shorter than the supplied byte buffer")
        self._digest.update(data)
        self._size_bytes += written
        return written

    def seal(self) -> StoredEvidence:
        if self._closed:
            raise ValueError("cannot seal a closed evidence writer")

        self._stream.flush()
        os.fsync(self._stream.fileno())
        self._stream.close()
        self._closed = True

        lock_descriptor: int | None = None
        try:
            lock_descriptor = os.open(self._lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            if self._target.exists() or self._target.is_symlink():
                raise EvidenceAlreadyExistsError(self.storage_key)
            self._store._assert_safe_existing_chain(self._target)
            os.replace(self._partial, self._target)
            _restrict_permissions(self._target, directory=False)
            _sync_directory(self._target.parent)
        finally:
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            self._lock.unlink(missing_ok=True)

        self._sealed = True
        return StoredEvidence(
            storage_key=self.storage_key,
            size_bytes=self._size_bytes,
            sha256=self._digest.hexdigest(),
        )

    def close(self, *, preserve_partial: bool = True) -> None:
        if not self._closed:
            self._stream.flush()
            self._stream.close()
            self._closed = True
        if not preserve_partial and not self._sealed:
            self._partial.unlink(missing_ok=True)

    def __enter__(self) -> "AtomicEvidenceWriter":
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close(preserve_partial=exception_type is not None)


def _validate_storage_key(storage_key: str) -> tuple[str, ...]:
    if not storage_key or len(storage_key) > 1024:
        raise InvalidStorageKeyError("it must contain between 1 and 1024 characters")
    if "\\" in storage_key or "\x00" in storage_key or ":" in storage_key:
        raise InvalidStorageKeyError("it contains a forbidden separator or character")
    if storage_key.startswith("/") or storage_key.endswith("/"):
        raise InvalidStorageKeyError("it must be a relative key without a trailing separator")

    parts = storage_key.split("/")
    for part in parts:
        if part in {"", ".", ".."}:
            raise InvalidStorageKeyError("dot, empty, and parent segments are forbidden")
        if not _SEGMENT_PATTERN.fullmatch(part):
            raise InvalidStorageKeyError(
                "each segment must use portable letters, digits, dot, dash, or underscore"
            )
        if part.rstrip(". ") != part:
            raise InvalidStorageKeyError("segments cannot end with a dot or space")
        if part.split(".", maxsplit=1)[0].upper() in _WINDOWS_RESERVED_NAMES:
            raise InvalidStorageKeyError("a segment uses a reserved Windows device name")
    return tuple(parts)


def _is_link_or_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _restrict_permissions(path: Path, *, directory: bool) -> None:
    try:
        path.chmod(0o700 if directory else 0o600, follow_symlinks=False)
    except (NotImplementedError, OSError):
        # Platform ACL hardening is performed by the future native installer.
        return


def _sync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        return
    finally:
        os.close(descriptor)
