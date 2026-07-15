"""Streaming integrity helpers for evidence bytes."""

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

DEFAULT_HASH_CHUNK_SIZE = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class HashResult:
    algorithm: str
    hexdigest: str
    size_bytes: int


def sha256_file(path: Path, *, chunk_size: int = DEFAULT_HASH_CHUNK_SIZE) -> HashResult:
    """Hash a regular file without loading it completely into memory."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    if path.is_symlink() or not path.is_file():
        raise ValueError("path must identify a non-symlink regular file")

    digest = sha256()
    size_bytes = 0
    with path.open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
            size_bytes += len(chunk)

    return HashResult(
        algorithm="sha256",
        hexdigest=digest.hexdigest(),
        size_bytes=size_bytes,
    )
