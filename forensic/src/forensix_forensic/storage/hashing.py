"""Streaming integrity helpers for evidence bytes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

DEFAULT_HASH_CHUNK_SIZE = 4 * 1024 * 1024


class _HasherProtocol(Protocol):
    def update(self, data: bytes, /) -> None: ...
    def hexdigest(self) -> str: ...


@dataclass(frozen=True, slots=True)
class HashResult:
    algorithm: str
    hexdigest: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class DualHashResult:
    primary_algorithm: str
    primary_hexdigest: str
    secondary_algorithm: str
    secondary_hexdigest: str
    size_bytes: int


class StreamHasher:
    """Simultaneously streams evidence bytes across primary and secondary hash accumulators."""

    def __init__(
        self,
        secondary_algo: Literal["blake3", "blake2b", "sha3_256"] = "blake2b",
    ) -> None:
        self._primary: _HasherProtocol = hashlib.sha256()
        self._secondary_algo = secondary_algo
        self._blake3_inst: _HasherProtocol | None = None
        self._secondary_hasher: _HasherProtocol | None = None

        if secondary_algo == "blake3":
            try:
                import blake3  # type: ignore[import-not-found]

                self._blake3_inst = blake3.blake3()
            except ImportError:
                # Graceful fallback to blake2b if blake3 module is not installed in the environment
                self._secondary_algo = "blake2b"
                self._secondary_hasher = hashlib.blake2b(digest_size=32)
        elif secondary_algo == "sha3_256":
            self._secondary_hasher = hashlib.sha3_256()
        else:
            self._secondary_hasher = hashlib.blake2b(digest_size=32)

        self._size_bytes = 0

    def update(self, chunk: bytes) -> None:
        self._primary.update(chunk)
        if self._blake3_inst is not None:
            self._blake3_inst.update(chunk)
        elif self._secondary_hasher is not None:
            self._secondary_hasher.update(chunk)
        self._size_bytes += len(chunk)

    def finalize(self) -> DualHashResult:
        if self._blake3_inst is not None:
            sec_hex = self._blake3_inst.hexdigest()
        elif self._secondary_hasher is not None:
            sec_hex = self._secondary_hasher.hexdigest()
        else:
            sec_hex = ""

        return DualHashResult(
            primary_algorithm="sha256",
            primary_hexdigest=self._primary.hexdigest(),
            secondary_algorithm=self._secondary_algo,
            secondary_hexdigest=sec_hex,
            size_bytes=self._size_bytes,
        )


def sha256_file(path: Path, *, chunk_size: int = DEFAULT_HASH_CHUNK_SIZE) -> HashResult:
    """Hash a regular file without loading it completely into memory."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    if path.is_symlink() or not path.is_file():
        raise ValueError("path must identify a non-symlink regular file")

    digest = hashlib.sha256()
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


def dual_hash_file(
    path: Path,
    *,
    chunk_size: int = DEFAULT_HASH_CHUNK_SIZE,
    secondary_algo: Literal["blake3", "blake2b", "sha3_256"] = "blake2b",
) -> DualHashResult:
    """Stream a file through two hash engines in a single I/O pass."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    if path.is_symlink() or not path.is_file():
        raise ValueError("path must identify a non-symlink regular file")

    hasher = StreamHasher(secondary_algo=secondary_algo)
    with path.open("rb") as source:
        while chunk := source.read(chunk_size):
            hasher.update(chunk)

    return hasher.finalize()


def dual_hash_bytes(
    data: bytes,
    secondary_algo: Literal["blake3", "blake2b", "sha3_256"] = "blake2b",
) -> DualHashResult:
    """Compute dual hashes for in-memory bytes."""
    hasher = StreamHasher(secondary_algo=secondary_algo)
    hasher.update(data)
    return hasher.finalize()
