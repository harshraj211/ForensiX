"""Bounded extraction of ZIP and TAR working-copy derivatives."""

import re
import stat
import tarfile
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import IO, Literal

from forensix_forensic.storage import EvidenceStore

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


class ArchiveExtractionError(ValueError):
    """Raised when an archive violates the extraction policy."""


@dataclass(frozen=True, slots=True)
class ArchivePolicy:
    max_members: int = 10_000
    max_member_bytes: int = 512 * 1024 * 1024
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_compression_ratio: int = 200
    max_path_depth: int = 20
    stream_chunk_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if (
            min(
                self.max_members,
                self.max_member_bytes,
                self.max_total_bytes,
                self.max_compression_ratio,
                self.max_path_depth,
                self.stream_chunk_bytes,
            )
            < 1
        ):
            raise ValueError("Archive policy limits must be positive integers.")


@dataclass(frozen=True, slots=True)
class ExtractedArchiveMember:
    ordinal: int
    original_name: str
    storage_key: str
    size_bytes: int
    sha256: str
    archive_format: Literal["zip", "tar"]


class SafeArchiveExtractor:
    """Extracts regular files into generated contained keys under fixed limits."""

    def __init__(self, policy: ArchivePolicy | None = None) -> None:
        self.policy = policy or ArchivePolicy()

    def extract(
        self,
        source: Path,
        store: EvidenceStore,
        storage_prefix: str,
    ) -> list[ExtractedArchiveMember]:
        _validate_source(source)
        if zipfile.is_zipfile(source):
            return self._extract_zip(source, store, storage_prefix)
        if tarfile.is_tarfile(source):
            return self._extract_tar(source, store, storage_prefix)
        raise ArchiveExtractionError("The working copy is not a supported ZIP or TAR archive.")

    def _extract_zip(
        self, source: Path, store: EvidenceStore, storage_prefix: str
    ) -> list[ExtractedArchiveMember]:
        with zipfile.ZipFile(source) as archive:
            members = [item for item in archive.infolist() if not item.is_dir()]
            self._validate_count(members)
            declared_total = 0
            normalized_names: set[str] = set()
            for item in members:
                normalized = _validate_member_name(item.filename, self.policy.max_path_depth)
                if normalized in normalized_names:
                    raise ArchiveExtractionError("The archive contains duplicate member paths.")
                normalized_names.add(normalized)
                if item.flag_bits & 0x1:
                    raise ArchiveExtractionError("Encrypted ZIP members are not extracted.")
                mode = item.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    raise ArchiveExtractionError("Archive links are not extracted.")
                self._validate_declared_size(item.file_size)
                declared_total += item.file_size
                self._validate_total(declared_total)
                if item.file_size and item.compress_size == 0:
                    raise ArchiveExtractionError("The ZIP member has an invalid compression size.")
                if (
                    item.compress_size
                    and item.file_size / item.compress_size > self.policy.max_compression_ratio
                ):
                    raise ArchiveExtractionError(
                        "The ZIP member exceeds the compression-ratio limit."
                    )
            extracted: list[ExtractedArchiveMember] = []
            for ordinal, item in enumerate(members):
                with archive.open(item, "r") as stream:
                    extracted.append(
                        self._copy_member(
                            stream,
                            store,
                            storage_prefix,
                            ordinal,
                            item.filename,
                            "zip",
                            item.file_size,
                        )
                    )
            return extracted

    def _extract_tar(
        self, source: Path, store: EvidenceStore, storage_prefix: str
    ) -> list[ExtractedArchiveMember]:
        with tarfile.open(source, mode="r:*") as archive:
            all_members = archive.getmembers()
            if any(not item.isfile() and not item.isdir() for item in all_members):
                raise ArchiveExtractionError(
                    "TAR links, devices, and special members are not extracted."
                )
            members = [item for item in all_members if item.isfile()]
            self._validate_count(members)
            declared_total = 0
            normalized_names: set[str] = set()
            for item in members:
                normalized = _validate_member_name(item.name, self.policy.max_path_depth)
                if normalized in normalized_names:
                    raise ArchiveExtractionError("The archive contains duplicate member paths.")
                normalized_names.add(normalized)
                self._validate_declared_size(item.size)
                declared_total += item.size
                self._validate_total(declared_total)
            extracted: list[ExtractedArchiveMember] = []
            for ordinal, item in enumerate(members):
                stream = archive.extractfile(item)
                if stream is None:
                    raise ArchiveExtractionError(
                        "A TAR member could not be opened as a regular file."
                    )
                with stream:
                    extracted.append(
                        self._copy_member(
                            stream,
                            store,
                            storage_prefix,
                            ordinal,
                            item.name,
                            "tar",
                            item.size,
                        )
                    )
            return extracted

    def _copy_member(
        self,
        stream: IO[bytes],
        store: EvidenceStore,
        storage_prefix: str,
        ordinal: int,
        original_name: str,
        archive_format: Literal["zip", "tar"],
        declared_size: int,
    ) -> ExtractedArchiveMember:
        name_digest = sha256(original_name.encode("utf-8", "surrogatepass")).hexdigest()[:20]
        storage_key = f"{storage_prefix}/member-{ordinal:06d}-{name_digest}.bin"
        writer = store.open_writer(storage_key)
        observed_size = 0
        try:
            while True:
                chunk = stream.read(self.policy.stream_chunk_bytes)
                if not chunk:
                    break
                observed_size += len(chunk)
                if observed_size > self.policy.max_member_bytes:
                    raise ArchiveExtractionError("An archive member exceeded its byte limit.")
                writer.write(chunk)
            if observed_size != declared_size:
                raise ArchiveExtractionError(
                    "An archive member size did not match its declaration."
                )
            stored = writer.seal()
        except Exception:
            writer.close(preserve_partial=False)
            raise
        return ExtractedArchiveMember(
            ordinal=ordinal,
            original_name=original_name,
            storage_key=stored.storage_key,
            size_bytes=stored.size_bytes,
            sha256=stored.sha256,
            archive_format=archive_format,
        )

    def _validate_count(self, members: Sequence[object]) -> None:
        if len(members) > self.policy.max_members:
            raise ArchiveExtractionError("The archive exceeds the member-count limit.")

    def _validate_declared_size(self, size: int) -> None:
        if size < 0 or size > self.policy.max_member_bytes:
            raise ArchiveExtractionError("An archive member exceeds the byte limit.")

    def _validate_total(self, size: int) -> None:
        if size > self.policy.max_total_bytes:
            raise ArchiveExtractionError("The archive exceeds the total extracted-byte limit.")


def _validate_source(source: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ArchiveExtractionError("The archive source must be a regular non-link file.")


def _validate_member_name(value: str, max_depth: int) -> str:
    if not value or "\x00" in value or "\\" in value or _DRIVE_PREFIX.match(value):
        raise ArchiveExtractionError("The archive contains an unsafe member path.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveExtractionError("The archive contains an unsafe member path.")
    if len(path.parts) > max_depth or any(ord(character) < 32 for character in value):
        raise ArchiveExtractionError("The archive member path violates policy limits.")
    return "/".join(path.parts).casefold()
