"""Read-only normalization of a supplied, unencrypted Android Backup file."""

from __future__ import annotations

import tempfile
import zlib
from collections import Counter
from dataclasses import replace
from pathlib import Path

from forensix_forensic.evidence_io import (
    ArchivePolicy,
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    SafeArchiveExtractor,
    SafeSQLiteError,
)
from forensix_forensic.extractors.smart_switch import _sqlite_artifacts
from forensix_forensic.storage import EvidenceStore

MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARTIFACTS = 25_000


class LegacyAndroidBackupParser:
    metadata = ParserMetadata(
        parser_id="android.legacy_backup.archive",
        name="Legacy Android Backup archive",
        version="1.0.0",
        artifact_categories=("system", "file", "contact", "communication", "application"),
        required_tables=frozenset(),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=(".ab",),
        supported_artifact_types=("android_backup_summary", "android_backup_file"),
        description="Indexes files and supported Android SQLite records in unencrypted .ab files.",
        input_formats=("ab",),
    )

    def can_parse(self, source_locator: str) -> bool:
        return Path(source_locator).suffix.casefold() == ".ab"

    def parse(self, path: Path, context: ParserContext) -> list[ParsedArtifact]:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Android Backup input must be a regular examination copy")
        with tempfile.TemporaryDirectory(prefix="android-backup-") as temp:
            temp_root = Path(temp)
            tar_path = temp_root / "payload.tar"
            compression = _unpack_ab(path, tar_path)
            store = EvidenceStore(temp_root / "members")
            members = SafeArchiveExtractor(ArchivePolicy(
                max_members=10_000, max_member_bytes=512 * 1024 * 1024,
                max_total_bytes=MAX_UNCOMPRESSED_BYTES, max_path_depth=20,
            )).extract(tar_path, store, "files")
            artifacts: list[ParsedArtifact] = []
            issues: list[str] = []
            for member in members:
                if len(artifacts) >= MAX_ARTIFACTS:
                    issues.append("Artifact count reached the parser limit")
                    break
                name = member.original_name
                parts = name.split("/")
                package_name = parts[1] if len(parts) > 1 and parts[0] == "apps" else None
                common = {
                    "archive_member": name, "member_sha256": member.sha256,
                    "member_size_bytes": member.size_bytes, "package_name": package_name,
                }
                artifacts.append(ParsedArtifact(
                    category="file", subtype="android_backup_file", title=Path(name).name,
                    summary=name, event_time=None, source_locator=name,
                    status="active", confidence="high", metadata=common,
                ))
                if Path(name).suffix.casefold() not in {".db", ".sqlite", ".sqlite3"}:
                    continue
                try:
                    parsed = _sqlite_artifacts(
                        store.resolve(member.storage_key, require_file=True), name, context
                    )
                    for item in parsed[:MAX_ARTIFACTS - len(artifacts)]:
                        artifacts.append(replace(
                            item, source_locator=f"{name}#{item.source_locator}",
                            metadata={**item.metadata, **common},
                        ))
                except (ValueError, SafeSQLiteError) as error:
                    issues.append(f"{name}: {type(error).__name__}")
            summary = ParsedArtifact(
                category="system", subtype="android_backup_summary",
                title="Legacy Android Backup examination",
                summary=f"{len(members)} files; {len(artifacts)} indexed artifacts; {len(issues)} issues",
                event_time=None, source_locator="backup#summary",
                status="partial" if issues else "active", confidence="high",
                metadata={"member_count": len(members), "compression": compression,
                          "record_counts": dict(Counter(item.subtype for item in artifacts)),
                          "issues": issues[:200]},
            )
            return [summary, *artifacts]


def _unpack_ab(source: Path, destination: Path) -> str:
    with source.open("rb") as stream:
        header = [stream.readline(257).rstrip(b"\n") for _ in range(4)]
        if header[0] != b"ANDROID BACKUP" or header[1] not in {b"1", b"2", b"3", b"4", b"5"}:
            raise ValueError("Invalid Android Backup header")
        if header[2] not in {b"0", b"1"} or header[3].lower() != b"none":
            raise ValueError("Only unencrypted Android Backup payloads are supported")
        compressed = header[2] == b"1"
        decoder = zlib.decompressobj() if compressed else None
        total = 0
        with destination.open("wb") as output:
            while chunk := stream.read(1024 * 1024):
                decoded = decoder.decompress(chunk, MAX_UNCOMPRESSED_BYTES - total + 1) if decoder else chunk
                total += len(decoded)
                if total > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("Android Backup payload exceeds the unpacked size limit")
                output.write(decoded)
            if decoder:
                tail = decoder.flush(MAX_UNCOMPRESSED_BYTES - total + 1)
                total += len(tail)
                if total > MAX_UNCOMPRESSED_BYTES or not decoder.eof:
                    raise ValueError("Malformed or oversized Android Backup compressed payload")
                output.write(tail)
    return "zlib" if compressed else "none"
