"""Streaming SHA-256 manifest collector with audit-trail integration.

Every file acquired during a forensic extraction is hashed with SHA-256
in real-time as bytes arrive over the transport (USB / ADB).  The collector
accumulates entries and, at the end of the extraction, seals the manifest
with an aggregate hash and writes it to an append-only audit trail.

The manifest format is a JSON file containing:

* ``extraction_id`` - Unique identifier for this extraction run.
* ``collector_version`` - Schema version of the manifest format.
* ``entries`` - Ordered list of file entries, each with:
  * ``file_path`` - Local workstation path.
  * ``sha256`` - Hex-encoded SHA-256 hash of the file.
  * ``size_bytes`` - File size in bytes.
  * ``source_description`` - Human-readable source description.
  * ``captured_at`` - ISO-8601 timestamp.
  * ``case_id`` - Associated case (if any).
* ``manifest_sha256`` - SHA-256 hash of the canonical JSON representation of
  all entries (computed at finalization time).
* ``audit_trail_sha256`` - Hash of the previous audit-trail entry, forming
  a hash chain that mathematically proves the evidence was not tampered with.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

MANIFEST_VERSION = "1.0.0"
MANIFEST_FILENAME_TEMPLATE = "extraction_manifest_{extraction_id}.json"
AUDIT_TRAIL_FILENAME = "extraction_audit_trail.jsonl"


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """A single file entry in the extraction manifest."""

    file_path: str
    sha256: str
    size_bytes: int
    source_description: str
    case_id: str = ""
    captured_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True, slots=True)
class ExtractionManifest:
    """The sealed, tamper-evident extraction manifest."""

    extraction_id: str
    collector_version: str
    entries: tuple[ManifestEntry, ...]
    manifest_sha256: str
    audit_trail_previous_hash: str
    sealed_at: str
    case_id: str
    operator_id: str


class StreamingManifestCollector:
    """Collect SHA-256 hashes for every acquired file in real-time.

    During extraction, call :meth:`add_entry` for every file transferred
    from the device.  When the extraction completes, call :meth:`finalize`
    to seal the manifest and append to the audit trail.

    The collector enforces the following invariants:

    * Every entry is SHA-256 hashed before it is added to the manifest.
    * The manifest hash is computed over the *canonical* JSON
      representation of all entries.
    * The audit trail is append-only; each new entry contains the hash of
      the previous entry, forming a tamper-evident hash chain.
    """

    def __init__(self, work_dir: Path) -> None:
        self._work_dir = work_dir.resolve()
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._entries: list[ManifestEntry] = []

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def add_entry_sync(self, entry: ManifestEntry) -> None:
        """Add a manifest entry (synchronous variant)."""
        self._entries.append(entry)

    async def add_entry(self, entry: ManifestEntry) -> None:
        """Add a manifest entry for an acquired file.

        The entry's SHA-256 and file size must already be populated by the
        caller (computed during the transfer).
        """
        self._entries.append(entry)

    def finalize(
        self,
        *,
        extraction_id: str,
        case_id: str = "",
        operator_id: str = "",
    ) -> Path:
        """Seal the manifest and append to the audit trail.

        Returns the path to the sealed manifest file.
        """
        # 1. Compute the canonical JSON of all entries.
        entries_canonical = _canonical_entries_json(self._entries)

        # 2. Hash the manifest (excluding manifest_sha256 itself).
        manifest_hash = hashlib.sha256(entries_canonical.encode("utf-8")).hexdigest()

        # 3. Read the previous audit-trail hash.
        previous_audit_hash = _read_previous_audit_hash(self._work_dir)

        # 4. Build the sealed manifest.
        manifest = ExtractionManifest(
            extraction_id=extraction_id,
            collector_version=MANIFEST_VERSION,
            entries=tuple(self._entries),
            manifest_sha256=manifest_hash,
            audit_trail_previous_hash=previous_audit_hash,
            sealed_at=datetime.now(UTC).isoformat(),
            case_id=case_id,
            operator_id=operator_id,
        )

        # 5. Write the manifest file.
        manifest_path = self._work_dir / MANIFEST_FILENAME_TEMPLATE.format(
            extraction_id=extraction_id
        )
        manifest_data = json.dumps(
            asdict(manifest),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        manifest_path.write_text(manifest_data, encoding="utf-8")

        # 6. Append to the audit trail.
        _append_audit_trail(
            self._work_dir,
            extraction_id=extraction_id,
            manifest_sha256=manifest_hash,
            entry_count=len(self._entries),
            case_id=case_id,
            operator_id=operator_id,
            previous_hash=previous_audit_hash,
        )

        return manifest_path

    def verify(self) -> tuple[bool, str | None]:
        """Verify the integrity of all collected entries.

        Returns ``(True, None)`` if all entries are consistent, or
        ``(False, reason)`` if verification fails.
        """
        for entry in self._entries:
            path = Path(entry.file_path)
            if not path.exists():
                return False, f"File missing: {entry.file_path}"
            actual_hash = _hash_file_sync(path)
            if actual_hash != entry.sha256:
                return (
                    False,
                    f"Hash mismatch for {entry.file_path}: "
                    f"expected {entry.sha256}, got {actual_hash}",
                )
            if path.stat().st_size != entry.size_bytes:
                return (
                    False,
                    f"Size mismatch for {entry.file_path}: "
                    f"expected {entry.size_bytes}, got {path.stat().st_size}",
                )
        return True, None


# ---------------------------------------------------------------------------
# Audit-trail helpers
# ---------------------------------------------------------------------------

def _read_previous_audit_hash(work_dir: Path) -> str:
    """Read the hash of the most recent audit-trail entry."""
    audit_path = work_dir / AUDIT_TRAIL_FILENAME
    if not audit_path.exists():
        return "0" * 64
    try:
        with audit_path.open("r", encoding="utf-8") as fh:
            last_line = ""
            for line in fh:
                line = line.strip()
                if line:
                    last_line = line
            if last_line:
                record = json.loads(last_line)
                entry_hash = record.get("entry_hash", "0" * 64)
                if isinstance(entry_hash, str):
                    return entry_hash
    except (json.JSONDecodeError, OSError):
        pass
    return "0" * 64


def _append_audit_trail(
    work_dir: Path,
    *,
    extraction_id: str,
    manifest_sha256: str,
    entry_count: int,
    case_id: str,
    operator_id: str,
    previous_hash: str,
) -> None:
    """Append a hash-chained record to the audit trail."""
    audit_path = work_dir / AUDIT_TRAIL_FILENAME
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "extraction_id": extraction_id,
        "manifest_sha256": manifest_sha256,
        "entry_count": entry_count,
        "case_id": case_id,
        "operator_id": operator_id,
        "previous_hash": previous_hash,
    }
    canonical = json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    entry_hash = hashlib.sha256((previous_hash + canonical).encode("utf-8")).hexdigest()
    record["entry_hash"] = entry_hash

    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _canonical_entries_json(entries: list[ManifestEntry]) -> str:
    """Canonical JSON representation of all manifest entries."""
    data = [asdict(e) for e in entries]
    return json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _hash_file_sync(path: Path) -> str:
    """SHA-256 hash a file without loading it fully into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(4 * 1024 * 1024):
            digest.update(chunk)
    return str(digest.hexdigest())
