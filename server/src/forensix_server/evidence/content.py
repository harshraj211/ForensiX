"""Integrity-checked access to sealed acquired files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Principal
from forensix_server.db import AcquiredEvidenceFileRecord, Database

from .service import ArtifactError, ArtifactService

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_TEXT_MIMES = frozenset(
    {
        "application/json",
        "application/xml",
        "text/csv",
        "text/plain",
    }
)


class ArtifactContentError(ArtifactError):
    code = "ARTIFACT_CONTENT_UNAVAILABLE"


class ArtifactContentIntegrityError(ArtifactContentError):
    code = "ARTIFACT_CONTENT_INTEGRITY_FAILED"


@dataclass(frozen=True, slots=True)
class ArtifactContent:
    path: Path
    filename: str
    declared_media_type: str
    inline_media_type: str | None
    sha256: str
    size_bytes: int


class ArtifactContentService:
    """Resolves a sealed object only after independently verifying its SHA-256."""

    def resolve(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        artifact_id: str,
    ) -> ArtifactContent:
        with database.session() as session:
            artifact = ArtifactService().get(session, principal, case_id, artifact_id)
            evidence = session.get(AcquiredEvidenceFileRecord, artifact.evidence_file_id)
            if (
                evidence is None
                or evidence.case_id != case_id
                or evidence.status != "completed"
                or evidence.sha256 is None
                or evidence.size_bytes is None
            ):
                raise ArtifactContentError("The sealed acquired file is unavailable.")
            storage_key = evidence.storage_key
            expected_sha256 = evidence.sha256
            expected_size = evidence.size_bytes
            filename = _safe_filename(artifact.title, artifact.id)
            declared_media_type = artifact.detected_mime

        store = EvidenceStore(database.data_dir / "evidence")
        path = store.resolve(storage_key, require_file=True)
        observed = store.hash(storage_key)
        if observed.hexdigest != expected_sha256 or observed.size_bytes != expected_size:
            raise ArtifactContentIntegrityError(
                "The acquired file failed integrity verification and cannot be opened "
                "or downloaded."
            )
        return ArtifactContent(
            path=path,
            filename=filename,
            declared_media_type=declared_media_type,
            inline_media_type=_verified_inline_media_type(path, declared_media_type),
            sha256=expected_sha256,
            size_bytes=expected_size,
        )


def _safe_filename(value: str, artifact_id: str) -> str:
    name = Path(value.replace("\\", "/")).name.strip()
    name = _CONTROL_CHARACTERS.sub("_", name)
    if not name or name in {".", ".."}:
        return f"forensix-artifact-{artifact_id}"
    return name[:240]


def _verified_inline_media_type(path: Path, declared_media_type: str) -> str | None:
    with path.open("rb") as stream:
        header = stream.read(4096)
    if declared_media_type == "application/pdf":
        return declared_media_type if header.startswith(b"%PDF-") else None
    if declared_media_type in _TEXT_MIMES:
        if b"\x00" in header:
            return None
        try:
            header.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return "text/plain; charset=utf-8"
    if declared_media_type in {"video/mp4", "video/quicktime", "video/3gpp", "audio/mp4"}:
        return declared_media_type if len(header) >= 12 and header[4:8] == b"ftyp" else None
    if declared_media_type in {"video/webm", "video/x-matroska"}:
        return declared_media_type if header.startswith(b"\x1a\x45\xdf\xa3") else None
    if declared_media_type == "audio/wav":
        is_wave = header.startswith(b"RIFF") and header[8:12] == b"WAVE"
        return declared_media_type if is_wave else None
    if declared_media_type == "audio/ogg":
        return declared_media_type if header.startswith(b"OggS") else None
    if declared_media_type == "audio/flac":
        return declared_media_type if header.startswith(b"fLaC") else None
    if declared_media_type == "audio/mpeg":
        is_frame = len(header) >= 2 and header[0] == 0xFF and header[1] & 0xE0 == 0xE0
        return declared_media_type if header.startswith(b"ID3") or is_frame else None
    if declared_media_type == "audio/aac":
        is_adts = len(header) >= 2 and header[0] == 0xFF and header[1] & 0xF6 == 0xF0
        return declared_media_type if is_adts else None
    return None
