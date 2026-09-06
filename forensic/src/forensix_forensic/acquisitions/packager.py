"""Forensic Evidence Packager.

Computes SHA-256 digests for all extracted evidence files, constructs canonical evidence manifests,
and seals the acquisition into an immutable evidence archive.
"""

import json
import zipfile
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from forensix_forensic.capabilities.decision_engine import AcquisitionVector

from .models import (
    AcquisitionArtifactFile,
    AcquisitionContainerManifest,
    AcquisitionExecutionState,
    AcquisitionPipelineResult,
)


class ForensicEvidencePackager:
    """Packages raw extraction directories into sealed evidence containers."""

    def package(
        self,
        *,
        acquisition_id: str,
        case_id: str,
        device_serial: str,
        vector_used: AcquisitionVector,
        yield_score: int,
        started_at: datetime,
        finished_at: datetime,
        raw_extraction_dir: Path,
        output_archive_dir: Path,
        limitations: tuple[str, ...] = (),
    ) -> AcquisitionPipelineResult:
        if not raw_extraction_dir.exists() or not raw_extraction_dir.is_dir():
            return AcquisitionPipelineResult(
                acquisition_id=acquisition_id,
                success=False,
                state=AcquisitionExecutionState.FAILED,
                vector_used=vector_used,
                output_dir=str(raw_extraction_dir),
                error_message=f"Raw extraction directory does not exist: {raw_extraction_dir}",
            )

        output_archive_dir.mkdir(parents=True, exist_ok=True)
        archive_path = output_archive_dir / f"forensix_evidence_{acquisition_id}.zip"

        artifacts: list[AcquisitionArtifactFile] = []
        total_size = 0

        # Gather all files in raw_extraction_dir
        all_files = sorted(
            [f for f in raw_extraction_dir.rglob("*") if f.is_file()],
            key=lambda p: str(p.relative_to(raw_extraction_dir)),
        )

        for file_path in all_files:
            rel_path = file_path.relative_to(raw_extraction_dir).as_posix()
            size_bytes = file_path.stat().st_size
            total_size += size_bytes

            file_hash = self._compute_sha256(file_path)
            category = self._categorize_artifact(rel_path)

            artifacts.append(
                AcquisitionArtifactFile(
                    relative_path=rel_path,
                    size_bytes=size_bytes,
                    sha256_hash=file_hash,
                    category=category,
                    source_vector=vector_used,
                )
            )

        duration = (finished_at - started_at).total_seconds()

        # Construct unsigned manifest first to hash it canonically
        pre_manifest_dict = {
            "acquisition_id": acquisition_id,
            "case_id": case_id,
            "device_serial": device_serial,
            "duration_seconds": duration,
            "finished_at_iso": finished_at.isoformat(),
            "limitations": list(limitations),
            "started_at_iso": started_at.isoformat(),
            "artifacts": [art.model_dump() for art in artifacts],
            "total_size_bytes": total_size,
            "vector_used": vector_used.value,
            "yield_score": yield_score,
        }

        canonical_json = json.dumps(pre_manifest_dict, sort_keys=True, separators=(",", ":"))
        manifest_hash = sha256(canonical_json.encode("utf-8")).hexdigest()

        manifest = AcquisitionContainerManifest(
            acquisition_id=acquisition_id,
            case_id=case_id,
            device_serial=device_serial,
            vector_used=vector_used,
            yield_score=yield_score,
            started_at_iso=started_at.isoformat(),
            finished_at_iso=finished_at.isoformat(),
            duration_seconds=duration,
            artifacts=tuple(artifacts),
            total_size_bytes=total_size,
            manifest_sha256=manifest_hash,
            limitations=limitations,
        )

        # Write manifest file into extraction directory
        manifest_file = raw_extraction_dir / "evidence_manifest.json"
        manifest_file.write_text(
            json.dumps(manifest.model_dump(), indent=2, sort_keys=True), encoding="utf-8"
        )

        # Create zip archive
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zip_out:
            for item in raw_extraction_dir.rglob("*"):
                if item.is_file():
                    arc_name = item.relative_to(raw_extraction_dir).as_posix()
                    zip_out.write(item, arcname=arc_name)

        return AcquisitionPipelineResult(
            acquisition_id=acquisition_id,
            success=True,
            state=AcquisitionExecutionState.SEALED,
            vector_used=vector_used,
            output_dir=str(raw_extraction_dir),
            archive_path=str(archive_path),
            manifest=manifest,
        )

    @staticmethod
    def _compute_sha256(file_path: Path) -> str:
        hasher = sha256()
        with file_path.open("rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def _categorize_artifact(relative_path: str) -> str:
        path_lower = relative_path.lower()
        if "device_metadata" in path_lower:
            return "device_metadata"
        if "installed_apps" in path_lower or "app_artifacts" in path_lower:
            return "app_intelligence"
        if "contacts" in path_lower:
            return "contacts"
        if "sms" in path_lower:
            return "sms"
        if "calls" in path_lower or "call_log" in path_lower:
            return "call_logs"
        if "media" in path_lower or path_lower.endswith(
            (".jpg", ".png", ".mp4", ".mp3", ".opus", ".webp")
        ):
            return "media"
        if "backup" in path_lower or path_lower.endswith((".db", ".sqlite", ".crypt14")):
            return "database_backup"
        return "general_artifact"
