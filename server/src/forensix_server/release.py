"""Integrity sealing and independent verification for portable release bundles."""

import hashlib
import json
import os
import re
import shutil
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
_MAX_RELEASE_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ReleaseArtifact:
    archive_path: Path
    archive_sha256: str
    manifest_sha256: str


def seal_portable_bundle(
    bundle_dir: Path,
    output_dir: Path,
    *,
    version: str,
    platform_tag: str,
    source_commit: str,
    source_dirty: bool,
    sbom_path: Path,
    signature_status: str = "unsigned",
) -> ReleaseArtifact:
    """Create a deterministic ZIP with an internal per-file hash manifest."""
    if not _VERSION_PATTERN.fullmatch(version):
        raise ValueError("Release version must be a semantic version.")
    if not re.fullmatch(r"[a-z0-9._-]{3,80}", platform_tag):
        raise ValueError("Platform tag is invalid.")
    if not re.fullmatch(r"[a-f0-9]{40}", source_commit):
        raise ValueError("Source commit must be a full Git SHA-1.")
    if signature_status not in {"unsigned", "authenticode"}:
        raise ValueError("Signature status must be unsigned or authenticode.")
    bundle = bundle_dir.expanduser().resolve()
    output = output_dir.expanduser().resolve()
    sbom = sbom_path.expanduser().resolve()
    if not bundle.is_dir() or bundle.is_symlink():
        raise ValueError("Bundle directory must be an existing regular directory.")
    if not sbom.is_file() or sbom.is_symlink():
        raise ValueError("SBOM must be an existing regular file.")
    output.mkdir(parents=True, exist_ok=True)
    bundled_sbom = bundle / "ForensiX.cdx.json"
    shutil.copyfile(sbom, bundled_sbom)
    members = _bundle_members(bundle, excluded={"release-manifest.json"})
    manifest = {
        "schema_version": "forensix-release/1.0",
        "product": "ForensiX",
        "version": version,
        "platform": platform_tag,
        "source_commit": source_commit,
        "source_dirty": source_dirty,
        "signature_status": signature_status,
        "limitations": [
            *([] if signature_status == "authenticode" else [
                "This portable engineering build is not code-signed or notarized.",
            ]),
            "Verify the archive and internal manifest before controlled evaluation.",
        ],
        "files": members,
    }
    manifest_bytes = _canonical_json(manifest)
    manifest_path = bundle / "release-manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    archive = output / f"ForensiX-{version}-{platform_tag}.zip"
    temporary = output / f".{archive.name}.partial"
    if temporary.exists():
        temporary.unlink()
    _write_deterministic_zip(bundle, temporary)
    os.replace(temporary, archive)
    archive_sha256 = _hash_file(archive)
    checksum = archive.with_suffix(f"{archive.suffix}.sha256")
    checksum.write_text(f"{archive_sha256}  {archive.name}\n", encoding="ascii")
    return ReleaseArtifact(archive, archive_sha256, manifest_sha256)


def verify_portable_bundle(archive_path: Path) -> bool:
    """Verify archive SHA-256 sidecar, safe names, manifest, and every bundled file."""
    archive = archive_path.expanduser().resolve()
    sidecar = archive.with_suffix(f"{archive.suffix}.sha256")
    if not archive.is_file() or not sidecar.is_file():
        return False
    if sidecar.stat().st_size > 256:
        return False
    expected_archive = sidecar.read_text(encoding="ascii").split(maxsplit=1)[0]
    if not re.fullmatch(r"[a-f0-9]{64}", expected_archive):
        return False
    if _hash_file(archive) != expected_archive:
        return False
    try:
        with zipfile.ZipFile(archive) as zipped:
            zip_members = zipped.infolist()
            names = {member.filename for member in zip_members}
            if len(names) != len(zip_members):
                return False
            if "release-manifest.json" not in names or not all(
                _safe_member(name) for name in names
            ):
                return False
            if sum(member.file_size for member in zip_members) > _MAX_RELEASE_UNCOMPRESSED_BYTES:
                return False
            manifest = json.loads(zipped.read("release-manifest.json"))
            expected_files = manifest.get("files")
            if not isinstance(expected_files, list):
                return False
            if not all(isinstance(item, dict) for item in expected_files):
                return False
            if names != {item.get("path") for item in expected_files} | {"release-manifest.json"}:
                return False
            for item in expected_files:
                name = item.get("path")
                size = item.get("size_bytes")
                digest = item.get("sha256")
                if (
                    not isinstance(name, str)
                    or not isinstance(size, int)
                    or size < 0
                    or not isinstance(digest, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", digest)
                    or zipped.getinfo(name).file_size != size
                ):
                    return False
                payload = zipped.read(name)
                if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
                    return False
    except (OSError, ValueError, KeyError, json.JSONDecodeError, zipfile.BadZipFile):
        return False
    return True


def _bundle_members(bundle: Path, *, excluded: set[str]) -> list[dict[str, str | int]]:
    members: list[dict[str, str | int]] = []
    for path in sorted(bundle.rglob("*")):
        if path.is_symlink():
            resolved = path.resolve()
            if not resolved.is_file() or not resolved.is_relative_to(bundle):
                raise ValueError("Release bundles cannot contain external symbolic links.")
        if not path.is_file():
            continue
        relative = path.relative_to(bundle).as_posix()
        if relative in excluded:
            continue
        members.append(
            {"path": relative, "size_bytes": path.stat().st_size, "sha256": _hash_file(path)}
        )
    if not members:
        raise ValueError("Release bundle is empty.")
    return members


def _write_deterministic_zip(bundle: Path, destination: Path) -> None:
    with zipfile.ZipFile(
        destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as zipped:
        for path in sorted(item for item in bundle.rglob("*") if item.is_file()):
            relative = path.relative_to(bundle).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = stat.S_IMODE(path.stat().st_mode)
            info.external_attr = (mode or 0o644) << 16
            with path.open("rb") as source, zipped.open(info, "w") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)


def _safe_member(name: str) -> bool:
    candidate = PurePosixPath(name)
    return bool(name) and not candidate.is_absolute() and ".." not in candidate.parts


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
