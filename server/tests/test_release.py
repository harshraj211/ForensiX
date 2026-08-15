import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from forensix_server.release import seal_portable_bundle, verify_portable_bundle


def test_release_bundle_is_sealed_and_independently_verified(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "ForensiX.exe"
    executable.write_bytes(b"controlled executable fixture")
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"bomFormat":"CycloneDX"}\n', encoding="utf-8")

    artifact = seal_portable_bundle(
        bundle,
        tmp_path / "release",
        version="0.1.0-test.1",
        platform_tag="windows-x86_64",
        source_commit="a" * 40,
        source_dirty=False,
        sbom_path=sbom,
    )

    assert artifact.archive_path.is_file()
    assert verify_portable_bundle(artifact.archive_path)
    assert artifact.archive_sha256 == hashlib.sha256(artifact.archive_path.read_bytes()).hexdigest()
    with zipfile.ZipFile(artifact.archive_path) as zipped:
        manifest = json.loads(zipped.read("release-manifest.json"))
    assert manifest["signature_status"] == "unsigned"
    assert manifest["source_dirty"] is False
    assert {item["path"] for item in manifest["files"]} == {
        "ForensiX.cdx.json",
        "ForensiX.exe",
    }


def test_release_bundle_records_authenticode_status(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "ForensiX.exe").write_bytes(b"signed executable fixture")
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")

    artifact = seal_portable_bundle(
        bundle,
        tmp_path / "release",
        version="1.0.0",
        platform_tag="windows-x86_64",
        source_commit="d" * 40,
        source_dirty=False,
        sbom_path=sbom,
        signature_status="authenticode",
    )

    with zipfile.ZipFile(artifact.archive_path) as zipped:
        manifest = json.loads(zipped.read("release-manifest.json"))
    assert manifest["signature_status"] == "authenticode"
    assert all("not code-signed" not in item for item in manifest["limitations"])


def test_release_verification_detects_archive_tampering(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "ForensiX").write_bytes(b"binary")
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    artifact = seal_portable_bundle(
        bundle,
        tmp_path / "release",
        version="1.0.0",
        platform_tag="linux-x86_64",
        source_commit="b" * 40,
        source_dirty=False,
        sbom_path=sbom,
    )

    with artifact.archive_path.open("ab") as target:
        target.write(b"tampered")

    assert not verify_portable_bundle(artifact.archive_path)


def test_release_bundle_rejects_symlinks(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    target = tmp_path / "outside"
    target.write_bytes(b"outside")
    try:
        (bundle / "link").symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable in this environment")
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="symbolic links"):
        seal_portable_bundle(
            bundle,
            tmp_path / "release",
            version="1.0.0",
            platform_tag="linux-x86_64",
            source_commit="c" * 40,
            source_dirty=True,
            sbom_path=sbom,
        )
