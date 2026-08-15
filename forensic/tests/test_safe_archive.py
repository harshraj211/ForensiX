import io
import stat
import tarfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

from forensix_forensic.evidence_io import (
    ArchiveExtractionError,
    ArchivePolicy,
    SafeArchiveExtractor,
    validate_archive_member_name,
)
from forensix_forensic.storage import EvidenceStore


def test_zip_extracts_to_generated_contained_keys(tmp_path: Path) -> None:
    source = tmp_path / "evidence.bin"
    with ZipFile(source, "w", ZIP_DEFLATED) as archive:
        archive.writestr("data/contacts2.db", b"fixture-database")
    store = EvidenceStore(tmp_path / "store")

    result = SafeArchiveExtractor().extract(source, store, "case/derivatives")

    assert len(result) == 1
    assert result[0].original_name == "data/contacts2.db"
    assert result[0].storage_key.startswith("case/derivatives/member-000000-")
    assert (
        store.resolve(result[0].storage_key, require_file=True).read_bytes() == b"fixture-database"
    )


@pytest.mark.parametrize("name", ["../escape.db", "/absolute.db", "C:/drive.db"])
def test_zip_rejects_unsafe_member_paths(tmp_path: Path, name: str) -> None:
    source = tmp_path / "unsafe.zip"
    with ZipFile(source, "w") as archive:
        archive.writestr(name, b"content")

    with pytest.raises(ArchiveExtractionError, match="unsafe"):
        SafeArchiveExtractor().extract(source, EvidenceStore(tmp_path / "store"), "safe/output")


def test_zip_rejects_excessive_compression_ratio(tmp_path: Path) -> None:
    source = tmp_path / "bomb.zip"
    with ZipFile(source, "w", ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", b"0" * 100_000)

    with pytest.raises(ArchiveExtractionError, match="compression-ratio"):
        SafeArchiveExtractor(ArchivePolicy(max_compression_ratio=2)).extract(
            source, EvidenceStore(tmp_path / "store"), "safe/output"
        )


def test_zip_rejects_symbolic_link_members(tmp_path: Path) -> None:
    source = tmp_path / "link.zip"
    link = ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ZipFile(source, "w") as archive:
        archive.writestr(link, "target")

    with pytest.raises(ArchiveExtractionError, match="links"):
        SafeArchiveExtractor().extract(source, EvidenceStore(tmp_path / "store"), "safe/output")


def test_tar_rejects_symbolic_link_members(tmp_path: Path) -> None:
    source = tmp_path / "link.tar"
    with tarfile.open(source, "w") as archive:
        regular = tarfile.TarInfo("data.db")
        regular.size = 4
        archive.addfile(regular, io.BytesIO(b"data"))
        link = tarfile.TarInfo("shortcut")
        link.type = tarfile.SYMTYPE
        link.linkname = "data.db"
        archive.addfile(link)

    with pytest.raises(ArchiveExtractionError, match="special"):
        SafeArchiveExtractor().extract(source, EvidenceStore(tmp_path / "store"), "safe/output")


def test_public_member_name_validator_normalizes_safe_paths() -> None:
    assert validate_archive_member_name("Data/Contacts2.DB", 4) == "data/contacts2.db"


@pytest.mark.parametrize("name", ["../escape.db", "/absolute.db", "C:/drive.db", "a\\b.db"])
def test_public_member_name_validator_rejects_unsafe_paths(name: str) -> None:
    with pytest.raises(ArchiveExtractionError):
        validate_archive_member_name(name, 4)
