import hashlib
from pathlib import Path

import pytest

from forensix_forensic.storage import (
    EvidenceAlreadyExistsError,
    EvidenceStore,
    InvalidStorageKeyError,
    StorageBoundaryError,
    sha256_file,
)


@pytest.mark.parametrize(
    "storage_key",
    [
        "",
        "/absolute/file.bin",
        "../escape.bin",
        "case/../escape.bin",
        "case\\escape.bin",
        "C:/escape.bin",
        "case//file.bin",
        "case/CON.txt",
        "case/name with spaces.bin",
    ],
)
def test_store_rejects_unsafe_storage_keys(tmp_path: Path, storage_key: str) -> None:
    store = EvidenceStore(tmp_path / "evidence")

    with pytest.raises(InvalidStorageKeyError):
        store.resolve(storage_key)


def test_writer_seals_bytes_and_returns_streaming_hash(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")
    payload = (b"ForensiX-evidence\x00" * 128_000) + b"tail"

    with store.open_writer("cases/case-1/acquisitions/acq-1/raw/item.bin") as writer:
        for offset in range(0, len(payload), 8191):
            writer.write(payload[offset : offset + 8191])
        result = writer.seal()

    final_path = store.resolve(result.storage_key, require_file=True)
    assert final_path.read_bytes() == payload
    assert result.size_bytes == len(payload)
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert store.hash(result.storage_key).hexdigest == result.sha256
    assert store.verify(result.storage_key, result.sha256)


def test_writer_refuses_to_overwrite_existing_evidence(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")
    storage_key = "cases/case-1/raw/item.bin"

    with store.open_writer(storage_key) as writer:
        writer.write(b"original")
        writer.seal()

    with pytest.raises(EvidenceAlreadyExistsError):
        store.open_writer(storage_key)

    assert store.resolve(storage_key).read_bytes() == b"original"


def test_writer_preserves_partial_bytes_after_interruption(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")

    with pytest.raises(ConnectionError), store.open_writer("cases/case-1/raw/item.bin") as writer:
        writer.write(b"partial-evidence")
        partial_path = writer.partial_path
        raise ConnectionError("simulated device disconnect")

    assert partial_path.exists()
    assert partial_path.read_bytes() == b"partial-evidence"
    assert not store.resolve("cases/case-1/raw/item.bin").exists()


def test_writer_removes_unsealed_partial_after_clean_exit(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")

    with store.open_writer("cases/case-1/raw/item.bin") as writer:
        writer.write(b"not-sealed")
        partial_path = writer.partial_path

    assert not partial_path.exists()


def test_external_reservation_seals_subprocess_created_bytes(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")

    with store.reserve_external("cases/case-1/raw/file.bin") as reservation:
        reservation.partial_path.write_bytes(b"known external bytes")
        result = reservation.seal()

    assert (
        store.resolve(result.storage_key, require_file=True).read_bytes() == b"known external bytes"
    )
    assert result.sha256 == hashlib.sha256(b"known external bytes").hexdigest()


def test_store_rejects_symlink_component(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_directory = store.root / "cases"

    try:
        linked_directory.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is not available in this test environment")

    with pytest.raises(StorageBoundaryError):
        store.resolve("cases/case-1/raw/item.bin")


def test_hash_helper_rejects_invalid_chunk_size(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"sample")

    with pytest.raises(ValueError, match="chunk_size"):
        sha256_file(path, chunk_size=0)


def test_verification_rejects_malformed_expected_hash(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")

    with pytest.raises(ValueError, match="64 lowercase"):
        store.verify("cases/case-1/raw/item.bin", "NOT-A-HASH")


def test_dual_hash_streaming_integrity(tmp_path: Path) -> None:
    from forensix_forensic.storage import StreamHasher, dual_hash_bytes, dual_hash_file

    data = b"forensic-evidence-block-" * 5000
    expected_sha256 = hashlib.sha256(data).hexdigest()
    expected_blake2b = hashlib.blake2b(data, digest_size=32).hexdigest()
    expected_sha3 = hashlib.sha3_256(data).hexdigest()

    # In-memory dual hash
    mem_res = dual_hash_bytes(data, secondary_algo="blake2b")
    assert mem_res.primary_algorithm == "sha256"
    assert mem_res.primary_hexdigest == expected_sha256
    assert mem_res.secondary_algorithm == "blake2b"
    assert mem_res.secondary_hexdigest == expected_blake2b

    # File streaming dual hash
    file_path = tmp_path / "stream_test.bin"
    file_path.write_bytes(data)

    file_res = dual_hash_file(file_path, chunk_size=4096, secondary_algo="blake2b")
    assert file_res.primary_hexdigest == expected_sha256
    assert file_res.secondary_hexdigest == expected_blake2b

    # SHA3-256 secondary option
    sha3_res = dual_hash_file(file_path, chunk_size=4096, secondary_algo="sha3_256")
    assert sha3_res.primary_hexdigest == expected_sha256
    assert sha3_res.secondary_hexdigest == expected_sha3

    # Incremental StreamHasher
    hasher = StreamHasher(secondary_algo="blake2b")
    for i in range(0, len(data), 1024):
        hasher.update(data[i : i + 1024])
    inc_res = hasher.finalize()
    assert inc_res.primary_hexdigest == expected_sha256
    assert inc_res.secondary_hexdigest == expected_blake2b


def test_store_dual_hash_and_verify(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")
    payload = b"dual-hash-custody-provenance-test-data"

    with store.open_writer("cases/case-100/raw/payload.bin") as writer:
        writer.write(payload)
        sealed = writer.seal()

    assert sealed.sha256 == hashlib.sha256(payload).hexdigest()
    assert sealed.blake2b == hashlib.blake2b(payload, digest_size=32).hexdigest()

    dhash = store.dual_hash("cases/case-100/raw/payload.bin")
    assert dhash.primary_hexdigest == sealed.sha256
    assert dhash.secondary_hexdigest == sealed.blake2b

    assert store.verify_dual(
        "cases/case-100/raw/payload.bin",
        expected_sha256=sealed.sha256,
        expected_secondary=sealed.blake2b,
    )
