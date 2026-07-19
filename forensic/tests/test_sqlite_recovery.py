from pathlib import Path

from forensix_forensic.evidence_io import assess_sqlite_recovery_file


def test_sqlite_freelist_probe_reports_candidates_without_recovery_claim(tmp_path: Path) -> None:
    header = bytearray(100)
    header[:16] = b"SQLite format 3\x00"
    header[16:18] = (4096).to_bytes(2, "big")
    header[28:32] = (20).to_bytes(4, "big")
    header[32:36] = (7).to_bytes(4, "big")
    header[36:40] = (3).to_bytes(4, "big")
    source = tmp_path / "messages.db"
    source.write_bytes(header)

    candidate = assess_sqlite_recovery_file(source, "data/messages.db")

    assert candidate.source_kind == "sqlite_database"
    assert candidate.status == "candidate_regions_observed"
    assert candidate.candidate_region_count == 3
    assert "do not prove deleted records" in candidate.limitations[0]
    assert len(candidate.canonical_sha256) == 64


def test_sqlite_wal_probe_counts_only_complete_frames(tmp_path: Path) -> None:
    page_size = 1024
    header = bytearray(32)
    header[:4] = b"\x37\x7f\x06\x82"
    header[4:8] = (3_007_000).to_bytes(4, "big")
    header[8:12] = page_size.to_bytes(4, "big")
    source = tmp_path / "messages.db-wal"
    source.write_bytes(header + bytes((24 + page_size) * 2) + b"partial")

    candidate = assess_sqlite_recovery_file(source, "data/messages.db-wal")

    assert candidate.source_kind == "sqlite_wal"
    assert candidate.candidate_region_count == 2
    assert candidate.confidence == "low"
    assert candidate.metadata["trailing_bytes"] == 7


def test_rollback_journal_probe_remains_low_confidence(tmp_path: Path) -> None:
    header = bytearray(28)
    header[:8] = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"
    header[8:12] = (4).to_bytes(4, "big")
    header[16:20] = (30).to_bytes(4, "big")
    header[20:24] = (512).to_bytes(4, "big")
    header[24:28] = (4096).to_bytes(4, "big")
    source = tmp_path / "contacts2.db-journal"
    source.write_bytes(header + b"page records not interpreted")

    candidate = assess_sqlite_recovery_file(source, "data/contacts2.db-journal")

    assert candidate.source_kind == "sqlite_rollback_journal"
    assert candidate.status == "candidate_regions_observed"
    assert candidate.confidence == "low"
    assert "not proof" in candidate.limitations[0]


def test_unsupported_input_does_not_become_recovered(tmp_path: Path) -> None:
    source = tmp_path / "opaque.bin"
    source.write_bytes(b"not sqlite")

    candidate = assess_sqlite_recovery_file(source, "opaque.bin")

    assert candidate.source_kind == "unknown"
    assert candidate.status == "unsupported"
    assert candidate.candidate_region_count == 0
