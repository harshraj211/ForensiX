"""Tests for Kirin, Rockchip, OfflineHashExtractor, and HashcatLauncher modules."""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path

from forensix_forensic.extractors.hardware import (
    HashcatConfig,
    HashcatLauncher,
    HashcatMode,
    KirinExtractor,
    RockchipExtractor,
    build_erecovery_packet,
    build_rk_command,
    parse_partition_table,
    parse_rk_flash_id,
    parse_rk_partition_table,
    verify_erecovery_handshake,
)


class TestKirinAndRockchip:
    def test_build_erecovery_packet(self) -> None:
        pkt = build_erecovery_packet(cmd=0x01, payload=b"test")
        assert pkt.startswith(bytes([0x55, 0xAA, 0x5A, 0xA5]))
        assert len(pkt) == 4 + 6 + 4

    def test_verify_erecovery_handshake(self) -> None:
        resp = bytes([0xAA, 0x55, 0xA5, 0x5A, 0x00, 0x00])
        assert verify_erecovery_handshake(b"", resp) is True

    def test_parse_partition_table(self) -> None:
        header = b"\x00" * 16
        name_bytes = b"userdata".ljust(32, b"\x00")
        rec = name_bytes + struct.pack("<III", 2048, 8192, 1) + b"\x00" * 20
        data = header + rec
        parts = parse_partition_table(data)
        assert len(parts) == 1
        assert parts[0].name == "userdata"
        assert parts[0].start_block == 2048
        assert parts[0].num_blocks == 8192

    def test_kirin_extractor_missing_recovery(self, tmp_path: Path) -> None:
        extractor = KirinExtractor(
            recovery_image_path=tmp_path / "missing.img",
            output_dir=tmp_path / "out",
        )
        res = asyncio.run(extractor.acquire(["userdata"], "CASE-001", "examiner"))
        assert res.success is False
        assert "not found" in (res.error_message or "")

    def test_build_rk_command(self) -> None:
        cbw = build_rk_command(cmd=0x14, start_sector=1024, num_sectors=64)
        assert len(cbw) == 31
        assert cbw.startswith(b"USBC")

    def test_parse_rk_partition_table(self) -> None:
        name_utf16 = "system".encode("utf-16-le").ljust(32, b"\x00")
        rec = name_utf16 + struct.pack("<II", 1024, 4096) + b"\x00" * 32
        parts = parse_rk_partition_table(rec)
        assert len(parts) == 1
        assert parts[0].name == "system"
        assert parts[0].start_sector == 1024
        assert parts[0].num_sectors == 4096

    def test_parse_rk_flash_id(self) -> None:
        mfr, flash_type = parse_rk_flash_id(bytes([0x15, 0x01, 0x02, 0x03, 0x04]))
        assert flash_type == "emmc"

    def test_rockchip_extractor_missing_loader(self, tmp_path: Path) -> None:
        extractor = RockchipExtractor(
            loader_path=tmp_path / "missing.bin",
            output_dir=tmp_path / "out",
        )
        res = asyncio.run(extractor.acquire(["userdata"], "CASE-001", "examiner"))
        assert res.success is False
        assert "not found" in (res.error_message or "")


class TestOfflineHashAndHashcat:
    def test_hashcat_launcher_missing_binary(self, tmp_path: Path) -> None:
        cfg = HashcatConfig(hashcat_binary=tmp_path / "missing_hashcat.exe")
        launcher = HashcatLauncher(cfg, tmp_path / "hashcat_out")
        mode = HashcatMode.ANDROID_GATEKEEPER
        res = asyncio.run(launcher.run(tmp_path / "hash.txt", mode, "CASE-001"))
        assert res.success is False
        assert "not found" in (res.error_message or "")

    def test_hashcat_build_command_mask(self, tmp_path: Path) -> None:
        hc_bin = tmp_path / "hashcat.exe"
        hc_bin.write_bytes(b"fake")
        cfg = HashcatConfig(hashcat_binary=hc_bin, mask="?d?d?d?d")
        launcher = HashcatLauncher(cfg, tmp_path / "out")
        mode = HashcatMode.ANDROID_GATEKEEPER
        cmd = launcher._build_command(tmp_path / "hash.txt", mode, tmp_path / "pot.txt")
        assert "-a" in cmd
        assert "3" in cmd
        assert "?d?d?d?d" in cmd
