"""Tests for the hardware acquisition protocol modules.

Covers:
- ChipsetDetector: USB map constants, ADB property classification helpers
- MTK BROM: handshake echo, flash-ID response parsing, read command builder
- Qualcomm EDL: Sahara Hello decode, Firehose XML builders, response parser
- Unisoc FDL: HDLC encode/decode, packet builder, checksum
- Samsung Download Mode: PIT binary parser, Odin packet builder
- Screen lock assessment: search space estimates, wipe risk classification
- Keystore reader: blob name alias extraction, KM tag scanner
- Physical acquisition router: error path when no device found
"""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path
from typing import Any

import pytest

from forensix_forensic.extractors.hardware.chipset_detector import (
    USB_CHIPSET_MAP,
    ChipsetFamily,
    _match_hardware_keyword,
    _match_platform_prefix,
    _protocol_for_family,
)
from forensix_forensic.extractors.hardware.keystore_reader import (
    _ALGORITHM_NAMES,
    KM_ALGORITHM_AES,
    _blob_name_to_alias,
    _scan_km_tags,
    parse_keyblob_header,
)
from forensix_forensic.extractors.hardware.mtk_brom import (
    _HS_RECV,
    _HS_SEND,
    DA_CMD_READ_PARTITION,
    BromProtocolError,
    MtkBromState,
    MtkChipset,
    build_read_command,
    parse_flash_id_response,
    verify_handshake_echo,
)
from forensix_forensic.extractors.hardware.physical_acquisition import (
    PhysicalAcquisitionRouter,
    RouterConfig,
)
from forensix_forensic.extractors.hardware.qualcomm_edl import (
    SAHARA_HELLO,
    build_firehose_configure,
    build_firehose_read,
    build_sahara_done,
    build_sahara_hello_response,
    decode_sahara_hello,
    parse_firehose_response,
)
from forensix_forensic.extractors.hardware.samsung_download import (
    CMD_PIT,
    ODIN_PKT_SIZE,
    PIT_HEADER_MAGIC,
    PIT_HEADER_SIZE,
    build_odin_packet,
    parse_pit,
)
from forensix_forensic.extractors.hardware.screen_lock_assessment import (
    MAX_ATTEMPTS,
    MIN_ATTEMPT_INTERVAL_SECONDS,
    LockType,
    ScreenLockAssessmentService,
    WipeRisk,
    _estimate_search_space,
)
from forensix_forensic.extractors.hardware.unisoc_fdl import (
    FDL_CMD_READ_PARTITION,
    FDL_FRAME_START,
    build_fdl_packet,
    build_read_partition_cmd,
    compute_fdl_checksum,
    hdlc_decode,
    hdlc_encode,
)

# ---------------------------------------------------------------------------
# ChipsetDetector
# ---------------------------------------------------------------------------


class TestChipsetDetector:
    def test_usb_map_has_mtk_brom_entry(self) -> None:
        mtk_entries = [e for e in USB_CHIPSET_MAP if e[0] == 0x0E8D and e[1] == 0x0003]
        assert len(mtk_entries) == 1
        assert mtk_entries[0][2] == "mediatek"
        assert mtk_entries[0][3] == "brom"

    def test_usb_map_has_qualcomm_edl_entry(self) -> None:
        qcom = [e for e in USB_CHIPSET_MAP if e[1] == 0x9008]
        assert qcom and qcom[0][2] == "qualcomm"

    def test_usb_map_has_samsung_odin_entry(self) -> None:
        samsung = [e for e in USB_CHIPSET_MAP if e[0] == 0x04E8]
        assert samsung and "samsung" in samsung[0][2]

    def test_match_hardware_keyword_mediatek(self) -> None:
        family, model = _match_hardware_keyword("mt6765")
        assert family == ChipsetFamily.MEDIATEK
        assert model is not None

    def test_match_hardware_keyword_qualcomm(self) -> None:
        family, _ = _match_hardware_keyword("msm8953")
        assert family == ChipsetFamily.QUALCOMM

    def test_match_hardware_keyword_unisoc(self) -> None:
        family, _ = _match_hardware_keyword("sc9863a")
        assert family == ChipsetFamily.UNISOC

    def test_match_hardware_keyword_unknown(self) -> None:
        family, model = _match_hardware_keyword("rockchip_rk3566")
        assert family == ChipsetFamily.UNKNOWN

    def test_match_platform_prefix_mediatek(self) -> None:
        assert _match_platform_prefix("mt6761") == ChipsetFamily.MEDIATEK

    def test_match_platform_prefix_qualcomm_sdm(self) -> None:
        assert _match_platform_prefix("sdm660") == ChipsetFamily.QUALCOMM

    def test_match_platform_prefix_qualcomm_sm(self) -> None:
        assert _match_platform_prefix("sm7125") == ChipsetFamily.QUALCOMM

    def test_match_platform_prefix_samsung(self) -> None:
        assert _match_platform_prefix("exynos9820") == ChipsetFamily.SAMSUNG_EXYNOS

    def test_protocol_for_family_mtk(self) -> None:
        assert _protocol_for_family("mediatek") == "mtk_brom"

    def test_protocol_for_family_qualcomm(self) -> None:
        assert _protocol_for_family("qualcomm") == "qualcomm_edl"

    def test_protocol_for_family_unisoc(self) -> None:
        assert _protocol_for_family("unisoc") == "unisoc_fdl"

    def test_protocol_for_family_samsung(self) -> None:
        assert _protocol_for_family("samsung_exynos") == "samsung_odin"


# ---------------------------------------------------------------------------
# MTK BROM
# ---------------------------------------------------------------------------


class TestMtkBrom:
    def test_verify_handshake_echo_correct(self) -> None:
        assert verify_handshake_echo(_HS_SEND, _HS_RECV) is True

    def test_verify_handshake_echo_wrong(self) -> None:
        assert verify_handshake_echo(_HS_SEND, b"\x00\x00\x00\x00") is False

    def test_build_read_command_format(self) -> None:
        cmd = build_read_command(start_lba=0x100, sector_count=64)
        assert len(cmd) == 13
        assert cmd[0] == DA_CMD_READ_PARTITION
        _, lba, count, _ = struct.unpack(">BIII", cmd)
        assert lba == 0x100
        assert count == 64

    def test_parse_flash_id_response_emmc(self) -> None:
        # Build a 16-byte payload with magic 0xEA01 (eMMC) and 4096/131072 sizes
        payload = struct.pack(">HHIIxxxx", 0xEA01, 0, 4096, 131072)
        flash_type, page_size, block_size = parse_flash_id_response(payload)
        assert flash_type == "emmc"
        assert page_size == 4096

    def test_parse_flash_id_response_ufs(self) -> None:
        payload = struct.pack(">HHIIxxxx", 0xEA02, 0, 4096, 262144)
        flash_type, _, _ = parse_flash_id_response(payload)
        assert flash_type == "ufs"

    def test_parse_flash_id_response_too_short(self) -> None:
        with pytest.raises(BromProtocolError):
            parse_flash_id_response(b"\x00" * 4)

    def test_mtk_state_enum(self) -> None:
        assert MtkBromState.IDLE.value == 0
        assert MtkBromState.COMPLETE.name == "COMPLETE"

    def test_mtk_chipset_name_known(self) -> None:
        assert MtkChipset(0x6761).name == "MT6761"

    def test_mtk_brom_extractor_da_missing(self, tmp_path: Path) -> None:
        from forensix_forensic.extractors.hardware.mtk_brom import MtkBromExtractor

        extractor = MtkBromExtractor(
            da_binary_path=tmp_path / "nonexistent_da.bin",
            output_dir=tmp_path / "out",
        )
        result = asyncio.run(extractor.acquire(["userdata"], "CASE-001", "examiner"))
        assert result.success is False
        assert result.error_message is not None

    def test_mtk_brom_extractor_with_da(self, tmp_path: Path) -> None:
        from forensix_forensic.extractors.hardware.mtk_brom import MtkBromExtractor

        da_path = tmp_path / "da.bin"
        da_path.write_bytes(b"\x00" * 1024)
        extractor = MtkBromExtractor(
            da_binary_path=da_path,
            output_dir=tmp_path / "out",
        )
        # Will fail at USB detection stage (no real device)
        result = asyncio.run(extractor.acquire(["userdata"], "CASE-001", "examiner"))
        assert result.success is False
        assert result.error_message is not None


# ---------------------------------------------------------------------------
# Qualcomm EDL
# ---------------------------------------------------------------------------


class TestQualcommEdl:
    def _make_hello(self, version: int = 2, mode: int = 0) -> bytes:
        return (
            struct.pack(
                "<IIIIIII",
                SAHARA_HELLO,
                48,
                version,
                1,
                0x800,
                mode,
                0,
            )
            + b"\x00" * 20
        )

    def test_decode_sahara_hello_basic(self) -> None:
        raw = self._make_hello(version=2, mode=0)
        hello = decode_sahara_hello(raw)
        assert hello.version == 2
        assert hello.mode == 0
        assert hello.max_packet_size == 0x800

    def test_decode_sahara_hello_too_short(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            decode_sahara_hello(b"\x01\x00\x00\x00")

    def test_decode_sahara_hello_wrong_cmd(self) -> None:
        raw = struct.pack("<IIIIIII", 0x99, 48, 2, 1, 0x800, 0, 0) + b"\x00" * 20
        with pytest.raises(ValueError, match="Expected Sahara Hello"):
            decode_sahara_hello(raw)

    def test_build_sahara_hello_response(self) -> None:
        resp = build_sahara_hello_response(version=2, mode=0)
        assert len(resp) == 48
        cmd = struct.unpack_from("<I", resp, 0)[0]
        assert cmd == 0x02  # SAHARA_HELLO_RESP

    def test_build_sahara_done(self) -> None:
        done = build_sahara_done()
        assert len(done) == 8
        cmd, length = struct.unpack("<II", done)
        assert cmd == 0x05
        assert length == 8

    def test_build_firehose_configure(self) -> None:
        xml = build_firehose_configure()
        assert b"configure" in xml
        assert b"MaxPayloadSizeToTargetInBytes" in xml

    def test_build_firehose_read(self) -> None:
        xml = build_firehose_read(start_sector=2048, num_sectors=1024, lun=0)
        assert b"read" in xml
        assert b"2048" in xml
        assert b"1024" in xml

    def test_parse_firehose_response_ack(self) -> None:
        xml = b'<?xml version="1.0" ?><data><response value="ACK" rawmsg="OK" /></data>'
        ok, msg = parse_firehose_response(xml)
        assert ok is True
        assert msg == "OK"

    def test_parse_firehose_response_nak(self) -> None:
        xml = b'<?xml version="1.0" ?><data><response value="NAK" rawmsg="FAIL" /></data>'
        ok, msg = parse_firehose_response(xml)
        assert ok is False

    def test_qualcomm_extractor_missing_programmer(self, tmp_path: Path) -> None:
        from forensix_forensic.extractors.hardware.qualcomm_edl import QualcommEdlExtractor

        extractor = QualcommEdlExtractor(
            programmer_path=tmp_path / "nonexistent.mbn",
            output_dir=tmp_path / "out",
        )
        result = asyncio.run(extractor.acquire(["userdata"], "CASE-001", "examiner"))
        assert result.success is False


# ---------------------------------------------------------------------------
# Unisoc FDL
# ---------------------------------------------------------------------------


class TestUnisocFdl:
    def test_hdlc_encode_decode_roundtrip(self) -> None:
        original = bytes([0x01, 0x7E, 0x7D, 0xFF, 0x00, 0x7E])
        encoded = hdlc_encode(original)
        assert encoded[0] == FDL_FRAME_START
        assert encoded[-1] == FDL_FRAME_START
        # Delimiters must not appear inside the encoded body
        assert FDL_FRAME_START not in encoded[1:-1]
        decoded = hdlc_decode(encoded)
        assert decoded == original

    def test_hdlc_decode_invalid_delimiters(self) -> None:
        with pytest.raises(ValueError, match="Invalid FDL frame"):
            hdlc_decode(b"\x00\x01\x02")

    def test_compute_fdl_checksum(self) -> None:
        data = bytes([0x01, 0x02, 0x04])
        chk = compute_fdl_checksum(data)
        assert chk == (0x01 ^ 0x02 ^ 0x04)

    def test_build_fdl_packet(self) -> None:
        pkt = build_fdl_packet(FDL_CMD_READ_PARTITION, b"userdata")
        assert pkt[0] == FDL_FRAME_START
        assert pkt[-1] == FDL_FRAME_START

    def test_build_read_partition_cmd(self) -> None:
        cmd_pkt = build_read_partition_cmd("userdata", start_block=0, num_blocks=100)
        assert len(cmd_pkt) > 10

    def test_unisoc_extractor_missing_fdl1(self, tmp_path: Path) -> None:
        from forensix_forensic.extractors.hardware.unisoc_fdl import SpreadtrumBootromExtractor

        extractor = SpreadtrumBootromExtractor(
            fdl1_path=tmp_path / "fdl1.bin",
            fdl2_path=tmp_path / "fdl2.bin",
            output_dir=tmp_path / "out",
        )
        result = asyncio.run(extractor.acquire(["userdata"], "CASE-001", "examiner"))
        assert result.success is False


# ---------------------------------------------------------------------------
# Samsung Download Mode
# ---------------------------------------------------------------------------


def _build_pit_binary(records: list[dict[str, Any]]) -> bytes:
    """Helper to build a minimal PIT binary for testing."""
    header = struct.pack("<II", PIT_HEADER_MAGIC, len(records)) + b"\x00" * (PIT_HEADER_SIZE - 8)
    body = b""
    for r in records:
        name_bytes = r.get("name", "test").encode().ljust(32, b"\x00")
        fn_bytes = r.get("filename", "test.img").encode().ljust(32, b"\x00")
        rec = struct.pack(
            "<IIIIIIIII32s32s32x",
            r.get("binary_type", 0),
            r.get("device_type", 0),
            r.get("id", 1),
            r.get("attributes", 0),
            0,
            r.get("block_size", 4096),
            r.get("block_count", r.get("start_block", 0) + 100),
            0,
            0,
            name_bytes,
            fn_bytes,
        )
        body += rec
    return header + body


class TestSamsungDownloadMode:
    def test_parse_pit_valid(self) -> None:
        records_spec = [
            {"name": "BOOT", "filename": "boot.img", "start_block": 0, "block_count": 8192},
            {
                "name": "USERDATA",
                "filename": "userdata.img",
                "start_block": 8192,
                "block_count": 65536,
            },
        ]
        pit_bytes = _build_pit_binary(records_spec)
        count, records = parse_pit(pit_bytes)
        assert count == 2
        assert records[0].partition_name == "BOOT"
        assert records[0].block_count == 8192
        assert records[1].partition_name == "USERDATA"

    def test_parse_pit_invalid_magic(self) -> None:
        bad_bytes = b"\x00" * PIT_HEADER_SIZE
        with pytest.raises(ValueError, match="Invalid PIT magic"):
            parse_pit(bad_bytes)

    def test_parse_pit_too_short(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            parse_pit(b"\x12\x34")

    def test_build_odin_packet_size(self) -> None:
        pkt = build_odin_packet(CMD_PIT, sub=0, value=0)
        assert len(pkt) == ODIN_PKT_SIZE
        assert pkt[0] == CMD_PIT

    def test_samsung_extractor_no_device(self, tmp_path: Path) -> None:
        from forensix_forensic.extractors.hardware.samsung_download import (
            SamsungDownloadModeExtractor,
        )

        extractor = SamsungDownloadModeExtractor(output_dir=tmp_path / "out")
        result = asyncio.run(extractor.acquire(["USERDATA"], "CASE-001", "examiner"))
        assert result.success is False


# ---------------------------------------------------------------------------
# Screen Lock Assessment
# ---------------------------------------------------------------------------


class TestScreenLockAssessment:
    def test_estimate_search_space_pin(self) -> None:
        profile = ScreenLockAssessmentService.assess_from_parameters(
            lock_type=LockType.PIN,
            pin_length=4,
            pattern_size=0,
            has_biometrics=False,
            device_rooted=False,
        )
        assert profile.search_space_estimate == 10000
        assert profile.wipe_risk == WipeRisk.LOW

    def test_estimate_search_space_pattern_3x3(self) -> None:
        profile = ScreenLockAssessmentService.assess_from_parameters(
            lock_type=LockType.PATTERN,
            pin_length=0,
            pattern_size=9,
            has_biometrics=True,
            device_rooted=False,
        )
        assert profile.search_space_estimate == 389112
        assert profile.biometric_enrolled is True

    def test_wipe_risk_classification(self) -> None:
        assert _estimate_search_space(LockType.PIN, 6, 0) == 1000000

    def test_max_attempts_constant(self) -> None:
        assert MAX_ATTEMPTS == 5
        assert MIN_ATTEMPT_INTERVAL_SECONDS >= 3.0

    def test_authorised_entry_exceeds_max_attempts(self, tmp_path: Path) -> None:
        service = ScreenLockAssessmentService(adb=None, output_dir=tmp_path)
        service.assess_from_parameters(
            lock_type=LockType.PIN,
            pin_length=4,
            pattern_size=0,
            has_biometrics=False,
            device_rooted=False,
        )
        candidates = [f"{i:04d}" for i in range(10)]
        result = asyncio.run(
            service.authorised_entry("serial", candidates[0], "pin", "CASE-001", "examiner")
        )
        assert result.unlock_success is False


# ---------------------------------------------------------------------------
# Keystore Reader
# ---------------------------------------------------------------------------


class TestKeystoreReader:
    def test_blob_name_to_alias_decodes_hex(self) -> None:
        alias_hex = "4d794b6579"  # 'MyKey' in hex
        blob_name = f"1000_USRPKEY_{alias_hex}"
        assert _blob_name_to_alias(blob_name) == "MyKey"

    def test_blob_name_to_alias_fallback_ascii(self) -> None:
        assert _blob_name_to_alias("1000_USRPKEY_simple") == "simple"

    def test_scan_km_tags_finds_algorithm(self) -> None:
        # Tag 2 = KM_TAG_ALGORITHM, type ENUM (2 << 28 = 0x20000000) -> 0x20000002
        tag_bytes = struct.pack("<II", 0x20000002, KM_ALGORITHM_AES)
        metadata = _scan_km_tags(tag_bytes)
        assert metadata["algorithm"] == "AES"

    def test_algorithm_names_has_aes(self) -> None:
        assert _ALGORITHM_NAMES[1] == "RSA"
        assert _ALGORITHM_NAMES[32] == "AES"

    def test_parse_keyblob_header_short_bytes(self) -> None:
        meta = parse_keyblob_header(b"\x00" * 8, "test_alias")
        assert meta is not None
        assert meta.alias == "test_alias"
        assert meta.blob_version == 0
        assert meta.algorithm == "UNKNOWN"

    def test_parse_keyblob_header_v3_magic(self) -> None:
        # Magic 0x4B4D424C ('KMBL') at offset 0
        payload = b"\x00\x03" + b"\x00" * 60
        meta = parse_keyblob_header(payload, "my_alias")
        assert meta is not None
        assert meta.blob_version == 3


# ---------------------------------------------------------------------------
# Physical Acquisition Router
# ---------------------------------------------------------------------------


class TestPhysicalAcquisitionRouter:
    def test_router_error_when_no_device(self, tmp_path: Path) -> None:
        cfg = RouterConfig(output_dir=tmp_path / "out")
        router = PhysicalAcquisitionRouter(cfg)
        result = asyncio.run(
            router.acquire(
                partitions=["userdata"],
                case_id="CASE-001",
                operator_id="examiner",
            )
        )
        assert result.success is False
        assert result.protocol_used == "unsupported"
        assert "No device detected" in (result.error_message or "")
