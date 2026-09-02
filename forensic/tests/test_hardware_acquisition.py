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

import pytest

# ---------------------------------------------------------------------------
# ChipsetDetector
# ---------------------------------------------------------------------------
from forensix_forensic.extractors.hardware.chipset_detector import (
    USB_CHIPSET_MAP,
    ChipsetFamily,
    _match_hardware_keyword,
    _match_platform_prefix,
    _protocol_for_family,
)


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

from forensix_forensic.extractors.hardware.mtk_brom import (
    _HS_RECV,
    _HS_SEND,
    DA_CMD_READ_PARTITION,
    MtkBromState,
    MtkChipset,
    build_read_command,
    parse_flash_id_response,
    verify_handshake_echo,
)


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
        with pytest.raises(Exception):
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

from forensix_forensic.extractors.hardware.qualcomm_edl import (
    SAHARA_HELLO,
    build_firehose_configure,
    build_firehose_read,
    build_sahara_done,
    build_sahara_hello_response,
    decode_sahara_hello,
    parse_firehose_response,
)


class TestQualcommEdl:
    def _make_hello(self, version: int = 2, mode: int = 0) -> bytes:
        return struct.pack(
            "<IIIIIII",
            SAHARA_HELLO,
            48,
            version,
            1,
            0x800,
            mode,
            0,
        ) + b"\x00" * 20

    def test_decode_sahara_hello_basic(self) -> None:
        raw = self._make_hello(version=2, mode=0)
        hello = decode_sahara_hello(raw)
        assert hello.version == 2
        assert hello.mode == 0

    def test_decode_sahara_hello_too_short(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            decode_sahara_hello(b"\x01" * 10)

    def test_decode_sahara_hello_wrong_cmd(self) -> None:
        bad = struct.pack("<II", 0xFF, 48) + b"\x00" * 40
        with pytest.raises(ValueError, match="Expected Sahara Hello"):
            decode_sahara_hello(bad)

    def test_build_hello_response_length(self) -> None:
        resp = build_sahara_hello_response(2, 0)
        assert len(resp) == 48

    def test_build_sahara_done_length(self) -> None:
        done = build_sahara_done()
        assert len(done) == 8
        cmd, length = struct.unpack("<II", done)
        assert cmd == 0x05  # SAHARA_DONE
        assert length == 8

    def test_build_firehose_configure_xml(self) -> None:
        xml = build_firehose_configure()
        assert b"configure" in xml
        assert b"MaxPayloadSizeToTargetInBytes" in xml

    def test_build_firehose_read_xml(self) -> None:
        xml = build_firehose_read(start_sector=2048, num_sectors=64, lun=0)
        assert b"start_sector" in xml
        assert b"2048" in xml
        assert b"64" in xml

    def test_parse_firehose_response_ack(self) -> None:
        xml = b'<?xml version="1.0" ?><data><response value="ACK" rawmsg="Ok" /></data>'
        success, msg = parse_firehose_response(xml)
        assert success is True
        assert msg == "Ok"

    def test_parse_firehose_response_nak(self) -> None:
        xml = b'<?xml version="1.0" ?><data><response value="NAK" rawmsg="Error" /></data>'
        success, _ = parse_firehose_response(xml)
        assert success is False

    def test_parse_firehose_response_bad_xml(self) -> None:
        success, msg = parse_firehose_response(b"not xml")
        assert success is False

    def test_qualcomm_extractor_programmer_missing(self, tmp_path: Path) -> None:
        from forensix_forensic.extractors.hardware.qualcomm_edl import QualcommEdlExtractor

        extractor = QualcommEdlExtractor(
            programmer_path=tmp_path / "missing.mbn",
            output_dir=tmp_path / "out",
        )
        result = asyncio.run(extractor.acquire(["userdata"], "CASE-001", "examiner"))
        assert result.success is False


# ---------------------------------------------------------------------------
# Unisoc FDL
# ---------------------------------------------------------------------------

from forensix_forensic.extractors.hardware.unisoc_fdl import (
    FDL_CMD_READ_PARTITION,
    FDL_FRAME_START,
    build_fdl_packet,
    build_read_partition_cmd,
    compute_fdl_checksum,
    hdlc_decode,
    hdlc_encode,
)


class TestUnisocFdl:
    def test_hdlc_encode_simple(self) -> None:
        raw = b"\x01\x02\x03"
        encoded = hdlc_encode(raw)
        assert encoded[0] == FDL_FRAME_START
        assert encoded[-1] == FDL_FRAME_START
        assert encoded[1:-1] == raw

    def test_hdlc_encode_escape_7e(self) -> None:
        raw = bytes([0x7E, 0x01])
        encoded = hdlc_encode(raw)
        assert 0x7D in encoded  # escape byte present
        assert encoded.count(0x7E) == 2  # only start/end delimiters

    def test_hdlc_decode_roundtrip(self) -> None:
        raw = b"\x01\x02\x03\x04\x7D\x55"
        encoded = hdlc_encode(raw)
        decoded = hdlc_decode(encoded)
        assert decoded == raw

    def test_hdlc_decode_bad_frame(self) -> None:
        with pytest.raises(ValueError):
            hdlc_decode(b"\x00\x01\x02\x7E")

    def test_compute_fdl_checksum(self) -> None:
        # XOR of [0x01, 0x02, 0x03] = 0x00
        assert compute_fdl_checksum(b"\x01\x02\x03") == 0x00

    def test_compute_fdl_checksum_nonzero(self) -> None:
        assert compute_fdl_checksum(b"\xFF") == 0xFF

    def test_build_fdl_packet_structure(self) -> None:
        pkt = build_fdl_packet(FDL_CMD_READ_PARTITION, b"payload")
        decoded = hdlc_decode(pkt)
        cmd, length = struct.unpack(">HH", decoded[:4])
        assert cmd == FDL_CMD_READ_PARTITION
        assert length == 7  # len("payload")

    def test_build_read_partition_cmd_name(self) -> None:
        cmd_pkt = build_read_partition_cmd("userdata", 1024, 8192)
        decoded = hdlc_decode(cmd_pkt)
        # Payload starts at offset 4 (after cmd+len header)
        payload = decoded[4:-1]  # strip checksum
        partition_name_raw = payload[:32]
        name = partition_name_raw.split(b"\x00", 1)[0].decode()
        assert name == "userdata"

    def test_spreadtrum_extractor_fdl_missing(self, tmp_path: Path) -> None:
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

from forensix_forensic.extractors.hardware.samsung_download import (
    CMD_PIT,
    ODIN_PKT_SIZE,
    PIT_HEADER_MAGIC,
    PIT_HEADER_SIZE,
    PIT_RECORD_SIZE,
    build_odin_packet,
    parse_pit,
)


from typing import Any

def _build_pit_binary(records: list[dict[str, Any]]) -> bytes:
    """Helper to build a minimal PIT binary for testing."""
    header = struct.pack("<II", PIT_HEADER_MAGIC, len(records)) + b"\x00" * (PIT_HEADER_SIZE - 8)
    body = b""
    for rec in records:
        name = rec.get("name", "test").encode("ascii")[:31].ljust(32, b"\x00")
        file_name = b"\x00" * 32
        delta_name = b"\x00" * 32
        fields = struct.pack(
            "<IIIIIIIII",
            rec.get("binary_type", 1),
            rec.get("device_type", 2),
            rec.get("partition_id", 1),
            rec.get("attributes", 1),
            rec.get("update_attr", 0),
            rec.get("block_size", 1),
            rec.get("block_count", 1024),
            rec.get("file_offset", 0),
            rec.get("file_size", 0),
        )
        entry = fields + name + file_name + delta_name
        assert len(entry) == PIT_RECORD_SIZE, f"PIT record wrong size: {len(entry)}"
        body += entry
    return header + body


class TestSamsungDownloadMode:
    def test_parse_pit_empty(self) -> None:
        pit = _build_pit_binary([])
        count, records = parse_pit(pit)
        assert count == 0
        assert records == []

    def test_parse_pit_single_record(self) -> None:
        pit = _build_pit_binary([{"name": "userdata", "block_count": 2048}])
        count, records = parse_pit(pit)
        assert count == 1
        assert records[0].partition_name == "userdata"
        assert records[0].block_count == 2048

    def test_parse_pit_multiple_records(self) -> None:
        parts = [
            {"name": "system", "block_count": 4096, "partition_id": 1},
            {"name": "userdata", "block_count": 8192, "partition_id": 2},
            {"name": "boot", "block_count": 512, "partition_id": 3},
        ]
        pit = _build_pit_binary(parts)
        count, records = parse_pit(pit)
        assert count == 3
        names = [r.partition_name for r in records]
        assert "system" in names
        assert "userdata" in names

    def test_parse_pit_wrong_magic(self) -> None:
        bad_pit = b"\xDE\xAD\xBE\xEF" + b"\x00" * 100
        with pytest.raises(ValueError, match="Invalid PIT magic"):
            parse_pit(bad_pit)

    def test_parse_pit_too_short(self) -> None:
        with pytest.raises(ValueError):
            parse_pit(b"\x00" * 4)

    def test_pit_record_size_bytes(self) -> None:
        pit = _build_pit_binary([{"name": "data", "block_size": 1, "block_count": 1024}])
        _, records = parse_pit(pit)
        assert records[0].size_bytes == 1 * 1024 * 512

    def test_build_odin_packet_length(self) -> None:
        pkt = build_odin_packet(CMD_PIT)
        assert len(pkt) == ODIN_PKT_SIZE

    def test_build_odin_packet_cmd_byte(self) -> None:
        pkt = build_odin_packet(CMD_PIT)
        assert pkt[0] == CMD_PIT

    def test_samsung_extractor_no_usb(self, tmp_path: Path) -> None:
        from forensix_forensic.extractors.hardware.samsung_download import (
            SamsungDownloadModeExtractor,
        )

        extractor = SamsungDownloadModeExtractor(output_dir=tmp_path / "out")
        result = asyncio.run(extractor.acquire(["userdata"], "CASE-001", "examiner"))
        assert result.success is False


# ---------------------------------------------------------------------------
# Screen Lock Assessment
# ---------------------------------------------------------------------------

from forensix_forensic.extractors.hardware.screen_lock_assessment import (
    MAX_ATTEMPTS,
    MIN_ATTEMPT_INTERVAL_SECONDS,
    LockType,
    ScreenLockAssessmentService,
    WipeRisk,
    _estimate_search_space,
)


class TestScreenLockAssessment:
    def test_estimate_none(self) -> None:
        assert _estimate_search_space(LockType.NONE, None, None) == 0

    def test_estimate_swipe(self) -> None:
        assert _estimate_search_space(LockType.SWIPE, None, None) == 0

    def test_estimate_pin_4(self) -> None:
        assert _estimate_search_space(LockType.PIN, 4, None) == 10_000

    def test_estimate_pin_6(self) -> None:
        assert _estimate_search_space(LockType.PIN, 6, None) == 1_000_000

    def test_estimate_pin_default(self) -> None:
        # None pin_length defaults to 4
        assert _estimate_search_space(LockType.PIN, None, None) == 10_000

    def test_estimate_pattern(self) -> None:
        space = _estimate_search_space(LockType.PATTERN, None, "medium")
        assert space == 389_112

    def test_estimate_password(self) -> None:
        space = _estimate_search_space(LockType.PASSWORD, None, None)
        assert space == 62 ** 8

    def test_max_attempts_constant(self) -> None:
        assert MAX_ATTEMPTS == 5

    def test_min_interval_constant(self) -> None:
        assert MIN_ATTEMPT_INTERVAL_SECONDS >= 1.0

    def test_classify_lock_type_none(self) -> None:
        svc = ScreenLockAssessmentService.__new__(ScreenLockAssessmentService)
        svc._timeline = []  # type: ignore[attr-defined]
        result = svc._classify_lock_type({"lockscreen.password_type": "0"})
        assert result == LockType.NONE

    def test_classify_lock_type_pin(self) -> None:
        svc = ScreenLockAssessmentService.__new__(ScreenLockAssessmentService)
        result = svc._classify_lock_type({"lockscreen.password_type": "196608"})
        assert result == LockType.PIN

    def test_classify_lock_type_pattern(self) -> None:
        svc = ScreenLockAssessmentService.__new__(ScreenLockAssessmentService)
        result = svc._classify_lock_type({"lockscreen.password_type": "131072"})
        assert result == LockType.PATTERN

    def test_classify_wipe_risk_high(self) -> None:
        risk = ScreenLockAssessmentService._classify_wipe_risk(5, {})
        assert risk == WipeRisk.HIGH

    def test_classify_wipe_risk_medium(self) -> None:
        risk = ScreenLockAssessmentService._classify_wipe_risk(10, {})
        assert risk == WipeRisk.MEDIUM

    def test_classify_wipe_risk_low(self) -> None:
        risk = ScreenLockAssessmentService._classify_wipe_risk(None, {})
        assert risk == WipeRisk.LOW


# ---------------------------------------------------------------------------
# Keystore Reader
# ---------------------------------------------------------------------------

from forensix_forensic.extractors.hardware.keystore_reader import (
    _ALGORITHM_NAMES,
    KM_ALGORITHM_AES,
    _blob_name_to_alias,
    _scan_km_tags,
    parse_keyblob_header,
)


class TestKeystoreReader:
    def test_blob_name_to_alias_uid_prefix(self) -> None:
        assert _blob_name_to_alias("1000_mykey") == "mykey"

    def test_blob_name_to_alias_no_prefix(self) -> None:
        assert _blob_name_to_alias("USRPKEY_myalias") == "USRPKEY_myalias"

    def test_blob_name_to_alias_dot_key(self) -> None:
        assert _blob_name_to_alias("0_keyalias.key") == "keyalias"

    def test_parse_keyblob_header_too_short(self) -> None:
        result = parse_keyblob_header(b"\x00\x01", "alias", 0)
        assert result is None

    def test_parse_keyblob_header_encrypted(self) -> None:
        # Encrypted blob (type=1): header should still parse without crash
        data = bytes([0x01, 0x02]) + b"\x00" * 50
        result = parse_keyblob_header(data, "mykey", 0)
        assert result is not None
        assert result.blob_type == 1

    def test_parse_keyblob_header_sha256_populated(self) -> None:
        import hashlib

        data = b"\x00" * 64
        result = parse_keyblob_header(data, "k", 0)
        assert result is not None
        assert result.blob_sha256 == hashlib.sha256(data).hexdigest()

    def test_scan_km_tags_aes(self) -> None:
        # Build a minimal tag stream: KM_TAG_ALGORITHM (tag_num=2) = AES (32)
        tag_id = (0x01 << 24) | 2  # enum tag type, tag number 2
        payload = struct.pack("<II", tag_id, KM_ALGORITHM_AES)
        algorithm, key_size, purposes, origin = _scan_km_tags(payload)
        assert algorithm == "AES"

    def test_algorithm_names_complete(self) -> None:
        assert _ALGORITHM_NAMES[KM_ALGORITHM_AES] == "AES"


# ---------------------------------------------------------------------------
# Physical Acquisition Router
# ---------------------------------------------------------------------------

from forensix_forensic.extractors.hardware.physical_acquisition import (
    PhysicalAcquisitionRouter,
    RouterConfig,
)


class TestPhysicalAcquisitionRouter:
    def test_router_no_device(self, tmp_path: Path) -> None:
        """Without pyusb or a real device, router should fail gracefully."""
        config = RouterConfig(output_dir=tmp_path / "out")
        router = PhysicalAcquisitionRouter(config)
        result = asyncio.run(
            router.acquire(["userdata"], case_id="CASE-001", operator_id="examiner")
        )
        assert result.success is False
        assert result.protocol_used == "unsupported"
        assert result.error_message is not None

    def test_router_config_defaults(self, tmp_path: Path) -> None:
        config = RouterConfig(output_dir=tmp_path)
        assert config.mtk_da_path is None
        assert config.qualcomm_programmer_path is None
        assert config.usb_timeout_ms == 10000
